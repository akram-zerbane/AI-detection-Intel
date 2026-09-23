import json
import re
from fastapi import FastAPI, HTTPException
import yaml
from agent.config import settings
from agent.schemas import CIRefinementPayload, DirectTelemetryPayload, RuleRefineRequest
from agent.services.agent_service import AgentService
from agent.services.gitlab_service import GitLabService

app = FastAPI(
    title="Detection-as-Code AI Agent Service",
    description="Autonomous Agent generating, staging, and refining Sigma detection rules",
    version="2.0.0"
)

agent_service = AgentService(
    groq_api_key=settings.GROQ_API_KEY,
    model_name=settings.GROQ_MODEL
)

gitlab_service = GitLabService(
    url=settings.GITLAB_URL,
    private_token=settings.GITLAB_TOKEN,
    project_id=settings.GITLAB_PROJECT_ID
)


def extract_technique_from_text(text: str) -> str:
    """Dynamically extracts MITRE ATT&CK technique IDs (e.g., T1059, T1059.001) from arbitrary strings."""
    match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", text, re.IGNORECASE)
    if match:
        return match.group(1).upper().replace(".", "_")
    return ""


@app.get("/health")
async def health_check():
    return {"status": "ok", "model": settings.GROQ_MODEL}


@app.post("/v1/telemetry/analyze")
async def receive_and_generate_rule(payload: DirectTelemetryPayload):
    try:
        if not payload.logs:
            raise HTTPException(
                status_code=400,
                detail="No log entries provided in 'logs' array."
            )

        artifacts = agent_service.parse_raw_logs(payload.logs)

        # 1. Dynamically identify technique ID across payload attributes
        raw_tech = (
            getattr(payload, "technique_id", None)
            or getattr(payload, "expected_technique", None)
        )

        if not raw_tech and payload.operation_name:
            raw_tech = extract_technique_from_text(payload.operation_name)

        if not raw_tech:
            for artifact in artifacts:
                if artifact.command_line:
                    raw_tech = extract_technique_from_text(artifact.command_line)
                    if raw_tech:
                        break

        if not raw_tech:
            raise HTTPException(
                status_code=422,
                detail="Missing technique_id. SOAR must forward a valid MITRE technique."
            )

        clean_tech = raw_tech.strip().upper().replace(".", "_").replace("/", "_").replace(" ", "_")
        payload.expected_technique = clean_tech
        payload.technique_id = clean_tech

        # 2. Synthesize Sigma Rule via Agent LLM
        sigma_yaml = agent_service.generate_sigma_rule(payload, artifacts)

        # 3. Dynamic Staging Path: Named strictly by technique ID without arbitrary prefixes
        staging_path = f"rules/rules_staging/{clean_tech.lower()}.yml"
        commit_success = False

        if gitlab_service:
            raw_telemetry_json = json.dumps(
                [log.dict() if hasattr(log, "dict") else log for log in payload.logs],
                indent=2
            )
            commit_success = gitlab_service.commit_staging_rule_with_fixture(
                technique_id=clean_tech,
                rule_yaml=sigma_yaml,
                raw_telemetry_json=raw_telemetry_json,
                branch="main"
            )

        return {
            "status": "success",
            "operation_id": payload.operation_id,
            "technique_id": clean_tech,
            "logs_processed": len(payload.logs),
            "artifacts_extracted": len(artifacts),
            "staging_path": staging_path,
            "committed_to_staging": commit_success,
            "sigma_rule": sigma_yaml,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/telemetry/refine")
async def refine_detection_rule(payload: CIRefinementPayload):
    try:
        feedback = payload.feedback
        current_rule_raw = feedback.rule_raw or ""

        # Dynamically determine the proper target file path
        parsed_yaml = yaml.safe_load(current_rule_raw) or {}
        extracted_tech = ""
        for tag in parsed_yaml.get("tags", []):
            extracted_tech = extract_technique_from_text(tag)
            if extracted_tech:
                break

        if not extracted_tech:
            extracted_tech = extract_technique_from_text(feedback.rule_path or "")

        # Target file is always the clean technique path
        if extracted_tech:
            target_path = f"rules/rules_staging/{extracted_tech.lower()}.yml"
        else:
            target_path = feedback.rule_path or "rules/rules_staging/refined_detection.yml"

        refine_req = RuleRefineRequest(
            current_sigma_yaml=current_rule_raw,
            false_positive_logs=feedback.fp_samples,
            missed_attack_logs=getattr(feedback, "missed_attack_logs", []) or [],
            feedback_notes=(
                f"Rule failed verification gates. True Positive Rate: {feedback.tp_rate:.1f}%, "
                f"False Positives: {feedback.fp_count}."
            )
        )
        refined_yaml = agent_service.refine_rule(refine_req)

        commit_success = False
        if gitlab_service:
            commit_success = gitlab_service.update_file_commit(
                file_path=target_path,
                branch=payload.branch,
                content=refined_yaml,
                commit_message=f"fix(dac): autonomous refinement for {target_path} [retry-ai]"
            )

        return {
            "status": "success",
            "refined": True,
            "committed": commit_success,
            "rule_path": target_path,
            "refined_rule": refined_yaml
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
