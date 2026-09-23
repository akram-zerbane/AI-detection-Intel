import json
import os
import re
import uuid
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from agent.schemas import (
    DetectionLogArtifact,
    DirectTelemetryPayload,
    RuleRefineRequest,
    SigmaRuleOutput,
)


def flatten_event(nested: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    """Flattens any nested log telemetry into flat key-value pairs."""
    flat: Dict[str, Any] = {}
    for k, v in nested.items():
        comp_key = f"{prefix}.{k}".strip(".") if prefix else k
        if isinstance(v, dict):
            flat.update(flatten_event(v, comp_key))
        elif isinstance(v, (str, int, float, bool)):
            flat[comp_key] = v
            leaf = comp_key.split(".")[-1]
            if leaf not in flat:
                flat[leaf] = v
    return flat


def extract_dynamic_evidence(missed_logs: List[Any], fp_logs: List[Any]) -> Dict[str, Any]:
    """Mines discriminative tokens while ignoring universal benign command fragments."""
    benign_corpus = []
    for entry in fp_logs:
        raw = entry.get("raw_fields", entry) if isinstance(entry, dict) else {}
        flat = flatten_event(raw) if isinstance(raw, dict) else {}
        benign_corpus.append(" ".join(str(val) for val in flat.values()).lower())
    benign_blob = " ".join(benign_corpus)

    # Universal low-signal noise to reject from selection
    noise_blacklist = {
        "cmd", "cmd.exe", "powershell", "powershell.exe", "/c", "/k",
        "conhost.exe", "system32", "windows", "true", "false", "exit"
    }

    raw_cmds = []
    unique_executables = set()

    for entry in missed_logs:
        raw = entry.get("raw_fields", entry) if isinstance(entry, dict) else {}
        flat = flatten_event(raw) if isinstance(raw, dict) else {}
        for k, v in flat.items():
            k_low = k.lower()
            val_str = str(v).strip()
            if any(term in k_low for term in ["commandline", "cmd", "scriptblock"]) and val_str:
                raw_cmds.append(val_str)
            if any(term in k_low for term in ["image", "process.name", "executable"]) and val_str:
                base = os.path.basename(val_str).lower()
                if base not in noise_blacklist and base not in benign_blob:
                    unique_executables.add(base)

    token_counter = Counter()
    for cmd in raw_cmds:
        # Match parameter flags, cmdlets, path tokens, or specific invocation switches
        tokens = re.findall(r"\b[A-Za-z0-9_-]{4,}\b|/[a-zA-Z0-9_-]+|-[a-zA-Z0-9_-]+", cmd)
        for t in tokens:
            t_low = t.lower()
            if t_low not in noise_blacklist and t_low not in benign_blob:
                token_counter[t] += 1

    high_signal_tokens = [tok for tok, count in token_counter.most_common(12)]
    
    suggested_criteria = {}
    if high_signal_tokens:
        suggested_criteria["CommandLine|contains"] = high_signal_tokens
    if unique_executables:
        suggested_criteria["Image|endswith"] = list(unique_executables)[:4]

    return suggested_criteria


def resolve_metadata(rule_yaml_str: str, payload: Optional[DirectTelemetryPayload] = None) -> Tuple[str, str, Dict[str, str]]:
    rule_data = yaml.safe_load(rule_yaml_str) if rule_yaml_str else {}
    if not isinstance(rule_data, dict):
        rule_data = {}

    technique = (
        getattr(payload, "technique_id", None)
        or (getattr(payload, "expected_technique", None) if payload else None)
    )
    if not technique:
        for tag in rule_data.get("tags", []):
            match = re.search(r"t\d{4}(?:\.\d{3})?", tag, re.IGNORECASE)
            if match:
                technique = match.group(0).upper().replace(".", "_")
                break
    technique = technique or "T1059"

    tactic = getattr(payload, "tactic", None) if payload else None
    if not tactic:
        for tag in rule_data.get("tags", []):
            if tag.startswith("attack.") and not re.search(r"t\d", tag, re.I) and len(tag) > 7:
                tactic = tag.split("attack.")[1]
                break
    tactic = (tactic or "execution").lower()

    logsource = rule_data.get("logsource") or {"category": "process_creation", "product": "windows"}
    return technique, tactic, logsource


class AgentService:

    def __init__(self, groq_api_key: str, model_name: str = "openai/gpt-oss-120b"):
        self.llm = ChatGroq(api_key=groq_api_key, model=model_name, temperature=0.0)
        self.structured_llm = self.llm.with_structured_output(SigmaRuleOutput, method="function_calling")

    def parse_raw_logs(self, raw_logs: List[Dict[str, Any]]) -> List[DetectionLogArtifact]:
        artifacts = []
        for log in raw_logs:
            flat = flatten_event(log)
            artifacts.append(
                DetectionLogArtifact(
                    event_id=flat.get("event_id") or flat.get("event.code"),
                    image=flat.get("Image") or flat.get("process.executable") or flat.get("image"),
                    command_line=flat.get("CommandLine") or flat.get("process.command_line") or flat.get("cmd"),
                    parent_image=flat.get("ParentImage") or flat.get("process.parent.executable"),
                    network_destination=flat.get("DestinationIp") or flat.get("destination.ip"),
                    raw_log=log,
                )
            )
        return artifacts

    def generate_sigma_rule(self, payload: DirectTelemetryPayload, artifacts: List[DetectionLogArtifact]) -> str:
        technique, tactic, default_logsource = resolve_metadata("", payload=payload)
        telemetry_lines = [
            str({k: v for k, v in a.model_dump().items() if v and k != "raw_log"})
            for a in artifacts
            if (a.command_line or a.image or a.network_destination)
        ]

        telemetry_summary = "\n".join(telemetry_lines[:35]) if telemetry_lines else (
            f"- [ACTION]: {payload.ability_command or technique}\n"
            f"- [HOST]: {payload.target_host or 'Endpoint'}"
        )

        prompt = ChatPromptTemplate.from_messages([
            (
                "system",
                "You are an expert Detection Engineer creating production-ready Sigma rules.\n\n"
                "STRICT PRODUCTION REQUIREMENTS:\n"
                "1. NO AMBIGUOUS MATCHES: Never match solely on bare utility names ('whoami', 'ipconfig', 'powershell') without suspicious arguments or flags.\n"
                "2. UNIFIED SELECTION: Group criteria into a single 'selection' block with list-based OR matching.\n"
                "3. CONDITION: Must simply be 'selection'.\n"
                "4. STATUS: Set 'status: test'.\n"
                "5. TAGS: Output 'attack.{tactic}' and 'attack.{technique}'."
            ),
            (
                "human",
                "Operation: {operation_name}\n"
                "Technique: {technique}\n"
                "Telemetry:\n{telemetry}"
            ),
        ])

        formatted = prompt.format_messages(
            operation_name=payload.operation_name or "Adversary Emulation",
            technique=technique,
            tactic=tactic,
            telemetry=telemetry_summary,
        )

        try:
            result: SigmaRuleOutput = self.structured_llm.invoke(formatted)
        except Exception:
            extracted = re.findall(r"\b[A-Za-z0-9_-]{4,}\b", payload.ability_command or technique)
            result = SigmaRuleOutput(
                title=f"Suspicious {technique} Activity",
                id=str(uuid.uuid4()),
                status="test",
                description=f"Detects execution behaviors associated with {technique}.",
                mitre_attack_id=technique,
                mitre_tactic=tactic,
                logsource=default_logsource,
                detection={"selection": {"CommandLine|contains": extracted[:4] or [technique]}, "condition": "selection"},
                falsepositives=["Administrative activities"],
                level="high",
            )

        sanitized_tech = result.mitre_attack_id.lower().replace(".", "_").replace("/", "_")
        rule_dict = {
            "title": result.title,
            "id": result.id or str(uuid.uuid4()),
            "status": "test",
            "description": result.description,
            "author": f"Autonomous AI Detection Agent ({self.llm.model_name})",
            "tags": [f"attack.{result.mitre_tactic.lower()}", f"attack.{sanitized_tech}"],
            "logsource": result.logsource,
            "detection": result.detection,
            "falsepositives": result.falsepositives,
            "level": result.level,
        }
        return yaml.dump(rule_dict, sort_keys=False)

    def refine_rule(self, req: RuleRefineRequest) -> str:
        technique, tactic, logsource = resolve_metadata(req.current_sigma_yaml)
        suggested_criteria = extract_dynamic_evidence(req.missed_attack_logs, req.false_positive_logs)

        prompt = ChatPromptTemplate.from_messages([
            (
                "system",
                "You are an expert Detection Engineer refining a failing Sigma rule for production.\n"
                "Target: Reach >= 80% True Positive with 0 False Positives.\n\n"
                "CONVERGENCE SPECIFICATIONS:\n"
                "1. DATA-GROUNDED SELECTION: Integrate the verified mined criteria into a single 'selection' block:\n"
                "   {suggested_criteria}\n"
                "2. NO GENERIC ISOLATED WORDS: Do not use isolated single-character switches or universal tokens (/c, whoami, -Command).\n"
                "3. CONDITION: Set condition to 'selection' (or 'selection and not 1 of filter_*' if filters are present).\n"
                "4. STATUS: Set 'status: test'."
            ),
            (
                "human",
                "Current Rule:\n{current_rule}\n\n"
                "Evaluation Feedback:\n{feedback_notes}\n\n"
                "Unmatched Events:\n{missed_samples}"
            ),
        ])

        formatted = prompt.format_messages(
            technique=technique,
            current_rule=req.current_sigma_yaml,
            feedback_notes=req.feedback_notes,
            suggested_criteria=json.dumps(suggested_criteria, indent=2),
            missed_samples=json.dumps(req.missed_attack_logs[:5], indent=2),
        )

        try:
            result: SigmaRuleOutput = self.structured_llm.invoke(formatted)
        except Exception:
            parsed = yaml.safe_load(req.current_sigma_yaml) or {}
            result = SigmaRuleOutput(
                title=parsed.get("title", f"Refined {technique} Detection"),
                id=parsed.get("id", str(uuid.uuid4())),
                status="test",
                description=parsed.get("description", f"Refined detection for {technique}"),
                mitre_attack_id=technique,
                mitre_tactic=tactic,
                logsource=logsource,
                detection={"selection": suggested_criteria or {"CommandLine|contains": [technique]}, "condition": "selection"},
                falsepositives=["Administrative activities"],
                level="high",
            )

        sanitized_tech = result.mitre_attack_id.lower().replace(".", "_").replace("/", "_")
        rule_dict = {
            "title": result.title,
            "id": result.id,
            "status": "test",
            "description": result.description,
            "author": "Autonomous AI Detection Agent (Refined)",
            "tags": [f"attack.{result.mitre_tactic.lower()}", f"attack.{sanitized_tech}"],
            "logsource": result.logsource,
            "detection": result.detection,
            "falsepositives": result.falsepositives,
            "level": result.level,
        }
        return yaml.dump(rule_dict, sort_keys=False)
