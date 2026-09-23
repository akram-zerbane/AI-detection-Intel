from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DetectionLogArtifact(BaseModel):
    event_id: Optional[Any] = None
    image: Optional[str] = None
    command_line: Optional[str] = None
    parent_image: Optional[str] = None
    network_destination: Optional[str] = None
    raw_log: Dict[str, Any] = Field(default_factory=dict)


class DirectTelemetryPayload(BaseModel):
    operation_id: Optional[str] = None
    operation_name: Optional[str] = None
    technique_id: Optional[str] = None
    expected_technique: Optional[str] = None
    tactic: Optional[str] = "execution"
    target_host: Optional[str] = None
    ability_command: Optional[str] = None
    logs: List[Dict[str, Any]] = Field(default_factory=list)


class CIFeedbackDetail(BaseModel):
    rule_path: str
    rule_raw: str
    tp_rate: float = 0.0
    fp_count: int = 0
    fp_samples: List[Any] = Field(default_factory=list)
    missed_attack_logs: List[Any] = Field(default_factory=list)


class CIRefinementPayload(BaseModel):
    branch: str = "main"
    feedback: CIFeedbackDetail


class RuleRefineRequest(BaseModel):
    current_sigma_yaml: str
    false_positive_logs: List[Any] = Field(default_factory=list)
    missed_attack_logs: List[Any] = Field(default_factory=list)
    feedback_notes: str = ""


class SigmaRuleOutput(BaseModel):
    title: str = Field(description="Descriptive, technique-focused rule title")
    id: str = Field(description="UUID v4 identifier for the rule")
    status: str = Field(default="experimental")
    description: str = Field(description="Technical summary of adversary action and indicators")
    mitre_attack_id: str = Field(description="Standard MITRE Technique ID, e.g. T1005 or T1059.001")
    mitre_tactic: str = Field(default="execution", description="MITRE ATT&CK tactic category")
    logsource: Dict[str, Any] = Field(description="Sigma logsource schema dictionary")
    detection: Dict[str, Any] = Field(description="Detection blocks containing selection, filters, and condition")
    falsepositives: List[str] = Field(default_factory=list, description="Common benign workflows")
    level: str = Field(default="medium", description="Alert severity: low, medium, high, or critical")
