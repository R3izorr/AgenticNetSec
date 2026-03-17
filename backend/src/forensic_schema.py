from __future__ import annotations

from typing import Any, List
from pydantic import BaseModel, Field


class HeaderBlock(BaseModel):
    case_id: str
    timestamp: str
    analyst_mode: str = "Autonomous Agent"
    data_sources: List[str]


class EvidenceRef(BaseModel):
    ref_id: str
    detector: str
    claim: str
    source_file: str
    summary: str
    frame_numbers: List[int] = Field(default_factory=list)
    flow: str = ""
    wireshark_filter: str = ""


class EvidenceBlock(BaseModel):
    key_packets_flows: List[str] = Field(default_factory=list)
    ioc_list: List[str] = Field(default_factory=list)
    suspicious_sessions: List[str] = Field(default_factory=list)
    correlated_events_timeline: List[str] = Field(default_factory=list)
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)


class FindingsBlock(BaseModel):
    primary_finding: str
    supporting_evidence: List[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    alternative_hypotheses: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    evidence_ref_ids: List[str] = Field(default_factory=list)
    direct_evidence: List[str] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    observation: str
    inference: str
    recommendation: str


class ImpactBlock(BaseModel):
    affected_assets: List[str] = Field(default_factory=list)
    attack_type: str = "Unknown"
    risk_level: str = "low"


class RecommendedActionsBlock(BaseModel):
    immediate_containment: List[str] = Field(default_factory=list)
    validation_steps: List[str] = Field(default_factory=list)
    longer_term_hardening: List[str] = Field(default_factory=list)


class GuardrailVerificationBlock(BaseModel):
    data_validity_check: str
    tool_output_validation: str
    human_review_required: str


class ForensicReport(BaseModel):
    header: HeaderBlock
    evidence: EvidenceBlock
    findings: FindingsBlock
    impact: ImpactBlock
    recommended_actions: RecommendedActionsBlock
    guardrail_verification: GuardrailVerificationBlock
    analyst_summary_markdown: str


class RunMetrics(BaseModel):
    status: str
    runtime_seconds_total: float
    phase_timings_seconds: dict
    cpu_percent_peak: float | None = None
    ram_mb_peak: float | None = None
    provider: str = "unknown"
    model: str = "unknown"
    fallback_used: bool = False
    llm_tokens_in: int = 0
    llm_tokens_out: int = 0
    artifact_bytes: dict[str, int] = Field(default_factory=dict)
    cost_assumptions: dict[str, Any] = Field(default_factory=dict)
    cost_compute: float = 0.0
    cost_llm: float = 0.0
    cost_storage: float = 0.0
    estimated_cost_total: float = 0.0


class JobStatusResponse(BaseModel):
    analysis_job_id: str
    status: str
    current_phase: str
    progress: float
    guardrail_state: str
    error: str | None = None
