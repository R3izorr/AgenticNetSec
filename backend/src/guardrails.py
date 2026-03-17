from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class GuardrailResult:
    data_validity_check: str
    tool_output_validation: str
    human_review_required: str
    policy_reason: str
    contradiction_count: int = 0


@dataclass
class GuardrailAudit:
    input_validity: dict[str, Any]
    tool_validation: dict[str, Any]
    claim_checks: list[dict[str, Any]] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    confidence_decision: dict[str, Any] = field(default_factory=dict)
    human_review_required: str = "No"
    read_only_mode: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_validity": self.input_validity,
            "tool_validation": self.tool_validation,
            "claim_checks": self.claim_checks,
            "contradictions": self.contradictions,
            "confidence_decision": self.confidence_decision,
            "human_review_required": self.human_review_required,
            "read_only_mode": self.read_only_mode,
        }


class Guardrails:
    allowed_suffixes = {".pcap", ".pcapng", ".cap"}

    def validate_input(self, pcap_path: str) -> None:
        path = Path(pcap_path)
        if path.suffix.lower() not in self.allowed_suffixes:
            raise ValueError(f"Unsupported file format: {path.suffix}")
        if not path.exists():
            raise FileNotFoundError(f"PCAP path not found: {path}")
        if not path.is_file():
            raise ValueError(f"PCAP path must be a file: {path}")

    def describe_input(self, pcap_path: str) -> dict[str, Any]:
        path = Path(pcap_path)
        return {
            "status": "pass",
            "path": str(path.resolve()),
            "suffix": path.suffix.lower(),
            "allowed_suffixes": sorted(self.allowed_suffixes),
        }

    def validate_tool_outputs(self, summary: dict, findings: dict) -> str:
        if summary.get("error"):
            return "fail"
        if not findings:
            return "fail"
        return "pass"

    def describe_tool_validation(self, summary: dict, findings: dict) -> dict[str, Any]:
        issues: list[str] = []
        if summary.get("error"):
            issues.append("summary_error")
        if not findings:
            issues.append("empty_findings")
        return {
            "status": "fail" if issues else "pass",
            "issues": issues,
        }

    def apply_policy(
        self,
        confidence_score: float,
        tool_validation: str,
        contradictions: list[str] | None = None,
    ) -> GuardrailResult:
        confidence_threshold = 0.65
        low_confidence = confidence_score < confidence_threshold
        tool_failed = tool_validation != "pass"
        contradiction_count = len(contradictions or [])
        consistency_failed = contradiction_count > 0

        human_review = "Yes" if (low_confidence or tool_failed or consistency_failed) else "No"
        reason = []
        if low_confidence:
            reason.append("low_confidence")
        if tool_failed:
            reason.append("tool_validation_failed")
        if consistency_failed:
            reason.append("consistency_check_failed")

        return GuardrailResult(
            data_validity_check="pass",
            tool_output_validation=tool_validation,
            human_review_required=human_review,
            policy_reason=",".join(reason) if reason else "none",
            contradiction_count=contradiction_count,
        )

    def evaluate_consistency(
        self,
        *,
        attack_type: str,
        primary_finding: str,
        inference: str,
        markdown_report: str,
        evidence_refs: list[dict[str, Any]],
        patient_zero_candidate: dict[str, Any] | None,
        has_lateral_evidence: bool,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        evidence_by_claim = {
            "exfiltration": any(ref.get("claim") == "exfiltration" for ref in evidence_refs),
            "patient_zero": any(ref.get("claim") == "patient_zero" for ref in evidence_refs),
            "lateral_movement": any(ref.get("claim") == "lateral_movement" for ref in evidence_refs),
        }
        text_structured = " ".join([attack_type, primary_finding, inference]).lower()
        markdown_lower = markdown_report.lower()

        structured_claims = {
            "exfiltration": attack_type == "exfiltration" or "exfil" in text_structured,
            "patient_zero": bool(patient_zero_candidate) or "patient zero" in text_structured,
            "lateral_movement": (
                attack_type == "scan/lateral-movement"
                or "lateral" in text_structured
                or "scan" in text_structured
            ),
        }
        markdown_claims = {
            "exfiltration": "exfil" in markdown_lower or "data loss" in markdown_lower,
            "patient_zero": "patient zero" in markdown_lower or "initial access" in markdown_lower,
            "lateral_movement": "lateral movement" in markdown_lower or "discovery" in markdown_lower,
        }

        claim_checks = [
            {
                "claim": "exfiltration_requires_evidence",
                "passed": (not structured_claims["exfiltration"]) or evidence_by_claim["exfiltration"],
                "details": "Exfiltration claims must have exfil-related evidence references.",
            },
            {
                "claim": "patient_zero_requires_candidate",
                "passed": (not structured_claims["patient_zero"]) or bool(patient_zero_candidate),
                "details": "Patient-zero claims must resolve to a concrete candidate flow.",
            },
            {
                "claim": "lateral_movement_requires_activity",
                "passed": (not structured_claims["lateral_movement"]) or has_lateral_evidence,
                "details": "Lateral-movement claims require SMB/RPC, internal RDP spread, or manual deployment evidence.",
            },
        ]

        contradictions: list[str] = []
        for check in claim_checks:
            if not check["passed"]:
                contradictions.append(check["claim"])

        for claim_name, markdown_present in markdown_claims.items():
            if markdown_present and not structured_claims[claim_name]:
                contradictions.append(f"markdown_claim_without_structured_match:{claim_name}")
                claim_checks.append(
                    {
                        "claim": f"markdown_alignment_{claim_name}",
                        "passed": False,
                        "details": f"Markdown mentions {claim_name} but structured findings do not.",
                    }
                )

        return claim_checks, contradictions

    def build_audit(
        self,
        *,
        input_validity: dict[str, Any],
        tool_validation: dict[str, Any],
        claim_checks: list[dict[str, Any]],
        contradictions: list[str],
        confidence_score: float,
        confidence_threshold: float,
        result: GuardrailResult,
    ) -> GuardrailAudit:
        return GuardrailAudit(
            input_validity=input_validity,
            tool_validation=tool_validation,
            claim_checks=claim_checks,
            contradictions=contradictions,
            confidence_decision={
                "score": round(confidence_score, 3),
                "threshold": confidence_threshold,
                "status": "pass" if confidence_score >= confidence_threshold else "fail",
                "policy_reason": result.policy_reason,
            },
            human_review_required=result.human_review_required,
            read_only_mode=True,
        )

    def enforce_output_sections(self, observation: str, inference: str, recommendation: str) -> tuple[str, str, str]:
        observation = observation.strip() or "No direct packet-level observation recorded."
        inference = inference.strip() or "No reliable inference could be made from current evidence."
        recommendation = recommendation.strip() or "Perform manual analyst review before containment actions."
        return observation, inference, recommendation
