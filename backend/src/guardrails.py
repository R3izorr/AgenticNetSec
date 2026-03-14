from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class GuardrailResult:
    data_validity_check: str
    tool_output_validation: str
    human_review_required: str
    policy_reason: str


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

    def validate_tool_outputs(self, summary: dict, findings: dict) -> str:
        if summary.get("error"):
            return "fail"
        if not findings:
            return "fail"
        return "pass"

    def apply_policy(self, confidence_score: float, tool_validation: str) -> GuardrailResult:
        confidence_threshold = 0.65
        low_confidence = confidence_score < confidence_threshold
        tool_failed = tool_validation != "pass"

        human_review = "Yes" if (low_confidence or tool_failed) else "No"
        reason = []
        if low_confidence:
            reason.append("low_confidence")
        if tool_failed:
            reason.append("tool_validation_failed")

        return GuardrailResult(
            data_validity_check="pass",
            tool_output_validation=tool_validation,
            human_review_required=human_review,
            policy_reason=",".join(reason) if reason else "none",
        )

    def enforce_output_sections(self, observation: str, inference: str, recommendation: str) -> tuple[str, str, str]:
        observation = observation.strip() or "No direct packet-level observation recorded."
        inference = inference.strip() or "No reliable inference could be made from current evidence."
        recommendation = recommendation.strip() or "Perform manual analyst review before containment actions."
        return observation, inference, recommendation
