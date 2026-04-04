from __future__ import annotations

import json
from textwrap import dedent
from typing import Any

from report_ai import generate_text_result


STAGE_TO_CHECKS = {
    "A": ["remote_management"],
    "B": ["internal_scanning"],
    "C": ["exfiltration"],
    "D": ["payload_deployment"],
}


def build_verification_plan(
    record: dict[str, Any],
    *,
    use_ai: bool,
    provider: str = "auto",
    model: str | None = None,
    require_ai: bool = False,
) -> dict[str, Any]:
    heuristic_plan = _heuristic_plan(record)
    if not use_ai:
        return heuristic_plan

    prompt = _build_prompt(record, heuristic_plan)
    result = generate_text_result(
        prompt=prompt,
        system_prompt=_planner_system_prompt(),
        provider=provider,
        model=model,
        require_ai=require_ai,
    )
    if not result:
        return heuristic_plan

    parsed = _parse_plan(result.text)
    if not parsed:
        fallback = {**heuristic_plan}
        fallback["planner_provider"] = result.provider
        fallback["planner_model"] = result.model
        fallback["planner_source"] = "heuristic_fallback_after_ai_parse_failure"
        return fallback

    parsed["planner_provider"] = result.provider
    parsed["planner_model"] = result.model
    parsed["planner_source"] = "ai"
    return parsed


def _heuristic_plan(record: dict[str, Any]) -> dict[str, Any]:
    weak_sections: list[str] = []
    reasons: dict[str, str] = {}

    patient_zero = record.get("patient_zero_candidate") or {}
    if not patient_zero:
        weak_sections.append("A")
        reasons["A"] = "No patient-zero candidate is present in the existing results."
    elif patient_zero.get("post_login_unique_internal_targets", 0) == 0:
        weak_sections.append("A")
        reasons["A"] = "Initial access exists but lacks strong follow-on behavior in the existing results."

    if not record.get("suspicious_smb_rpc_scanners") and not record.get("possible_dcerpc_account_changes"):
        weak_sections.append("B")
        reasons["B"] = "Lateral movement and account-change evidence is weak or absent."

    if not record.get("temp_sh_hits") and not record.get("possible_outbound_exfil_flows") and not record.get("large_http_uploads"):
        weak_sections.append("C")
        reasons["C"] = "Exfiltration evidence is weak or absent."

    if not record.get("manual_payload_deployment_candidates") and not record.get("suspicious_internal_rdp_spread"):
        weak_sections.append("D")
        reasons["D"] = "Payload-deployment evidence is weak or absent."

    requested_checks = []
    for stage in weak_sections:
        requested_checks.extend(STAGE_TO_CHECKS.get(stage, []))
    requested_checks = list(dict.fromkeys(requested_checks or ["remote_management", "internal_scanning", "exfiltration", "payload_deployment"]))

    return {
        "weak_sections": weak_sections,
        "requested_checks": requested_checks,
        "stage_reasons": reasons,
        "planner_source": "heuristic",
    }


def _planner_system_prompt() -> str:
    return dedent(
        """
        You are a network-forensics verification planner.
        You are given one per-PCAP summary record from a ransomware investigation.
        Decide which investigation sections are weak or ambiguous:
        A = Initial Access
        B = Lateral Movement & Discovery
        C = Exfiltration
        D = Payload Deployment

        Output strict JSON with:
        {
          "weak_sections": ["A","C"],
          "requested_checks": ["remote_management","exfiltration"],
          "stage_reasons": {"A":"...", "C":"..."}
        }

        Allowed requested_checks values:
        - remote_management
        - internal_scanning
        - exfiltration
        - payload_deployment

        Keep reasons short and evidence-grounded.
        """
    ).strip()


def _build_prompt(record: dict[str, Any], heuristic_plan: dict[str, Any]) -> str:
    compact = {
        "file": record.get("file"),
        "path": record.get("path"),
        "patient_zero_candidate": record.get("patient_zero_candidate"),
        "suspicious_external_rdp_count": record.get("suspicious_external_rdp_count"),
        "suspicious_smb_rpc_scanners": record.get("suspicious_smb_rpc_scanners"),
        "possible_dcerpc_account_changes": record.get("possible_dcerpc_account_changes"),
        "temp_sh_hits": record.get("temp_sh_hits"),
        "large_http_uploads": record.get("large_http_uploads"),
        "possible_outbound_exfil_flows": record.get("possible_outbound_exfil_flows"),
        "suspicious_internal_rdp_spread": record.get("suspicious_internal_rdp_spread"),
        "manual_payload_deployment_candidates": record.get("manual_payload_deployment_candidates"),
        "deep_dive_focus_host": record.get("deep_dive_focus_host"),
    }
    return dedent(
        f"""
        Existing per-PCAP result:
        {json.dumps(compact, indent=2)}

        Heuristic weak-section draft:
        {json.dumps(heuristic_plan, indent=2)}

        Decide which sections A/B/C/D are weak enough to justify targeted tshark verification.
        """
    ).strip()


def _parse_plan(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    weak_sections = [item for item in data.get("weak_sections", []) if item in {"A", "B", "C", "D"}]
    requested_checks = [
        item
        for item in data.get("requested_checks", [])
        if item in {"remote_management", "internal_scanning", "exfiltration", "payload_deployment"}
    ]
    stage_reasons = data.get("stage_reasons", {})
    if not isinstance(stage_reasons, dict):
        stage_reasons = {}
    return {
        "weak_sections": weak_sections,
        "requested_checks": requested_checks,
        "stage_reasons": stage_reasons,
    }
