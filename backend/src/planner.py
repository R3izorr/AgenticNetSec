from __future__ import annotations

from dataclasses import dataclass


ANALYSIS_PROFILES = {"fast", "standard", "full"}


@dataclass
class PlanConfig:
    analysis_profile: str
    run_deep_dive: bool
    deep_dive_reason: str
    run_payload_carving: bool
    payload_carving_reason: str
    use_llm_reasoning: bool
    enable_zero_day_heuristics: bool
    enable_sandbox_verification: bool


class AnalysisPlanner:
    """Simple planner that selects pipeline depth based on input profile."""

    def create_plan(
        self,
        metadata: dict,
        use_ai: bool,
        analysis_profile: str = "standard",
        enable_sandbox: bool | None = None,
    ) -> PlanConfig:
        import os

        file_size = int(metadata.get("size_bytes", 0) or 0)
        packet_count = int(metadata.get("packet_count", 0) or 0)

        enable_zero_day_heuristics = True
        if enable_sandbox is None:
            enable_sandbox_verification = os.getenv("AGENTIC_SANDBOX_VERIFY", "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
        else:
            enable_sandbox_verification = bool(enable_sandbox)

        # Keep LLM optional to support offline/local fallback.
        use_llm_reasoning = bool(use_ai)

        resolved_profile = analysis_profile if analysis_profile in ANALYSIS_PROFILES else "standard"
        if resolved_profile == "fast":
            run_deep_dive = False
            deep_dive_reason = "Skipped in fast profile."
            run_payload_carving = False
            payload_carving_reason = "Skipped in fast profile; payload carving is reserved for explicit heavy analysis."
        elif resolved_profile == "full":
            run_deep_dive = packet_count > 20000 or file_size > 50 * 1024 * 1024
            deep_dive_reason = (
                "Full profile kept deep dive enabled because the file matched the size/packet threshold."
                if run_deep_dive
                else "Full profile kept the legacy size/packet gate, and this file did not match it."
            )
            run_payload_carving = True
            payload_carving_reason = "Full profile always runs payload carving."
        else:
            run_deep_dive = False
            deep_dive_reason = "Awaiting evidence gate from base findings."
            run_payload_carving = False
            payload_carving_reason = (
                "Skipped in standard profile; payload-deployment follow-up is deferred to sandbox enrichment."
            )

        return PlanConfig(
            analysis_profile=resolved_profile,
            run_deep_dive=run_deep_dive,
            deep_dive_reason=deep_dive_reason,
            run_payload_carving=run_payload_carving,
            payload_carving_reason=payload_carving_reason,
            use_llm_reasoning=use_llm_reasoning,
            enable_zero_day_heuristics=enable_zero_day_heuristics,
            enable_sandbox_verification=enable_sandbox_verification,
        )

    def refine_plan(self, plan: PlanConfig, findings: dict) -> PlanConfig:
        if plan.analysis_profile != "standard":
            return plan

        run_deep_dive, deep_dive_reason = self._should_run_deep_dive(findings)
        plan.run_deep_dive = run_deep_dive
        plan.deep_dive_reason = deep_dive_reason
        return plan

    def _should_run_deep_dive(self, findings: dict) -> tuple[bool, str]:
        suspicious_rdp = [
            item for item in (findings.get("external_rdp", {}) or {}).get("sessions", []) if item.get("suspicious")
        ]
        suspicious_vpn = [
            item
            for item in (findings.get("vpn_like_traffic", {}) or {}).get("sessions", [])
            if item.get("total_bytes", 0) >= 50000
        ]
        suspicious_external_scanners = [
            item
            for item in (findings.get("external_port_scans", {}) or {}).get("sources", [])
            if item.get("suspicious")
        ]
        suspicious_smb_scanners = [
            item
            for item in (findings.get("smb_rpc_scans", {}) or {}).get("scanners", [])
            if item.get("suspicious")
        ]
        suspicious_dcerpc = [
            item
            for item in (findings.get("dcerpc_account_activity", {}) or {}).get("events", [])
            if item.get("possible_account_or_group_change")
        ]
        temp_hits = list((findings.get("temp_sh_traffic", {}) or {}).get("hits", []) or [])
        uploads = list((findings.get("large_http_posts", {}) or {}).get("uploads", []) or [])
        outbound_exfil = [
            item
            for item in (findings.get("outbound_exfiltration_candidates", {}) or {}).get("flows", [])
            if item.get("suspicious")
        ]
        suspicious_spreaders = [
            item
            for item in (findings.get("rdp_payload_deployment", {}) or {}).get("spreaders", [])
            if item.get("suspicious")
        ]
        manual_drop_candidates = [
            item
            for item in (findings.get("manual_payload_deployment", {}) or {}).get("candidates", [])
            if item.get("suspicious")
        ]

        if any(
            (
                suspicious_rdp,
                suspicious_vpn,
                suspicious_external_scanners,
                suspicious_smb_scanners,
                suspicious_dcerpc,
                temp_hits,
                uploads,
                outbound_exfil,
                suspicious_spreaders,
                manual_drop_candidates,
            )
        ):
            return True, "Standard profile enabled deep dive because base findings showed suspicious evidence."
        return False, "Standard profile skipped deep dive because base findings were clean."
