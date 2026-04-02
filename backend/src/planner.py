from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PlanConfig:
    run_deep_dive: bool
    use_llm_reasoning: bool
    enable_zero_day_heuristics: bool
    enable_sandbox_verification: bool


class AnalysisPlanner:
    """Simple planner that selects pipeline depth based on input profile."""

    def create_plan(self, metadata: dict, use_ai: bool, enable_sandbox: bool | None = None) -> PlanConfig:
        import os

        file_size = int(metadata.get("size_bytes", 0))
        packet_count = int(metadata.get("packet_count", 0))

        run_deep_dive = packet_count > 20000 or file_size > 50 * 1024 * 1024
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

        return PlanConfig(
            run_deep_dive=run_deep_dive,
            use_llm_reasoning=use_llm_reasoning,
            enable_zero_day_heuristics=enable_zero_day_heuristics,
            enable_sandbox_verification=enable_sandbox_verification,
        )
