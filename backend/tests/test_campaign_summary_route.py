from __future__ import annotations

import sys
from pathlib import Path
import unittest
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "backend" / "scripts"
SRC_DIR = PROJECT_ROOT / "backend" / "src"
for module_dir in (SCRIPTS_DIR, SRC_DIR):
    module_dir_str = str(module_dir)
    if module_dir_str not in sys.path:
        sys.path.insert(0, module_dir_str)

from enrich_results_with_sandbox import run_campaign_summary_route  # noqa: E402


class CampaignSummaryRouteTests(unittest.TestCase):
    def test_route_runs_initial_summary_then_sandbox_then_targeted_follow_up_then_final_report(self) -> None:
        records = [
            {
                "file": "a.pcap",
                "path": "/tmp/a.pcap",
                "manual_payload_deployment_candidates": [{"src_ip": "10.0.0.5", "unique_targets": 2, "suspicious": True, "targets": []}],
            },
            {"file": "b.pcap", "path": "/tmp/b.pcap"},
        ]
        aggregate = {"file_count": 2}
        progress_events: list[tuple[str, float]] = []

        with (
            patch(
                "enrich_results_with_sandbox.build_case_summary",
                return_value={
                    "provider": "gemini",
                    "model": None,
                    "report_text": "initial report",
                    "api_attempted": True,
                    "failure_reason": None,
                },
            ) as build_case_summary,
            patch(
                "enrich_results_with_sandbox.build_campaign_weak_sections",
                return_value={"planner_source": "ai", "weak_sections": ["C"], "section_reasons": {"C": "Need more validation"}},
            ) as build_campaign_weak_sections,
            patch(
                "enrich_results_with_sandbox.select_records_for_sections",
                return_value=[records[1]],
            ) as select_records_for_sections,
            patch(
                "enrich_results_with_sandbox.enrich_record_with_plan",
                side_effect=lambda record, plan: {
                    **record,
                    "sandbox_verification": {"status": "completed", "requested_checks": plan["requested_checks"]},
                },
            ) as enrich_record_with_plan,
            patch(
                "enrich_results_with_sandbox.build_ai_tshark_plan",
                return_value={"weak_sections": ["C"], "queries": [{"name": "temp_sh_follow_up", "stage": "C"}]},
            ) as build_ai_tshark_plan,
            patch(
                "enrich_results_with_sandbox.run_ai_tshark_queries",
                return_value={
                    "status": "completed",
                    "query_count": 1,
                    "queries": [{"name": "temp_sh_follow_up", "stage": "C", "row_count": 2, "sample_rows": [{"ip.src": "10.0.0.5"}]}],
                },
            ) as run_ai_tshark_queries,
            patch(
                "enrich_results_with_sandbox.build_aggregate",
                return_value={"file_count": 2, "files_with_ai_tshark_follow_up": 1},
            ) as build_aggregate,
            patch(
                "enrich_results_with_sandbox.run_payload_carving",
                return_value={
                    "status": "heuristic_only",
                    "candidate_count": 1,
                    "selected_candidates": [{"candidate_id": "smb-0-0"}],
                    "carved_payloads": [],
                    "payload_iocs": ["sha256:abc123"],
                    "payload_deployment_confidence": 0.35,
                    "manifest_path": "carved_manifest.json",
                },
            ) as run_payload_carving,
            patch(
                "enrich_results_with_sandbox.generate_results_report_result",
                return_value=type(
                    "Result",
                    (),
                    {
                        "text": "final report",
                        "provider": "gemini",
                        "model": "gemini-2.5-flash",
                        "fallback_used": False,
                        "api_attempted": True,
                        "failure_reason": None,
                        "llm_tokens_in": 12,
                        "llm_tokens_out": 34,
                    },
                )(),
            ) as generate_results_report_result,
        ):
            result = run_campaign_summary_route(
                records,
                aggregate,
                report_provider="gemini",
                report_model="gemini-2.5-flash",
                planner_provider="openrouter",
                planner_model="openai/gpt-5-mini",
                require_ai=False,
                progress_callback=lambda stage, progress: progress_events.append((stage, progress)),
                artifacts_dir="/tmp/total-job",
            )

        build_case_summary.assert_called_once_with(
            aggregate,
            records,
            provider="gemini",
            model="gemini-2.5-flash",
            require_ai=False,
        )
        build_campaign_weak_sections.assert_called_once_with(
            aggregate=aggregate,
            report_text="initial report",
            provider="openrouter",
            model="openai/gpt-5-mini",
            require_ai=False,
        )
        select_records_for_sections.assert_called_once()
        self.assertEqual(enrich_record_with_plan.call_count, 2)
        build_ai_tshark_plan.assert_called_once_with(
            record=result["enriched_records"][1],
            aggregate=aggregate,
            report_text="initial report",
            focus_sections=["C"],
            provider="openrouter",
            model="openai/gpt-5-mini",
            require_ai=False,
        )
        run_ai_tshark_queries.assert_called_once_with("/tmp/b.pcap", [{"name": "temp_sh_follow_up", "stage": "C"}])
        run_payload_carving.assert_called_once_with(
            "/tmp/a.pcap",
            {
                "manual_payload_deployment": {
                    "candidates": [{"src_ip": "10.0.0.5", "unique_targets": 2, "suspicious": True, "targets": []}],
                },
                "rdp_payload_deployment": {"spreaders": []},
                "large_http_posts": {"uploads": []},
                "temp_sh_traffic": {"hits": []},
            },
            artifacts_dir="/tmp/total-job/sandbox-payload-carving/001-a.pcap",
        )
        build_aggregate.assert_called_once()
        generate_results_report_result.assert_called_once_with(
            {"file_count": 2, "files_with_ai_tshark_follow_up": 1},
            result["enriched_records"],
            provider="gemini",
            model="gemini-2.5-flash",
            use_ai=True,
            require_ai=False,
        )

        self.assertEqual(result["initial_summary"]["report_text"], "initial report")
        self.assertEqual(result["campaign_plan"]["weak_sections"], ["C"])
        self.assertEqual(result["selected_follow_up_records"], [{"file": "b.pcap", "path": "/tmp/b.pcap"}])
        self.assertEqual(result["final_report_markdown"], "final report")
        self.assertEqual(result["final_report"]["status"], "ai_generated")
        self.assertTrue(result["final_report"]["ai_callable"])
        self.assertEqual(result["enriched_records"][0]["payload_carving_status"], "heuristic_only")
        self.assertEqual(result["enriched_records"][0]["payload_iocs"], ["sha256:abc123"])
        self.assertEqual(
            result["enriched_records"][0]["payload_carving_manifest_path"],
            "/tmp/total-job/sandbox-payload-carving/001-a.pcap/carved_manifest.json",
        )
        self.assertEqual(result["enriched_records"][0]["ai_tshark_query_count"], 0)
        self.assertEqual(result["enriched_records"][1]["ai_tshark_query_count"], 1)
        self.assertIn(("initial_summary", 0.35), progress_events)
        self.assertIn(("campaign_plan", 0.45), progress_events)
        self.assertIn(("final_aggregate", 0.85), progress_events)
        self.assertIn(("final_report", 0.95), progress_events)


if __name__ == "__main__":
    unittest.main()
