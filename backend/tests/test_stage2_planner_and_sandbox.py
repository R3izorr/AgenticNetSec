from __future__ import annotations

import os
import sys
from pathlib import Path
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ai_tshark_planner import build_ai_tshark_plan, build_campaign_weak_sections, select_records_for_sections  # noqa: E402
from report_ai import ReportGenerationResult  # noqa: E402
from sandbox_verifier import _load_config  # noqa: E402


class Stage2PlannerAndSandboxTests(unittest.TestCase):
    @mock.patch("ai_tshark_planner.generate_text_result")
    def test_campaign_weak_sections_falls_back_heuristically_when_ai_makes_no_api_call(
        self,
        mock_generate_text_result: mock.Mock,
    ) -> None:
        mock_generate_text_result.return_value = ReportGenerationResult(
            text="",
            provider="openrouter",
            model="openai/gpt-5-mini",
            fallback_used=True,
            api_attempted=False,
            failure_reason="missing_api_key",
        )

        result = build_campaign_weak_sections(
            aggregate={
                "file_count": 10,
                "files_with_external_rdp": 3,
                "files_with_vpn_like_ingress": 0,
                "files_with_smb_rpc_scanning": 0,
                "files_with_dcerpc_account_markers": 0,
                "files_with_temp_sh_hits": 0,
                "files_with_outbound_exfil_candidates": 0,
                "files_with_large_http_uploads": 0,
                "files_with_manual_payload_deployment": 0,
                "files_with_internal_rdp_spread": 0,
                "files_with_recovered_payload_artifacts": 0,
            },
            report_text=(
                "## Exfiltration\n"
                "No direct evidence of exfiltration was identified.\n\n"
                "## Payload Deployment\n"
                "Payload deployment remains mostly inferred.\n"
            ),
            provider="openrouter",
            model="openai/gpt-5-mini",
            require_ai=False,
        )

        self.assertEqual(result["planner_source"], "heuristic_no_api_call")
        self.assertFalse(result["ai_api_attempted"])
        self.assertIn("C", result["weak_sections"])
        self.assertIn("D", result["weak_sections"])

    @mock.patch("ai_tshark_planner.generate_text_result")
    def test_ai_tshark_plan_falls_back_to_heuristic_queries_after_parse_failure(
        self,
        mock_generate_text_result: mock.Mock,
    ) -> None:
        mock_generate_text_result.return_value = ReportGenerationResult(
            text='{"weak_sections":["C"],"queries":[{"name":"broken"}]',
            provider="openrouter",
            model="openai/gpt-5-mini",
            fallback_used=True,
            api_attempted=True,
            failure_reason="empty_response",
        )

        result = build_ai_tshark_plan(
            record={
                "file": "sample.pcap",
                "path": "/tmp/sample.pcap",
                "possible_outbound_exfil_flows": [{"external_ip": "203.0.113.99"}],
                "patient_zero_candidate": {"internal_ip": "10.0.0.5"},
            },
            aggregate={"top_patient_zero_candidates": [{"internal_ip": "10.0.0.5"}]},
            report_text="## Exfiltration\nNo direct evidence of exfiltration was identified.",
            focus_sections=["C"],
            provider="openrouter",
            model="openai/gpt-5-mini",
            require_ai=False,
        )

        self.assertEqual(result["planner_source"], "heuristic_after_ai_parse_failure")
        self.assertTrue(result["ai_api_attempted"])
        self.assertEqual(result["weak_sections"], ["C"])
        self.assertTrue(result["queries"])
        self.assertEqual(result["queries"][0]["stage"], "C")

    def test_sandbox_defaults_to_enabled_host_mode_when_tshark_is_available(self) -> None:
        with (
            mock.patch("sandbox_verifier.shutil.which", return_value="/usr/bin/tshark"),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            cfg = _load_config()

        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.mode, "host")

    def test_select_records_for_sections_falls_back_to_representative_records_when_interesting_files_are_empty(self) -> None:
        records = [
            {"file": "a.pcap", "patient_zero_candidate": {"internal_ip": "10.0.0.5"}, "suspicious_external_rdp_count": 4},
            {"file": "b.pcap", "suspicious_internal_rdp_spread": [{"src_ip": "10.0.0.5"}]},
        ]
        selected = select_records_for_sections(
            records=records,
            aggregate={"interesting_files": {}, "top_patient_zero_candidates": []},
            weak_sections=["B", "D"],
            limit=2,
        )

        self.assertEqual([item["file"] for item in selected], ["b.pcap", "a.pcap"])


if __name__ == "__main__":
    unittest.main()
