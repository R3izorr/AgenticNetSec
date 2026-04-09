from __future__ import annotations

import sys
from pathlib import Path
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from report_ai import (  # noqa: E402
    _build_aggregate,
    build_prompt,
    build_results_prompt,
    generate_report,
    generate_results_report,
    generate_results_report_result,
)


class ReportAiTests(unittest.TestCase):
    def test_generate_report_distinguishes_confirmed_payload_artifact(self) -> None:
        text = generate_report(
            {"total_packets": 42},
            {
                "external_rdp": {"patient_zero_candidate": None},
                "external_port_scans": {"sources": []},
                "temp_sh_traffic": {"hits": []},
                "large_http_posts": {"uploads": []},
                "outbound_exfiltration_candidates": {"flows": []},
                "smb_rpc_scans": {"scanners": []},
                "rdp_payload_deployment": {"spreaders": []},
                "manual_payload_deployment": {"candidates": []},
                "payload_carving": {
                    "status": "confirmed_artifact",
                    "payload_deployment_confidence": 0.95,
                    "payload_iocs": ["sha256:abcdef"],
                    "carved_payloads": [
                        {
                            "artifact_id": "http-upload-0-body",
                            "recovery_status": "confirmed_artifact",
                            "recovered_filename": "dropper.exe",
                            "sha256": "abcdef1234567890",
                            "file_magic": "pe",
                        }
                    ],
                },
            },
            use_ai=False,
        )

        self.assertIn("Recovered payload artifacts confirm transferred payload evidence.", text)
        self.assertIn("dropper.exe", text)
        self.assertIn("Confidence=0.95", text)

    def test_generate_report_distinguishes_partial_payload_evidence(self) -> None:
        text = generate_report(
            {"total_packets": 24},
            {
                "external_rdp": {"patient_zero_candidate": None},
                "external_port_scans": {"sources": []},
                "temp_sh_traffic": {"hits": []},
                "large_http_posts": {"uploads": []},
                "outbound_exfiltration_candidates": {"flows": []},
                "smb_rpc_scans": {"scanners": []},
                "rdp_payload_deployment": {"spreaders": []},
                "manual_payload_deployment": {"candidates": []},
                "payload_carving": {
                    "status": "partial_evidence",
                    "payload_deployment_confidence": 0.7,
                    "payload_iocs": ["sha256:abcdef", "filename:temp_payload.bin"],
                    "carved_payloads": [
                        {
                            "artifact_id": "http-hit-0-body",
                            "recovery_status": "partial_evidence",
                            "recovered_filename": "temp_payload.bin",
                            "sha256": "abcdef1234567890",
                            "file_magic": "script",
                        }
                    ],
                },
            },
            use_ai=False,
        )

        self.assertIn("Partial or hash-only payload evidence was recovered", text)
        self.assertIn("Payload IOCs: sha256:abcdef, filename:temp_payload.bin.", text)
        self.assertIn("Confidence=0.70", text)

    def test_generate_report_distinguishes_heuristic_only_payload_evidence(self) -> None:
        text = generate_report(
            {"total_packets": 99},
            {
                "external_rdp": {"patient_zero_candidate": None},
                "external_port_scans": {"sources": []},
                "temp_sh_traffic": {"hits": []},
                "large_http_posts": {"uploads": []},
                "outbound_exfiltration_candidates": {"flows": []},
                "smb_rpc_scans": {"scanners": []},
                "rdp_payload_deployment": {"spreaders": []},
                "manual_payload_deployment": {
                    "candidates": [
                        {
                            "suspicious": True,
                            "src_ip": "10.0.0.5",
                            "unique_targets": 3,
                            "targets_with_admin_share_markers": 2,
                            "targets_with_remote_exec_markers": 1,
                        }
                    ]
                },
                "payload_carving": {
                    "status": "heuristic_only",
                    "payload_deployment_confidence": 0.35,
                    "payload_iocs": ["admin_share_marker:admin$"],
                    "carved_payloads": [],
                },
            },
            use_ai=False,
        )

        self.assertIn("Heuristic deployment evidence is present through correlated RDP plus SMB/DCERPC admin-share activity", text)
        self.assertIn("Confidence=0.35", text)

    def test_report_ai_build_aggregate_counts_payload_evidence_states(self) -> None:
        aggregate = _build_aggregate(
            [
                {
                    "file": "confirmed.pcap",
                    "payload_carving_candidate_count": 1,
                    "payload_carving_status": "confirmed_artifact",
                    "carved_payloads": [{"recovery_status": "confirmed_artifact"}],
                },
                {
                    "file": "partial.pcap",
                    "payload_carving_candidate_count": 1,
                    "payload_carving_status": "partial_evidence",
                    "carved_payloads": [{"recovery_status": "partial_evidence"}],
                },
                {
                    "file": "heuristic.pcap",
                    "payload_carving_candidate_count": 1,
                    "payload_carving_status": "heuristic_only",
                    "carved_payloads": [],
                },
            ]
        )

        self.assertEqual(aggregate["files_with_payload_carving_candidates"], 3)
        self.assertEqual(aggregate["files_with_recovered_payload_artifacts"], 1)
        self.assertEqual(aggregate["files_with_partial_payload_evidence"], 1)
        self.assertEqual(aggregate["files_with_heuristic_payload_only"], 1)

    def test_generate_results_report_distinguishes_payload_evidence_states(self) -> None:
        records = [
            {"file": "confirmed.pcap", "payload_carving_candidate_count": 1, "payload_carving_status": "confirmed_artifact", "carved_payloads": []},
            {"file": "partial.pcap", "payload_carving_candidate_count": 1, "payload_carving_status": "partial_evidence", "carved_payloads": []},
            {"file": "heuristic.pcap", "payload_carving_candidate_count": 1, "payload_carving_status": "heuristic_only", "carved_payloads": []},
        ]
        aggregate = {
            "file_count": 3,
            "attack_flow": {"likely_path": None},
            "files_with_external_rdp": 0,
            "files_with_external_port_scans": 0,
            "files_with_vpn_like_ingress": 0,
            "files_with_smb_rpc_scanning": 0,
            "files_with_dcerpc_account_markers": 0,
            "files_with_temp_sh_hits": 0,
            "files_with_outbound_exfil_candidates": 0,
            "files_with_large_http_uploads": 0,
            "files_with_internal_rdp_spread": 0,
            "files_with_manual_payload_deployment": 0,
            "files_with_payload_carving_candidates": 3,
            "files_with_recovered_payload_artifacts": 1,
            "files_with_partial_payload_evidence": 1,
            "files_with_heuristic_payload_only": 1,
            "interesting_files": {},
            "top_patient_zero_candidates": [],
            "top_deep_dive_focus_hosts": [],
        }

        text = generate_results_report(aggregate, records, use_ai=False)

        self.assertIn("Confirmed recovered payload artifacts appear in confirmed.pcap", text)
        self.assertIn("Partial or hash-only payload evidence appears in partial.pcap", text)
        self.assertIn("Heuristic-only payload deployment evidence appears in heuristic.pcap", text)

    def test_build_prompts_include_payload_evidence_state_keys(self) -> None:
        single_prompt = build_prompt(
            {"total_packets": 1, "top_ips": [], "top_ports": [], "protocols": {}, "average_packet_size": 1, "unusual_ports": [], "unusual_protocols": [], "scan_candidates": []},
            {
                "external_rdp": {"patient_zero_candidate": None},
                "external_port_scans": {"sources": []},
                "smb_rpc_scans": {"scanners": []},
                "dcerpc_account_activity": {"changes": []},
                "temp_sh_traffic": {"hits": []},
                "large_http_posts": {"uploads": []},
                "outbound_exfiltration_candidates": {"flows": []},
                "rdp_payload_deployment": {"spreaders": []},
                "manual_payload_deployment": {"candidates": []},
                "payload_carving": {"status": "heuristic_only", "candidate_count": 1, "carved_payloads": [], "payload_iocs": [], "payload_deployment_confidence": 0.35},
            },
        )
        batch_prompt = build_results_prompt(
            {
                "file_count": 1,
                "files_with_payload_carving_candidates": 1,
                "files_with_recovered_payload_artifacts": 0,
                "files_with_partial_payload_evidence": 0,
                "files_with_heuristic_payload_only": 1,
                "files_with_ai_tshark_follow_up": 1,
                "interesting_files": {},
                "top_patient_zero_candidates": [],
                "top_deep_dive_focus_hosts": [],
                "attack_flow": {},
            },
            [
                {
                    "file": "followup.pcap",
                    "ai_tshark_review": {
                        "status": "completed",
                        "query_count": 1,
                        "queries": [
                            {
                                "name": "temp_sh_follow_up",
                                "stage": "C",
                                "row_count": 2,
                                "sample_rows": [{"ip.src": "10.0.0.5"}],
                            }
                        ],
                    },
                }
            ],
        )

        self.assertIn("payload_carving_status", single_prompt)
        self.assertIn("files_with_heuristic_payload_only", batch_prompt)
        self.assertIn("ai_tshark_review", batch_prompt)
        self.assertIn("files_with_ai_tshark_follow_up", batch_prompt)

    @mock.patch("report_ai._generate_with_ollama")
    @mock.patch("report_ai._generate_with_groq")
    @mock.patch("report_ai._generate_with_openai")
    @mock.patch("report_ai._generate_with_openrouter")
    @mock.patch("report_ai._generate_with_gemini")
    def test_generate_results_report_does_not_cross_fallback_providers(
        self,
        mock_gemini: mock.Mock,
        mock_openrouter: mock.Mock,
        mock_openai: mock.Mock,
        mock_groq: mock.Mock,
        mock_ollama: mock.Mock,
    ) -> None:
        mock_gemini.return_value = None
        aggregate = {
            "file_count": 1,
            "attack_flow": {"likely_path": None},
            "files_with_external_rdp": 0,
            "files_with_external_port_scans": 0,
            "files_with_vpn_like_ingress": 0,
            "files_with_smb_rpc_scanning": 0,
            "files_with_dcerpc_account_markers": 0,
            "files_with_temp_sh_hits": 0,
            "files_with_outbound_exfil_candidates": 0,
            "files_with_large_http_uploads": 0,
            "files_with_internal_rdp_spread": 0,
            "files_with_manual_payload_deployment": 0,
            "files_with_payload_carving_candidates": 0,
            "files_with_recovered_payload_artifacts": 0,
            "files_with_partial_payload_evidence": 0,
            "files_with_heuristic_payload_only": 0,
            "interesting_files": {},
            "top_patient_zero_candidates": [],
            "top_deep_dive_focus_hosts": [],
        }

        result = generate_results_report_result(
            aggregate,
            [],
            provider="gemini",
            model="gemini-test",
            use_ai=True,
            require_ai=False,
        )

        self.assertTrue(result.fallback_used)
        self.assertEqual(result.provider, "gemini")
        self.assertEqual(result.model, "gemini-test")
        mock_gemini.assert_called_once()
        mock_openrouter.assert_not_called()
        mock_openai.assert_not_called()
        mock_groq.assert_not_called()
        mock_ollama.assert_not_called()

    @mock.patch("report_ai._get_setting")
    @mock.patch("report_ai._generate_with_ollama")
    @mock.patch("report_ai._generate_with_groq")
    @mock.patch("report_ai._generate_with_openai")
    @mock.patch("report_ai._generate_with_openrouter")
    @mock.patch("report_ai._generate_with_gemini")
    def test_generate_results_report_fallback_keeps_provider_default_model_metadata(
        self,
        mock_gemini: mock.Mock,
        mock_openrouter: mock.Mock,
        mock_openai: mock.Mock,
        mock_groq: mock.Mock,
        mock_ollama: mock.Mock,
        mock_get_setting: mock.Mock,
    ) -> None:
        def fake_get_setting(name: str, default: object = None) -> object:
            if name == "GEMINI_MODEL":
                return "gemini-default-test"
            if name == "REPORT_MODEL":
                return None
            return default

        mock_get_setting.side_effect = fake_get_setting
        mock_gemini.return_value = None
        aggregate = {
            "file_count": 1,
            "attack_flow": {"likely_path": None},
            "files_with_external_rdp": 0,
            "files_with_external_port_scans": 0,
            "files_with_vpn_like_ingress": 0,
            "files_with_smb_rpc_scanning": 0,
            "files_with_dcerpc_account_markers": 0,
            "files_with_temp_sh_hits": 0,
            "files_with_outbound_exfil_candidates": 0,
            "files_with_large_http_uploads": 0,
            "files_with_internal_rdp_spread": 0,
            "files_with_manual_payload_deployment": 0,
            "files_with_payload_carving_candidates": 0,
            "files_with_recovered_payload_artifacts": 0,
            "files_with_partial_payload_evidence": 0,
            "files_with_heuristic_payload_only": 0,
            "interesting_files": {},
            "top_patient_zero_candidates": [],
            "top_deep_dive_focus_hosts": [],
        }

        result = generate_results_report_result(
            aggregate,
            [],
            provider="gemini",
            model=None,
            use_ai=True,
            require_ai=False,
        )

        self.assertTrue(result.fallback_used)
        self.assertEqual(result.provider, "gemini")
        self.assertEqual(result.model, "gemini-default-test")
        mock_gemini.assert_called_once()
        mock_openrouter.assert_not_called()
        mock_openai.assert_not_called()
        mock_groq.assert_not_called()
        mock_ollama.assert_not_called()


if __name__ == "__main__":
    unittest.main()
