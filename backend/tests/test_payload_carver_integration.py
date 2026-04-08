from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import types
import unittest
from unittest.mock import Mock


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def _install_fake_scapy() -> None:
    if "scapy.all" in sys.modules:
        return

    fake_scapy = types.ModuleType("scapy")
    fake_scapy_all = types.ModuleType("scapy.all")
    fake_scapy_layers = types.ModuleType("scapy.layers")
    fake_scapy_dcerpc = types.ModuleType("scapy.layers.dcerpc")

    for name in ("DNS", "DNSQR", "IP", "IPv6", "Raw", "TCP", "UDP"):
        setattr(fake_scapy_all, name, type(name, (), {}))

    class _DummyPcapReader:
        def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
            self.args = args
            self.kwargs = kwargs

        def __enter__(self) -> "_DummyPcapReader":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
            return None

        def __iter__(self):
            return iter(())

    fake_scapy_all.PcapReader = _DummyPcapReader
    fake_scapy.layers = fake_scapy_layers

    sys.modules["scapy"] = fake_scapy
    sys.modules["scapy.all"] = fake_scapy_all
    sys.modules["scapy.layers"] = fake_scapy_layers
    sys.modules["scapy.layers.dcerpc"] = fake_scapy_dcerpc


_install_fake_scapy()

from analysis_engine import AnalysisEngine, AnalysisRequest  # noqa: E402
from report_ai import ReportGenerationResult, build_prompt  # noqa: E402


class _DummyStructuredReport:
    def model_dump(self) -> dict:
        return {
            "guardrail_verification": {"human_review_required": "No"},
            "impact": {"attack_type": "Unknown", "risk_level": "low"},
            "findings": {"confidence_score": 0.0},
        }


class PayloadCarverIntegrationTests(unittest.TestCase):
    def test_analysis_engine_runs_payload_carving_before_reasoning(self) -> None:
        engine = AnalysisEngine()
        engine.guardrails.validate_input = Mock()
        engine.guardrails.describe_input = Mock(return_value={"valid": True})
        engine._extract_metadata = Mock(
            return_value={
                "filename": "sample.pcap",
                "path": "/tmp/sample.pcap",
                "size_bytes": 1234,
                "packet_count": 10,
                "flow_count": 2,
                "capture_start": None,
                "capture_end": None,
            }
        )
        engine._summary_from_detection_surfaces = Mock(
            return_value={
                "total_packets": 10,
                "top_ips": [],
                "top_ports": [],
                "protocols": {},
                "average_packet_size": 100.0,
                "unusual_ports": [],
                "unusual_protocols": [],
                "scan_candidates": [],
            }
        )
        engine.planner.create_plan = Mock(
            return_value=SimpleNamespace(
                analysis_profile="full",
                run_deep_dive=False,
                deep_dive_reason="full profile disabled deep dive for this file",
                run_payload_carving=True,
                payload_carving_reason="full profile always runs payload carving",
                enable_zero_day_heuristics=False,
                enable_sandbox_verification=False,
                use_llm_reasoning=False,
            )
        )
        engine.planner.refine_plan = Mock(
            side_effect=lambda plan, findings: plan
        )
        engine._build_forensic_report = Mock(return_value=(_DummyStructuredReport(), {"audit": "ok"}))

        tool_calls: list[str] = []
        reasoning_context: dict | None = None
        findings = {
            "external_rdp": {"sessions": [], "patient_zero_candidate": None},
            "external_port_scans": {"sources": []},
            "vpn_like_traffic": {"sessions": []},
            "smb_rpc_scans": {"scanners": []},
            "dcerpc_account_activity": {"events": []},
            "temp_sh_traffic": {"hits": []},
            "large_http_posts": {"uploads": []},
            "outbound_exfiltration_candidates": {"flows": []},
            "rdp_payload_deployment": {"spreaders": []},
            "manual_payload_deployment": {"candidates": []},
        }
        payload_carving = {
            "status": "candidate_selection_only",
            "manifest_path": "carved_manifest.json",
            "candidate_count": 2,
            "selected_candidates": [{"candidate_id": "smb-0-0"}, {"candidate_id": "http-upload-0"}],
            "carved_payloads": [],
            "payload_iocs": ["sha256:abc123"],
            "payload_deployment_confidence": 0.35,
            "bytes_reconstructed": 0,
            "notes": ["Candidate selection is implemented."],
        }

        def fake_execute(name, func, *args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal reasoning_context
            tool_calls.append(name)
            if name == "collect_findings":
                return findings
            if name == "payload_carving":
                self.assertEqual(args[0], "backend/tests/test_payload_carver_integration.py")
                self.assertEqual(args[1], findings)
                self.assertEqual(kwargs.get("artifacts_dir"), "/tmp/analysis-job")
                return payload_carving
            if name == "reasoning":
                reasoning_context = args[1]
                return ReportGenerationResult(
                    text="deterministic report",
                    provider="test",
                    model="test-model",
                    fallback_used=True,
                )
            raise AssertionError(f"Unexpected tool invocation: {name}")

        engine.executor.execute = fake_execute  # type: ignore[assignment]

        artifacts = engine.run(
            AnalysisRequest(
                pcap_path="backend/tests/test_payload_carver_integration.py",
                use_ai=False,
                artifacts_dir="/tmp/analysis-job",
            )
        )

        self.assertEqual(tool_calls, ["collect_findings", "payload_carving", "reasoning"])
        self.assertIsNotNone(reasoning_context)
        self.assertEqual((reasoning_context or {}).get("payload_carving"), payload_carving)
        self.assertEqual(artifacts.analysis_record["payload_iocs"], ["sha256:abc123"])
        self.assertEqual(artifacts.analysis_record["payload_deployment_confidence"], 0.35)
        self.assertEqual(artifacts.analysis_record["payload_carving_candidate_count"], 2)
        self.assertEqual(artifacts.analysis_record["payload_carving_status"], "candidate_selection_only")
        self.assertEqual(artifacts.analysis_record["payload_carving_manifest_path"], "carved_manifest.json")
        self.assertEqual(artifacts.analysis_record["analysis_profile"], "full")
        self.assertTrue(artifacts.analysis_record["stage1_execution"]["payload_carving"]["executed"])

    def test_build_prompt_includes_payload_carving_context(self) -> None:
        prompt = build_prompt(
            {
                "total_packets": 10,
                "top_ips": [],
                "top_ports": [],
                "protocols": {},
                "average_packet_size": 100.0,
                "unusual_ports": [],
                "unusual_protocols": [],
                "scan_candidates": [],
            },
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
                "payload_carving": {
                    "candidate_count": 2,
                    "carved_payloads": [],
                    "payload_iocs": ["sha256:abc123"],
                    "payload_deployment_confidence": 0.35,
                },
            },
        )

        self.assertIn("payload_iocs", prompt)
        self.assertIn("sha256:abc123", prompt)
        self.assertIn("payload_deployment_confidence", prompt)
        self.assertIn("payload_carving_candidate_count", prompt)


if __name__ == "__main__":
    unittest.main()
