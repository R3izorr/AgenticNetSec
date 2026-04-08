from __future__ import annotations

import sys
from pathlib import Path
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
from report_ai import ReportGenerationResult  # noqa: E402


class _DummyStructuredReport:
    def model_dump(self) -> dict:
        return {
            "guardrail_verification": {"human_review_required": "No"},
            "impact": {"attack_type": "Unknown", "risk_level": "low"},
            "findings": {"confidence_score": 0.0},
        }


def _summary_payload() -> dict:
    return {
        "total_packets": 10,
        "top_ips": [],
        "top_ports": [],
        "protocols": {},
        "average_packet_size": 100.0,
        "unusual_ports": [],
        "unusual_protocols": [],
        "scan_candidates": [],
    }


def _base_findings() -> dict:
    return {
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


class AnalysisProfileEngineTests(unittest.TestCase):
    def _run_engine(
        self,
        *,
        analysis_profile: str,
        findings: dict,
        metadata: dict | None = None,
    ) -> tuple[list[str], dict]:
        engine = AnalysisEngine()
        engine.guardrails.validate_input = Mock()
        engine.guardrails.describe_input = Mock(return_value={"valid": True})
        engine._extract_metadata = Mock(
            return_value=metadata
            or {
                "filename": "sample.pcap",
                "path": "/tmp/sample.pcap",
                "size_bytes": 1234,
                "packet_count": 10,
                "flow_count": 2,
                "capture_start": None,
                "capture_end": None,
            }
        )
        engine._summary_from_detection_surfaces = Mock(return_value=_summary_payload())
        engine._build_forensic_report = Mock(return_value=(_DummyStructuredReport(), {"audit": "ok"}))

        tool_calls: list[str] = []

        def fake_execute(name, func, *args, **kwargs):  # type: ignore[no-untyped-def]
            tool_calls.append(name)
            if name == "collect_findings":
                return findings
            if name == "payload_carving":
                return {
                    "status": "candidate_selection_only",
                    "manifest_path": "carved_manifest.json",
                    "candidate_count": 1,
                    "selected_candidates": [{"candidate_id": "http-upload-0"}],
                    "carved_payloads": [],
                    "payload_iocs": ["sha256:abc123"],
                    "payload_deployment_confidence": 0.35,
                    "bytes_reconstructed": 0,
                    "notes": ["Candidate selection is implemented."],
                }
            if name == "deep_dive":
                return {"focus_host": "10.0.0.5"}
            if name == "zero_day_heuristics":
                return {}
            if name == "reasoning":
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
                pcap_path="backend/tests/test_analysis_profiles.py",
                analysis_profile=analysis_profile,
                use_ai=False,
                artifacts_dir="/tmp/analysis-job",
            )
        )
        return tool_calls, artifacts.analysis_record

    def test_fast_profile_skips_deep_dive_and_payload_carving(self) -> None:
        findings = _base_findings()
        findings["manual_payload_deployment"] = {"candidates": [{"suspicious": True}]}
        tool_calls, record = self._run_engine(analysis_profile="fast", findings=findings)

        self.assertEqual(tool_calls, ["collect_findings", "zero_day_heuristics", "reasoning"])
        self.assertEqual(record["analysis_profile"], "fast")
        self.assertEqual(record["payload_carving_status"], "skipped_profile_policy")
        self.assertFalse(record["stage1_execution"]["deep_dive"]["executed"])
        self.assertFalse(record["stage1_execution"]["payload_carving"]["executed"])
        self.assertIn("fast profile", record["stage1_execution"]["payload_carving"]["reason"].lower())

    def test_standard_profile_skips_heavy_steps_when_findings_are_clean(self) -> None:
        tool_calls, record = self._run_engine(analysis_profile="standard", findings=_base_findings())

        self.assertEqual(tool_calls, ["collect_findings", "zero_day_heuristics", "reasoning"])
        self.assertEqual(record["analysis_profile"], "standard")
        self.assertEqual(record["payload_carving_status"], "skipped_profile_policy")
        self.assertIn("clean", record["stage1_execution"]["deep_dive"]["reason"].lower())
        self.assertIn("sandbox enrichment", record["stage1_execution"]["payload_carving"]["reason"].lower())

    def test_standard_profile_runs_deep_dive_for_non_payload_evidence_only(self) -> None:
        findings = _base_findings()
        findings["external_port_scans"] = {"sources": [{"suspicious": True}]}
        tool_calls, record = self._run_engine(analysis_profile="standard", findings=findings)

        self.assertIn("deep_dive", tool_calls)
        self.assertNotIn("payload_carving", tool_calls)
        self.assertTrue(record["stage1_execution"]["deep_dive"]["executed"])
        self.assertFalse(record["stage1_execution"]["payload_carving"]["executed"])

    def test_standard_profile_defers_payload_carving_even_when_payload_evidence_exists(self) -> None:
        findings = _base_findings()
        findings["large_http_posts"] = {"uploads": [{"dst_ip": "10.0.0.7"}]}
        tool_calls, record = self._run_engine(analysis_profile="standard", findings=findings)

        self.assertIn("deep_dive", tool_calls)
        self.assertNotIn("payload_carving", tool_calls)
        self.assertEqual(record["payload_carving_status"], "skipped_profile_policy")
        self.assertFalse(record["stage1_execution"]["payload_carving"]["executed"])
        self.assertIn("sandbox enrichment", record["stage1_execution"]["payload_carving"]["reason"].lower())

    def test_full_profile_preserves_heavy_behavior(self) -> None:
        metadata = {
            "filename": "sample.pcap",
            "path": "/tmp/sample.pcap",
            "size_bytes": 1234,
            "packet_count": 25000,
            "flow_count": 2,
            "capture_start": None,
            "capture_end": None,
        }
        tool_calls, record = self._run_engine(
            analysis_profile="full",
            findings=_base_findings(),
            metadata=metadata,
        )

        self.assertIn("deep_dive", tool_calls)
        self.assertIn("payload_carving", tool_calls)
        self.assertEqual(record["analysis_profile"], "full")
        self.assertTrue(record["stage1_execution"]["deep_dive"]["executed"])
        self.assertTrue(record["stage1_execution"]["payload_carving"]["executed"])

    def test_non_full_evidence_refs_skip_frame_number_resolution(self) -> None:
        engine = AnalysisEngine()
        engine._frame_numbers_for_tcp_pair = Mock(side_effect=AssertionError("frame lookup should not run"))  # type: ignore[method-assign]

        findings = _base_findings()
        findings["external_rdp"] = {
            "sessions": [],
            "patient_zero_candidate": {
                "external_ip": "203.0.113.10",
                "internal_ip": "10.0.0.5",
            },
        }

        refs = engine._build_evidence_refs(
            "backend/tests/test_analysis_profiles.py",
            {
                "filename": "sample.pcap",
                "path": "/tmp/sample.pcap",
                "size_bytes": 1234,
            },
            findings,
            include_frame_numbers=False,
        )

        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].frame_numbers, [])


if __name__ == "__main__":
    unittest.main()
