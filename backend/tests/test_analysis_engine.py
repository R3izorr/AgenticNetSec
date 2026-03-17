from __future__ import annotations

import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analysis_engine import AnalysisEngine  # noqa: E402


class TestAnalysisEngineEvidenceRefs(unittest.TestCase):
    def test_builds_evidence_refs_for_supported_detector_families(self) -> None:
        engine = AnalysisEngine()
        pcap_path = PROJECT_ROOT / "outputs" / "smoke_inputs" / "suspicious_scan_small.pcap"
        metadata = {"filename": pcap_path.name}
        findings = {
            "external_rdp": {
                "patient_zero_candidate": {"external_ip": "203.0.113.10", "internal_ip": "10.0.0.5"},
            },
            "smb_rpc_scans": {"scanners": [{"src_ip": "10.0.0.5", "unique_targets": 4}]},
            "temp_sh_traffic": {"hits": [{"src_ip": "10.0.0.5", "dst_ip": "198.51.100.5", "dst_port": 443}]},
            "large_http_posts": {"uploads": [{"src_ip": "10.0.0.5", "dst_ip": "198.51.100.5", "dst_port": 443, "inferred_upload_bytes": 4096}]},
            "outbound_exfiltration_candidates": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "198.51.100.5", "dst_port": 443, "transport": "TCP", "total_bytes": 8192}]},
            "rdp_payload_deployment": {"spreaders": [{"src_ip": "10.0.0.5", "unique_targets": 3}]},
            "manual_payload_deployment": {"candidates": [{"src_ip": "10.0.0.5", "unique_targets": 2, "targets": [{"dst_ip": "10.0.0.6"}]}]},
        }

        refs = engine._build_evidence_refs(str(pcap_path), metadata, findings)

        self.assertGreaterEqual(len(refs), 7)
        self.assertEqual(refs[0].ref_id, "EV-001")
        self.assertIn("external_rdp", {ref.detector for ref in refs})
        self.assertIn("payload_deployment", {ref.claim for ref in refs})


if __name__ == "__main__":
    unittest.main()
