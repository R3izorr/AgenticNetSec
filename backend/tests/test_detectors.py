from __future__ import annotations

import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analyzer import analyze_pcap_summary  # noqa: E402
from detectors import (  # noqa: E402
    _is_external_ip,
    _is_internal_ip,
    collect_all_findings,
)


class TestDetectors(unittest.TestCase):
    def test_ip_role_classification_uses_explicit_internal_ranges(self) -> None:
        self.assertTrue(_is_internal_ip("10.0.0.9"))
        self.assertFalse(_is_internal_ip("198.51.100.25"))
        self.assertTrue(_is_external_ip("198.51.100.25"))
        self.assertTrue(_is_external_ip("203.0.113.10"))

    def test_suspicious_smoke_pcap_surfaces_external_scan(self) -> None:
        pcap_path = PROJECT_ROOT / "outputs" / "smoke_inputs" / "suspicious_scan_small.pcap"

        summary = analyze_pcap_summary(str(pcap_path))
        findings = collect_all_findings(str(pcap_path))

        self.assertTrue(summary.get("scan_candidates"))
        detector_hits = findings.get("external_port_scans", {}).get("sources", [])
        self.assertTrue(detector_hits)
        self.assertTrue(detector_hits[0].get("suspicious"))
        self.assertEqual(detector_hits[0].get("src_ip"), "198.51.100.25")
        self.assertGreaterEqual(detector_hits[0].get("unique_ports", 0), 100)
        self.assertTrue(detector_hits[0].get("sample_events"))
        self.assertEqual(detector_hits[0]["sample_events"][0].get("dst_ip"), "10.0.0.9")

    def test_benign_smoke_pcap_does_not_trigger_external_scan(self) -> None:
        pcap_path = PROJECT_ROOT / "outputs" / "smoke_inputs" / "benign_small.pcap"

        summary = analyze_pcap_summary(str(pcap_path))
        findings = collect_all_findings(str(pcap_path))

        self.assertEqual(summary.get("scan_candidates"), [])
        self.assertEqual(findings.get("external_port_scans", {}).get("sources", []), [])


if __name__ == "__main__":
    unittest.main()
