from __future__ import annotations

import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from flow_analysis import build_attack_flow  # noqa: E402


class TestFlowAnalysis(unittest.TestCase):
    def test_external_reconnaissance_forms_a_stage_without_patient_zero(self) -> None:
        records = [
            {
                "file": "suspicious_scan_small.pcap",
                "patient_zero_candidate": None,
                "suspicious_external_port_scanners": [
                    {
                        "src_ip": "198.51.100.25",
                        "first_seen": 1773684384.586999,
                        "unique_ports": 100,
                        "unique_targets": 1,
                        "top_targets": [{"dst_ip": "10.0.0.9", "count": 100}],
                    }
                ],
                "suspicious_smb_rpc_scanners": [],
                "possible_dcerpc_account_changes": [],
                "possible_outbound_exfil_flows": [],
                "large_http_uploads": [],
                "suspicious_internal_rdp_spread": [],
                "manual_payload_deployment_candidates": [],
            }
        ]

        attack_flow = build_attack_flow(records)

        self.assertEqual(attack_flow.get("focus_host"), "10.0.0.9")
        self.assertEqual(attack_flow.get("stage_counts", {}).get("reconnaissance"), 1)
        self.assertEqual(attack_flow.get("likely_path"), "Reconnaissance")
        self.assertEqual(attack_flow.get("primary_external_ips", [])[0].get("external_ip"), "198.51.100.25")


if __name__ == "__main__":
    unittest.main()
