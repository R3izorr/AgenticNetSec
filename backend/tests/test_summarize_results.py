from __future__ import annotations

import sys
from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "backend" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from summarize_results import build_aggregate  # noqa: E402


class SummarizeResultsTests(unittest.TestCase):
    def test_build_aggregate_counts_payload_evidence_states(self) -> None:
        records = [
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
                "payload_carving_candidate_count": 2,
                "payload_carving_status": "heuristic_only",
                "carved_payloads": [],
            },
            {
                "file": "none.pcap",
                "payload_carving_candidate_count": 0,
                "carved_payloads": [],
            },
        ]

        aggregate = build_aggregate(records)

        self.assertEqual(aggregate["file_count"], 4)
        self.assertEqual(aggregate["files_with_payload_carving_candidates"], 3)
        self.assertEqual(aggregate["files_with_recovered_payload_artifacts"], 1)
        self.assertEqual(aggregate["files_with_partial_payload_evidence"], 1)
        self.assertEqual(aggregate["files_with_heuristic_payload_only"], 1)
        self.assertEqual(aggregate["interesting_files"]["recovered_payload_artifacts"], ["confirmed.pcap"])
        self.assertEqual(aggregate["interesting_files"]["partial_payload_evidence"], ["partial.pcap"])
        self.assertEqual(aggregate["interesting_files"]["heuristic_payload_only"], ["heuristic.pcap"])

    def test_build_aggregate_treats_hash_only_as_partial_payload_evidence(self) -> None:
        aggregate = build_aggregate(
            [
                {
                    "file": "hash-only.pcap",
                    "payload_carving_candidate_count": 1,
                    "payload_carving_status": "hash_only",
                    "carved_payloads": [],
                }
            ]
        )

        self.assertEqual(aggregate["files_with_payload_carving_candidates"], 1)
        self.assertEqual(aggregate["files_with_recovered_payload_artifacts"], 0)
        self.assertEqual(aggregate["files_with_partial_payload_evidence"], 1)
        self.assertEqual(aggregate["files_with_heuristic_payload_only"], 0)
        self.assertEqual(aggregate["interesting_files"]["partial_payload_evidence"], ["hash-only.pcap"])


if __name__ == "__main__":
    unittest.main()
