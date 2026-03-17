from __future__ import annotations

import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from forensic_schema import ForensicReport, RunMetrics  # noqa: E402


class TestForensicSchema(unittest.TestCase):
    def test_schema_fields_exist(self) -> None:
        fields = set(ForensicReport.model_fields.keys())
        expected = {
            "header",
            "evidence",
            "findings",
            "impact",
            "recommended_actions",
            "guardrail_verification",
            "analyst_summary_markdown",
        }
        self.assertEqual(fields, expected)

    def test_nested_schema_supports_evidence_refs_and_uncertainty_fields(self) -> None:
        evidence_fields = set(ForensicReport.model_fields["evidence"].annotation.model_fields.keys())
        findings_fields = set(ForensicReport.model_fields["findings"].annotation.model_fields.keys())
        metrics_fields = set(RunMetrics.model_fields.keys())

        self.assertIn("evidence_refs", evidence_fields)
        self.assertTrue({"mitre_techniques", "evidence_ref_ids", "direct_evidence", "uncertainties"}.issubset(findings_fields))
        self.assertTrue({"provider", "model", "fallback_used", "artifact_bytes", "cost_assumptions"}.issubset(metrics_fields))


if __name__ == "__main__":
    unittest.main()
