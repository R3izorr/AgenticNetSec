from __future__ import annotations

import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from forensic_schema import ForensicReport  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
