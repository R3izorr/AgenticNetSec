from __future__ import annotations

import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from guardrails import Guardrails  # noqa: E402


class TestGuardrails(unittest.TestCase):
    def test_policy_requires_human_review_when_confidence_low(self) -> None:
        guardrails = Guardrails()
        result = guardrails.apply_policy(confidence_score=0.2, tool_validation="pass")
        self.assertEqual(result.human_review_required, "Yes")

    def test_policy_no_human_review_when_confidence_high(self) -> None:
        guardrails = Guardrails()
        result = guardrails.apply_policy(confidence_score=0.9, tool_validation="pass")
        self.assertEqual(result.human_review_required, "No")

    def test_policy_requires_human_review_when_contradictions_exist(self) -> None:
        guardrails = Guardrails()
        result = guardrails.apply_policy(
            confidence_score=0.9,
            tool_validation="pass",
            contradictions=["markdown_claim_without_structured_match:exfiltration"],
        )
        self.assertEqual(result.human_review_required, "Yes")

    def test_consistency_check_fails_when_markdown_claim_lacks_structured_support(self) -> None:
        guardrails = Guardrails()
        claim_checks, contradictions = guardrails.evaluate_consistency(
            attack_type="unknown",
            primary_finding="No single attack path reached a high-confidence autonomous conclusion.",
            inference="Likely attack class: unknown with risk level low.",
            markdown_report="## Exfiltration\nEvidence supports exfiltration.",
            evidence_refs=[],
            patient_zero_candidate=None,
            has_lateral_evidence=False,
        )
        self.assertTrue(claim_checks)
        self.assertIn("markdown_claim_without_structured_match:exfiltration", contradictions)


if __name__ == "__main__":
    unittest.main()
