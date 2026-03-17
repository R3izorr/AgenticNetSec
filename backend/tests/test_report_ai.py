from __future__ import annotations

import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from report_ai import _extract_usage_tokens, _result_from_text  # noqa: E402


class _Object:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestReportAiUsage(unittest.TestCase):
    def test_extracts_openai_style_usage(self) -> None:
        payload = _Object(usage=_Object(input_tokens=123, output_tokens=45))
        self.assertEqual(_extract_usage_tokens(payload), (123, 45))

    def test_extracts_gemini_style_usage(self) -> None:
        payload = _Object(usage_metadata=_Object(prompt_token_count=77, candidates_token_count=11))
        self.assertEqual(_extract_usage_tokens(payload), (77, 11))

    def test_extracts_ollama_style_usage(self) -> None:
        payload = {"prompt_eval_count": 89, "eval_count": 34}
        self.assertEqual(_extract_usage_tokens(payload), (89, 34))

    def test_result_from_text_marks_fallback(self) -> None:
        result = _result_from_text(
            text="report body",
            provider="openai",
            model="gpt-test",
            usage_payload={"prompt_eval_count": 1, "eval_count": 2},
            fallback_used=True,
        )
        self.assertTrue(result.fallback_used)
        self.assertEqual(result.llm_tokens_in, 1)
        self.assertEqual(result.llm_tokens_out, 2)


if __name__ == "__main__":
    unittest.main()
