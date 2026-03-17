from __future__ import annotations

import json
import sys
from pathlib import Path
import unittest

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ROOT_DIR = PROJECT_ROOT
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.api.app import app, job_store  # noqa: E402


class TestApiArtifacts(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.job = job_store.create_job()
        job_store.update(
            self.job.analysis_job_id,
            status="completed",
            current_phase="completed",
            progress=1.0,
            guardrail_state="No",
        )
        job_store.save_artifact(
            self.job.analysis_job_id,
            "guardrail_audit.json",
            {
                "input_validity": {"status": "pass"},
                "tool_validation": {"status": "pass"},
                "claim_checks": [],
                "contradictions": [],
                "confidence_decision": {"score": 0.9},
                "human_review_required": "No",
                "read_only_mode": True,
            },
        )

    def test_guardrail_audit_endpoint_returns_saved_artifact(self) -> None:
        response = self.client.get(f"/api/v1/analysis/{self.job.analysis_job_id}/guardrail-audit")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["human_review_required"], "No")
        self.assertTrue(payload["read_only_mode"])


if __name__ == "__main__":
    unittest.main()
