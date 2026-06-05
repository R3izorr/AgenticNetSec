from __future__ import annotations

import io
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.api import app as app_module
from analysis_engine import AnalysisRequest
from backend.api.job_store import JobStore
from backend.api.total_job_store import TotalJobChildRef, TotalJobStore
from backend.db.models import OrganizationMember
from backend.db.session import SessionLocal


PASSWORD = "ChangeMe123!"


class WorkerQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.original_job_store = app_module.job_store
        self.original_total_job_store = app_module.total_job_store
        root = Path(self.tempdir.name)
        app_module.job_store = JobStore(root / "analysis_jobs")
        app_module.total_job_store = TotalJobStore(root / "total_jobs")
        self.clients: list[TestClient] = []

    def tearDown(self) -> None:
        for client in self.clients:
            client.close()
        app_module.job_store = self.original_job_store
        app_module.total_job_store = self.original_total_job_store
        self.tempdir.cleanup()

    def _registered_client(self, label: str, role: str = "owner") -> tuple[TestClient, dict]:
        client = TestClient(app_module.app)
        self.clients.append(client)
        response = client.post(
            "/api/v1/auth/register",
            json={"email": f"{label}-{uuid.uuid4().hex}@example.test", "password": PASSWORD, "display_name": label},
        )
        self.assertEqual(response.status_code, 201, response.text)
        payload = response.json()
        if role != "owner":
            with SessionLocal() as session:
                membership = session.scalar(
                    select(OrganizationMember).where(
                        OrganizationMember.user_id == uuid.UUID(payload["user"]["id"]),
                        OrganizationMember.organization_id == uuid.UUID(payload["organization"]["id"]),
                    )
                )
                self.assertIsNotNone(membership)
                membership.role = role
                session.commit()
            refreshed = client.get("/api/v1/auth/me")
            self.assertEqual(refreshed.status_code, 200, refreshed.text)
            payload = refreshed.json()
        return client, payload

    def _pcap_file(self, name: str = "sample.pcap") -> dict:
        return {"file": (name, io.BytesIO(b"pcap"), "application/vnd.tcpdump.pcap")}

    def _fake_artifacts(self) -> SimpleNamespace:
        return SimpleNamespace(
            report_json={
                "guardrail_verification": {"human_review_required": "No"},
                "impact": {"attack_type": "scan", "risk_level": "low"},
                "findings": {"confidence_score": 0.8},
            },
            report_markdown="# Report",
            metrics={"runtime_seconds_total": 1.25},
            guardrail_audit={"checks": []},
            metadata={"packets": 1},
            analysis_record={"analysis_profile": "standard", "stage1_execution": {"profile": "standard"}},
        )

    def _create_queued_job(self, session_payload: dict) -> str:
        job = app_module.job_store.create_job(
            source_type="upload",
            source_name="worker.pcap",
            source_path=str(Path(self.tempdir.name) / "worker.pcap"),
            analysis_profile="standard",
            organization_id=session_payload["organization"]["id"],
            user_id=session_payload["user"]["id"],
        )
        req = AnalysisRequest(
            pcap_path=job.source_path,
            provider="gemini",
            model=None,
            use_ai=False,
            require_ai=False,
            analysis_profile="standard",
            artifacts_dir=job.artifacts_dir,
        )
        app_module._persist_analysis_request(job.analysis_job_id, req)
        return job.analysis_job_id

    def test_single_upload_enqueues_without_running_inline(self) -> None:
        owner, session_payload = self._registered_client("queue-single")

        with patch("backend.api.app._enqueue_analysis_job", return_value="rq-job") as enqueue:
            response = owner.post(
                "/api/v1/analysis",
                files=self._pcap_file(),
                data={"use_ai": "false", "analysis_profile": "standard"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["status"], "queued")
        self.assertEqual(payload["current_phase"], "queued")
        self.assertEqual(payload["progress"], 0.0)
        self.assertIsNone(payload["error"])
        enqueue.assert_called_once_with(payload["analysis_job_id"], session_payload["organization"]["id"])
        persisted = app_module.job_store.get(payload["analysis_job_id"], organization_id=session_payload["organization"]["id"])
        self.assertIn("analysis_request", persisted.metadata)

    def test_batch_upload_enqueues_total_job_and_preserves_response_shape(self) -> None:
        analyst, session_payload = self._registered_client("queue-batch", role="analyst")

        with patch("backend.api.app._enqueue_total_job", return_value="rq-total") as enqueue:
            response = analyst.post(
                "/api/v1/analysis/batch",
                files=[
                    ("files", ("one.pcap", io.BytesIO(b"one"), "application/vnd.tcpdump.pcap")),
                    ("files", ("two.pcap", io.BytesIO(b"two"), "application/vnd.tcpdump.pcap")),
                ],
                data={"worker_count": "2", "analysis_profile": "standard"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["status"], "queued")
        self.assertEqual(payload["current_stage"], "queued")
        self.assertEqual(payload["accepted_file_count"], 2)
        self.assertEqual(payload["skipped_files"], [])
        self.assertEqual(len(payload["children"]), 2)
        enqueue.assert_called_once_with(payload["total_job_id"], session_payload["organization"]["id"])
        for child in payload["children"]:
            persisted = app_module.job_store.get(child["analysis_job_id"], organization_id=session_payload["organization"]["id"])
            self.assertIn("analysis_request", persisted.metadata)

    def test_total_job_enrichment_enqueues_without_running_inline(self) -> None:
        owner, session_payload = self._registered_client("queue-enrich")
        child_id = self._create_queued_job(session_payload)
        app_module.job_store.save_artifact(child_id, "analysis_record.json", {"file": "worker.pcap", "analysis_profile": "standard"})
        app_module.job_store.update(child_id, status="completed", current_phase="completed", progress=1.0)
        total_job = app_module.total_job_store.create_job(
            worker_count=2,
            files=[],
            organization_id=session_payload["organization"]["id"],
            user_id=session_payload["user"]["id"],
        )
        app_module.total_job_store.update(
            total_job.total_job_id,
            status="completed",
            current_stage="ready_for_enrichment",
            progress=1.0,
            deterministic_complete=True,
            file_count=1,
            children=[TotalJobChildRef(analysis_job_id=child_id, filename="worker.pcap")],
        )

        with patch("backend.api.app._enqueue_total_job_enrichment", return_value="rq-enrich") as enqueue:
            response = owner.post(f"/api/v1/total-jobs/{total_job.total_job_id}/enrich", data={"require_ai": "false"})

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["enrichment_status"], "queued")
        self.assertEqual(payload["enrichment_progress"], 0.0)
        enqueue.assert_called_once_with(total_job.total_job_id, session_payload["organization"]["id"], "gemini", None, False)

    def test_worker_run_analysis_job_marks_completed(self) -> None:
        _owner, session_payload = self._registered_client("worker-success")
        job_id = self._create_queued_job(session_payload)

        fake_engine = SimpleNamespace(run=lambda req, callback: self._fake_artifacts())
        with patch("backend.api.app.AnalysisEngine", return_value=fake_engine):
            app_module.run_analysis_job(job_id, session_payload["organization"]["id"])

        job = app_module.job_store.get(job_id, organization_id=session_payload["organization"]["id"])
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.current_phase, "completed")
        self.assertEqual(job.progress, 1.0)
        self.assertIsNone(job.error)
        self.assertTrue(job.artifact_ready["report_json"])
        self.assertTrue(job.artifact_ready["report_markdown"])

    def test_worker_run_analysis_job_failure_persists_error(self) -> None:
        _owner, session_payload = self._registered_client("worker-failure")
        job_id = self._create_queued_job(session_payload)

        def fail(_req, _callback):
            raise RuntimeError("forced analysis failure")

        fake_engine = SimpleNamespace(run=fail)
        with patch("backend.api.app.AnalysisEngine", return_value=fake_engine):
            app_module.run_analysis_job(job_id, session_payload["organization"]["id"])

        job = app_module.job_store.get(job_id, organization_id=session_payload["organization"]["id"])
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.guardrail_state, "error")
        self.assertIn("forced analysis failure", job.error or "")

    def test_worker_rejects_cross_tenant_org_metadata(self) -> None:
        _owner_a, session_a = self._registered_client("worker-tenant-a")
        _owner_b, session_b = self._registered_client("worker-tenant-b")
        job_id = self._create_queued_job(session_b)

        with self.assertRaises(KeyError):
            app_module.run_analysis_job(job_id, session_a["organization"]["id"])

        job = app_module.job_store.get(job_id, organization_id=session_b["organization"]["id"])
        self.assertEqual(job.status, "queued")

    def test_worker_total_job_enrichment_failure_persists_error(self) -> None:
        _owner, session_payload = self._registered_client("worker-enrich-failure")
        total_job = app_module.total_job_store.create_job(
            worker_count=2,
            files=[],
            organization_id=session_payload["organization"]["id"],
            user_id=session_payload["user"]["id"],
        )
        app_module.total_job_store.update(
            total_job.total_job_id,
            status="completed",
            current_stage="ready_for_enrichment",
            progress=1.0,
            deterministic_complete=True,
        )

        with patch("backend.api.app._run_total_job_enrichment_sync", side_effect=RuntimeError("forced enrichment failure")):
            app_module.run_total_job_enrichment(total_job.total_job_id, session_payload["organization"]["id"], "gemini", None, False)

        refreshed = app_module.total_job_store.get(total_job.total_job_id, organization_id=session_payload["organization"]["id"])
        self.assertEqual(refreshed.status, "completed")
        self.assertEqual(refreshed.current_stage, "ready_for_enrichment")
        self.assertEqual(refreshed.enrichment_status, "failed")
        self.assertIn("forced enrichment failure", refreshed.enrichment_error or "")


if __name__ == "__main__":
    unittest.main()
