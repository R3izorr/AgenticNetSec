from __future__ import annotations

import io
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.api import app as app_module
from backend.api.job_store import JobStore
from backend.api.total_job_store import TotalJobStore, TotalJobChildRef
from backend.db.models import OrganizationMember
from backend.db.session import SessionLocal


PASSWORD = "ChangeMe123!"


class RBACTenantIsolationTests(unittest.TestCase):
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
        email = f"{label}-{uuid.uuid4().hex}@example.test"
        response = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": PASSWORD, "display_name": label},
        )
        self.assertEqual(response.status_code, 201, response.text)
        session_payload = response.json()
        if role != "owner":
            self._set_role(session_payload["user"]["id"], session_payload["organization"]["id"], role)
            refreshed = client.get("/api/v1/auth/me")
            self.assertEqual(refreshed.status_code, 200, refreshed.text)
            session_payload = refreshed.json()
            self.assertEqual(session_payload["organization"]["role"], role)
        return client, session_payload

    def _set_role(self, user_id: str, organization_id: str, role: str) -> str:
        with SessionLocal() as session:
            membership = session.scalar(
                select(OrganizationMember).where(
                    OrganizationMember.user_id == uuid.UUID(user_id),
                    OrganizationMember.organization_id == uuid.UUID(organization_id),
                )
            )
            self.assertIsNotNone(membership)
            membership.role = role
            session.commit()
            return str(membership.id)

    def _add_member(self, organization_id: str, user_id: str, role: str) -> str:
        with SessionLocal() as session:
            membership = session.scalar(
                select(OrganizationMember).where(
                    OrganizationMember.user_id == uuid.UUID(user_id),
                    OrganizationMember.organization_id == uuid.UUID(organization_id),
                )
            )
            if membership is None:
                membership = OrganizationMember(
                    organization_id=uuid.UUID(organization_id),
                    user_id=uuid.UUID(user_id),
                    role=role,
                )
                session.add(membership)
            else:
                membership.role = role
            session.commit()
            return str(membership.id)

    def test_viewer_cannot_upload_and_analyst_can_upload(self) -> None:
        viewer, _viewer_session = self._registered_client("viewer", role="viewer")
        analyst, _analyst_session = self._registered_client("analyst", role="analyst")

        viewer_single = viewer.post(
            "/api/v1/analysis",
            files={"file": ("viewer.pcap", io.BytesIO(b"pcap"), "application/vnd.tcpdump.pcap")},
        )
        self.assertEqual(viewer_single.status_code, 403, viewer_single.text)

        viewer_batch = viewer.post(
            "/api/v1/analysis/batch",
            files={"files": ("viewer.pcap", io.BytesIO(b"pcap"), "application/vnd.tcpdump.pcap")},
            data={"worker_count": "2", "analysis_profile": "standard"},
        )
        self.assertEqual(viewer_batch.status_code, 403, viewer_batch.text)

        with patch("backend.api.app._enqueue_total_job", return_value="rq-total-job"):
            analyst_batch = analyst.post(
                "/api/v1/analysis/batch",
                files={"files": ("analyst.pcap", io.BytesIO(b"pcap"), "application/vnd.tcpdump.pcap")},
                data={"worker_count": "2", "analysis_profile": "standard"},
            )
        self.assertEqual(analyst_batch.status_code, 200, analyst_batch.text)
        payload = analyst_batch.json()
        self.assertTrue(payload["total_job_id"])
        self.assertEqual(payload["accepted_file_count"], 1)

    def test_cross_tenant_analysis_job_and_artifacts_are_404(self) -> None:
        owner_a, _session_a = self._registered_client("owner-a")
        _owner_b, session_b = self._registered_client("owner-b")

        job = app_module.job_store.create_job(
            source_type="upload",
            source_name="tenant-b.pcap",
            source_path=str(Path(self.tempdir.name) / "tenant-b.pcap"),
            organization_id=session_b["organization"]["id"],
            user_id=session_b["user"]["id"],
        )
        app_module.job_store.save_artifact(job.analysis_job_id, "report.json", {"tenant": "b"})
        app_module.job_store.save_artifact(job.analysis_job_id, "report.md", "# Tenant B")
        app_module.job_store.save_artifact(job.analysis_job_id, "metrics.json", {"runtime_seconds_total": 1})
        app_module.job_store.save_artifact(job.analysis_job_id, "guardrail_audit.json", {"checks": []})
        app_module.job_store.save_artifact(job.analysis_job_id, "analysis_record.json", {"analysis_profile": "standard"})
        app_module.job_store.update(job.analysis_job_id, status="completed", current_phase="completed", progress=1.0)

        for path in (
            f"/api/v1/analysis/{job.analysis_job_id}",
            f"/api/v1/analysis/{job.analysis_job_id}/report.json",
            f"/api/v1/analysis/{job.analysis_job_id}/report.md",
            f"/api/v1/analysis/{job.analysis_job_id}/metrics",
            f"/api/v1/analysis/{job.analysis_job_id}/guardrail-audit",
        ):
            response = owner_a.get(path)
            self.assertEqual(response.status_code, 404, f"{path}: {response.text}")

        history = owner_a.get("/api/v1/analysis")
        self.assertEqual(history.status_code, 200, history.text)
        self.assertNotIn(job.analysis_job_id, {item["analysis_job_id"] for item in history.json()["jobs"]})

    def test_cross_tenant_total_job_and_artifacts_are_404(self) -> None:
        owner_a, _session_a = self._registered_client("total-owner-a")
        _owner_b, session_b = self._registered_client("total-owner-b")

        total_job = app_module.total_job_store.create_job(
            worker_count=2,
            files=[],
            organization_id=session_b["organization"]["id"],
            user_id=session_b["user"]["id"],
        )
        app_module.total_job_store.update(
            total_job.total_job_id,
            status="completed",
            current_stage="enrichment_completed",
            progress=1.0,
            deterministic_complete=True,
            enrichment_status="completed",
            enrichment_progress=1.0,
            children=[TotalJobChildRef(analysis_job_id="analysis_child", filename="child.pcap")],
            file_count=1,
        )
        app_module.total_job_store.save_json_artifact(total_job.total_job_id, "summary.json", {"tenant": "b"})
        app_module.total_job_store.save_text_artifact(total_job.total_job_id, "summary.md", "# Tenant B")
        app_module.total_job_store.save_json_artifact(total_job.total_job_id, "sandbox.json", {"tenant": "b"})

        for path in (
            f"/api/v1/total-jobs/{total_job.total_job_id}",
            f"/api/v1/total-jobs/{total_job.total_job_id}/summary.json",
            f"/api/v1/total-jobs/{total_job.total_job_id}/summary.md",
            f"/api/v1/total-jobs/{total_job.total_job_id}/sandbox",
        ):
            response = owner_a.get(path)
            self.assertEqual(response.status_code, 404, f"{path}: {response.text}")

        listing = owner_a.get("/api/v1/total-jobs")
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertNotIn(total_job.total_job_id, {item["total_job_id"] for item in listing.json()["jobs"]})

    def test_owner_can_update_member_role_and_non_owner_cannot(self) -> None:
        owner, owner_session = self._registered_client("member-owner")
        analyst, analyst_session = self._registered_client("member-analyst", role="analyst")
        _target, target_session = self._registered_client("member-target")

        target_member_id = self._add_member(
            owner_session["organization"]["id"],
            target_session["user"]["id"],
            "analyst",
        )

        owner_response = owner.patch(
            f"/api/v1/organization/members/{target_member_id}/role",
            json={"role": "viewer"},
        )
        self.assertEqual(owner_response.status_code, 200, owner_response.text)
        self.assertEqual(owner_response.json()["member"]["role"], "viewer")

        analyst_response = analyst.patch(
            f"/api/v1/organization/members/{target_member_id}/role",
            json={"role": "analyst"},
        )
        self.assertEqual(analyst_response.status_code, 403, analyst_response.text)

        last_owner_response = owner.patch(
            f"/api/v1/organization/members/{self._set_role(owner_session['user']['id'], owner_session['organization']['id'], 'owner')}/role",
            json={"role": "viewer"},
        )
        self.assertEqual(last_owner_response.status_code, 409, last_owner_response.text)

    def test_all_total_jobs_summary_is_organization_scoped(self) -> None:
        owner_a, session_a = self._registered_client("summary-owner-a")
        owner_b, session_b = self._registered_client("summary-owner-b")

        app_module._write_all_total_jobs_summary_status(
            {"status": "completed", "progress": 1.0},
            session_b["organization"]["id"],
        )
        summary_dir = app_module._all_total_jobs_summary_dir(session_b["organization"]["id"])
        (summary_dir / "summary.json").write_text('{"tenant":"b"}\n', encoding="utf-8")
        (summary_dir / "summary.md").write_text("# Tenant B\n", encoding="utf-8")
        (summary_dir / "sandbox.json").write_text('{"tenant":"b"}\n', encoding="utf-8")

        for path in (
            "/api/v1/total-jobs/summary/json",
            "/api/v1/total-jobs/summary/markdown",
            "/api/v1/total-jobs/summary/sandbox",
        ):
            response = owner_a.get(path)
            self.assertEqual(response.status_code, 409, f"{path}: {response.text}")

        status_a = owner_a.get("/api/v1/total-jobs/summary/status")
        self.assertEqual(status_a.status_code, 200, status_a.text)
        self.assertEqual(status_a.json()["status"], "not_started")

        status_b = owner_b.get("/api/v1/total-jobs/summary/status")
        self.assertEqual(status_b.status_code, 200, status_b.text)
        self.assertEqual(status_b.json()["status"], "completed")
        self.assertEqual(session_a["organization"]["role"], "owner")


if __name__ == "__main__":
    unittest.main()
