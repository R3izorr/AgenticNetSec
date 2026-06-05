from __future__ import annotations

import io
import tempfile
import unittest
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.api import app as app_module
from backend.api.artifact_service import ArtifactService
from backend.api.auth import AUTH_COOKIE_NAME
from backend.api.job_store import JobStore
from backend.api.total_job_store import TotalJobChildRef, TotalJobStore
from backend.db.models import OrganizationMember
from backend.db.session import SessionLocal


PASSWORD = "ChangeMe123!"


class ApiValidationLifecycleTests(unittest.TestCase):
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

    def _client(self) -> TestClient:
        client = TestClient(app_module.app)
        self.clients.append(client)
        return client

    def _registered_client(self, label: str, role: str = "owner") -> tuple[TestClient, dict]:
        client = self._client()
        email = f"{label}-{uuid.uuid4().hex}@example.test"
        response = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": PASSWORD, "display_name": label},
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
            self.assertEqual(payload["organization"]["role"], role)
        return client, payload

    def test_duplicate_register_logout_and_tampered_cookie(self) -> None:
        client = self._client()
        email = f"auth-{uuid.uuid4().hex}@example.test"

        registered = client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": PASSWORD, "display_name": "Auth"},
        )
        self.assertEqual(registered.status_code, 201, registered.text)
        self.assertIn(AUTH_COOKIE_NAME, client.cookies)

        duplicate = client.post(
            "/api/v1/auth/register",
            json={"email": email.upper(), "password": PASSWORD, "display_name": "Duplicate"},
        )
        self.assertEqual(duplicate.status_code, 409, duplicate.text)

        me = client.get("/api/v1/auth/me")
        self.assertEqual(me.status_code, 200, me.text)

        logout = client.post("/api/v1/auth/logout")
        self.assertEqual(logout.status_code, 204, logout.text)
        self.assertEqual(client.get("/api/v1/auth/me").status_code, 401)

        client.cookies.set(AUTH_COOKIE_NAME, "tampered-token")
        self.assertEqual(client.get("/api/v1/auth/me").status_code, 401)

    def test_anonymous_protected_routes_return_401(self) -> None:
        client = self._client()

        for path in ("/api/v1/analysis", "/api/v1/total-jobs", "/api/v1/auth/me"):
            response = client.get(path)
            self.assertEqual(response.status_code, 401, f"{path}: {response.text}")

    def test_upload_rejects_unsafe_or_unsupported_filenames(self) -> None:
        owner, _session_payload = self._registered_client("upload-validation")

        for filename in ("../evil.pcap", "dir/file.pcap", "notes.txt"):
            with self.subTest(filename=filename):
                response = owner.post(
                    "/api/v1/analysis",
                    files={"file": (filename, io.BytesIO(b"pcap"), "application/octet-stream")},
                )
                self.assertEqual(response.status_code, 400, f"{filename}: {response.text}")

        with self.assertRaises(ValueError):
            ArtifactService.validate_upload_filename(r"C:\temp\evil.pcap")

    def test_server_pcap_paths_are_rejected_when_disabled(self) -> None:
        owner, _session_payload = self._registered_client("server-path-disabled")

        single = owner.post(
            "/api/v1/analysis",
            json={"pcap_path": "/tmp/example.pcap", "analysis_profile": "standard"},
        )
        self.assertEqual(single.status_code, 400, single.text)
        self.assertIn("disabled", single.json()["detail"])

        batch = owner.post(
            "/api/v1/analysis/batch",
            json={"pcap_paths": ["/tmp/example.pcap"], "worker_count": 2},
        )
        self.assertEqual(batch.status_code, 400, batch.text)
        self.assertIn("disabled", batch.json()["detail"])

    def test_incomplete_artifact_endpoints_return_409(self) -> None:
        owner, session_payload = self._registered_client("artifact-not-ready")
        job = app_module.job_store.create_job(
            source_type="upload",
            source_name="queued.pcap",
            source_path=str(Path(self.tempdir.name) / "queued.pcap"),
            organization_id=session_payload["organization"]["id"],
            user_id=session_payload["user"]["id"],
        )

        for path in (
            f"/api/v1/analysis/{job.analysis_job_id}/report.json",
            f"/api/v1/analysis/{job.analysis_job_id}/report.md",
            f"/api/v1/analysis/{job.analysis_job_id}/metrics",
            f"/api/v1/analysis/{job.analysis_job_id}/guardrail-audit",
        ):
            response = owner.get(path)
            self.assertEqual(response.status_code, 409, f"{path}: {response.text}")

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
            children=[TotalJobChildRef(analysis_job_id=job.analysis_job_id, filename="queued.pcap")],
            file_count=1,
        )

        for path in (
            f"/api/v1/total-jobs/{total_job.total_job_id}/summary.json",
            f"/api/v1/total-jobs/{total_job.total_job_id}/summary.md",
            f"/api/v1/total-jobs/{total_job.total_job_id}/sandbox",
        ):
            response = owner.get(path)
            self.assertEqual(response.status_code, 409, f"{path}: {response.text}")

    def test_viewer_cannot_delete_or_trigger_enrichment(self) -> None:
        viewer, session_payload = self._registered_client("viewer-mutations", role="viewer")
        job = app_module.job_store.create_job(
            source_type="upload",
            source_name="viewer.pcap",
            source_path=str(Path(self.tempdir.name) / "viewer.pcap"),
            organization_id=session_payload["organization"]["id"],
            user_id=session_payload["user"]["id"],
        )
        total_job = app_module.total_job_store.create_job(
            worker_count=2,
            files=[],
            organization_id=session_payload["organization"]["id"],
            user_id=session_payload["user"]["id"],
        )

        delete_response = viewer.delete(f"/api/v1/analysis/{job.analysis_job_id}")
        self.assertEqual(delete_response.status_code, 403, delete_response.text)

        enrich_response = viewer.post(f"/api/v1/total-jobs/{total_job.total_job_id}/enrich")
        self.assertEqual(enrich_response.status_code, 403, enrich_response.text)

        all_summary_response = viewer.post("/api/v1/total-jobs/summary/enrich")
        self.assertEqual(all_summary_response.status_code, 403, all_summary_response.text)


if __name__ == "__main__":
    unittest.main()
