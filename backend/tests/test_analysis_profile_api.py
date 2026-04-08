from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from fastapi import HTTPException

analysis_engine_stub = types.ModuleType("analysis_engine")


@dataclass
class _AnalysisRequestStub:
    pcap_path: str
    provider: str = "openrouter"
    model: str | None = None
    use_ai: bool = True
    require_ai: bool = False
    analysis_profile: str = "standard"
    enable_sandbox: bool | None = None
    artifacts_dir: str | None = None


class _AnalysisEngineStub:
    def run(self, *args, **kwargs):  # noqa: ANN002, ANN003
        raise NotImplementedError("AnalysisEngine is not used by this test.")


analysis_engine_stub.AnalysisEngine = _AnalysisEngineStub
analysis_engine_stub.AnalysisRequest = _AnalysisRequestStub
sys.modules.setdefault("analysis_engine", analysis_engine_stub)

from backend.api import app as api_app
from backend.api.job_store import JobStore
from backend.api.total_job_store import TotalJobChildRef, TotalJobStore


class _JsonRequest:
    def __init__(self, payload: dict):
        self.headers = {"content-type": "application/json"}
        self._payload = payload

    async def json(self) -> dict:
        return self._payload


class AnalysisProfileApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_single_analysis_defaults_to_standard_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            job_store = JobStore(temp_root / "analysis_jobs")

            created_coroutines: list[object] = []

            def _fake_create_task(coro):
                created_coroutines.append(coro)
                coro.close()
                return None

            with (
                patch.object(api_app, "job_store", job_store),
                patch("backend.api.app.asyncio.create_task", side_effect=_fake_create_task),
            ):
                response = await api_app.create_analysis_job(
                    request=_JsonRequest({"pcap_path": str(temp_root / "single.pcap")}),
                    file=None,
                    pcap_path=None,
                    provider=None,
                    model=None,
                    use_ai=None,
                    require_ai=None,
                    analysis_profile=None,
                )

            self.assertEqual(response["analysis_profile"], "standard")
            self.assertEqual(len(created_coroutines), 1)

    async def test_single_analysis_rejects_invalid_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            with self.assertRaises(HTTPException) as context:
                await api_app.create_analysis_job(
                    request=_JsonRequest(
                        {
                            "pcap_path": str(temp_root / "single.pcap"),
                            "analysis_profile": "invalid",
                        }
                    ),
                    file=None,
                    pcap_path=None,
                    provider=None,
                    model=None,
                    use_ai=None,
                    require_ai=None,
                    analysis_profile=None,
                )

            self.assertEqual(context.exception.status_code, 400)
            self.assertIn("analysis_profile", str(context.exception.detail))

    async def test_batch_analysis_defaults_to_standard_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            pcap_path = temp_root / "batch-default.pcap"
            pcap_path.write_bytes(b"pcap")
            job_store = JobStore(temp_root / "analysis_jobs")
            total_job_store = TotalJobStore(temp_root / "total_jobs")

            created_coroutines: list[object] = []

            def _fake_create_task(coro):
                created_coroutines.append(coro)
                coro.close()
                return None

            with (
                patch.object(api_app, "job_store", job_store),
                patch.object(api_app, "total_job_store", total_job_store),
                patch("backend.api.app.asyncio.create_task", side_effect=_fake_create_task),
            ):
                response = await api_app.create_batch_analysis_job(
                    request=_JsonRequest({"pcap_paths": [str(pcap_path)], "worker_count": 4}),
                    files=[],
                    worker_count=4,
                    pcap_paths=None,
                    analysis_profile=None,
                )

            self.assertEqual(response["analysis_profile"], "standard")
            self.assertEqual(response["children"][0]["analysis_profile"], "standard")
            self.assertEqual(len(created_coroutines), 1)

    async def test_batch_analysis_rejects_invalid_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            pcap_path = temp_root / "batch-invalid.pcap"
            pcap_path.write_bytes(b"pcap")

            with self.assertRaises(HTTPException) as context:
                await api_app.create_batch_analysis_job(
                    request=_JsonRequest(
                        {
                            "pcap_paths": [str(pcap_path)],
                            "worker_count": 4,
                            "analysis_profile": "bad-profile",
                        }
                    ),
                    files=[],
                    worker_count=4,
                    pcap_paths=None,
                    analysis_profile=None,
                )

            self.assertEqual(context.exception.status_code, 400)
            self.assertIn("analysis_profile", str(context.exception.detail))

    async def test_total_job_progress_reflects_running_child_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            job_store = JobStore(temp_root / "analysis_jobs")
            total_job_store = TotalJobStore(temp_root / "total_jobs")

            total_job = total_job_store.create_job(worker_count=2, files=[], analysis_profile="standard")
            child_job = job_store.create_job(
                source_type="path",
                source_name="sample.pcap",
                source_path=str(temp_root / "sample.pcap"),
                group_id=total_job.total_job_id,
                group_index=0,
                group_total=1,
                analysis_profile="standard",
            )
            job_store.update(
                child_job.analysis_job_id,
                status="running",
                current_phase="analysis",
                progress=0.2,
            )
            total_job_store.update(
                total_job.total_job_id,
                status="running",
                current_stage="deterministic_analysis",
                progress=0.02,
                file_count=1,
                children=[
                    TotalJobChildRef(
                        analysis_job_id=child_job.analysis_job_id,
                        filename=child_job.source_name or "sample.pcap",
                        source_path=child_job.source_path,
                    )
                ],
            )

            with (
                patch.object(api_app, "job_store", job_store),
                patch.object(api_app, "total_job_store", total_job_store),
            ):
                response = await api_app.get_total_job_status(total_job.total_job_id)

            self.assertEqual(response.analysis_profile, "standard")
            self.assertAlmostEqual(response.progress, 0.2)
            self.assertEqual(response.children[0].analysis_profile, "standard")
            self.assertAlmostEqual(response.children[0].progress, 0.2)


if __name__ == "__main__":
    unittest.main()
