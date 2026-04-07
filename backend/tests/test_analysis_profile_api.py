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
from backend.api.total_job_store import TotalJobStore


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


if __name__ == "__main__":
    unittest.main()
