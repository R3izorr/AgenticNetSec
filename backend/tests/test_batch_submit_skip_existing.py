from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

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


class BatchSubmitSkipExistingTests(unittest.IsolatedAsyncioTestCase):
    async def test_skips_all_existing_path_based_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            pcap_path = temp_root / "existing.pcap"
            pcap_path.write_bytes(b"pcap")

            job_store = JobStore(temp_root / "analysis_jobs")
            total_job_store = TotalJobStore(temp_root / "total_jobs")
            existing_job = job_store.create_job(
                source_type="path",
                source_name=pcap_path.name,
                source_path=str(pcap_path),
            )
            job_store.update(existing_job.analysis_job_id, status="completed", current_phase="completed", progress=1.0)

            with (
                patch.object(api_app, "job_store", job_store),
                patch.object(api_app, "total_job_store", total_job_store),
            ):
                response = await api_app.create_batch_analysis_job(
                    request=_JsonRequest({"pcap_paths": [str(pcap_path)], "worker_count": 4, "analysis_profile": "fast"}),
                    files=[],
                    worker_count=4,
                    pcap_paths=None,
                )

            self.assertIsNone(response["total_job_id"])
            self.assertEqual(response["status"], "skipped")
            self.assertEqual(response["analysis_profile"], "fast")
            self.assertEqual(response["accepted_file_count"], 0)
            self.assertEqual(len(response["skipped_files"]), 1)
            self.assertEqual(response["skipped_files"][0]["path"], str(pcap_path.resolve()))
            self.assertEqual(response["skipped_files"][0]["existing_analysis_job_id"], existing_job.analysis_job_id)

    async def test_submits_only_new_path_based_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            existing_path = temp_root / "existing.pcap"
            new_path = temp_root / "new.pcap"
            existing_path.write_bytes(b"pcap1")
            new_path.write_bytes(b"pcap2")

            job_store = JobStore(temp_root / "analysis_jobs")
            total_job_store = TotalJobStore(temp_root / "total_jobs")
            existing_job = job_store.create_job(
                source_type="path",
                source_name=existing_path.name,
                source_path=str(existing_path),
            )
            job_store.update(existing_job.analysis_job_id, status="completed", current_phase="completed", progress=1.0)

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
                    request=_JsonRequest(
                        {
                            "pcap_paths": [str(existing_path), str(new_path)],
                            "worker_count": 4,
                            "analysis_profile": "full",
                        }
                    ),
                    files=[],
                    worker_count=4,
                    pcap_paths=None,
                )

            self.assertIsNotNone(response["total_job_id"])
            self.assertEqual(response["analysis_profile"], "full")
            self.assertEqual(response["accepted_file_count"], 1)
            self.assertEqual(response["file_count"], 1)
            self.assertEqual(len(response["children"]), 1)
            self.assertEqual(response["children"][0]["filename"], new_path.name)
            self.assertEqual(response["children"][0]["analysis_profile"], "full")
            self.assertEqual(len(response["skipped_files"]), 1)
            self.assertEqual(response["skipped_files"][0]["existing_analysis_job_id"], existing_job.analysis_job_id)
            self.assertEqual(len(created_coroutines), 1)


if __name__ == "__main__":
    unittest.main()
