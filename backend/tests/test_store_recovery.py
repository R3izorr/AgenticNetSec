from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from backend.api.job_store import JobStore
from backend.api.total_job_store import TotalJobStore


class StoreRecoveryTests(unittest.TestCase):
    def test_job_store_marks_stale_running_job_as_failed_on_reload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir) / "analysis_jobs"
            store = JobStore(base_dir)
            job = store.create_job(
                source_type="path",
                source_name="sample.pcap",
                source_path="/tmp/sample.pcap",
            )
            store.update(
                job.analysis_job_id,
                status="running",
                current_phase="analysis",
                progress=0.4,
            )

            reloaded = JobStore(base_dir)
            recovered = reloaded.get(job.analysis_job_id)

            self.assertIsNotNone(recovered)
            self.assertEqual(recovered.status, "failed")
            self.assertEqual(recovered.current_phase, "interrupted")
            self.assertEqual(recovered.error, "Interrupted by backend shutdown before analysis completed.")

    def test_total_job_store_marks_stale_deterministic_job_as_failed_on_reload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir) / "total_jobs"
            store = TotalJobStore(base_dir)
            total_job = store.create_job(worker_count=4, files=[])
            store.update(
                total_job.total_job_id,
                status="running",
                current_stage="deterministic_analysis",
                progress=0.3,
                deterministic_complete=False,
            )

            reloaded = TotalJobStore(base_dir)
            recovered = reloaded.get(total_job.total_job_id)

            self.assertIsNotNone(recovered)
            self.assertEqual(recovered.status, "failed")
            self.assertEqual(recovered.current_stage, "failed")
            self.assertEqual(recovered.error, "Interrupted by backend shutdown before deterministic analysis completed.")

    def test_total_job_store_marks_stale_enrichment_as_failed_on_reload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir) / "total_jobs"
            store = TotalJobStore(base_dir)
            total_job = store.create_job(worker_count=4, files=[])
            store.update(
                total_job.total_job_id,
                status="running",
                current_stage="enrichment_running",
                progress=1.0,
                deterministic_complete=True,
                enrichment_status="running",
                enrichment_progress=0.6,
            )

            reloaded = TotalJobStore(base_dir)
            recovered = reloaded.get(total_job.total_job_id)

            self.assertIsNotNone(recovered)
            self.assertEqual(recovered.status, "completed")
            self.assertEqual(recovered.current_stage, "ready_for_enrichment")
            self.assertEqual(recovered.enrichment_status, "failed")
            self.assertEqual(recovered.enrichment_error, "Interrupted by backend shutdown during enrichment.")


if __name__ == "__main__":
    unittest.main()
