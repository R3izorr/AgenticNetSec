from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import ANY, patch

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


class TotalJobEnrichmentCampaignRouteTests(unittest.TestCase):
    def test_all_jobs_summary_status_recovers_stale_running_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            summary_dir = temp_root / "total_jobs" / "__all_jobs_summary"
            summary_dir.mkdir(parents=True)
            status_path = summary_dir / "status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "progress": 0.2,
                        "error": None,
                        "updated_at": (
                            datetime.now(timezone.utc)
                            - timedelta(seconds=api_app.ALL_TOTAL_JOBS_SUMMARY_STALE_SECONDS + 1)
                        ).isoformat(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with (
                patch.object(api_app, "ALL_TOTAL_JOBS_SUMMARY_DIR", summary_dir),
                patch.object(api_app, "ALL_TOTAL_JOBS_SUMMARY_STATUS_PATH", status_path),
                patch.object(api_app, "job_store", JobStore(temp_root / "analysis_jobs")),
                patch.object(api_app, "total_job_store", TotalJobStore(temp_root / "total_jobs")),
            ):
                status = api_app._serialize_all_total_jobs_summary_status()

            persisted_status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(status["status"], "failed")
            self.assertEqual(persisted_status["status"], "failed")
            self.assertEqual(persisted_status["route_stage"], "interrupted")
            self.assertIn("backend shutdown", persisted_status["error"])

    def test_all_jobs_summary_uses_enriched_json_without_campaign_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            job_store = JobStore(temp_root / "analysis_jobs")
            total_job_store = TotalJobStore(temp_root / "total_jobs")
            summary_dir = temp_root / "total_jobs" / "__all_jobs_summary"
            summary_dir.mkdir(parents=True)

            total_job = total_job_store.create_job(
                worker_count=2,
                files=[
                    {
                        "analysis_job_id": "analysis_1",
                        "filename": "campaign-a.pcap",
                        "source_path": "/tmp/campaign-a.pcap",
                    }
                ],
            )
            total_job_store.update(
                total_job.total_job_id,
                status="completed",
                current_stage="enrichment_completed",
                deterministic_complete=True,
                enrichment_status="completed",
                enrichment_progress=1.0,
            )
            total_job_store.save_json_artifact(
                total_job.total_job_id,
                "scan_results.json",
                [
                    {
                        "file": "campaign-a.pcap",
                        "path": "/tmp/campaign-a.pcap",
                        "size_bytes": 1234,
                        "sandbox_verification": {"status": "completed"},
                    }
                ],
            )

            final_report_result = type(
                "Result",
                (),
                {
                    "text": "# Final\n\nCombined report.",
                    "provider": "gemini",
                    "model": "gemini-2.5-flash",
                    "fallback_used": False,
                    "api_attempted": True,
                    "failure_reason": None,
                    "llm_tokens_in": 10,
                    "llm_tokens_out": 20,
                },
            )()

            with (
                patch.object(api_app, "ALL_TOTAL_JOBS_SUMMARY_DIR", summary_dir),
                patch.object(api_app, "ALL_TOTAL_JOBS_SUMMARY_STATUS_PATH", summary_dir / "status.json"),
                patch.object(api_app, "job_store", job_store),
                patch.object(api_app, "total_job_store", total_job_store),
                patch("backend.api.app.build_aggregate", return_value={"file_count": 1}) as build_aggregate,
                patch("backend.api.app.generate_results_report_result", return_value=final_report_result) as generate_report,
                patch("backend.api.app.run_campaign_summary_route") as run_campaign_summary_route,
            ):
                api_app._run_all_total_jobs_summary_sync(
                    provider="gemini",
                    model="gemini-2.5-flash",
                    require_ai=False,
                )

            run_campaign_summary_route.assert_not_called()
            build_aggregate.assert_called_once()
            generate_report.assert_called_once()
            summary = json.loads((summary_dir / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["route"], "combined_enriched_json_final_report")
            self.assertEqual(summary["record_source"]["sources"][0]["record_source"], "parent_enrichment")
            self.assertEqual(summary["records"][0]["sandbox_verification"]["status"], "completed")

    def test_total_job_enrichment_uses_campaign_route_and_persists_richer_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            job_store = JobStore(temp_root / "analysis_jobs")
            total_job_store = TotalJobStore(temp_root / "total_jobs")

            child_job = job_store.create_job(
                source_type="upload",
                source_name="campaign-a.pcap",
                source_path="/tmp/campaign-a.pcap",
            )
            job_store.update(
                child_job.analysis_job_id,
                status="completed",
                current_phase="completed",
                progress=1.0,
            )
            job_store.save_artifact(
                child_job.analysis_job_id,
                "analysis_record.json",
                {
                    "file": "campaign-a.pcap",
                    "path": "/tmp/campaign-a.pcap",
                    "size_bytes": 1234,
                },
            )

            total_job = total_job_store.create_job(
                worker_count=2,
                files=[
                    {
                        "analysis_job_id": child_job.analysis_job_id,
                        "filename": "campaign-a.pcap",
                        "source_path": "/tmp/campaign-a.pcap",
                    }
                ],
            )
            total_job_store.update(
                total_job.total_job_id,
                status="completed",
                current_stage="ready_for_enrichment",
                deterministic_complete=True,
            )

            campaign_result = {
                "initial_summary": {
                    "provider": "gemini",
                    "model": "gemini-2.5-flash",
                    "report_text": "# Initial Campaign Summary\n\nWeak point in section C.",
                    "fallback_used": False,
                    "api_attempted": True,
                    "llm_tokens_in": 11,
                    "llm_tokens_out": 22,
                    "ai_callable": True,
                    "failure_reason": None,
                    "status": "ai_generated",
                },
                "campaign_plan": {
                    "planner_source": "ai",
                    "ai_api_attempted": True,
                    "weak_sections": ["C"],
                    "failure_reason": None,
                    "section_reasons": {"C": "Exfiltration evidence needed more validation."},
                },
                "selected_follow_up_records": [
                    {
                        "file": "campaign-a.pcap",
                        "path": "/tmp/campaign-a.pcap",
                    }
                ],
                "enriched_records": [
                    {
                        "file": "campaign-a.pcap",
                        "path": "/tmp/campaign-a.pcap",
                        "ai_tshark_query_count": 1,
                        "ai_tshark_review": {
                            "status": "completed",
                            "query_count": 1,
                            "queries": [{"name": "temp_sh_follow_up", "stage": "C"}],
                        },
                        "sandbox_verification": {"status": "completed"},
                    }
                ],
                "aggregate": {
                    "file_count": 1,
                    "files_with_ai_tshark_follow_up": 1,
                },
                "final_report": {
                    "provider": "gemini",
                    "model": "gemini-2.5-flash",
                    "fallback_used": True,
                    "api_attempted": False,
                    "ai_callable": False,
                    "failure_reason": "no_api_call",
                    "status": "fallback_report",
                    "report_text": "# Final Campaign Report\n\nFollow-up complete.",
                },
                "final_report_markdown": "# Final Campaign Report\n\nFollow-up complete.",
            }

            with (
                patch.object(api_app, "job_store", job_store),
                patch.object(api_app, "total_job_store", total_job_store),
                patch("backend.api.app.build_aggregate", return_value={"file_count": 1}) as build_aggregate,
                patch("backend.api.app.run_campaign_summary_route", return_value=campaign_result) as run_campaign_summary_route,
            ):
                api_app._run_total_job_enrichment_sync(
                    total_job.total_job_id,
                    provider="gemini",
                    model=None,
                    require_ai=False,
                )

            build_aggregate.assert_called_once_with(
                [
                    {
                        "file": "campaign-a.pcap",
                        "path": "/tmp/campaign-a.pcap",
                        "size_bytes": 1234,
                    }
                ]
            )
            run_campaign_summary_route.assert_called_once_with(
                [
                    {
                        "file": "campaign-a.pcap",
                        "path": "/tmp/campaign-a.pcap",
                        "size_bytes": 1234,
                    }
                ],
                {"file_count": 1},
                report_provider="gemini",
                report_model=None,
                planner_provider="openrouter",
                planner_model=None,
                require_ai=False,
                progress_callback=ANY,
                artifacts_dir=total_job.artifacts_dir,
            )

            summary_payload = total_job_store.read_json_artifact(total_job.total_job_id, "summary.json")
            sandbox_payload = total_job_store.read_json_artifact(total_job.total_job_id, "sandbox.json")
            campaign_plan_payload = total_job_store.read_json_artifact(total_job.total_job_id, "campaign_plan.json")
            initial_summary_markdown = total_job_store.read_text_artifact(total_job.total_job_id, "initial_summary.md")
            final_summary_markdown = total_job_store.read_text_artifact(total_job.total_job_id, "summary.md")

            self.assertEqual(summary_payload["route"], "campaign_ai_then_sandbox_then_final_report")
            self.assertEqual(summary_payload["scope"], "total_job")
            self.assertEqual(summary_payload["source_total_job_id"], total_job.total_job_id)
            self.assertEqual(summary_payload["source_file_count"], 1)
            self.assertEqual(summary_payload["initial_summary"]["report_text"], campaign_result["initial_summary"]["report_text"])
            self.assertEqual(summary_payload["campaign_plan"]["weak_sections"], ["C"])
            self.assertTrue(summary_payload["ai_execution"]["initial_summary"]["ai_callable"])
            self.assertTrue(summary_payload["ai_execution"]["initial_summary"]["api_attempted"])
            self.assertFalse(summary_payload["ai_execution"]["final_report"]["ai_callable"])
            self.assertTrue(summary_payload["ai_execution"]["final_report"]["fallback_used"])
            self.assertFalse(summary_payload["ai_execution"]["final_report"]["api_attempted"])
            self.assertEqual(
                summary_payload["selected_follow_up_records"],
                [{"file": "campaign-a.pcap", "path": "/tmp/campaign-a.pcap"}],
            )
            self.assertEqual(sandbox_payload["scope"], "total_job")
            self.assertEqual(sandbox_payload["record_count"], 1)
            self.assertEqual(campaign_plan_payload["campaign_plan"]["weak_sections"], ["C"])
            self.assertIn("> Initial Campaign Summary AI Status", initial_summary_markdown)
            self.assertIn("> API attempted: yes", initial_summary_markdown)
            self.assertIn("> AI callable: yes", initial_summary_markdown)
            self.assertIn("# Initial Campaign Summary", initial_summary_markdown)
            self.assertIn("> Final Campaign Report AI Status", final_summary_markdown)
            self.assertIn("> API attempted: no", final_summary_markdown)
            self.assertIn("> AI callable: no", final_summary_markdown)
            self.assertIn("> Fallback used: yes", final_summary_markdown)
            self.assertIn("> Provider requested: gemini", final_summary_markdown)
            self.assertIn("> Model requested: gemini-2.5-flash", final_summary_markdown)
            self.assertIn("# Final Campaign Report", final_summary_markdown)

            ai_tshark_jsonl_path = Path(total_job.artifacts_dir or "") / "scan_results.ai-tshark.jsonl"
            self.assertTrue(ai_tshark_jsonl_path.exists())
            self.assertEqual(
                [json.loads(line) for line in ai_tshark_jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()],
                campaign_result["enriched_records"],
            )

            updated_total_job = total_job_store.get(total_job.total_job_id)
            self.assertIsNotNone(updated_total_job)
            self.assertEqual(updated_total_job.enrichment_status, "completed")
            self.assertEqual(updated_total_job.current_stage, "enrichment_completed")
            self.assertEqual(updated_total_job.progress, 1.0)


if __name__ == "__main__":
    unittest.main()
