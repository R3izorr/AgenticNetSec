from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import time
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analysis_engine import AnalysisEngine, AnalysisRequest
from forensic_schema import JobStatusResponse
from .job_store import JobStore

OUTPUTS_DIR = PROJECT_ROOT / "outputs"
UPLOADS_DIR = OUTPUTS_DIR / "uploads"
JOBS_DIR = OUTPUTS_DIR / "analysis_jobs"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="AgenticNetSec API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

job_store = JobStore(JOBS_DIR)
engine = AnalysisEngine()


def _to_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


async def _run_job(job_id: str, req: AnalysisRequest) -> None:
    try:
        job_store.update(job_id, status="running", current_phase="pipeline", progress=0.2)
        loop = asyncio.get_running_loop()
        artifacts = await loop.run_in_executor(None, engine.run, req)

        job_store.save_artifact(job_id, "report.json", artifacts.report_json)
        job_store.save_artifact(job_id, "report.md", artifacts.report_markdown)
        job_store.save_artifact(job_id, "metrics.json", artifacts.metrics)
        job_store.save_artifact(job_id, "guardrail_audit.json", artifacts.guardrail_audit)

        guardrail_state = (
            artifacts.report_json.get("guardrail_verification", {}).get("human_review_required", "No")
        )
        job_store.update(
            job_id,
            status="completed",
            current_phase="completed",
            progress=1.0,
            guardrail_state=guardrail_state,
        )
    except Exception as exc:  # noqa: BLE001
        job_store.update(
            job_id,
            status="failed",
            current_phase="failed",
            progress=1.0,
            guardrail_state="error",
            error=str(exc),
        )


@app.post("/api/v1/analysis")
async def create_analysis_job(
    request: Request,
    file: UploadFile | None = File(default=None),
    pcap_path: str | None = Form(default=None),
    provider: str | None = Form(default=None),
    model: str | None = Form(default=None),
    use_ai: str | bool | None = Form(default=None),
    require_ai: str | bool | None = Form(default=None),
):
    if not file and not pcap_path and "application/json" in request.headers.get("content-type", ""):
        payload = await request.json()
        pcap_path = payload.get("pcap_path")
        provider = provider or payload.get("provider")
        model = model or payload.get("model")
        use_ai = payload.get("use_ai", use_ai)
        require_ai = payload.get("require_ai", require_ai)

    if file is None and not pcap_path:
        raise HTTPException(status_code=400, detail="Provide either 'file' upload or 'pcap_path'.")

    if file is not None:
        safe_name = Path(file.filename or "upload.pcap").name
        dest = UPLOADS_DIR / f"upload_{int(time.time())}_{safe_name}"
        dest.write_bytes(await file.read())
        target_path = str(dest)
    else:
        target_path = str(Path(pcap_path).expanduser().resolve())

    job = job_store.create_job()

    req = AnalysisRequest(
        pcap_path=target_path,
        provider=(provider or "gemini"),
        model=model,
        use_ai=_to_bool(use_ai, True),
        require_ai=_to_bool(require_ai, False),
    )

    asyncio.create_task(_run_job(job.analysis_job_id, req))

    return {
        "analysis_job_id": job.analysis_job_id,
        "status": job.status,
        "current_phase": job.current_phase,
        "progress": job.progress,
    }


@app.get("/api/v1/analysis/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(
        analysis_job_id=job.analysis_job_id,
        status=job.status,
        current_phase=job.current_phase,
        progress=job.progress,
        guardrail_state=job.guardrail_state,
        error=job.error,
    )


@app.get("/api/v1/analysis/{job_id}/report.json")
async def get_report_json(job_id: str):
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail=f"Job is {job.status}")
    return job_store.read_json_artifact(job_id, "report.json")


@app.get("/api/v1/analysis/{job_id}/report.md")
async def get_report_markdown(job_id: str):
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail=f"Job is {job.status}")
    return {"markdown": job_store.read_text_artifact(job_id, "report.md")}


@app.get("/api/v1/analysis/{job_id}/metrics")
async def get_metrics(job_id: str):
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail=f"Job is {job.status}")
    return job_store.read_json_artifact(job_id, "metrics.json")


@app.get("/api/v1/analysis/{job_id}/guardrail-audit")
async def get_guardrail_audit(job_id: str):
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail=f"Job is {job.status}")
    return job_store.read_json_artifact(job_id, "guardrail_audit.json")


@app.get("/api/v1/analysis")
async def list_jobs():
    """List all analysis jobs, ordered by creation time (newest first)."""
    all_jobs = job_store.list_jobs()
    print(all_jobs)
    # Convert to dict format
    return {
        "total": len(all_jobs),
        "jobs": [
            {
                "analysis_job_id": job.analysis_job_id,
                "status": job.status,
                "current_phase": job.current_phase,
                "progress": job.progress,
                "guardrail_state": job.guardrail_state,
                "created_at": job.created_at,
                "updated_at": job.updated_at,
                "error": job.error,
            }
            for job in all_jobs
        ],
    }

