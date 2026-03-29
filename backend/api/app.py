from __future__ import annotations

import asyncio
import os
from pathlib import Path
from pathlib import PureWindowsPath
import re
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
from .job_store import JobRecord, JobStore

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


def _serialize_job(job: JobRecord) -> dict[str, Any]:
    return {
        "analysis_job_id": job.analysis_job_id,
        "status": job.status,
        "current_phase": job.current_phase,
        "progress": job.progress,
        "guardrail_state": job.guardrail_state,
        "error": job.error,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "source_type": job.source_type,
        "source_name": job.source_name,
        "source_path": job.source_path,
        "metadata": job.metadata,
        "artifact_ready": job.artifact_ready,
        "attack_type": job.attack_type,
        "risk_level": job.risk_level,
        "confidence_score": job.confidence_score,
        "runtime_seconds_total": job.runtime_seconds_total,
    }


WINDOWS_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _normalize_pcap_path(raw_path: str) -> str:
    candidate = raw_path.strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="pcap_path cannot be empty.")

    if WINDOWS_DRIVE_PATH_RE.match(candidate):
        if os.name == "nt":
            return str(PureWindowsPath(candidate))

        windows_path = PureWindowsPath(candidate)
        drive_letter = windows_path.drive.rstrip(":").lower()
        relative_parts = windows_path.parts[1:]
        wsl_path = Path("/mnt") / drive_letter / Path(*relative_parts)
        return str(wsl_path if wsl_path.exists() else Path(candidate))

    return str(Path(candidate).expanduser().resolve())


async def _run_job(job_id: str, req: AnalysisRequest) -> None:
    last_phase = "queued"
    last_progress = 0.0

    def on_progress(phase: str, progress: float) -> None:
        nonlocal last_phase, last_progress
        last_phase = phase
        last_progress = progress
        job_store.update(job_id, status="running", current_phase=phase, progress=progress)

    try:
        job_store.update(job_id, status="running", current_phase="ingest", progress=0.05)
        loop = asyncio.get_running_loop()
        artifacts = await loop.run_in_executor(None, engine.run, req, on_progress)

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
            metadata=artifacts.metadata,
            attack_type=(artifacts.report_json.get("impact") or {}).get("attack_type"),
            risk_level=(artifacts.report_json.get("impact") or {}).get("risk_level"),
            confidence_score=(artifacts.report_json.get("findings") or {}).get("confidence_score"),
            runtime_seconds_total=artifacts.metrics.get("runtime_seconds_total"),
        )
    except Exception as exc:  # noqa: BLE001
        job_store.update(
            job_id,
            status="failed",
            current_phase=last_phase,
            progress=last_progress,
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
        source_type = "upload"
        source_name = safe_name
        source_path = target_path
    else:
        target_path = _normalize_pcap_path(pcap_path)
        source_type = "path"
        source_name = Path(target_path).name
        source_path = target_path

    job = job_store.create_job(
        source_type=source_type,
        source_name=source_name,
        source_path=source_path,
    )

    req = AnalysisRequest(
        pcap_path=target_path,
        provider=(provider or "gemini"),
        model=model,
        use_ai=_to_bool(use_ai, True),
        require_ai=_to_bool(require_ai, False),
    )

    asyncio.create_task(_run_job(job.analysis_job_id, req))

    return _serialize_job(job)


@app.get("/api/v1/analysis/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(**_serialize_job(job))


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
    all_jobs = job_store.list_jobs()
    return {
        "total": len(all_jobs),
        "jobs": [_serialize_job(job) for job in all_jobs],
    }
