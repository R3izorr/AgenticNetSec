from __future__ import annotations

import asyncio
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from pathlib import PureWindowsPath
import re
import sys
import time
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
SCRIPTS_DIR = PROJECT_ROOT / "backend" / "scripts"
for module_dir in (SRC_DIR, SCRIPTS_DIR):
    module_dir_str = str(module_dir)
    if module_dir_str not in sys.path:
        sys.path.insert(0, module_dir_str)

from analysis_engine import AnalysisEngine, AnalysisRequest
from enrich_results_with_sandbox import run_campaign_summary_route
from forensic_schema import JobStatusResponse, TotalJobStatusResponse
from planner import ANALYSIS_PROFILES
from report_ai import generate_results_report_result
from summarize_results import build_aggregate
from backend.db.session import check_database_connection
from .auth import CurrentPrincipal, organization_router, require_permission, router as auth_router
from .job_store import JobRecord, JobStore
from .total_job_store import TotalJobChildRef, TotalJobRecord, TotalJobStore

OUTPUTS_DIR = PROJECT_ROOT / "outputs"
UPLOADS_DIR = OUTPUTS_DIR / "uploads"
JOBS_DIR = OUTPUTS_DIR / "analysis_jobs"
TOTAL_JOBS_DIR = OUTPUTS_DIR / "total_jobs"
ALL_TOTAL_JOBS_SUMMARY_DIR = TOTAL_JOBS_DIR / "__all_jobs_summary"
ALL_TOTAL_JOBS_SUMMARY_STALE_SECONDS = int(os.getenv("ALL_TOTAL_JOBS_SUMMARY_STALE_SECONDS", "7200"))
ALLOW_SERVER_PCAP_PATHS = os.getenv("AGENTIC_ALLOW_SERVER_PCAP_PATHS", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "y",
    "on",
}
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
ALL_TOTAL_JOBS_SUMMARY_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="AgenticNetSec API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv("AGENTIC_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router)
app.include_router(organization_router)

job_store = JobStore(JOBS_DIR)
total_job_store = TotalJobStore(TOTAL_JOBS_DIR)
engine = AnalysisEngine()


@app.get("/")
async def root():
    return {"message": "AgenticNetSec API is running", "version": "1.0.0"}


@app.on_event("startup")
async def startup_database_check() -> None:
    database_health_result = await asyncio.to_thread(check_database_connection)
    app.state.database_health = database_health_result
    if (
        database_health_result["status"] != "ok"
        and os.getenv("AGENTIC_DATABASE_REQUIRED", "").strip().lower() in {"1", "true", "yes", "y", "on"}
    ):
        raise RuntimeError(f"Database unavailable: {database_health_result.get('error', 'unknown error')}")


@app.get("/api/v1/health/database")
async def database_health():
    return await asyncio.to_thread(check_database_connection)


def _to_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _to_int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _normalize_analysis_profile(value: Any, default: str = "standard") -> str:
    candidate = str(value or default).strip().lower()
    if candidate not in ANALYSIS_PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"analysis_profile must be one of: {', '.join(sorted(ANALYSIS_PROFILES))}.",
        )
    return candidate


def _serialize_job(job: JobRecord) -> dict[str, Any]:
    return {
        "analysis_job_id": job.analysis_job_id,
        "group_id": job.group_id,
        "group_index": job.group_index,
        "group_total": job.group_total,
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
        "analysis_profile": job.analysis_profile,
        "stage1_execution": job.stage1_execution,
    }


def _serialize_total_job(job: TotalJobRecord, *, organization_id: str | None = None) -> dict[str, Any]:
    children: list[dict[str, Any]] = []
    completed_children = 0
    failed_children = 0
    child_progress_total = 0.0
    for child_ref in job.children:
        child_job = job_store.get(child_ref.analysis_job_id, organization_id=organization_id)
        child_payload = {
            "analysis_job_id": child_ref.analysis_job_id,
            "filename": child_ref.filename,
            "source_path": child_ref.source_path,
            "status": child_job.status if child_job else "queued",
            "current_phase": child_job.current_phase if child_job else "queued",
            "progress": child_job.progress if child_job else 0.0,
            "error": child_job.error if child_job else None,
            "attack_type": child_job.attack_type if child_job else None,
            "risk_level": child_job.risk_level if child_job else None,
            "confidence_score": child_job.confidence_score if child_job else None,
            "runtime_seconds_total": child_job.runtime_seconds_total if child_job else None,
            "analysis_profile": child_job.analysis_profile if child_job else job.analysis_profile,
            "stage1_execution": child_job.stage1_execution if child_job else {},
        }
        if child_payload["status"] == "completed":
            completed_children += 1
        elif child_payload["status"] == "failed":
            failed_children += 1
        child_progress_total += max(0.0, min(1.0, float(child_payload["progress"] or 0.0)))
        children.append(child_payload)

    progress = job.progress
    if job.file_count > 0 and job.current_stage in {"deterministic_analysis", "ready_for_enrichment"}:
        completed_fraction = (completed_children + failed_children) / job.file_count
        child_progress_fraction = child_progress_total / job.file_count
        progress = max(progress, completed_fraction, child_progress_fraction)

    return {
        "total_job_id": job.total_job_id,
        "status": job.status,
        "current_stage": job.current_stage,
        "progress": min(1.0, progress),
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "error": job.error,
        "worker_count": job.worker_count,
        "file_count": job.file_count,
        "completed_children": completed_children,
        "failed_children": failed_children,
        "deterministic_complete": job.deterministic_complete,
        "enrichment_status": job.enrichment_status,
        "enrichment_progress": job.enrichment_progress,
        "enrichment_error": job.enrichment_error,
        "analysis_profile": job.analysis_profile,
        "children": children,
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


def _normalize_batch_pcap_paths(raw_paths: list[Any]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_path in raw_paths:
        if raw_path is None:
            continue
        normalized_path = _normalize_pcap_path(str(raw_path))
        if normalized_path in seen:
            continue
        seen.add(normalized_path)
        normalized.append(normalized_path)
    return normalized


def _save_upload(file: UploadFile, principal: CurrentPrincipal) -> tuple[str, str, str | None]:
    try:
        artifact = job_store.artifact_service.save_upload(
            file,
            organization_id=principal.organization_id,
            user_id=principal.user_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return str(artifact.path), artifact.filename, artifact.artifact_id


def _artifacts_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "report_json": payload["report_json"],
        "report_markdown": payload["report_markdown"],
        "metrics": payload["metrics"],
        "guardrail_audit": payload["guardrail_audit"],
        "metadata": payload["metadata"],
        "analysis_record": payload["analysis_record"],
    }


def _run_analysis_request(payload: dict[str, Any]) -> dict[str, Any]:
    local_engine = AnalysisEngine()
    req = AnalysisRequest(**payload)
    artifacts = local_engine.run(req)
    return {
        "report_json": artifacts.report_json,
        "report_markdown": artifacts.report_markdown,
        "metrics": artifacts.metrics,
        "guardrail_audit": artifacts.guardrail_audit,
        "metadata": artifacts.metadata,
        "analysis_record": artifacts.analysis_record,
    }


def _persist_job_artifacts(job_id: str, artifacts: dict[str, Any]) -> None:
    job_store.save_artifact(job_id, "report.json", artifacts["report_json"])
    job_store.save_artifact(job_id, "report.md", artifacts["report_markdown"])
    job_store.save_artifact(job_id, "metrics.json", artifacts["metrics"])
    job_store.save_artifact(job_id, "guardrail_audit.json", artifacts["guardrail_audit"])
    job_store.save_artifact(job_id, "analysis_record.json", artifacts["analysis_record"])

    guardrail_state = (
        artifacts["report_json"].get("guardrail_verification", {}).get("human_review_required", "No")
    )
    job_store.update(
        job_id,
        status="completed",
        current_phase="completed",
        progress=1.0,
        guardrail_state=guardrail_state,
        metadata=artifacts["metadata"],
        attack_type=(artifacts["report_json"].get("impact") or {}).get("attack_type"),
        risk_level=(artifacts["report_json"].get("impact") or {}).get("risk_level"),
        confidence_score=(artifacts["report_json"].get("findings") or {}).get("confidence_score"),
        runtime_seconds_total=artifacts["metrics"].get("runtime_seconds_total"),
        analysis_profile=artifacts["analysis_record"].get("analysis_profile", "standard"),
        stage1_execution=artifacts["analysis_record"].get("stage1_execution") or {},
        error=None,
    )


def _load_analysis_record(job_id: str, *, organization_id: str | None = None) -> dict[str, Any]:
    return job_store.read_json_artifact(job_id, "analysis_record.json", organization_id=organization_id)


_PCAP_FINGERPRINT_CACHE: dict[tuple[str, int, int], str] = {}


def _fingerprint_pcap(path: str | None) -> str | None:
    if not path:
        return None

    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return None

    stat = file_path.stat()
    cache_key = (str(file_path.resolve()), stat.st_size, int(stat.st_mtime_ns))
    cached = _PCAP_FINGERPRINT_CACHE.get(cache_key)
    if cached:
        return cached

    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    fingerprint = digest.hexdigest()
    _PCAP_FINGERPRINT_CACHE[cache_key] = fingerprint
    return fingerprint


def _dedupe_analysis_records(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    unique_records: list[dict[str, Any]] = []
    duplicates_removed: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for record in records:
        record_copy = dict(record)
        file_path = record_copy.get("path")
        fingerprint = _fingerprint_pcap(file_path)

        if fingerprint:
            dedupe_key = f"sha256:{fingerprint}"
            record_copy["pcap_sha256"] = fingerprint
        else:
            normalized_path = str(Path(file_path).resolve()).lower() if file_path else ""
            filename = str(record_copy.get("file") or "").lower()
            size_bytes = record_copy.get("size_bytes")
            dedupe_key = f"fallback:{normalized_path}::{filename}::{size_bytes}"

        if dedupe_key in seen_keys:
            duplicates_removed.append(
                {
                    "file": record_copy.get("file"),
                    "path": file_path,
                    "dedupe_key": dedupe_key,
                }
            )
            continue

        seen_keys.add(dedupe_key)
        unique_records.append(record_copy)

    dedupe_metadata = {
        "strategy": "sha256_then_path_filename_size_fallback",
        "input_record_count": len(records),
        "unique_record_count": len(unique_records),
        "duplicate_record_count": len(duplicates_removed),
        "duplicates_removed": duplicates_removed,
    }
    return unique_records, dedupe_metadata


def _path_leaf(path_value: Any) -> str:
    if not path_value:
        return ""
    path_text = str(path_value)
    posix_name = Path(path_text).name
    windows_name = PureWindowsPath(path_text).name
    if windows_name and windows_name != path_text and len(windows_name) <= len(posix_name or path_text):
        return windows_name
    return posix_name


def _summary_record_dedupe_key(record: dict[str, Any]) -> str:
    fingerprint = record.get("pcap_sha256")
    if isinstance(fingerprint, str) and fingerprint.strip():
        return f"sha256:{fingerprint.strip().lower()}"

    source_name = (
        record.get("source_name")
        or record.get("file")
        or record.get("filename")
        or _path_leaf(record.get("path"))
    )
    normalized_name = str(source_name or "").strip().lower()
    path_leaf = _path_leaf(record.get("path")).lower()
    size_bytes = record.get("size_bytes") or record.get("bytes") or ""
    return f"metadata:{normalized_name}::{path_leaf}::{size_bytes}"


def _dedupe_summary_records(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    unique_records: list[dict[str, Any]] = []
    duplicates_removed: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for record in records:
        record_copy = dict(record)
        dedupe_key = _summary_record_dedupe_key(record_copy)
        if dedupe_key in seen_keys:
            duplicates_removed.append(
                {
                    "file": record_copy.get("file") or record_copy.get("filename"),
                    "path": record_copy.get("path"),
                    "dedupe_key": dedupe_key,
                    "source_total_job_id": record_copy.get("source_total_job_id"),
                }
            )
            continue

        seen_keys.add(dedupe_key)
        unique_records.append(record_copy)

    return (
        unique_records,
        {
            "strategy": "existing_sha256_then_filename_path_size_metadata",
            "input_record_count": len(records),
            "unique_record_count": len(unique_records),
            "duplicate_record_count": len(duplicates_removed),
            "duplicates_removed": duplicates_removed,
        },
    )


def _save_total_job_jsonl_artifact(
    total_job_id: str,
    name: str,
    records: list[dict[str, Any]],
    *,
    organization_id: str | None = None,
) -> Path:
    total_job = total_job_store.get(total_job_id, organization_id=organization_id)
    if not total_job or not total_job.artifacts_dir:
        raise KeyError(f"Unknown total job: {total_job_id}")

    artifact_path = Path(total_job.artifacts_dir) / name
    with artifact_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record))
            handle.write("\n")
    total_job_store.artifact_service.record_file(
        artifact_path,
        artifact_type="total_job_jsonl",
        total_job_id=total_job_id,
        organization_id=total_job.organization_id,
        user_id=total_job.created_by_user_id,
    )
    total_job_store.update(total_job_id, updated_at=datetime.now(timezone.utc).isoformat())
    return artifact_path


def _all_total_jobs_summary_dir(organization_id: str | None) -> Path:
    org_key = str(organization_id or "legacy").strip() or "legacy"
    org_key = re.sub(r"[^A-Za-z0-9_.-]", "_", org_key)
    summary_dir = ALL_TOTAL_JOBS_SUMMARY_DIR / org_key
    summary_dir.mkdir(parents=True, exist_ok=True)
    return summary_dir


def _all_total_jobs_summary_status_path(organization_id: str | None) -> Path:
    return _all_total_jobs_summary_dir(organization_id) / "status.json"


def _save_all_total_jobs_jsonl_artifact(
    name: str,
    records: list[dict[str, Any]],
    *,
    organization_id: str | None = None,
) -> Path:
    artifact_path = _all_total_jobs_summary_dir(organization_id) / name
    with artifact_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record))
            handle.write("\n")
    return artifact_path


def _build_ai_markdown_notice(
    *,
    stage_label: str,
    provider: str | None,
    model: str | None,
    fallback_used: bool | None,
    api_attempted: bool | None = None,
    status: str | None,
) -> str:
    ai_callable = "yes" if fallback_used is False else "no"
    api_attempted_text = "unknown" if api_attempted is None else ("yes" if api_attempted else "no")
    fallback_text = "yes" if fallback_used else "no"
    provider_label = "Provider used" if fallback_used is False else "Provider requested"
    model_label = "Model used" if fallback_used is False else "Model requested"
    details = [
        f"AI requested: yes",
        f"API attempted: {api_attempted_text}",
        f"AI callable: {ai_callable}",
        f"Fallback used: {fallback_text}",
        f"Status: {status or 'unknown'}",
        f"{provider_label}: {provider or 'unknown'}",
        f"{model_label}: {model or 'default'}",
    ]
    return "\n".join(
        [
            f"> {stage_label}",
            *[f"> {line}" for line in details],
            ">",
            "> If `AI callable: no`, this markdown came from the deterministic fallback report.",
            "",
        ]
    )


def _read_all_total_jobs_summary_status(organization_id: str | None = None) -> dict[str, Any]:
    status_path = _all_total_jobs_summary_status_path(organization_id)
    if not status_path.exists():
        return {}
    try:
        return json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_all_total_jobs_summary_status(
    payload: dict[str, Any],
    organization_id: str | None = None,
) -> dict[str, Any]:
    status_payload = dict(payload)
    status_payload["organization_id"] = str(organization_id) if organization_id else None
    status_payload["updated_at"] = datetime.now(timezone.utc).isoformat()
    _all_total_jobs_summary_status_path(organization_id).write_text(
        json.dumps(status_payload, indent=2) + "\n",
        encoding="utf-8",
    )
    return status_payload


def _parse_status_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _recover_stale_all_total_jobs_summary_status(
    stored_status: dict[str, Any],
    organization_id: str | None = None,
) -> dict[str, Any]:
    if stored_status.get("status") not in {"queued", "running"}:
        return stored_status

    updated_at = _parse_status_timestamp(stored_status.get("updated_at"))
    stale = updated_at is None
    if updated_at is not None:
        age_seconds = (datetime.now(timezone.utc) - updated_at).total_seconds()
        stale = age_seconds >= ALL_TOTAL_JOBS_SUMMARY_STALE_SECONDS
    if not stale:
        return stored_status

    return _write_all_total_jobs_summary_status(
        {
            **stored_status,
            "status": "failed",
            "progress": stored_status.get("progress", 0.0),
            "route_stage": stored_status.get("route_stage") or "interrupted",
            "error": "Interrupted by backend shutdown during all-scans summary.",
        },
        organization_id,
    )


def _list_completed_total_job_children(organization_id: str | None = None) -> tuple[list[str], list[TotalJobChildRef]]:
    total_job_ids: list[str] = []
    completed_children: list[TotalJobChildRef] = []

    for total_job in total_job_store.list_jobs(organization_id=organization_id):
        job_children: list[TotalJobChildRef] = []
        for child in total_job.children:
            child_job = job_store.get(child.analysis_job_id, organization_id=organization_id)
            if child_job and child_job.status == "completed":
                job_children.append(child)
        if job_children:
            total_job_ids.append(total_job.total_job_id)
            completed_children.extend(job_children)

    return total_job_ids, completed_children


def _load_total_job_enriched_records(total_job: TotalJobRecord) -> list[dict[str, Any]]:
    if total_job.enrichment_status != "completed" or not total_job.artifacts_dir:
        return []

    artifact_path = Path(total_job.artifacts_dir) / "scan_results.json"
    if not artifact_path.exists():
        return []

    try:
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []

    records: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        record = dict(item)
        record.setdefault("source_total_job_id", total_job.total_job_id)
        record.setdefault("summary_record_source", "parent_enrichment")
        records.append(record)
    return records


def _load_total_job_child_analysis_records(total_job: TotalJobRecord, organization_id: str | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for child in total_job.children:
        child_job = job_store.get(child.analysis_job_id, organization_id=organization_id)
        if not child_job or child_job.status != "completed":
            continue
        try:
            record = _load_analysis_record(child.analysis_job_id, organization_id=organization_id)
        except FileNotFoundError:
            continue
        record.setdefault("file", child.filename)
        record.setdefault("path", child.source_path)
        record.setdefault("source_total_job_id", total_job.total_job_id)
        record.setdefault("summary_record_source", "child_analysis")
        records.append(record)
    return records


def _load_all_total_jobs_summary_records(
    organization_id: str | None = None,
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    source_total_job_ids: list[str] = []
    records: list[dict[str, Any]] = []
    source_manifest: list[dict[str, Any]] = []

    for total_job in total_job_store.list_jobs(organization_id=organization_id):
        job_records = _load_total_job_enriched_records(total_job)
        record_source = "parent_enrichment"
        if not job_records:
            job_records = _load_total_job_child_analysis_records(total_job, organization_id=organization_id)
            record_source = "child_analysis"
        if not job_records:
            continue

        source_total_job_ids.append(total_job.total_job_id)
        records.extend(job_records)
        source_manifest.append(
            {
                "total_job_id": total_job.total_job_id,
                "record_source": record_source,
                "record_count": len(job_records),
                "enrichment_status": total_job.enrichment_status,
            }
        )

    return source_total_job_ids, records, source_manifest


def _serialize_all_total_jobs_summary_status(organization_id: str | None = None) -> dict[str, Any]:
    source_total_job_ids, completed_children = _list_completed_total_job_children(organization_id)
    stored_status = _recover_stale_all_total_jobs_summary_status(
        _read_all_total_jobs_summary_status(organization_id),
        organization_id,
    )
    return {
        "status": stored_status.get("status", "not_started"),
        "progress": stored_status.get("progress", 0.0),
        "error": stored_status.get("error"),
        "generated_at": stored_status.get("generated_at"),
        "updated_at": stored_status.get("updated_at"),
        "route_stage": stored_status.get("route_stage"),
        "provider": stored_status.get("provider"),
        "model": stored_status.get("model"),
        "require_ai": bool(stored_status.get("require_ai", False)),
        "source_total_job_count": len(source_total_job_ids),
        "source_total_job_ids": source_total_job_ids,
        "source_file_count": len(completed_children),
        "record_count": stored_status.get("record_count"),
        "unique_record_count": stored_status.get("unique_record_count"),
        "duplicate_record_count": stored_status.get("duplicate_record_count"),
        "selected_follow_up_record_count": stored_status.get("selected_follow_up_record_count"),
    }


def _run_total_job_sync(
    total_job_id: str,
    worker_count: int,
    job_payloads: list[dict[str, Any]],
) -> None:
    total_job_store.update(
        total_job_id,
        status="running",
        current_stage="deterministic_analysis",
        progress=0.02,
        error=None,
        deterministic_complete=False,
        enrichment_status="not_started",
        enrichment_progress=0.0,
        enrichment_error=None,
    )

    file_count = len(job_payloads)
    completed = 0
    failed = 0
    max_workers = max(2, worker_count)

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_map = {}
        for payload in job_payloads:
            job_store.update(
                payload["analysis_job_id"],
                status="running",
                current_phase="analysis",
                progress=0.2,
                error=None,
            )
            future = executor.submit(_run_analysis_request, payload["request"])
            future_map[future] = payload

        for future in as_completed(future_map):
            payload = future_map[future]
            job_id = payload["analysis_job_id"]
            try:
                artifacts = _artifacts_from_payload(future.result())
                _persist_job_artifacts(job_id, artifacts)
                completed += 1
            except Exception as exc:  # noqa: BLE001
                failed += 1
                job_store.update(
                    job_id,
                    status="failed",
                    current_phase="analysis",
                    progress=0.2,
                    guardrail_state="error",
                    error=str(exc),
                )

            progress = (completed + failed) / file_count if file_count else 1.0
            total_job_store.update(
                total_job_id,
                progress=progress,
                completed_children=completed,
                failed_children=failed,
            )

    has_completed = completed > 0
    total_job_store.update(
        total_job_id,
        status="completed" if has_completed else "failed",
        current_stage="ready_for_enrichment" if has_completed else "failed",
        progress=1.0,
        completed_children=completed,
        failed_children=failed,
        deterministic_complete=True,
        error=None if has_completed else "All child analysis jobs failed.",
    )


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
        _persist_job_artifacts(
            job_id,
            {
                "report_json": artifacts.report_json,
                "report_markdown": artifacts.report_markdown,
                "metrics": artifacts.metrics,
                "guardrail_audit": artifacts.guardrail_audit,
                "metadata": artifacts.metadata,
                "analysis_record": artifacts.analysis_record,
            },
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


def _run_total_job_enrichment_sync(
    total_job_id: str,
    provider: str,
    model: str | None,
    require_ai: bool,
    organization_id: str | None = None,
) -> None:
    total_job = total_job_store.get(total_job_id, organization_id=organization_id)
    if not total_job:
        raise KeyError(f"Unknown total job: {total_job_id}")

    completed_children = []
    for child in total_job.children:
        child_job = job_store.get(child.analysis_job_id, organization_id=organization_id)
        if child_job and child_job.status == "completed":
            completed_children.append(child)

    if not completed_children:
        raise RuntimeError("No completed child analysis jobs are available for enrichment.")

    total_job_store.update(
        total_job_id,
        status="running",
        current_stage="enrichment_running",
        enrichment_status="running",
        enrichment_progress=0.05,
        enrichment_error=None,
        error=None,
    )

    records = [
        _load_analysis_record(child.analysis_job_id, organization_id=organization_id)
        for child in completed_children
    ]
    total_job_store.update(total_job_id, enrichment_progress=0.2)

    unique_records, dedupe_metadata = _dedupe_analysis_records(records)
    total_job_store.update(total_job_id, enrichment_progress=0.25)

    def _campaign_progress(stage: str, progress: float) -> None:
        total_job_store.update(
            total_job_id,
            enrichment_progress=progress,
        )

    campaign_result = run_campaign_summary_route(
        unique_records,
        build_aggregate(unique_records),
        report_provider=provider,
        report_model=model,
        planner_provider="openrouter",
        planner_model=None,
        require_ai=require_ai,
        progress_callback=_campaign_progress,
        artifacts_dir=total_job.artifacts_dir,
    )
    enriched_records = campaign_result["enriched_records"]
    aggregate = campaign_result["aggregate"]
    summary_markdown = campaign_result["final_report_markdown"]
    case_summary = campaign_result["initial_summary"]
    campaign_plan = campaign_result["campaign_plan"]
    final_report = campaign_result["final_report"]
    selected_follow_up_records = campaign_result["selected_follow_up_records"]

    # Mirror the legacy batch artifacts inside the parent total-job folder so
    # AI/sandbox comparisons can reuse the same artifact shape in one place.
    total_job_store.save_json_artifact(total_job_id, "aggregate_summary.json", aggregate)
    total_job_store.save_json_artifact(total_job_id, "scan_results.json", enriched_records)
    _save_total_job_jsonl_artifact(
        total_job_id,
        "scan_results.jsonl",
        enriched_records,
        organization_id=organization_id,
    )
    _save_total_job_jsonl_artifact(
        total_job_id,
        "scan_results.ai-tshark.jsonl",
        enriched_records,
        organization_id=organization_id,
    )
    total_job_store.save_json_artifact(
        total_job_id,
        "summary.json",
        {
            "scope": "total_job",
            "route": "campaign_ai_then_sandbox_then_final_report",
            "source_total_job_id": total_job_id,
            "source_file_count": len(completed_children),
            "source_analysis_job_ids": [child.analysis_job_id for child in completed_children],
            "dedupe": dedupe_metadata,
            "ai_execution": {
                "initial_summary": {
                    "provider": case_summary.get("provider"),
                    "model": case_summary.get("model"),
                    "fallback_used": bool(case_summary.get("fallback_used", False)),
                    "api_attempted": case_summary.get("api_attempted"),
                    "ai_callable": bool(case_summary.get("ai_callable", False)),
                    "status": case_summary.get("status"),
                    "failure_reason": case_summary.get("failure_reason"),
                },
                "campaign_plan": {
                    "planner_source": campaign_plan.get("planner_source"),
                    "planner_provider": campaign_plan.get("planner_provider"),
                    "planner_model": campaign_plan.get("planner_model"),
                    "ai_api_attempted": campaign_plan.get("ai_api_attempted"),
                    "failure_reason": campaign_plan.get("failure_reason"),
                },
                "final_report": {
                    "provider": final_report.get("provider"),
                    "model": final_report.get("model"),
                    "fallback_used": bool(final_report.get("fallback_used", False)),
                    "api_attempted": final_report.get("api_attempted"),
                    "ai_callable": bool(final_report.get("ai_callable", False)),
                    "status": final_report.get("status"),
                    "failure_reason": final_report.get("failure_reason"),
                },
            },
            "initial_summary": case_summary,
            "campaign_plan": campaign_plan,
            "selected_follow_up_records": selected_follow_up_records,
            "aggregate_summary": aggregate,
            "records": enriched_records,
        },
    )
    total_job_store.save_text_artifact(
        total_job_id,
        "initial_summary.md",
        _build_ai_markdown_notice(
            stage_label="Initial Campaign Summary AI Status",
            provider=case_summary.get("provider"),
            model=case_summary.get("model"),
            fallback_used=case_summary.get("fallback_used"),
            api_attempted=case_summary.get("api_attempted"),
            status=case_summary.get("status"),
        )
        + str(case_summary.get("report_text", "")),
    )
    total_job_store.save_json_artifact(
        total_job_id,
        "campaign_plan.json",
        {
            "initial_summary": case_summary,
            "campaign_plan": campaign_plan,
            "selected_follow_up_records": selected_follow_up_records,
        },
    )
    total_job_store.save_text_artifact(
        total_job_id,
        "summary.md",
        _build_ai_markdown_notice(
            stage_label="Final Campaign Report AI Status",
            provider=final_report.get("provider"),
            model=final_report.get("model"),
            fallback_used=final_report.get("fallback_used"),
            api_attempted=final_report.get("api_attempted"),
            status=final_report.get("status"),
        )
        + summary_markdown,
    )
    total_job_store.save_json_artifact(
        total_job_id,
        "sandbox.json",
        {
            "scope": "total_job",
            "source_total_job_id": total_job_id,
            "source_file_count": len(completed_children),
            "source_analysis_job_ids": [child.analysis_job_id for child in completed_children],
            "dedupe": dedupe_metadata,
            "record_count": len(enriched_records),
            "records": enriched_records,
        },
    )
    total_job_store.update(
        total_job_id,
        status="completed",
        current_stage="enrichment_completed",
        enrichment_status="completed",
        enrichment_progress=1.0,
        enrichment_error=None,
        progress=1.0,
    )


def _run_all_total_jobs_summary_sync_legacy_campaign_route(
    provider: str,
    model: str | None,
    require_ai: bool,
    organization_id: str | None = None,
) -> None:
    source_total_job_ids, records, source_manifest = _load_all_total_jobs_summary_records(organization_id)
    if not records:
        raise RuntimeError("No completed analysis or enrichment records are available across total jobs.")

    summary_dir = _all_total_jobs_summary_dir(organization_id)

    def write_summary_status(payload: dict[str, Any]) -> dict[str, Any]:
        return _write_all_total_jobs_summary_status(payload, organization_id)

    write_summary_status(
        {
            "status": "running",
            "progress": 0.05,
            "error": None,
            "provider": provider,
            "model": model,
            "require_ai": require_ai,
            "source_total_job_count": len(source_total_job_ids),
            "source_total_job_ids": source_total_job_ids,
            "source_file_count": len(records),
            "record_count": len(records),
            "route_stage": "loading_json_records",
        }
    )

    unique_records, dedupe_metadata = _dedupe_summary_records(records)
    write_summary_status(
        {
            "status": "running",
            "progress": 0.25,
            "error": None,
            "provider": provider,
            "model": model,
            "require_ai": require_ai,
            "source_total_job_count": len(source_total_job_ids),
            "source_total_job_ids": source_total_job_ids,
            "source_file_count": len(records),
            "record_count": len(records),
            "unique_record_count": len(unique_records),
            "duplicate_record_count": len(dedupe_metadata["duplicates_removed"]),
        }
    )

    def _campaign_progress(stage: str, progress: float) -> None:
        write_summary_status(
            {
                "status": "running",
                "progress": progress,
                "error": None,
                "provider": provider,
                "model": model,
                "require_ai": require_ai,
                "route_stage": stage,
                "source_total_job_count": len(source_total_job_ids),
                "source_total_job_ids": source_total_job_ids,
                "source_file_count": len(records),
                "record_count": len(records),
                "unique_record_count": len(unique_records),
                "duplicate_record_count": len(dedupe_metadata["duplicates_removed"]),
            }
        )

    campaign_result = run_campaign_summary_route(
        unique_records,
        build_aggregate(unique_records),
        report_provider=provider,
        report_model=model,
        planner_provider="openrouter",
        planner_model=None,
        require_ai=require_ai,
        progress_callback=_campaign_progress,
        artifacts_dir=summary_dir,
    )
    enriched_records = campaign_result["enriched_records"]
    aggregate = campaign_result["aggregate"]
    summary_markdown = campaign_result["final_report_markdown"]
    case_summary = campaign_result["initial_summary"]
    campaign_plan = campaign_result["campaign_plan"]
    final_report = campaign_result["final_report"]
    selected_follow_up_records = campaign_result["selected_follow_up_records"]

    (summary_dir / "aggregate_summary.json").write_text(
        json.dumps(aggregate, indent=2) + "\n",
        encoding="utf-8",
    )
    (summary_dir / "scan_results.json").write_text(
        json.dumps(enriched_records, indent=2) + "\n",
        encoding="utf-8",
    )
    _save_all_total_jobs_jsonl_artifact("scan_results.jsonl", enriched_records, organization_id=organization_id)
    _save_all_total_jobs_jsonl_artifact("scan_results.ai-tshark.jsonl", enriched_records, organization_id=organization_id)
    (summary_dir / "summary.json").write_text(
        json.dumps(
            {
                "scope": "all_total_jobs",
                "route": "campaign_ai_then_sandbox_then_final_report",
                "source_total_job_ids": source_total_job_ids,
                "source_total_job_count": len(source_total_job_ids),
                "source_file_count": len(records),
                "dedupe": dedupe_metadata,
                "ai_execution": {
                    "initial_summary": {
                        "provider": case_summary.get("provider"),
                        "model": case_summary.get("model"),
                        "fallback_used": bool(case_summary.get("fallback_used", False)),
                        "api_attempted": case_summary.get("api_attempted"),
                        "ai_callable": bool(case_summary.get("ai_callable", False)),
                        "status": case_summary.get("status"),
                        "failure_reason": case_summary.get("failure_reason"),
                    },
                    "campaign_plan": {
                        "planner_source": campaign_plan.get("planner_source"),
                        "planner_provider": campaign_plan.get("planner_provider"),
                        "planner_model": campaign_plan.get("planner_model"),
                        "ai_api_attempted": campaign_plan.get("ai_api_attempted"),
                        "failure_reason": campaign_plan.get("failure_reason"),
                    },
                    "final_report": {
                        "provider": final_report.get("provider"),
                        "model": final_report.get("model"),
                        "fallback_used": bool(final_report.get("fallback_used", False)),
                        "api_attempted": final_report.get("api_attempted"),
                        "ai_callable": bool(final_report.get("ai_callable", False)),
                        "status": final_report.get("status"),
                        "failure_reason": final_report.get("failure_reason"),
                    },
                },
                "initial_summary": case_summary,
                "campaign_plan": campaign_plan,
                "selected_follow_up_records": selected_follow_up_records,
                "aggregate_summary": aggregate,
                "records": enriched_records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (summary_dir / "initial_summary.md").write_text(
        _build_ai_markdown_notice(
            stage_label="Initial Campaign Summary AI Status",
            provider=case_summary.get("provider"),
            model=case_summary.get("model"),
            fallback_used=case_summary.get("fallback_used"),
            api_attempted=case_summary.get("api_attempted"),
            status=case_summary.get("status"),
        )
        + str(case_summary.get("report_text", ""))
        + ("\n" if case_summary.get("report_text") else ""),
        encoding="utf-8",
    )
    (summary_dir / "campaign_plan.json").write_text(
        json.dumps(
            {
                "initial_summary": case_summary,
                "campaign_plan": campaign_plan,
                "selected_follow_up_records": selected_follow_up_records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (summary_dir / "summary.md").write_text(
        _build_ai_markdown_notice(
            stage_label="Final Campaign Report AI Status",
            provider=final_report.get("provider"),
            model=final_report.get("model"),
            fallback_used=final_report.get("fallback_used"),
            api_attempted=final_report.get("api_attempted"),
            status=final_report.get("status"),
        )
        + summary_markdown
        + ("" if summary_markdown.endswith("\n") else "\n"),
        encoding="utf-8",
    )
    (summary_dir / "sandbox.json").write_text(
        json.dumps(
            {
                "scope": "all_total_jobs",
                "source_total_job_ids": source_total_job_ids,
                "source_total_job_count": len(source_total_job_ids),
                "source_file_count": len(records),
                "dedupe": dedupe_metadata,
                "record_count": len(enriched_records),
                "records": enriched_records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    write_summary_status(
        {
            "status": "completed",
            "progress": 1.0,
            "error": None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "model": model,
            "require_ai": require_ai,
            "source_total_job_count": len(source_total_job_ids),
            "source_total_job_ids": source_total_job_ids,
            "source_file_count": len(records),
            "record_count": len(records),
            "unique_record_count": len(unique_records),
            "duplicate_record_count": len(dedupe_metadata["duplicates_removed"]),
            "route_stage": "completed",
            "selected_follow_up_record_count": len(selected_follow_up_records),
        }
    )


def _run_all_total_jobs_summary_sync(
    provider: str,
    model: str | None,
    require_ai: bool,
    organization_id: str | None = None,
) -> None:
    source_total_job_ids, records, source_manifest = _load_all_total_jobs_summary_records(organization_id)
    if not records:
        raise RuntimeError("No completed analysis or enrichment records are available across total jobs.")

    summary_dir = _all_total_jobs_summary_dir(organization_id)

    def write_summary_status(payload: dict[str, Any]) -> dict[str, Any]:
        return _write_all_total_jobs_summary_status(payload, organization_id)

    unique_records, dedupe_metadata = _dedupe_summary_records(records)
    write_summary_status(
        {
            "status": "running",
            "progress": 0.25,
            "error": None,
            "provider": provider,
            "model": model,
            "require_ai": require_ai,
            "route_stage": "metadata_dedupe",
            "source_total_job_count": len(source_total_job_ids),
            "source_total_job_ids": source_total_job_ids,
            "source_file_count": len(records),
            "record_count": len(records),
            "unique_record_count": len(unique_records),
            "duplicate_record_count": len(dedupe_metadata["duplicates_removed"]),
        }
    )

    aggregate = build_aggregate(unique_records)
    write_summary_status(
        {
            "status": "running",
            "progress": 0.5,
            "error": None,
            "provider": provider,
            "model": model,
            "require_ai": require_ai,
            "route_stage": "final_summary",
            "source_total_job_count": len(source_total_job_ids),
            "source_total_job_ids": source_total_job_ids,
            "source_file_count": len(records),
            "record_count": len(records),
            "unique_record_count": len(unique_records),
            "duplicate_record_count": len(dedupe_metadata["duplicates_removed"]),
        }
    )

    final_report_result = generate_results_report_result(
        aggregate,
        unique_records,
        provider=provider,
        model=model,
        use_ai=True,
        require_ai=require_ai,
    )
    final_report = {
        "provider": final_report_result.provider,
        "model": final_report_result.model,
        "report_text": final_report_result.text,
        "fallback_used": final_report_result.fallback_used,
        "api_attempted": final_report_result.api_attempted,
        "llm_tokens_in": final_report_result.llm_tokens_in,
        "llm_tokens_out": final_report_result.llm_tokens_out,
        "failure_reason": final_report_result.failure_reason,
        "status": "fallback_report" if final_report_result.fallback_used else "ai_generated",
        "ai_callable": not final_report_result.fallback_used,
    }
    summary_markdown = final_report_result.text
    record_source = {
        "strategy": "prefer_parent_enrichment_scan_results_json",
        "sources": source_manifest,
    }

    (summary_dir / "aggregate_summary.json").write_text(
        json.dumps(aggregate, indent=2) + "\n",
        encoding="utf-8",
    )
    (summary_dir / "scan_results.json").write_text(
        json.dumps(unique_records, indent=2) + "\n",
        encoding="utf-8",
    )
    _save_all_total_jobs_jsonl_artifact("scan_results.jsonl", unique_records, organization_id=organization_id)
    _save_all_total_jobs_jsonl_artifact("scan_results.ai-tshark.jsonl", unique_records, organization_id=organization_id)
    (summary_dir / "summary.json").write_text(
        json.dumps(
            {
                "scope": "all_total_jobs",
                "route": "combined_enriched_json_final_report",
                "source_total_job_ids": source_total_job_ids,
                "source_total_job_count": len(source_total_job_ids),
                "source_file_count": len(records),
                "record_source": record_source,
                "dedupe": dedupe_metadata,
                "ai_execution": {
                    "initial_summary": None,
                    "campaign_plan": None,
                    "final_report": {
                        "provider": final_report.get("provider"),
                        "model": final_report.get("model"),
                        "fallback_used": bool(final_report.get("fallback_used", False)),
                        "api_attempted": final_report.get("api_attempted"),
                        "ai_callable": bool(final_report.get("ai_callable", False)),
                        "status": final_report.get("status"),
                        "failure_reason": final_report.get("failure_reason"),
                    },
                },
                "initial_summary": None,
                "campaign_plan": None,
                "selected_follow_up_records": [],
                "aggregate_summary": aggregate,
                "records": unique_records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (summary_dir / "initial_summary.md").write_text(
        "> Initial Campaign Summary AI Status\n"
        "> Not run for all-scans summary because parent total-job enrichment artifacts already exist.\n",
        encoding="utf-8",
    )
    (summary_dir / "campaign_plan.json").write_text(
        json.dumps(
            {
                "initial_summary": None,
                "campaign_plan": None,
                "selected_follow_up_records": [],
                "record_source": record_source,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (summary_dir / "summary.md").write_text(
        _build_ai_markdown_notice(
            stage_label="Final Campaign Report AI Status",
            provider=final_report.get("provider"),
            model=final_report.get("model"),
            fallback_used=final_report.get("fallback_used"),
            api_attempted=final_report.get("api_attempted"),
            status=final_report.get("status"),
        )
        + summary_markdown
        + ("" if summary_markdown.endswith("\n") else "\n"),
        encoding="utf-8",
    )
    (summary_dir / "sandbox.json").write_text(
        json.dumps(
            {
                "scope": "all_total_jobs",
                "source_total_job_ids": source_total_job_ids,
                "source_total_job_count": len(source_total_job_ids),
                "source_file_count": len(records),
                "record_source": record_source,
                "dedupe": dedupe_metadata,
                "record_count": len(unique_records),
                "records": unique_records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    write_summary_status(
        {
            "status": "completed",
            "progress": 1.0,
            "error": None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "model": model,
            "require_ai": require_ai,
            "source_total_job_count": len(source_total_job_ids),
            "source_total_job_ids": source_total_job_ids,
            "source_file_count": len(records),
            "record_count": len(records),
            "unique_record_count": len(unique_records),
            "duplicate_record_count": len(dedupe_metadata["duplicates_removed"]),
            "route_stage": "completed",
            "selected_follow_up_record_count": 0,
        }
    )


async def _run_total_job(total_job_id: str, worker_count: int, job_payloads: list[dict[str, Any]]) -> None:
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, _run_total_job_sync, total_job_id, worker_count, job_payloads)
    except Exception as exc:  # noqa: BLE001
        total_job_store.update(
            total_job_id,
            status="failed",
            current_stage="failed",
            error=str(exc),
        )


async def _run_total_job_enrichment(
    total_job_id: str,
    provider: str,
    model: str | None,
    require_ai: bool,
    organization_id: str | None = None,
) -> None:
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None,
            _run_total_job_enrichment_sync,
            total_job_id,
            provider,
            model,
            require_ai,
            organization_id,
        )
    except Exception as exc:  # noqa: BLE001
        total_job_store.update(
            total_job_id,
            status="completed",
            current_stage="ready_for_enrichment",
            enrichment_status="failed",
            enrichment_error=str(exc),
            error=None,
        )


async def _run_all_total_jobs_summary(
    provider: str,
    model: str | None,
    require_ai: bool,
    organization_id: str | None = None,
) -> None:
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None,
            _run_all_total_jobs_summary_sync,
            provider,
            model,
            require_ai,
            organization_id,
        )
    except Exception as exc:  # noqa: BLE001
        current_status = _read_all_total_jobs_summary_status(organization_id)
        _write_all_total_jobs_summary_status(
            {
                **current_status,
                "status": "failed",
                "progress": current_status.get("progress", 0.0),
                "error": str(exc),
            },
            organization_id,
        )


@app.post("/api/v1/analysis")
async def create_analysis_job(
    request: Request,
    principal: CurrentPrincipal = Depends(require_permission("analysis:create")),
    file: UploadFile | None = File(default=None),
    pcap_path: str | None = Form(default=None),
    provider: str | None = Form(default=None),
    model: str | None = Form(default=None),
    use_ai: str | bool | None = Form(default=None),
    require_ai: str | bool | None = Form(default=None),
    analysis_profile: str | None = Form(default=None),
):
    if not file and not pcap_path and "application/json" in request.headers.get("content-type", ""):
        payload = await request.json()
        pcap_path = payload.get("pcap_path")
        provider = provider or payload.get("provider")
        model = model or payload.get("model")
        use_ai = payload.get("use_ai", use_ai)
        require_ai = payload.get("require_ai", require_ai)
        analysis_profile = payload.get("analysis_profile", analysis_profile)

    if file is None and not pcap_path:
        raise HTTPException(status_code=400, detail="Provide either 'file' upload or 'pcap_path'.")

    if file is not None:
        target_path, source_name, source_artifact_id = _save_upload(file, principal)
        source_type = "upload"
        source_path = target_path
    else:
        if not ALLOW_SERVER_PCAP_PATHS:
            raise HTTPException(status_code=400, detail="Server pcap_path inputs are disabled for this environment.")
        target_path = _normalize_pcap_path(pcap_path)
        source_type = "path"
        source_name = Path(target_path).name
        source_path = target_path
        source_artifact_id = None

    resolved_analysis_profile = _normalize_analysis_profile(analysis_profile)

    job = job_store.create_job(
        source_type=source_type,
        source_name=source_name,
        source_path=source_path,
        analysis_profile=resolved_analysis_profile,
        source_artifact_id=source_artifact_id,
        organization_id=principal.organization_id,
        user_id=principal.user_id,
    )
    job_store.artifact_service.link_to_analysis_job(
        source_artifact_id,
        job.analysis_job_id,
        organization_id=principal.organization_id,
        user_id=principal.user_id,
    )

    req = AnalysisRequest(
        pcap_path=target_path,
        provider=(provider or "gemini"),
        model=model,
        use_ai=_to_bool(use_ai, True),
        require_ai=_to_bool(require_ai, False),
        analysis_profile=resolved_analysis_profile,
        artifacts_dir=job.artifacts_dir,
    )

    asyncio.create_task(_run_job(job.analysis_job_id, req))

    return _serialize_job(job)


@app.post("/api/v1/analysis/batch")
async def create_batch_analysis_job(
    request: Request,
    principal: CurrentPrincipal = Depends(require_permission("analysis:create")),
    files: list[UploadFile] = File(default=[]),
    worker_count: str | int | None = Form(default=2),
    pcap_paths: str | None = Form(default=None),
    analysis_profile: str | None = Form(default=None),
):
    requested_paths: list[str] = []
    if not files and "application/json" in request.headers.get("content-type", ""):
        payload = await request.json()
        worker_count = payload.get("worker_count", worker_count)
        if payload.get("pcap_paths") and not ALLOW_SERVER_PCAP_PATHS:
            raise HTTPException(status_code=400, detail="Server pcap_path inputs are disabled for this environment.")
        requested_paths = _normalize_batch_pcap_paths(payload.get("pcap_paths") or [])
        analysis_profile = payload.get("analysis_profile", analysis_profile)
    elif pcap_paths:
        if not ALLOW_SERVER_PCAP_PATHS:
            raise HTTPException(status_code=400, detail="Server pcap_path inputs are disabled for this environment.")
        try:
            requested_paths = _normalize_batch_pcap_paths(json.loads(pcap_paths))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid pcap_paths JSON: {exc}") from exc

    if files and requested_paths:
        raise HTTPException(status_code=400, detail="Provide either uploaded files or pcap_paths, not both.")
    if not files and not requested_paths:
        raise HTTPException(status_code=400, detail="Provide at least one file or pcap_paths entry for batch analysis.")

    resolved_worker_count = _to_int(worker_count, default=2, minimum=2, maximum=max(2, os.cpu_count() or 2))
    resolved_analysis_profile = _normalize_analysis_profile(analysis_profile)

    child_specs: list[dict[str, Any]] = []
    skipped_files: list[dict[str, Any]] = []

    if files:
        total_files = len(files)
        for index, file in enumerate(files):
            target_path, source_name, source_artifact_id = _save_upload(file, principal)
            child_specs.append(
                {
                    "filename": source_name,
                    "source_path": target_path,
                    "source_type": "upload",
                    "source_artifact_id": source_artifact_id,
                    "group_index": index,
                    "group_total": total_files,
                    "request": {
                        "pcap_path": target_path,
                        "provider": "gemini",
                        "model": None,
                        "use_ai": False,
                        "require_ai": False,
                        "analysis_profile": resolved_analysis_profile,
                        "enable_sandbox": False,
                    },
                }
            )
    else:
        existing_jobs_by_path = job_store.find_by_source_paths(
            requested_paths,
            statuses={"queued", "running", "completed"},
            organization_id=principal.organization_id,
        )
        existing_jobs_by_name = job_store.find_by_source_names(
            [Path(path).name for path in requested_paths],
            statuses={"queued", "running", "completed"},
            organization_id=principal.organization_id,
        )
        accepted_paths = [
            path
            for path in requested_paths
            if path.lower() not in existing_jobs_by_path
            and Path(path).name.lower() not in existing_jobs_by_name
        ]
        skipped_files = [
            {
                "path": path,
                "filename": Path(path).name,
                "reason": (
                    "already_in_system_same_path"
                    if path.lower() in existing_jobs_by_path
                    else "already_in_system_same_source_name"
                ),
                "existing_analysis_job_id": (
                    existing_jobs_by_path[path.lower()].analysis_job_id
                    if path.lower() in existing_jobs_by_path
                    else existing_jobs_by_name[Path(path).name.lower()].analysis_job_id
                ),
                "existing_status": (
                    existing_jobs_by_path[path.lower()].status
                    if path.lower() in existing_jobs_by_path
                    else existing_jobs_by_name[Path(path).name.lower()].status
                ),
            }
            for path in requested_paths
            if path.lower() in existing_jobs_by_path or Path(path).name.lower() in existing_jobs_by_name
        ]

        total_files = len(accepted_paths)
        for index, target_path in enumerate(accepted_paths):
            child_specs.append(
                {
                    "filename": Path(target_path).name,
                    "source_path": target_path,
                    "source_type": "path",
                    "source_artifact_id": None,
                    "group_index": index,
                    "group_total": total_files,
                    "request": {
                        "pcap_path": target_path,
                        "provider": "gemini",
                        "model": None,
                        "use_ai": False,
                        "require_ai": False,
                        "analysis_profile": resolved_analysis_profile,
                        "enable_sandbox": False,
                    },
                }
            )

    if not child_specs:
        return {
            "total_job_id": None,
            "status": "skipped",
            "current_stage": "skipped_existing_files",
            "progress": 1.0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "error": None,
            "worker_count": resolved_worker_count,
            "file_count": 0,
            "completed_children": 0,
            "failed_children": 0,
            "deterministic_complete": True,
            "enrichment_status": "not_started",
            "enrichment_progress": 0.0,
            "enrichment_error": None,
            "analysis_profile": resolved_analysis_profile,
            "children": [],
            "accepted_file_count": 0,
            "skipped_files": skipped_files,
        }

    total_job = total_job_store.create_job(
        worker_count=resolved_worker_count,
        files=[],
        analysis_profile=resolved_analysis_profile,
        organization_id=principal.organization_id,
        user_id=principal.user_id,
    )
    total_files = len(child_specs)
    finalized_child_specs: list[dict[str, Any]] = []
    for index, item in enumerate(child_specs):
        child_job = job_store.create_job(
            source_type=item["source_type"],
            source_name=item["filename"],
            source_path=item["source_path"],
            group_id=total_job.total_job_id,
            group_index=index,
            group_total=total_files,
            analysis_profile=resolved_analysis_profile,
            source_artifact_id=item.get("source_artifact_id"),
            organization_id=principal.organization_id,
            user_id=principal.user_id,
        )
        job_store.artifact_service.link_to_analysis_job(
            item.get("source_artifact_id"),
            child_job.analysis_job_id,
            organization_id=principal.organization_id,
            user_id=principal.user_id,
        )
        request_payload = {
            **item["request"],
            "artifacts_dir": child_job.artifacts_dir,
        }
        finalized_child_specs.append(
            {
                "analysis_job_id": child_job.analysis_job_id,
                "filename": item["filename"],
                "source_path": item["source_path"],
                "request": request_payload,
            }
        )

    total_job_store.update(
        total_job.total_job_id,
        file_count=len(finalized_child_specs),
        children=[
            TotalJobChildRef(
                analysis_job_id=item["analysis_job_id"],
                filename=item["filename"],
                source_path=item["source_path"],
            )
            for item in finalized_child_specs
        ],
    )

    asyncio.create_task(_run_total_job(total_job.total_job_id, resolved_worker_count, finalized_child_specs))
    return {
        **_serialize_total_job(
            total_job_store.get(total_job.total_job_id, organization_id=principal.organization_id) or total_job,
            organization_id=str(principal.organization_id),
        ),
        "accepted_file_count": len(finalized_child_specs),
        "skipped_files": skipped_files,
    }


@app.get("/api/v1/analysis/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    job = job_store.get(job_id, organization_id=principal.organization_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(**_serialize_job(job))


@app.get("/api/v1/analysis/{job_id}/report.json")
async def get_report_json(job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    job = job_store.get(job_id, organization_id=principal.organization_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail=f"Job is {job.status}")
    return job_store.read_json_artifact(job_id, "report.json", organization_id=principal.organization_id)


@app.get("/api/v1/analysis/{job_id}/report.md")
async def get_report_markdown(job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    job = job_store.get(job_id, organization_id=principal.organization_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail=f"Job is {job.status}")
    return {"markdown": job_store.read_text_artifact(job_id, "report.md", organization_id=principal.organization_id)}


@app.get("/api/v1/analysis/{job_id}/metrics")
async def get_metrics(job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    job = job_store.get(job_id, organization_id=principal.organization_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail=f"Job is {job.status}")
    return job_store.read_json_artifact(job_id, "metrics.json", organization_id=principal.organization_id)


@app.get("/api/v1/analysis/{job_id}/guardrail-audit")
async def get_guardrail_audit(job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    job = job_store.get(job_id, organization_id=principal.organization_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail=f"Job is {job.status}")
    return job_store.read_json_artifact(job_id, "guardrail_audit.json", organization_id=principal.organization_id)


@app.delete("/api/v1/analysis/{job_id}")
async def delete_analysis_job(job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:create"))):
    job = job_store.get(job_id, organization_id=principal.organization_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    deleted_artifacts = job_store.soft_delete_artifacts(job_id, organization_id=principal.organization_id)
    job_store.update(
        job_id,
        status="cancelled",
        current_phase="deleted",
        progress=job.progress,
        error="Artifacts soft-deleted.",
    )
    return {
        "analysis_job_id": job_id,
        "status": "deleted",
        "deleted_artifacts": deleted_artifacts,
    }


@app.get("/api/v1/analysis")
async def list_jobs(principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    all_jobs = job_store.list_jobs(organization_id=principal.organization_id)
    return {
        "total": len(all_jobs),
        "jobs": [_serialize_job(job) for job in all_jobs],
    }


@app.get("/api/v1/total-jobs")
async def list_total_jobs(principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    jobs = total_job_store.list_jobs(organization_id=principal.organization_id)
    return {
        "total": len(jobs),
        "jobs": [_serialize_total_job(job, organization_id=str(principal.organization_id)) for job in jobs],
    }


@app.get("/api/v1/total-jobs/summary/status")
async def get_all_total_jobs_summary_status(principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    return _serialize_all_total_jobs_summary_status(str(principal.organization_id))


@app.post("/api/v1/total-jobs/summary/enrich")
async def enrich_all_total_jobs_summary(
    principal: CurrentPrincipal = Depends(require_permission("analysis:create")),
    provider: str | None = Form(default=None),
    model: str | None = Form(default=None),
    require_ai: str | bool | None = Form(default=None),
):
    status = _serialize_all_total_jobs_summary_status(str(principal.organization_id))
    if status["source_file_count"] <= 0:
        raise HTTPException(
            status_code=409,
            detail="No completed child analysis jobs are available across total jobs yet.",
        )
    if status["status"] == "running":
        raise HTTPException(status_code=409, detail="All-jobs summary is already running.")

    _write_all_total_jobs_summary_status(
        {
            **status,
            "status": "queued",
            "progress": 0.0,
            "error": None,
            "provider": provider or "gemini",
            "model": model,
            "require_ai": _to_bool(require_ai, False),
        },
        str(principal.organization_id),
    )
    asyncio.create_task(
        _run_all_total_jobs_summary(
            provider or "gemini",
            model,
            _to_bool(require_ai, False),
            str(principal.organization_id),
        )
    )
    return _serialize_all_total_jobs_summary_status(str(principal.organization_id))


@app.get("/api/v1/total-jobs/summary/json")
async def get_all_total_jobs_summary_json(principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    status = _serialize_all_total_jobs_summary_status(str(principal.organization_id))
    if status["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"All-jobs summary is {status['status']}")
    artifact_path = _all_total_jobs_summary_dir(str(principal.organization_id)) / "summary.json"
    return json.loads(artifact_path.read_text(encoding="utf-8"))


@app.get("/api/v1/total-jobs/summary/markdown")
async def get_all_total_jobs_summary_markdown(principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    status = _serialize_all_total_jobs_summary_status(str(principal.organization_id))
    if status["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"All-jobs summary is {status['status']}")
    artifact_path = _all_total_jobs_summary_dir(str(principal.organization_id)) / "summary.md"
    return {"markdown": artifact_path.read_text(encoding="utf-8")}


@app.get("/api/v1/total-jobs/summary/sandbox")
async def get_all_total_jobs_summary_sandbox(principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    status = _serialize_all_total_jobs_summary_status(str(principal.organization_id))
    if status["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"All-jobs summary is {status['status']}")
    artifact_path = _all_total_jobs_summary_dir(str(principal.organization_id)) / "sandbox.json"
    return json.loads(artifact_path.read_text(encoding="utf-8"))


@app.get("/api/v1/total-jobs/{total_job_id}", response_model=TotalJobStatusResponse)
async def get_total_job_status(total_job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    total_job = total_job_store.get(total_job_id, organization_id=principal.organization_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")
    return TotalJobStatusResponse(**_serialize_total_job(total_job, organization_id=str(principal.organization_id)))


@app.post("/api/v1/total-jobs/{total_job_id}/enrich")
async def enrich_total_job(
    total_job_id: str,
    principal: CurrentPrincipal = Depends(require_permission("analysis:create")),
    provider: str | None = Form(default=None),
    model: str | None = Form(default=None),
    require_ai: str | bool | None = Form(default=None),
):
    total_job = total_job_store.get(total_job_id, organization_id=principal.organization_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")

    serialized = _serialize_total_job(total_job, organization_id=str(principal.organization_id))
    if not serialized["completed_children"]:
        raise HTTPException(status_code=409, detail="No completed child jobs are available for enrichment yet.")
    if serialized["enrichment_status"] == "running":
        raise HTTPException(status_code=409, detail="Enrichment is already running for this total job.")

    total_job_store.update(
        total_job_id,
        enrichment_status="queued",
        enrichment_progress=0.0,
        enrichment_error=None,
    )
    asyncio.create_task(
        _run_total_job_enrichment(
            total_job_id,
            provider or "gemini",
            model,
            _to_bool(require_ai, False),
            str(principal.organization_id),
        )
    )
    return _serialize_total_job(
        total_job_store.get(total_job_id, organization_id=principal.organization_id) or total_job,
        organization_id=str(principal.organization_id),
    )


@app.get("/api/v1/total-jobs/{total_job_id}/summary.json")
async def get_total_job_summary_json(total_job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    total_job = total_job_store.get(total_job_id, organization_id=principal.organization_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")
    if total_job.enrichment_status != "completed":
        raise HTTPException(status_code=409, detail=f"Enrichment is {total_job.enrichment_status}")
    return total_job_store.read_json_artifact(total_job_id, "summary.json", organization_id=principal.organization_id)


@app.get("/api/v1/total-jobs/{total_job_id}/summary.md")
async def get_total_job_summary_markdown(total_job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    total_job = total_job_store.get(total_job_id, organization_id=principal.organization_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")
    if total_job.enrichment_status != "completed":
        raise HTTPException(status_code=409, detail=f"Enrichment is {total_job.enrichment_status}")
    return {"markdown": total_job_store.read_text_artifact(total_job_id, "summary.md", organization_id=principal.organization_id)}


@app.get("/api/v1/total-jobs/{total_job_id}/sandbox")
async def get_total_job_sandbox(total_job_id: str, principal: CurrentPrincipal = Depends(require_permission("analysis:read"))):
    total_job = total_job_store.get(total_job_id, organization_id=principal.organization_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")
    if total_job.enrichment_status != "completed":
        raise HTTPException(status_code=409, detail=f"Enrichment is {total_job.enrichment_status}")
    return total_job_store.read_json_artifact(total_job_id, "sandbox.json", organization_id=principal.organization_id)
