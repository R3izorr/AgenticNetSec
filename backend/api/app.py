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

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
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
from summarize_results import build_aggregate
from .job_store import JobRecord, JobStore
from .total_job_store import TotalJobChildRef, TotalJobRecord, TotalJobStore

OUTPUTS_DIR = PROJECT_ROOT / "outputs"
UPLOADS_DIR = OUTPUTS_DIR / "uploads"
JOBS_DIR = OUTPUTS_DIR / "analysis_jobs"
TOTAL_JOBS_DIR = OUTPUTS_DIR / "total_jobs"
ALL_TOTAL_JOBS_SUMMARY_DIR = TOTAL_JOBS_DIR / "__all_jobs_summary"
ALL_TOTAL_JOBS_SUMMARY_STATUS_PATH = ALL_TOTAL_JOBS_SUMMARY_DIR / "status.json"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
ALL_TOTAL_JOBS_SUMMARY_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="AgenticNetSec API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

job_store = JobStore(JOBS_DIR)
total_job_store = TotalJobStore(TOTAL_JOBS_DIR)
engine = AnalysisEngine()


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


def _serialize_total_job(job: TotalJobRecord) -> dict[str, Any]:
    children: list[dict[str, Any]] = []
    completed_children = 0
    failed_children = 0
    child_progress_total = 0.0
    for child_ref in job.children:
        child_job = job_store.get(child_ref.analysis_job_id)
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


def _save_upload(file: UploadFile) -> tuple[str, str]:
    safe_name = Path(file.filename or "upload.pcap").name
    dest = UPLOADS_DIR / f"upload_{int(time.time())}_{safe_name}"
    dest.write_bytes(file.file.read())
    return str(dest), safe_name


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


def _load_analysis_record(job_id: str) -> dict[str, Any]:
    return job_store.read_json_artifact(job_id, "analysis_record.json")


def _fingerprint_pcap(path: str | None) -> str | None:
    if not path:
        return None

    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return None

    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


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


def _save_total_job_jsonl_artifact(
    total_job_id: str,
    name: str,
    records: list[dict[str, Any]],
) -> Path:
    total_job = total_job_store.get(total_job_id)
    if not total_job or not total_job.artifacts_dir:
        raise KeyError(f"Unknown total job: {total_job_id}")

    artifact_path = Path(total_job.artifacts_dir) / name
    with artifact_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record))
            handle.write("\n")
    total_job_store.update(total_job_id, updated_at=datetime.now(timezone.utc).isoformat())
    return artifact_path


def _save_all_total_jobs_jsonl_artifact(name: str, records: list[dict[str, Any]]) -> Path:
    artifact_path = ALL_TOTAL_JOBS_SUMMARY_DIR / name
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
    status: str | None,
) -> str:
    ai_callable = "yes" if fallback_used is False else "no"
    fallback_text = "yes" if fallback_used else "no"
    provider_label = "Provider used" if fallback_used is False else "Provider requested"
    model_label = "Model used" if fallback_used is False else "Model requested"
    details = [
        f"AI requested: yes",
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


def _read_all_total_jobs_summary_status() -> dict[str, Any]:
    if not ALL_TOTAL_JOBS_SUMMARY_STATUS_PATH.exists():
        return {}
    try:
        return json.loads(ALL_TOTAL_JOBS_SUMMARY_STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_all_total_jobs_summary_status(payload: dict[str, Any]) -> dict[str, Any]:
    status_payload = dict(payload)
    status_payload["updated_at"] = datetime.now(timezone.utc).isoformat()
    ALL_TOTAL_JOBS_SUMMARY_STATUS_PATH.write_text(
        json.dumps(status_payload, indent=2) + "\n",
        encoding="utf-8",
    )
    return status_payload


def _list_completed_total_job_children() -> tuple[list[str], list[TotalJobChildRef]]:
    total_job_ids: list[str] = []
    completed_children: list[TotalJobChildRef] = []

    for total_job in total_job_store.list_jobs():
        job_children: list[TotalJobChildRef] = []
        for child in total_job.children:
            child_job = job_store.get(child.analysis_job_id)
            if child_job and child_job.status == "completed":
                job_children.append(child)
        if job_children:
            total_job_ids.append(total_job.total_job_id)
            completed_children.extend(job_children)

    return total_job_ids, completed_children


def _serialize_all_total_jobs_summary_status() -> dict[str, Any]:
    source_total_job_ids, completed_children = _list_completed_total_job_children()
    stored_status = _read_all_total_jobs_summary_status()
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
) -> None:
    total_job = total_job_store.get(total_job_id)
    if not total_job:
        raise KeyError(f"Unknown total job: {total_job_id}")

    completed_children = []
    for child in total_job.children:
        child_job = job_store.get(child.analysis_job_id)
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

    records = [_load_analysis_record(child.analysis_job_id) for child in completed_children]
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
    _save_total_job_jsonl_artifact(total_job_id, "scan_results.jsonl", enriched_records)
    _save_total_job_jsonl_artifact(total_job_id, "scan_results.ai-tshark.jsonl", enriched_records)
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
                    "ai_callable": bool(case_summary.get("ai_callable", False)),
                    "status": case_summary.get("status"),
                },
                "campaign_plan": {
                    "planner_source": campaign_plan.get("planner_source"),
                    "planner_provider": campaign_plan.get("planner_provider"),
                    "planner_model": campaign_plan.get("planner_model"),
                },
                "final_report": {
                    "provider": final_report.get("provider"),
                    "model": final_report.get("model"),
                    "fallback_used": bool(final_report.get("fallback_used", False)),
                    "ai_callable": bool(final_report.get("ai_callable", False)),
                    "status": final_report.get("status"),
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


def _run_all_total_jobs_summary_sync(
    provider: str,
    model: str | None,
    require_ai: bool,
) -> None:
    source_total_job_ids, completed_children = _list_completed_total_job_children()
    if not completed_children:
        raise RuntimeError("No completed child analysis jobs are available across total jobs.")

    _write_all_total_jobs_summary_status(
        {
            "status": "running",
            "progress": 0.05,
            "error": None,
            "provider": provider,
            "model": model,
            "require_ai": require_ai,
            "source_total_job_count": len(source_total_job_ids),
            "source_total_job_ids": source_total_job_ids,
            "source_file_count": len(completed_children),
        }
    )

    records = [_load_analysis_record(child.analysis_job_id) for child in completed_children]
    _write_all_total_jobs_summary_status(
        {
            "status": "running",
            "progress": 0.2,
            "error": None,
            "provider": provider,
            "model": model,
            "require_ai": require_ai,
            "source_total_job_count": len(source_total_job_ids),
            "source_total_job_ids": source_total_job_ids,
            "source_file_count": len(completed_children),
            "record_count": len(records),
        }
    )

    unique_records, dedupe_metadata = _dedupe_analysis_records(records)
    _write_all_total_jobs_summary_status(
        {
            "status": "running",
            "progress": 0.25,
            "error": None,
            "provider": provider,
            "model": model,
            "require_ai": require_ai,
            "source_total_job_count": len(source_total_job_ids),
            "source_total_job_ids": source_total_job_ids,
            "source_file_count": len(completed_children),
            "record_count": len(records),
            "unique_record_count": len(unique_records),
            "duplicate_record_count": len(dedupe_metadata["duplicates_removed"]),
        }
    )

    def _campaign_progress(stage: str, progress: float) -> None:
        _write_all_total_jobs_summary_status(
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
                "source_file_count": len(completed_children),
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
        artifacts_dir=ALL_TOTAL_JOBS_SUMMARY_DIR,
    )
    enriched_records = campaign_result["enriched_records"]
    aggregate = campaign_result["aggregate"]
    summary_markdown = campaign_result["final_report_markdown"]
    case_summary = campaign_result["initial_summary"]
    campaign_plan = campaign_result["campaign_plan"]
    final_report = campaign_result["final_report"]
    selected_follow_up_records = campaign_result["selected_follow_up_records"]

    (ALL_TOTAL_JOBS_SUMMARY_DIR / "aggregate_summary.json").write_text(
        json.dumps(aggregate, indent=2) + "\n",
        encoding="utf-8",
    )
    (ALL_TOTAL_JOBS_SUMMARY_DIR / "scan_results.json").write_text(
        json.dumps(enriched_records, indent=2) + "\n",
        encoding="utf-8",
    )
    _save_all_total_jobs_jsonl_artifact("scan_results.jsonl", enriched_records)
    _save_all_total_jobs_jsonl_artifact("scan_results.ai-tshark.jsonl", enriched_records)
    (ALL_TOTAL_JOBS_SUMMARY_DIR / "summary.json").write_text(
        json.dumps(
            {
                "scope": "all_total_jobs",
                "route": "campaign_ai_then_sandbox_then_final_report",
                "source_total_job_ids": source_total_job_ids,
                "source_total_job_count": len(source_total_job_ids),
                "source_file_count": len(completed_children),
                "dedupe": dedupe_metadata,
                "ai_execution": {
                    "initial_summary": {
                        "provider": case_summary.get("provider"),
                        "model": case_summary.get("model"),
                        "fallback_used": bool(case_summary.get("fallback_used", False)),
                        "ai_callable": bool(case_summary.get("ai_callable", False)),
                        "status": case_summary.get("status"),
                    },
                    "campaign_plan": {
                        "planner_source": campaign_plan.get("planner_source"),
                        "planner_provider": campaign_plan.get("planner_provider"),
                        "planner_model": campaign_plan.get("planner_model"),
                    },
                    "final_report": {
                        "provider": final_report.get("provider"),
                        "model": final_report.get("model"),
                        "fallback_used": bool(final_report.get("fallback_used", False)),
                        "ai_callable": bool(final_report.get("ai_callable", False)),
                        "status": final_report.get("status"),
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
    (ALL_TOTAL_JOBS_SUMMARY_DIR / "initial_summary.md").write_text(
        _build_ai_markdown_notice(
            stage_label="Initial Campaign Summary AI Status",
            provider=case_summary.get("provider"),
            model=case_summary.get("model"),
            fallback_used=case_summary.get("fallback_used"),
            status=case_summary.get("status"),
        )
        + str(case_summary.get("report_text", ""))
        + ("\n" if case_summary.get("report_text") else ""),
        encoding="utf-8",
    )
    (ALL_TOTAL_JOBS_SUMMARY_DIR / "campaign_plan.json").write_text(
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
    (ALL_TOTAL_JOBS_SUMMARY_DIR / "summary.md").write_text(
        _build_ai_markdown_notice(
            stage_label="Final Campaign Report AI Status",
            provider=final_report.get("provider"),
            model=final_report.get("model"),
            fallback_used=final_report.get("fallback_used"),
            status=final_report.get("status"),
        )
        + summary_markdown
        + ("" if summary_markdown.endswith("\n") else "\n"),
        encoding="utf-8",
    )
    (ALL_TOTAL_JOBS_SUMMARY_DIR / "sandbox.json").write_text(
        json.dumps(
            {
                "scope": "all_total_jobs",
                "source_total_job_ids": source_total_job_ids,
                "source_total_job_count": len(source_total_job_ids),
                "source_file_count": len(completed_children),
                "dedupe": dedupe_metadata,
                "record_count": len(enriched_records),
                "records": enriched_records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_all_total_jobs_summary_status(
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
            "source_file_count": len(completed_children),
            "record_count": len(records),
            "unique_record_count": len(unique_records),
            "duplicate_record_count": len(dedupe_metadata["duplicates_removed"]),
            "route_stage": "completed",
            "selected_follow_up_record_count": len(selected_follow_up_records),
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
) -> None:
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None,
            _run_all_total_jobs_summary_sync,
            provider,
            model,
            require_ai,
        )
    except Exception as exc:  # noqa: BLE001
        current_status = _read_all_total_jobs_summary_status()
        _write_all_total_jobs_summary_status(
            {
                **current_status,
                "status": "failed",
                "progress": current_status.get("progress", 0.0),
                "error": str(exc),
            }
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
        target_path, source_name = _save_upload(file)
        source_type = "upload"
        source_path = target_path
    else:
        target_path = _normalize_pcap_path(pcap_path)
        source_type = "path"
        source_name = Path(target_path).name
        source_path = target_path

    resolved_analysis_profile = _normalize_analysis_profile(analysis_profile)

    job = job_store.create_job(
        source_type=source_type,
        source_name=source_name,
        source_path=source_path,
        analysis_profile=resolved_analysis_profile,
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
    files: list[UploadFile] = File(default=[]),
    worker_count: str | int | None = Form(default=2),
    pcap_paths: str | None = Form(default=None),
    analysis_profile: str | None = Form(default=None),
):
    requested_paths: list[str] = []
    if not files and "application/json" in request.headers.get("content-type", ""):
        payload = await request.json()
        worker_count = payload.get("worker_count", worker_count)
        requested_paths = _normalize_batch_pcap_paths(payload.get("pcap_paths") or [])
        analysis_profile = payload.get("analysis_profile", analysis_profile)
    elif pcap_paths:
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
            target_path, source_name = _save_upload(file)
            child_specs.append(
                {
                    "filename": source_name,
                    "source_path": target_path,
                    "source_type": "upload",
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
        )
        accepted_paths = [
            path for path in requested_paths if path.lower() not in existing_jobs_by_path
        ]
        skipped_files = [
            {
                "path": path,
                "filename": Path(path).name,
                "reason": "already_in_system",
                "existing_analysis_job_id": existing_jobs_by_path[path.lower()].analysis_job_id,
                "existing_status": existing_jobs_by_path[path.lower()].status,
            }
            for path in requested_paths
            if path.lower() in existing_jobs_by_path
        ]

        total_files = len(accepted_paths)
        for index, target_path in enumerate(accepted_paths):
            child_specs.append(
                {
                    "filename": Path(target_path).name,
                    "source_path": target_path,
                    "source_type": "path",
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
        **_serialize_total_job(total_job_store.get(total_job.total_job_id) or total_job),
        "accepted_file_count": len(finalized_child_specs),
        "skipped_files": skipped_files,
    }


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


@app.get("/api/v1/total-jobs")
async def list_total_jobs():
    jobs = total_job_store.list_jobs()
    return {
        "total": len(jobs),
        "jobs": [_serialize_total_job(job) for job in jobs],
    }


@app.get("/api/v1/total-jobs/summary/status")
async def get_all_total_jobs_summary_status():
    return _serialize_all_total_jobs_summary_status()


@app.post("/api/v1/total-jobs/summary/enrich")
async def enrich_all_total_jobs_summary(
    provider: str | None = Form(default=None),
    model: str | None = Form(default=None),
    require_ai: str | bool | None = Form(default=None),
):
    status = _serialize_all_total_jobs_summary_status()
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
        }
    )
    asyncio.create_task(
        _run_all_total_jobs_summary(
            provider or "gemini",
            model,
            _to_bool(require_ai, False),
        )
    )
    return _serialize_all_total_jobs_summary_status()


@app.get("/api/v1/total-jobs/summary/json")
async def get_all_total_jobs_summary_json():
    status = _serialize_all_total_jobs_summary_status()
    if status["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"All-jobs summary is {status['status']}")
    artifact_path = ALL_TOTAL_JOBS_SUMMARY_DIR / "summary.json"
    return json.loads(artifact_path.read_text(encoding="utf-8"))


@app.get("/api/v1/total-jobs/summary/markdown")
async def get_all_total_jobs_summary_markdown():
    status = _serialize_all_total_jobs_summary_status()
    if status["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"All-jobs summary is {status['status']}")
    artifact_path = ALL_TOTAL_JOBS_SUMMARY_DIR / "summary.md"
    return {"markdown": artifact_path.read_text(encoding="utf-8")}


@app.get("/api/v1/total-jobs/summary/sandbox")
async def get_all_total_jobs_summary_sandbox():
    status = _serialize_all_total_jobs_summary_status()
    if status["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"All-jobs summary is {status['status']}")
    artifact_path = ALL_TOTAL_JOBS_SUMMARY_DIR / "sandbox.json"
    return json.loads(artifact_path.read_text(encoding="utf-8"))


@app.get("/api/v1/total-jobs/{total_job_id}", response_model=TotalJobStatusResponse)
async def get_total_job_status(total_job_id: str):
    total_job = total_job_store.get(total_job_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")
    return TotalJobStatusResponse(**_serialize_total_job(total_job))


@app.post("/api/v1/total-jobs/{total_job_id}/enrich")
async def enrich_total_job(
    total_job_id: str,
    provider: str | None = Form(default=None),
    model: str | None = Form(default=None),
    require_ai: str | bool | None = Form(default=None),
):
    total_job = total_job_store.get(total_job_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")

    serialized = _serialize_total_job(total_job)
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
        )
    )
    return _serialize_total_job(total_job_store.get(total_job_id) or total_job)


@app.get("/api/v1/total-jobs/{total_job_id}/summary.json")
async def get_total_job_summary_json(total_job_id: str):
    total_job = total_job_store.get(total_job_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")
    if total_job.enrichment_status != "completed":
        raise HTTPException(status_code=409, detail=f"Enrichment is {total_job.enrichment_status}")
    return total_job_store.read_json_artifact(total_job_id, "summary.json")


@app.get("/api/v1/total-jobs/{total_job_id}/summary.md")
async def get_total_job_summary_markdown(total_job_id: str):
    total_job = total_job_store.get(total_job_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")
    if total_job.enrichment_status != "completed":
        raise HTTPException(status_code=409, detail=f"Enrichment is {total_job.enrichment_status}")
    return {"markdown": total_job_store.read_text_artifact(total_job_id, "summary.md")}


@app.get("/api/v1/total-jobs/{total_job_id}/sandbox")
async def get_total_job_sandbox(total_job_id: str):
    total_job = total_job_store.get(total_job_id)
    if not total_job:
        raise HTTPException(status_code=404, detail="Total job not found")
    if total_job.enrichment_status != "completed":
        raise HTTPException(status_code=409, detail=f"Enrichment is {total_job.enrichment_status}")
    return total_job_store.read_json_artifact(total_job_id, "sandbox.json")
