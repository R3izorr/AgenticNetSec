from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import threading
import uuid


ARTIFACT_KEYS = {
    "report.json": "report_json",
    "report.md": "report_markdown",
    "metrics.json": "metrics",
    "guardrail_audit.json": "guardrail_audit",
}


@dataclass
class JobRecord:
    analysis_job_id: str
    status: str = "queued"
    current_phase: str = "queued"
    progress: float = 0.0
    guardrail_state: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: str | None = None
    artifacts_dir: str | None = None
    source_type: str | None = None
    source_name: str | None = None
    source_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    artifact_ready: dict[str, bool] = field(
        default_factory=lambda: {
            "report_json": False,
            "report_markdown": False,
            "metrics": False,
            "guardrail_audit": False,
        }
    )
    attack_type: str | None = None
    risk_level: str | None = None
    confidence_score: float | None = None
    runtime_seconds_total: float | None = None
    group_id: str | None = None
    group_index: int | None = None
    group_total: int | None = None
    analysis_profile: str = "standard"
    stage1_execution: dict[str, Any] = field(default_factory=dict)


class JobStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, JobRecord] = {}
        self._lock = threading.Lock()
        self._load_existing_jobs()

    def create_job(
        self,
        *,
        source_type: str | None = None,
        source_name: str | None = None,
        source_path: str | None = None,
        group_id: str | None = None,
        group_index: int | None = None,
        group_total: int | None = None,
        analysis_profile: str = "standard",
    ) -> JobRecord:
        job_id = f"analysis_{uuid.uuid4().hex[:12]}"
        artifacts_dir = self.base_dir / job_id
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        record = JobRecord(
            analysis_job_id=job_id,
            artifacts_dir=str(artifacts_dir),
            source_type=source_type,
            source_name=source_name,
            source_path=source_path,
            group_id=group_id,
            group_index=group_index,
            group_total=group_total,
            analysis_profile=analysis_profile,
        )
        with self._lock:
            self._jobs[job_id] = record
            self._persist_record(record)
        return record

    def update(self, job_id: str, **kwargs) -> JobRecord:
        with self._lock:
            record = self._jobs[job_id]
            for key, value in kwargs.items():
                setattr(record, key, value)
            record.updated_at = datetime.now(timezone.utc).isoformat()
            self._persist_record(record)
            return record

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.get(job_id)

    def find_by_source_paths(
        self,
        source_paths: list[str],
        *,
        statuses: set[str] | None = None,
    ) -> dict[str, JobRecord]:
        normalized_targets = {
            self._normalize_source_path(path)
            for path in source_paths
            if self._normalize_source_path(path)
        }
        if not normalized_targets:
            return {}

        with self._lock:
            matches: dict[str, JobRecord] = {}
            for job in self._jobs.values():
                normalized_job_path = self._normalize_source_path(job.source_path)
                if not normalized_job_path or normalized_job_path not in normalized_targets:
                    continue
                if statuses is not None and job.status not in statuses:
                    continue
                existing = matches.get(normalized_job_path)
                if existing is None or existing.created_at < job.created_at:
                    matches[normalized_job_path] = job
            return matches

    def save_artifact(self, job_id: str, name: str, content: str | dict) -> Path:
        record = self.get(job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown job_id {job_id}")
        path = Path(record.artifacts_dir) / name

        if isinstance(content, dict):
            path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
        else:
            path.write_text(content + ("\n" if not content.endswith("\n") else ""), encoding="utf-8")

        artifact_key = ARTIFACT_KEYS.get(name)
        if artifact_key:
            with self._lock:
                record = self._jobs[job_id]
                record.artifact_ready[artifact_key] = True
                record.updated_at = datetime.now(timezone.utc).isoformat()
                self._persist_record(record)
        return path

    def read_json_artifact(self, job_id: str, name: str) -> dict:
        record = self.get(job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown job_id {job_id}")
        path = Path(record.artifacts_dir) / name
        return json.loads(path.read_text(encoding="utf-8"))

    def read_text_artifact(self, job_id: str, name: str) -> str:
        record = self.get(job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown job_id {job_id}")
        path = Path(record.artifacts_dir) / name
        return path.read_text(encoding="utf-8")

    def list_jobs(self) -> list[JobRecord]:
        with self._lock:
            jobs = list(self._jobs.values())
            jobs.sort(key=lambda job: job.created_at, reverse=True)
            return jobs

    def _load_existing_jobs(self) -> None:
        for job_dir in sorted(self.base_dir.iterdir() if self.base_dir.exists() else [], reverse=True):
            if not job_dir.is_dir():
                continue
            record = self._load_job_record(job_dir)
            if record:
                record = self._recover_interrupted_job(record)
                self._jobs[record.analysis_job_id] = record
                self._persist_record(record)

    def _load_job_record(self, job_dir: Path) -> JobRecord | None:
        manifest_path = job_dir / "job.json"
        if manifest_path.exists():
            try:
                payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                payload.setdefault("artifacts_dir", str(job_dir))
                payload.setdefault("metadata", {})
                payload.setdefault(
                    "artifact_ready",
                    {
                        "report_json": (job_dir / "report.json").exists(),
                        "report_markdown": (job_dir / "report.md").exists(),
                        "metrics": (job_dir / "metrics.json").exists(),
                        "guardrail_audit": (job_dir / "guardrail_audit.json").exists(),
                    },
                )
                return JobRecord(**payload)
            except (OSError, json.JSONDecodeError, TypeError):
                return None

        report_path = job_dir / "report.json"
        metrics_path = job_dir / "metrics.json"
        created_at = datetime.fromtimestamp(job_dir.stat().st_ctime, tz=timezone.utc).isoformat()
        updated_at = datetime.fromtimestamp(job_dir.stat().st_mtime, tz=timezone.utc).isoformat()
        record = JobRecord(
            analysis_job_id=job_dir.name,
            status="completed" if report_path.exists() else "queued",
            current_phase="completed" if report_path.exists() else "queued",
            progress=1.0 if report_path.exists() else 0.0,
            guardrail_state="pending",
            created_at=created_at,
            updated_at=updated_at,
            artifacts_dir=str(job_dir),
            source_type="legacy",
            source_name=job_dir.name,
            artifact_ready={
                "report_json": report_path.exists(),
                "report_markdown": (job_dir / "report.md").exists(),
                "metrics": metrics_path.exists(),
                "guardrail_audit": (job_dir / "guardrail_audit.json").exists(),
            },
        )

        if report_path.exists():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
                record.guardrail_state = (
                    (report.get("guardrail_verification") or {}).get("human_review_required")
                    or record.guardrail_state
                )
                record.attack_type = (report.get("impact") or {}).get("attack_type")
                record.risk_level = (report.get("impact") or {}).get("risk_level")
                record.confidence_score = (report.get("findings") or {}).get("confidence_score")
                record.metadata = (report.get("header") or {}).get("metadata") or {}
            except (OSError, json.JSONDecodeError):
                pass

        if metrics_path.exists():
            try:
                metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
                record.runtime_seconds_total = metrics.get("runtime_seconds_total")
            except (OSError, json.JSONDecodeError):
                pass

        self._persist_record(record)
        return record

    def _persist_record(self, record: JobRecord) -> None:
        if not record.artifacts_dir:
            return
        manifest_path = Path(record.artifacts_dir) / "job.json"
        payload = asdict(record)
        manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _normalize_source_path(source_path: str | None) -> str | None:
        if not source_path:
            return None
        try:
            return str(Path(source_path).expanduser().resolve()).lower()
        except OSError:
            return str(Path(source_path).expanduser()).lower()

    @staticmethod
    def _recover_interrupted_job(record: JobRecord) -> JobRecord:
        if record.status not in {"queued", "running"}:
            return record
        record.status = "failed"
        record.current_phase = "interrupted"
        record.error = "Interrupted by backend shutdown before analysis completed."
        return record
