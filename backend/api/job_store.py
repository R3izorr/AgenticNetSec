from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
import json
import threading
import uuid

from sqlalchemy import select

from backend.db.bootstrap import ensure_default_principal
from .artifact_service import ArtifactService
from backend.db.models import AnalysisJob, TotalJob
from backend.db.session import SessionLocal


ARTIFACT_KEYS = {
    "report.json": "report_json",
    "report.md": "report_markdown",
    "metrics.json": "metrics",
    "guardrail_audit.json": "guardrail_audit",
}

DEFAULT_ARTIFACT_READY = {
    "report_json": False,
    "report_markdown": False,
    "metrics": False,
    "guardrail_audit": False,
}


@dataclass
class JobRecord:
    analysis_job_id: str
    organization_id: str | None = None
    created_by_user_id: str | None = None
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
    artifact_ready: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_ARTIFACT_READY))
    attack_type: str | None = None
    risk_level: str | None = None
    confidence_score: float | None = None
    runtime_seconds_total: float | None = None
    group_id: str | None = None
    group_index: int | None = None
    group_total: int | None = None
    analysis_profile: str = "standard"
    stage1_execution: dict[str, Any] = field(default_factory=dict)
    source_artifact_id: str | None = None


class JobStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, JobRecord] = {}
        self._db_available = True
        self.artifact_service = ArtifactService(base_dir.parent / "artifacts")
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
        source_artifact_id: str | None = None,
        organization_id: str | uuid.UUID | None = None,
        user_id: str | uuid.UUID | None = None,
    ) -> JobRecord:
        job_id = f"analysis_{uuid.uuid4().hex[:12]}"
        artifacts_dir = self.base_dir / job_id
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        record = JobRecord(
            analysis_job_id=job_id,
            organization_id=str(organization_id) if organization_id else None,
            created_by_user_id=str(user_id) if user_id else None,
            artifacts_dir=str(artifacts_dir),
            source_type=source_type,
            source_name=source_name,
            source_path=source_path,
            group_id=group_id,
            group_index=group_index,
            group_total=group_total,
            analysis_profile=analysis_profile,
            source_artifact_id=source_artifact_id,
        )
        with self._lock:
            self._jobs[job_id] = record
            self._persist_record(record)
        return record

    def update(self, job_id: str, **kwargs: Any) -> JobRecord:
        with self._lock:
            record = self._jobs[job_id]
            for key, value in kwargs.items():
                if key == "updated_at":
                    continue
                setattr(record, key, value)
            record.updated_at = datetime.now(timezone.utc).isoformat()
            self._persist_record(record)
            return record

    def get(self, job_id: str, *, organization_id: str | uuid.UUID | None = None) -> JobRecord | None:
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None or not self._matches_organization(record, organization_id):
                return None
            return record

    def find_by_source_paths(
        self,
        source_paths: list[str],
        *,
        statuses: set[str] | None = None,
        organization_id: str | uuid.UUID | None = None,
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
                if not self._matches_organization(job, organization_id):
                    continue
                normalized_job_path = self._normalize_source_path(job.source_path)
                if not normalized_job_path or normalized_job_path not in normalized_targets:
                    continue
                if statuses is not None and job.status not in statuses:
                    continue
                existing = matches.get(normalized_job_path)
                if existing is None or existing.created_at < job.created_at:
                    matches[normalized_job_path] = job
            return matches

    def find_by_source_names(
        self,
        source_names: list[str],
        *,
        statuses: set[str] | None = None,
        organization_id: str | uuid.UUID | None = None,
    ) -> dict[str, JobRecord]:
        normalized_targets = {str(name).strip().lower() for name in source_names if str(name).strip()}
        if not normalized_targets:
            return {}

        with self._lock:
            matches: dict[str, JobRecord] = {}
            for job in self._jobs.values():
                if not self._matches_organization(job, organization_id):
                    continue
                normalized_name = str(job.source_name or "").strip().lower()
                if not normalized_name or normalized_name not in normalized_targets:
                    continue
                if statuses is not None and job.status not in statuses:
                    continue
                existing = matches.get(normalized_name)
                if existing is None or existing.created_at < job.created_at:
                    matches[normalized_name] = job
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
        artifact_type = self._artifact_type_for_name(name)
        self.artifact_service.record_file(
            path,
            artifact_type=artifact_type,
            analysis_job_id=job_id,
            organization_id=record.organization_id,
            user_id=record.created_by_user_id,
        )
        return path

    def read_json_artifact(self, job_id: str, name: str, *, organization_id: str | uuid.UUID | None = None) -> dict:
        record = self.get(job_id, organization_id=organization_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown job_id {job_id}")
        path = Path(record.artifacts_dir) / name
        self.artifact_service.ensure_readable(
            path,
            organization_id=record.organization_id,
            user_id=record.created_by_user_id,
        )
        return json.loads(path.read_text(encoding="utf-8"))

    def read_text_artifact(self, job_id: str, name: str, *, organization_id: str | uuid.UUID | None = None) -> str:
        record = self.get(job_id, organization_id=organization_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown job_id {job_id}")
        path = Path(record.artifacts_dir) / name
        self.artifact_service.ensure_readable(
            path,
            organization_id=record.organization_id,
            user_id=record.created_by_user_id,
        )
        return path.read_text(encoding="utf-8")

    def list_jobs(self, *, organization_id: str | uuid.UUID | None = None) -> list[JobRecord]:
        with self._lock:
            jobs = [job for job in self._jobs.values() if self._matches_organization(job, organization_id)]
            jobs.sort(key=lambda job: job.created_at, reverse=True)
            return jobs

    def _load_existing_jobs(self) -> None:
        db_records = self._load_db_jobs()
        self._jobs.update(db_records)

        for job_dir in sorted(self.base_dir.iterdir() if self.base_dir.exists() else [], reverse=True):
            if not job_dir.is_dir():
                continue
            record = self._load_job_record(job_dir)
            if record:
                record = self._recover_interrupted_job(record)
                self._jobs.setdefault(record.analysis_job_id, record)
                self._persist_record(self._jobs[record.analysis_job_id])

    def _load_db_jobs(self) -> dict[str, JobRecord]:
        if not self._db_available:
            return {}
        try:
            with SessionLocal() as session:
                rows = session.scalars(
                    select(AnalysisJob)
                    .where(AnalysisJob.public_id.is_not(None))
                    .order_by(AnalysisJob.created_at.desc())
                ).all()
                session.commit()
                return {record.analysis_job_id: record for record in (self._record_from_model(row) for row in rows)}
        except Exception:  # noqa: BLE001
            self._db_available = False
            return {}

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

        return record

    def _persist_record(self, record: JobRecord) -> None:
        if record.artifacts_dir:
            manifest_path = Path(record.artifacts_dir) / "job.json"
            payload = asdict(record)
            manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        self._persist_db_record(record)

    def _persist_db_record(self, record: JobRecord) -> None:
        if not self._db_available:
            return
        try:
            with SessionLocal() as session:
                user_id, organization_id = self._resolve_principal(session, record)
                row = session.scalar(
                    select(AnalysisJob).where(
                        AnalysisJob.organization_id == organization_id,
                        AnalysisJob.public_id == record.analysis_job_id,
                    )
                )
                if row is None:
                    row = AnalysisJob(
                        public_id=record.analysis_job_id,
                        organization_id=organization_id,
                        created_by_user_id=user_id,
                        source_type=record.source_type or "unknown",
                        source_name=record.source_name or record.analysis_job_id,
                        status=record.status,
                        current_phase=record.current_phase,
                        analysis_profile=record.analysis_profile,
                    )
                    session.add(row)
                self._apply_record_to_model(record, row, session, organization_id, user_id)
                session.commit()
        except Exception:  # noqa: BLE001
            self._db_available = False

    def _apply_record_to_model(
        self,
        record: JobRecord,
        row: AnalysisJob,
        session: Any,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> None:
        row.public_id = record.analysis_job_id
        row.organization_id = organization_id
        row.created_by_user_id = user_id
        row.source_type = record.source_type or "unknown"
        row.source_name = record.source_name or record.analysis_job_id
        row.source_path = record.source_path
        row.status = record.status
        row.current_phase = record.current_phase
        row.progress = Decimal(str(max(0.0, min(1.0, float(record.progress or 0.0)))))
        row.analysis_profile = record.analysis_profile
        row.risk_level = record.risk_level
        row.attack_type = record.attack_type
        row.confidence_score = self._decimal_or_none(record.confidence_score)
        row.artifacts_dir = record.artifacts_dir
        row.group_id = record.group_id
        row.group_index = record.group_index
        row.group_total = record.group_total
        row.guardrail_state = record.guardrail_state
        row.metadata_json = record.metadata or {}
        row.artifact_ready_json = record.artifact_ready or dict(DEFAULT_ARTIFACT_READY)
        row.runtime_seconds_total = self._decimal_or_none(record.runtime_seconds_total)
        row.stage1_execution_json = record.stage1_execution or {}
        if record.source_artifact_id:
            try:
                row.source_artifact_id = uuid.UUID(record.source_artifact_id)
            except ValueError:
                pass
        row.error = record.error
        row.completed_at = self._parse_datetime(record.updated_at) if record.status == "completed" else None
        if record.group_id:
            total_job = session.scalar(
                select(TotalJob).where(TotalJob.organization_id == organization_id, TotalJob.public_id == record.group_id)
            )
            row.total_job_id = total_job.id if total_job else None

    @classmethod
    def _record_from_model(cls, row: AnalysisJob) -> JobRecord:
        return JobRecord(
            analysis_job_id=str(row.public_id),
            organization_id=str(row.organization_id),
            created_by_user_id=str(row.created_by_user_id) if row.created_by_user_id else None,
            status=row.status,
            current_phase=row.current_phase,
            progress=float(row.progress or 0),
            guardrail_state=row.guardrail_state or "pending",
            created_at=cls._format_datetime(row.created_at),
            updated_at=cls._format_datetime(row.updated_at),
            error=row.error,
            artifacts_dir=row.artifacts_dir,
            source_type=row.source_type,
            source_name=row.source_name,
            source_path=row.source_path,
            metadata=dict(row.metadata_json or {}),
            artifact_ready={**DEFAULT_ARTIFACT_READY, **dict(row.artifact_ready_json or {})},
            attack_type=row.attack_type,
            risk_level=row.risk_level,
            confidence_score=cls._float_or_none(row.confidence_score),
            runtime_seconds_total=cls._float_or_none(row.runtime_seconds_total),
            group_id=row.group_id,
            group_index=row.group_index,
            group_total=row.group_total,
            analysis_profile=row.analysis_profile,
            stage1_execution=dict(row.stage1_execution_json or {}),
            source_artifact_id=str(row.source_artifact_id) if row.source_artifact_id else None,
        )

    def soft_delete_artifacts(self, job_id: str, *, organization_id: str | uuid.UUID | None = None) -> int:
        record = self.get(job_id, organization_id=organization_id)
        if record is None:
            return 0
        return self.artifact_service.soft_delete_analysis_artifacts(
            job_id,
            organization_id=record.organization_id,
            user_id=record.created_by_user_id,
        )

    @staticmethod
    def _matches_organization(record: JobRecord, organization_id: str | uuid.UUID | None) -> bool:
        if organization_id is None:
            return True
        return str(record.organization_id) == str(organization_id)

    @staticmethod
    def _resolve_principal(session: Any, record: JobRecord) -> tuple[uuid.UUID, uuid.UUID]:
        if record.organization_id and record.created_by_user_id:
            return uuid.UUID(record.created_by_user_id), uuid.UUID(record.organization_id)
        user_id, organization_id = ensure_default_principal(session)
        record.created_by_user_id = str(user_id)
        record.organization_id = str(organization_id)
        return user_id, organization_id

    @staticmethod
    def _artifact_type_for_name(name: str) -> str:
        artifact_types = {
            "report.json": "analysis_report_json",
            "report.md": "analysis_report_markdown",
            "metrics.json": "analysis_metrics",
            "guardrail_audit.json": "guardrail_audit",
            "analysis_record.json": "analysis_record",
        }
        return artifact_types.get(name, "analysis_artifact")

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

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _format_datetime(value: datetime | None) -> str:
        if value is None:
            return datetime.now(timezone.utc).isoformat()
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _decimal_or_none(value: float | int | str | None) -> Decimal | None:
        if value is None:
            return None
        return Decimal(str(value))

    @staticmethod
    def _float_or_none(value: Decimal | float | int | None) -> float | None:
        if value is None:
            return None
        return float(value)
