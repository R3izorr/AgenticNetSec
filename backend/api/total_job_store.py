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
from backend.db.models import TotalJob
from backend.db.session import SessionLocal


@dataclass
class TotalJobChildRef:
    analysis_job_id: str
    filename: str
    source_path: str | None = None


@dataclass
class TotalJobRecord:
    total_job_id: str
    organization_id: str | None = None
    created_by_user_id: str | None = None
    status: str = "queued"
    current_stage: str = "queued"
    progress: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: str | None = None
    artifacts_dir: str | None = None
    worker_count: int = 2
    file_count: int = 0
    completed_children: int = 0
    failed_children: int = 0
    deterministic_complete: bool = False
    enrichment_status: str = "not_started"
    enrichment_progress: float = 0.0
    enrichment_error: str | None = None
    analysis_profile: str = "standard"
    children: list[TotalJobChildRef] = field(default_factory=list)


class TotalJobStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, TotalJobRecord] = {}
        self._db_available = True
        self.artifact_service = ArtifactService(base_dir.parent / "artifacts")
        self._lock = threading.Lock()
        self._load_existing_jobs()

    def create_job(
        self,
        *,
        worker_count: int,
        files: list[dict[str, Any]],
        analysis_profile: str = "standard",
        organization_id: str | uuid.UUID | None = None,
        user_id: str | uuid.UUID | None = None,
    ) -> TotalJobRecord:
        total_job_id = f"total_{uuid.uuid4().hex[:12]}"
        artifacts_dir = self.base_dir / total_job_id
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        record = TotalJobRecord(
            total_job_id=total_job_id,
            organization_id=str(organization_id) if organization_id else None,
            created_by_user_id=str(user_id) if user_id else None,
            artifacts_dir=str(artifacts_dir),
            worker_count=worker_count,
            file_count=len(files),
            analysis_profile=analysis_profile,
            children=[
                TotalJobChildRef(
                    analysis_job_id=str(item["analysis_job_id"]),
                    filename=str(item["filename"]),
                    source_path=item.get("source_path"),
                )
                for item in files
            ],
        )
        with self._lock:
            self._jobs[total_job_id] = record
            self._persist_record(record)
        return record

    def update(self, total_job_id: str, **kwargs: Any) -> TotalJobRecord:
        with self._lock:
            record = self._jobs[total_job_id]
            for key, value in kwargs.items():
                if key == "updated_at":
                    continue
                setattr(record, key, value)
            record.updated_at = datetime.now(timezone.utc).isoformat()
            self._persist_record(record)
            return record

    def get(self, total_job_id: str, *, organization_id: str | uuid.UUID | None = None) -> TotalJobRecord | None:
        self._refresh_db_job(total_job_id, organization_id=organization_id)
        with self._lock:
            record = self._jobs.get(total_job_id)
            if record is None or not self._matches_organization(record, organization_id):
                return None
            return record

    def list_jobs(self, *, organization_id: str | uuid.UUID | None = None) -> list[TotalJobRecord]:
        self._refresh_db_jobs(organization_id=organization_id)
        with self._lock:
            jobs = [job for job in self._jobs.values() if self._matches_organization(job, organization_id)]
            jobs.sort(key=lambda job: job.created_at, reverse=True)
            return jobs

    def save_json_artifact(self, total_job_id: str, name: str, content: dict[str, Any] | list[Any]) -> Path:
        record = self.get(total_job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown total_job_id {total_job_id}")
        path = Path(record.artifacts_dir) / name
        path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
        self.artifact_service.record_file(
            path,
            artifact_type=self._artifact_type_for_name(name),
            total_job_id=total_job_id,
            organization_id=record.organization_id,
            user_id=record.created_by_user_id,
        )
        self.update(total_job_id, updated_at=datetime.now(timezone.utc).isoformat())
        return path

    def save_text_artifact(self, total_job_id: str, name: str, content: str) -> Path:
        record = self.get(total_job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown total_job_id {total_job_id}")
        path = Path(record.artifacts_dir) / name
        path.write_text(content + ("" if content.endswith("\n") else "\n"), encoding="utf-8")
        self.artifact_service.record_file(
            path,
            artifact_type=self._artifact_type_for_name(name),
            total_job_id=total_job_id,
            organization_id=record.organization_id,
            user_id=record.created_by_user_id,
        )
        self.update(total_job_id, updated_at=datetime.now(timezone.utc).isoformat())
        return path

    def read_json_artifact(self, total_job_id: str, name: str, *, organization_id: str | uuid.UUID | None = None) -> Any:
        record = self.get(total_job_id, organization_id=organization_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown total_job_id {total_job_id}")
        path = Path(record.artifacts_dir) / name
        self.artifact_service.ensure_readable(
            path,
            organization_id=record.organization_id,
            user_id=record.created_by_user_id,
        )
        return json.loads(path.read_text(encoding="utf-8"))

    def read_text_artifact(self, total_job_id: str, name: str, *, organization_id: str | uuid.UUID | None = None) -> str:
        record = self.get(total_job_id, organization_id=organization_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown total_job_id {total_job_id}")
        path = Path(record.artifacts_dir) / name
        self.artifact_service.ensure_readable(
            path,
            organization_id=record.organization_id,
            user_id=record.created_by_user_id,
        )
        return path.read_text(encoding="utf-8")

    def _load_existing_jobs(self) -> None:
        db_records = self._load_db_jobs()
        self._jobs.update(db_records)

        for job_dir in sorted(self.base_dir.iterdir() if self.base_dir.exists() else [], reverse=True):
            if not job_dir.is_dir():
                continue
            record = self._load_job_record(job_dir)
            if record:
                record = self._recover_interrupted_total_job(record)
                self._jobs.setdefault(record.total_job_id, record)
                self._persist_record(self._jobs[record.total_job_id])

    def _load_db_jobs(self) -> dict[str, TotalJobRecord]:
        if not self._db_available:
            return {}
        try:
            with SessionLocal() as session:
                rows = session.scalars(
                    select(TotalJob)
                    .where(TotalJob.public_id.is_not(None))
                    .order_by(TotalJob.created_at.desc())
                ).all()
                session.commit()
                return {record.total_job_id: record for record in (self._record_from_model(row) for row in rows)}
        except Exception:  # noqa: BLE001
            self._db_available = False
            return {}

    def _refresh_db_job(self, total_job_id: str, *, organization_id: str | uuid.UUID | None = None) -> None:
        if not self._db_available:
            return
        try:
            with SessionLocal() as session:
                query = select(TotalJob).where(TotalJob.public_id == total_job_id)
                if organization_id is not None:
                    query = query.where(TotalJob.organization_id == uuid.UUID(str(organization_id)))
                row = session.scalar(query)
                session.commit()
                if row is None:
                    return
                record = self._record_from_model(row)
            with self._lock:
                self._jobs[record.total_job_id] = record
        except Exception:  # noqa: BLE001
            self._db_available = False

    def _refresh_db_jobs(self, *, organization_id: str | uuid.UUID | None = None) -> None:
        if not self._db_available:
            return
        try:
            with SessionLocal() as session:
                query = select(TotalJob).where(TotalJob.public_id.is_not(None))
                if organization_id is not None:
                    query = query.where(TotalJob.organization_id == uuid.UUID(str(organization_id)))
                rows = session.scalars(query.order_by(TotalJob.created_at.desc())).all()
                session.commit()
                records = [self._record_from_model(row) for row in rows]
            with self._lock:
                for record in records:
                    self._jobs[record.total_job_id] = record
        except Exception:  # noqa: BLE001
            self._db_available = False

    def _load_job_record(self, job_dir: Path) -> TotalJobRecord | None:
        manifest_path = job_dir / "total_job.json"
        if not manifest_path.exists():
            return None
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload.setdefault("artifacts_dir", str(job_dir))
            payload["children"] = [
                child if isinstance(child, TotalJobChildRef) else TotalJobChildRef(**child)
                for child in payload.get("children", [])
            ]
            return TotalJobRecord(**payload)
        except (OSError, json.JSONDecodeError, TypeError):
            return None

    def _persist_record(self, record: TotalJobRecord) -> None:
        if record.artifacts_dir:
            manifest_path = Path(record.artifacts_dir) / "total_job.json"
            payload = asdict(record)
            manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        self._persist_db_record(record)

    def _persist_db_record(self, record: TotalJobRecord) -> None:
        if not self._db_available:
            return
        try:
            with SessionLocal() as session:
                user_id, organization_id = self._resolve_principal(session, record)
                row = session.scalar(
                    select(TotalJob).where(
                        TotalJob.organization_id == organization_id,
                        TotalJob.public_id == record.total_job_id,
                    )
                )
                if row is None:
                    row = TotalJob(
                        public_id=record.total_job_id,
                        organization_id=organization_id,
                        created_by_user_id=user_id,
                        status=record.status,
                        current_stage=record.current_stage,
                        analysis_profile=record.analysis_profile,
                    )
                    session.add(row)
                self._apply_record_to_model(record, row, organization_id, user_id)
                session.commit()
        except Exception:  # noqa: BLE001
            self._db_available = False

    @classmethod
    def _apply_record_to_model(
        cls,
        record: TotalJobRecord,
        row: TotalJob,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> None:
        row.public_id = record.total_job_id
        row.organization_id = organization_id
        row.created_by_user_id = user_id
        row.status = record.status
        row.current_stage = record.current_stage
        row.progress = Decimal(str(max(0.0, min(1.0, float(record.progress or 0.0)))))
        row.enrichment_status = record.enrichment_status
        row.enrichment_progress = Decimal(str(max(0.0, min(1.0, float(record.enrichment_progress or 0.0)))))
        row.analysis_profile = record.analysis_profile
        row.worker_count = record.worker_count
        row.file_count = record.file_count
        row.artifacts_dir = record.artifacts_dir
        row.error = record.error
        row.completed_children = record.completed_children
        row.failed_children = record.failed_children
        row.deterministic_complete = record.deterministic_complete
        row.enrichment_error = record.enrichment_error
        row.children_json = [asdict(child) for child in record.children]
        row.completed_at = cls._parse_datetime(record.updated_at) if record.status == "completed" else None

    @classmethod
    def _record_from_model(cls, row: TotalJob) -> TotalJobRecord:
        children = []
        for child in row.children_json or []:
            if isinstance(child, dict):
                children.append(TotalJobChildRef(**child))
        return TotalJobRecord(
            total_job_id=str(row.public_id),
            organization_id=str(row.organization_id),
            created_by_user_id=str(row.created_by_user_id) if row.created_by_user_id else None,
            status=row.status,
            current_stage=row.current_stage,
            progress=float(row.progress or 0),
            created_at=cls._format_datetime(row.created_at),
            updated_at=cls._format_datetime(row.updated_at),
            error=row.error,
            artifacts_dir=row.artifacts_dir,
            worker_count=row.worker_count,
            file_count=row.file_count,
            completed_children=row.completed_children,
            failed_children=row.failed_children,
            deterministic_complete=bool(row.deterministic_complete),
            enrichment_status=row.enrichment_status,
            enrichment_progress=float(row.enrichment_progress or 0),
            enrichment_error=row.enrichment_error,
            analysis_profile=row.analysis_profile,
            children=children,
        )

    @staticmethod
    def _matches_organization(record: TotalJobRecord, organization_id: str | uuid.UUID | None) -> bool:
        if organization_id is None:
            return True
        return str(record.organization_id) == str(organization_id)

    @staticmethod
    def _resolve_principal(session: Any, record: TotalJobRecord) -> tuple[uuid.UUID, uuid.UUID]:
        if record.organization_id and record.created_by_user_id:
            return uuid.UUID(record.created_by_user_id), uuid.UUID(record.organization_id)
        user_id, organization_id = ensure_default_principal(session)
        record.created_by_user_id = str(user_id)
        record.organization_id = str(organization_id)
        return user_id, organization_id

    @staticmethod
    def _artifact_type_for_name(name: str) -> str:
        artifact_types = {
            "aggregate_summary.json": "total_job_aggregate_summary",
            "scan_results.json": "total_job_scan_results",
            "summary.json": "total_job_summary_json",
            "summary.md": "total_job_summary_markdown",
            "sandbox.json": "total_job_sandbox",
            "campaign_plan.json": "total_job_campaign_plan",
            "initial_summary.md": "total_job_initial_summary",
        }
        return artifact_types.get(name, "total_job_artifact")

    @staticmethod
    def _recover_interrupted_total_job(record: TotalJobRecord) -> TotalJobRecord:
        if record.enrichment_status in {"queued", "running"}:
            record.enrichment_status = "failed"
            record.enrichment_error = "Interrupted by backend shutdown during enrichment."
            if record.deterministic_complete:
                record.status = "completed"
                record.current_stage = "ready_for_enrichment"
            else:
                record.status = "failed"
                record.current_stage = "failed"
                record.error = "Interrupted by backend shutdown before deterministic analysis completed."
            return record

        if record.status in {"queued", "running"} or record.current_stage in {"queued", "deterministic_analysis"}:
            record.status = "failed"
            record.current_stage = "failed"
            record.error = "Interrupted by backend shutdown before deterministic analysis completed."
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
