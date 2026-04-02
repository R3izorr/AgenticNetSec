from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import threading
import uuid


@dataclass
class TotalJobChildRef:
    analysis_job_id: str
    filename: str
    source_path: str | None = None


@dataclass
class TotalJobRecord:
    total_job_id: str
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
    children: list[TotalJobChildRef] = field(default_factory=list)


class TotalJobStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, TotalJobRecord] = {}
        self._lock = threading.Lock()
        self._load_existing_jobs()

    def create_job(self, *, worker_count: int, files: list[dict[str, Any]]) -> TotalJobRecord:
        total_job_id = f"total_{uuid.uuid4().hex[:12]}"
        artifacts_dir = self.base_dir / total_job_id
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        record = TotalJobRecord(
            total_job_id=total_job_id,
            artifacts_dir=str(artifacts_dir),
            worker_count=worker_count,
            file_count=len(files),
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
                setattr(record, key, value)
            record.updated_at = datetime.now(timezone.utc).isoformat()
            self._persist_record(record)
            return record

    def get(self, total_job_id: str) -> TotalJobRecord | None:
        with self._lock:
            return self._jobs.get(total_job_id)

    def list_jobs(self) -> list[TotalJobRecord]:
        with self._lock:
            jobs = list(self._jobs.values())
            jobs.sort(key=lambda job: job.created_at, reverse=True)
            return jobs

    def save_json_artifact(self, total_job_id: str, name: str, content: dict[str, Any] | list[Any]) -> Path:
        record = self.get(total_job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown total_job_id {total_job_id}")
        path = Path(record.artifacts_dir) / name
        path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
        self.update(total_job_id, updated_at=datetime.now(timezone.utc).isoformat())
        return path

    def save_text_artifact(self, total_job_id: str, name: str, content: str) -> Path:
        record = self.get(total_job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown total_job_id {total_job_id}")
        path = Path(record.artifacts_dir) / name
        path.write_text(content + ("" if content.endswith("\n") else "\n"), encoding="utf-8")
        self.update(total_job_id, updated_at=datetime.now(timezone.utc).isoformat())
        return path

    def read_json_artifact(self, total_job_id: str, name: str) -> Any:
        record = self.get(total_job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown total_job_id {total_job_id}")
        path = Path(record.artifacts_dir) / name
        return json.loads(path.read_text(encoding="utf-8"))

    def read_text_artifact(self, total_job_id: str, name: str) -> str:
        record = self.get(total_job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown total_job_id {total_job_id}")
        path = Path(record.artifacts_dir) / name
        return path.read_text(encoding="utf-8")

    def _load_existing_jobs(self) -> None:
        for job_dir in sorted(self.base_dir.iterdir() if self.base_dir.exists() else [], reverse=True):
            if not job_dir.is_dir():
                continue
            record = self._load_job_record(job_dir)
            if record:
                self._jobs[record.total_job_id] = record

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
        if not record.artifacts_dir:
            return
        manifest_path = Path(record.artifacts_dir) / "total_job.json"
        payload = asdict(record)
        manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
