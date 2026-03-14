from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import json
import threading
import uuid


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


class JobStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, JobRecord] = {}
        self._lock = threading.Lock()

    def create_job(self) -> JobRecord:
        job_id = f"analysis_{uuid.uuid4().hex[:12]}"
        artifacts_dir = self.base_dir / job_id
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        record = JobRecord(analysis_job_id=job_id, artifacts_dir=str(artifacts_dir))
        with self._lock:
            self._jobs[job_id] = record
        return record

    def update(self, job_id: str, **kwargs) -> JobRecord:
        with self._lock:
            record = self._jobs[job_id]
            for k, v in kwargs.items():
                setattr(record, k, v)
            record.updated_at = datetime.now(timezone.utc).isoformat()
            return record

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.get(job_id)

    def save_artifact(self, job_id: str, name: str, content: str | dict) -> Path:
        record = self.get(job_id)
        if not record or not record.artifacts_dir:
            raise KeyError(f"Unknown job_id {job_id}")
        path = Path(record.artifacts_dir) / name

        if isinstance(content, dict):
            path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
        else:
            path.write_text(content + ("\n" if not content.endswith("\n") else ""), encoding="utf-8")
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
