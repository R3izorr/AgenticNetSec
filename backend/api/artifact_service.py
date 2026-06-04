from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import BinaryIO
import hashlib
import mimetypes
import uuid

from sqlalchemy import select, update

from backend.db.bootstrap import ensure_default_principal
from backend.db.models import AnalysisJob, Artifact, TotalJob
from backend.db.session import SessionLocal

ALLOWED_UPLOAD_SUFFIXES = {".pcap", ".pcapng"}
CONTENT_TYPES_BY_NAME = {
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".md": "text/markdown; charset=utf-8",
    ".pcap": "application/vnd.tcpdump.pcap",
    ".pcapng": "application/x-pcapng",
}


@dataclass(frozen=True)
class StoredArtifact:
    artifact_id: str | None
    path: Path
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


class ArtifactService:
    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._db_available = True

    def save_upload(self, upload_file: object) -> StoredArtifact:
        original_name = str(getattr(upload_file, "filename", "") or "upload.pcap")
        safe_name = self.validate_upload_filename(original_name)
        artifact_dir = self.root_dir / "uploads" / uuid.uuid4().hex
        artifact_dir.mkdir(parents=True, exist_ok=True)
        path = artifact_dir / safe_name
        file_obj = getattr(upload_file, "file")
        self._write_binary(path, file_obj)
        return self.record_file(path, artifact_type="source_pcap", content_type=self.content_type_for_name(safe_name))

    def record_file(
        self,
        path: Path | str,
        *,
        artifact_type: str,
        content_type: str | None = None,
        analysis_job_id: str | None = None,
        total_job_id: str | None = None,
    ) -> StoredArtifact:
        file_path = Path(path)
        content_type = content_type or self.content_type_for_name(file_path.name)
        size_bytes, sha256 = self.file_stats(file_path)
        artifact_id = self._upsert_artifact_row(
            file_path,
            artifact_type=artifact_type,
            content_type=content_type,
            size_bytes=size_bytes,
            sha256=sha256,
            analysis_public_id=analysis_job_id,
            total_public_id=total_job_id,
        )
        return StoredArtifact(
            artifact_id=str(artifact_id) if artifact_id is not None else None,
            path=file_path,
            filename=file_path.name,
            content_type=content_type,
            size_bytes=size_bytes,
            sha256=sha256,
        )

    def link_to_analysis_job(self, artifact_id: str | None, analysis_public_id: str) -> None:
        if not artifact_id or not self._db_available:
            return
        try:
            artifact_uuid = uuid.UUID(str(artifact_id))
        except ValueError:
            return
        try:
            with SessionLocal() as session:
                _user_id, organization_id = ensure_default_principal(session)
                analysis_job = session.scalar(
                    select(AnalysisJob).where(
                        AnalysisJob.organization_id == organization_id,
                        AnalysisJob.public_id == analysis_public_id,
                    )
                )
                artifact = session.scalar(
                    select(Artifact).where(
                        Artifact.organization_id == organization_id,
                        Artifact.id == artifact_uuid,
                    )
                )
                if analysis_job is None or artifact is None:
                    session.commit()
                    return
                artifact.analysis_job_id = analysis_job.id
                analysis_job.source_artifact_id = artifact.id
                session.commit()
        except Exception:  # noqa: BLE001
            self._db_available = False

    def soft_delete_analysis_artifacts(self, analysis_public_id: str) -> int:
        if not self._db_available:
            return 0
        try:
            with SessionLocal() as session:
                _user_id, organization_id = ensure_default_principal(session)
                analysis_job = session.scalar(
                    select(AnalysisJob).where(
                        AnalysisJob.organization_id == organization_id,
                        AnalysisJob.public_id == analysis_public_id,
                    )
                )
                if analysis_job is None:
                    session.commit()
                    return 0
                result = session.execute(
                    update(Artifact)
                    .where(
                        Artifact.organization_id == organization_id,
                        Artifact.analysis_job_id == analysis_job.id,
                        Artifact.deleted_at.is_(None),
                    )
                    .values(deleted_at=datetime.now(timezone.utc))
                )
                session.commit()
                return int(result.rowcount or 0)
        except Exception:  # noqa: BLE001
            self._db_available = False
            return 0

    def artifact_is_deleted(self, path: Path | str) -> bool:
        if not self._db_available:
            return False
        try:
            storage_path = self.storage_path(path)
            with SessionLocal() as session:
                _user_id, organization_id = ensure_default_principal(session)
                artifact = session.scalar(
                    select(Artifact).where(
                        Artifact.organization_id == organization_id,
                        Artifact.storage_path == storage_path,
                    )
                )
                session.commit()
                return bool(artifact and artifact.deleted_at is not None)
        except Exception:  # noqa: BLE001
            self._db_available = False
            return False

    def ensure_readable(self, path: Path | str) -> None:
        if self.artifact_is_deleted(path):
            raise PermissionError("Artifact has been deleted.")

    def _upsert_artifact_row(
        self,
        path: Path,
        *,
        artifact_type: str,
        content_type: str,
        size_bytes: int,
        sha256: str,
        analysis_public_id: str | None,
        total_public_id: str | None,
    ) -> uuid.UUID | None:
        if not self._db_available:
            return None
        try:
            with SessionLocal() as session:
                _user_id, organization_id = ensure_default_principal(session)
                analysis_uuid = None
                total_uuid = None
                if analysis_public_id:
                    analysis_job = session.scalar(
                        select(AnalysisJob).where(
                            AnalysisJob.organization_id == organization_id,
                            AnalysisJob.public_id == analysis_public_id,
                        )
                    )
                    analysis_uuid = analysis_job.id if analysis_job else None
                if total_public_id:
                    total_job = session.scalar(
                        select(TotalJob).where(
                            TotalJob.organization_id == organization_id,
                            TotalJob.public_id == total_public_id,
                        )
                    )
                    total_uuid = total_job.id if total_job else None

                storage_path = self.storage_path(path)
                artifact = session.scalar(
                    select(Artifact).where(
                        Artifact.organization_id == organization_id,
                        Artifact.storage_path == storage_path,
                        Artifact.artifact_type == artifact_type,
                    )
                )
                if artifact is None:
                    artifact = Artifact(
                        organization_id=organization_id,
                        analysis_job_id=analysis_uuid,
                        total_job_id=total_uuid,
                        artifact_type=artifact_type,
                        storage_path=storage_path,
                        content_type=content_type,
                        size_bytes=size_bytes,
                        sha256=sha256,
                    )
                    session.add(artifact)
                else:
                    artifact.analysis_job_id = analysis_uuid or artifact.analysis_job_id
                    artifact.total_job_id = total_uuid or artifact.total_job_id
                    artifact.content_type = content_type
                    artifact.size_bytes = size_bytes
                    artifact.sha256 = sha256
                    artifact.deleted_at = None
                session.commit()
                return artifact.id
        except Exception:  # noqa: BLE001
            self._db_available = False
            return None

    def storage_path(self, path: Path | str) -> str:
        file_path = Path(path)
        try:
            return str(file_path.resolve().relative_to(self.root_dir.parent.resolve()))
        except ValueError:
            return str(file_path.resolve())

    @staticmethod
    def validate_upload_filename(filename: str) -> str:
        candidate = filename.strip()
        if not candidate:
            raise ValueError("Upload filename cannot be empty.")
        if "/" in candidate or "\\" in candidate:
            raise ValueError("Upload filename must not contain path separators.")
        if Path(candidate).name != candidate or PureWindowsPath(candidate).name != candidate:
            raise ValueError("Upload filename must not contain path components.")
        suffix = Path(candidate).suffix.lower()
        if suffix not in ALLOWED_UPLOAD_SUFFIXES:
            raise ValueError("Upload must be a .pcap or .pcapng file.")
        return candidate

    @staticmethod
    def content_type_for_name(name: str) -> str:
        suffix = Path(name).suffix.lower()
        if suffix in CONTENT_TYPES_BY_NAME:
            return CONTENT_TYPES_BY_NAME[suffix]
        guessed, _encoding = mimetypes.guess_type(name)
        return guessed or "application/octet-stream"

    @staticmethod
    def file_stats(path: Path) -> tuple[int, str]:
        digest = hashlib.sha256()
        size_bytes = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size_bytes += len(chunk)
                digest.update(chunk)
        return size_bytes, digest.hexdigest()

    @staticmethod
    def _write_binary(path: Path, file_obj: BinaryIO) -> None:
        if hasattr(file_obj, "seek"):
            file_obj.seek(0)
        with path.open("wb") as handle:
            while True:
                chunk = file_obj.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
