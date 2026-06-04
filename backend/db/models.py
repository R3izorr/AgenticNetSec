from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, Numeric, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import Uuid


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_email_lower_unique", text("lower(email)"), unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    memberships: Mapped[list[OrganizationMember]] = relationship(back_populates="user")


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"))
    plan: Mapped[str] = mapped_column(Text, nullable=False, server_default="free")

    members: Mapped[list[OrganizationMember]] = relationship(back_populates="organization")


class OrganizationMember(Base):
    __tablename__ = "organization_members"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_organization_members_org_user"),
        CheckConstraint("role in ('owner', 'analyst', 'viewer')", name="ck_organization_members_role"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="members")
    user: Mapped[User] = relationship(back_populates="memberships")


class TotalJob(TimestampMixin, Base):
    __tablename__ = "total_jobs"
    __table_args__ = (
        CheckConstraint("status in ('queued', 'running', 'completed', 'failed', 'cancelled')", name="ck_total_jobs_status"),
        CheckConstraint("progress >= 0 and progress <= 1", name="ck_total_jobs_progress"),
        CheckConstraint("enrichment_progress >= 0 and enrichment_progress <= 1", name="ck_total_jobs_enrichment_progress"),
        CheckConstraint(
            "enrichment_status in ('not_started', 'queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_total_jobs_enrichment_status",
        ),
        CheckConstraint("worker_count >= 1", name="ck_total_jobs_worker_count"),
        CheckConstraint("file_count >= 0", name="ck_total_jobs_file_count"),
        CheckConstraint("status != 'completed' or completed_at is not null", name="ck_total_jobs_completed_at"),
        Index("ix_total_jobs_org_created_at", "organization_id", text("created_at desc")),
        Index("ix_total_jobs_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(Text, nullable=False)
    current_stage: Mapped[str] = mapped_column(Text, nullable=False)
    progress: Mapped[Decimal] = mapped_column(Numeric, nullable=False, server_default="0")
    enrichment_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="not_started")
    enrichment_progress: Mapped[Decimal] = mapped_column(Numeric, nullable=False, server_default="0")
    analysis_profile: Mapped[str] = mapped_column(Text, nullable=False)
    worker_count: Mapped[int] = mapped_column(nullable=False, server_default="2")
    file_count: Mapped[int] = mapped_column(nullable=False, server_default="0")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AnalysisJob(TimestampMixin, Base):
    __tablename__ = "analysis_jobs"
    __table_args__ = (
        CheckConstraint("status in ('queued', 'running', 'completed', 'failed', 'cancelled')", name="ck_analysis_jobs_status"),
        CheckConstraint("progress >= 0 and progress <= 1", name="ck_analysis_jobs_progress"),
        CheckConstraint("status != 'completed' or completed_at is not null", name="ck_analysis_jobs_completed_at"),
        Index("ix_analysis_jobs_org_created_at", "organization_id", text("created_at desc")),
        Index("ix_analysis_jobs_org_status", "organization_id", "status"),
        Index("ix_analysis_jobs_total_job_id", "total_job_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"))
    total_job_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("total_jobs.id", ondelete="SET NULL"),
    )
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    source_name: Mapped[str] = mapped_column(Text, nullable=False)
    source_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("artifacts.id", name="fk_analysis_jobs_source_artifact_id_artifacts", use_alter=True),
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)
    current_phase: Mapped[str] = mapped_column(Text, nullable=False)
    progress: Mapped[Decimal] = mapped_column(Numeric, nullable=False, server_default="0")
    analysis_profile: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str | None] = mapped_column(Text)
    attack_type: Mapped[str | None] = mapped_column(Text)
    confidence_score: Mapped[Decimal | None] = mapped_column(Numeric)
    error: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        CheckConstraint("size_bytes >= 0", name="ck_artifacts_size_bytes"),
        Index("ix_artifacts_org_analysis_job", "organization_id", "analysis_job_id"),
        Index("ix_artifacts_org_total_job", "organization_id", "total_job_id"),
        Index("ix_artifacts_sha256", "sha256"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    analysis_job_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
    )
    total_job_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("total_jobs.id", ondelete="CASCADE"))
    artifact_type: Mapped[str] = mapped_column(Text, nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str] = mapped_column(Text, nullable=False)
    target_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
