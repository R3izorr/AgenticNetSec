"""create mvp tables

Revision ID: 20260604_0001
Revises:
Create Date: 2026-06-04
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "20260604_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email_lower_unique", "users", [sa.text("lower(email)")], unique=True)

    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("plan", sa.Text(), server_default="free", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )

    op.create_table(
        "organization_members",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("role in ('owner', 'analyst', 'viewer')", name="ck_organization_members_role"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_organization_members_org_user"),
    )

    op.create_table(
        "total_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("current_stage", sa.Text(), nullable=False),
        sa.Column("progress", sa.Numeric(), server_default="0", nullable=False),
        sa.Column("enrichment_status", sa.Text(), server_default="not_started", nullable=False),
        sa.Column("enrichment_progress", sa.Numeric(), server_default="0", nullable=False),
        sa.Column("analysis_profile", sa.Text(), nullable=False),
        sa.Column("worker_count", sa.Integer(), server_default="2", nullable=False),
        sa.Column("file_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status in ('queued', 'running', 'completed', 'failed', 'cancelled')", name="ck_total_jobs_status"),
        sa.CheckConstraint("progress >= 0 and progress <= 1", name="ck_total_jobs_progress"),
        sa.CheckConstraint("enrichment_progress >= 0 and enrichment_progress <= 1", name="ck_total_jobs_enrichment_progress"),
        sa.CheckConstraint(
            "enrichment_status in ('not_started', 'queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_total_jobs_enrichment_status",
        ),
        sa.CheckConstraint("worker_count >= 1", name="ck_total_jobs_worker_count"),
        sa.CheckConstraint("file_count >= 0", name="ck_total_jobs_file_count"),
        sa.CheckConstraint("status != 'completed' or completed_at is not null", name="ck_total_jobs_completed_at"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_total_jobs_org_created_at", "total_jobs", ["organization_id", sa.text("created_at desc")])
    op.create_index("ix_total_jobs_org_status", "total_jobs", ["organization_id", "status"])

    op.create_table(
        "analysis_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("total_job_id", sa.Uuid(), nullable=True),
        sa.Column("source_type", sa.Text(), nullable=False),
        sa.Column("source_name", sa.Text(), nullable=False),
        sa.Column("source_artifact_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("current_phase", sa.Text(), nullable=False),
        sa.Column("progress", sa.Numeric(), server_default="0", nullable=False),
        sa.Column("analysis_profile", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.Text(), nullable=True),
        sa.Column("attack_type", sa.Text(), nullable=True),
        sa.Column("confidence_score", sa.Numeric(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status in ('queued', 'running', 'completed', 'failed', 'cancelled')", name="ck_analysis_jobs_status"),
        sa.CheckConstraint("progress >= 0 and progress <= 1", name="ck_analysis_jobs_progress"),
        sa.CheckConstraint("status != 'completed' or completed_at is not null", name="ck_analysis_jobs_completed_at"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["total_job_id"], ["total_jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analysis_jobs_org_created_at", "analysis_jobs", ["organization_id", sa.text("created_at desc")])
    op.create_index("ix_analysis_jobs_org_status", "analysis_jobs", ["organization_id", "status"])
    op.create_index("ix_analysis_jobs_total_job_id", "analysis_jobs", ["total_job_id"])

    op.create_table(
        "artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_job_id", sa.Uuid(), nullable=True),
        sa.Column("total_job_id", sa.Uuid(), nullable=True),
        sa.Column("artifact_type", sa.Text(), nullable=False),
        sa.Column("storage_path", sa.Text(), nullable=False),
        sa.Column("content_type", sa.Text(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("size_bytes >= 0", name="ck_artifacts_size_bytes"),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["total_job_id"], ["total_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_artifacts_org_analysis_job", "artifacts", ["organization_id", "analysis_job_id"])
    op.create_index("ix_artifacts_org_total_job", "artifacts", ["organization_id", "total_job_id"])
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])

    op.create_foreign_key(
        "fk_analysis_jobs_source_artifact_id_artifacts",
        "analysis_jobs",
        "artifacts",
        ["source_artifact_id"],
        ["id"],
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_constraint("fk_analysis_jobs_source_artifact_id_artifacts", "analysis_jobs", type_="foreignkey")
    op.drop_index("ix_artifacts_sha256", table_name="artifacts")
    op.drop_index("ix_artifacts_org_total_job", table_name="artifacts")
    op.drop_index("ix_artifacts_org_analysis_job", table_name="artifacts")
    op.drop_table("artifacts")
    op.drop_index("ix_analysis_jobs_total_job_id", table_name="analysis_jobs")
    op.drop_index("ix_analysis_jobs_org_status", table_name="analysis_jobs")
    op.drop_index("ix_analysis_jobs_org_created_at", table_name="analysis_jobs")
    op.drop_table("analysis_jobs")
    op.drop_index("ix_total_jobs_org_status", table_name="total_jobs")
    op.drop_index("ix_total_jobs_org_created_at", table_name="total_jobs")
    op.drop_table("total_jobs")
    op.drop_table("organization_members")
    op.drop_table("organizations")
    op.drop_index("ix_users_email_lower_unique", table_name="users")
    op.drop_table("users")
