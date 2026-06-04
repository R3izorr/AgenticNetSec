"""persist public job state

Revision ID: 20260604_0002
Revises: 20260604_0001
Create Date: 2026-06-04
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "20260604_0002"
down_revision: Union[str, None] = "20260604_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("total_jobs", sa.Column("public_id", sa.Text(), nullable=True))
    op.add_column("total_jobs", sa.Column("artifacts_dir", sa.Text(), nullable=True))
    op.add_column("total_jobs", sa.Column("error", sa.Text(), nullable=True))
    op.add_column("total_jobs", sa.Column("completed_children", sa.Integer(), server_default="0", nullable=False))
    op.add_column("total_jobs", sa.Column("failed_children", sa.Integer(), server_default="0", nullable=False))
    op.add_column("total_jobs", sa.Column("deterministic_complete", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.add_column("total_jobs", sa.Column("enrichment_error", sa.Text(), nullable=True))
    op.add_column(
        "total_jobs",
        sa.Column("children_json", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
    )
    op.create_unique_constraint("uq_total_jobs_public_id", "total_jobs", ["public_id"])

    op.add_column("analysis_jobs", sa.Column("public_id", sa.Text(), nullable=True))
    op.add_column("analysis_jobs", sa.Column("source_path", sa.Text(), nullable=True))
    op.add_column("analysis_jobs", sa.Column("artifacts_dir", sa.Text(), nullable=True))
    op.add_column("analysis_jobs", sa.Column("group_id", sa.Text(), nullable=True))
    op.add_column("analysis_jobs", sa.Column("group_index", sa.Integer(), nullable=True))
    op.add_column("analysis_jobs", sa.Column("group_total", sa.Integer(), nullable=True))
    op.add_column("analysis_jobs", sa.Column("guardrail_state", sa.Text(), server_default="pending", nullable=False))
    op.add_column(
        "analysis_jobs",
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    )
    op.add_column(
        "analysis_jobs",
        sa.Column(
            "artifact_ready_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text(
                """'{"report_json": false, "report_markdown": false, "metrics": false, "guardrail_audit": false}'::jsonb"""
            ),
            nullable=False,
        ),
    )
    op.add_column("analysis_jobs", sa.Column("runtime_seconds_total", sa.Numeric(), nullable=True))
    op.add_column(
        "analysis_jobs",
        sa.Column("stage1_execution_json", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    )
    op.create_unique_constraint("uq_analysis_jobs_public_id", "analysis_jobs", ["public_id"])


def downgrade() -> None:
    op.drop_constraint("uq_analysis_jobs_public_id", "analysis_jobs", type_="unique")
    op.drop_column("analysis_jobs", "stage1_execution_json")
    op.drop_column("analysis_jobs", "runtime_seconds_total")
    op.drop_column("analysis_jobs", "artifact_ready_json")
    op.drop_column("analysis_jobs", "metadata_json")
    op.drop_column("analysis_jobs", "guardrail_state")
    op.drop_column("analysis_jobs", "group_total")
    op.drop_column("analysis_jobs", "group_index")
    op.drop_column("analysis_jobs", "group_id")
    op.drop_column("analysis_jobs", "artifacts_dir")
    op.drop_column("analysis_jobs", "source_path")
    op.drop_column("analysis_jobs", "public_id")

    op.drop_constraint("uq_total_jobs_public_id", "total_jobs", type_="unique")
    op.drop_column("total_jobs", "children_json")
    op.drop_column("total_jobs", "enrichment_error")
    op.drop_column("total_jobs", "deterministic_complete")
    op.drop_column("total_jobs", "failed_children")
    op.drop_column("total_jobs", "completed_children")
    op.drop_column("total_jobs", "error")
    op.drop_column("total_jobs", "artifacts_dir")
    op.drop_column("total_jobs", "public_id")
