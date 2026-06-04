from __future__ import annotations

import argparse
from pathlib import Path
import sys
import uuid

from sqlalchemy import select

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.db.models import AnalysisJob, Organization, OrganizationMember, User
from backend.db.session import SessionLocal, check_database_connection


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create and read one Sprint 1 analysis_jobs row.")
    parser.add_argument("--email-prefix", default="sprint1-smoke", help="Email prefix for the temporary user row")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    health = check_database_connection()
    if health["status"] != "ok":
        print(f"database unavailable: {health.get('error')}")
        return 1

    suffix = uuid.uuid4().hex[:12]
    with SessionLocal() as session:
        user = User(
            email=f"{args.email_prefix}-{suffix}@example.test",
            password_hash="not-a-real-password-hash",
            display_name="Sprint 1 Smoke",
        )
        session.add(user)
        session.flush()

        organization = Organization(
            name="Sprint 1 Smoke Org",
            slug=f"sprint1-smoke-{suffix}",
            created_by_user_id=user.id,
        )
        session.add(organization)
        session.flush()

        session.add(OrganizationMember(organization_id=organization.id, user_id=user.id, role="owner"))
        job = AnalysisJob(
            organization_id=organization.id,
            created_by_user_id=user.id,
            source_type="upload",
            source_name="sprint1-smoke.pcap",
            status="queued",
            current_phase="queued",
            analysis_profile="standard",
        )
        session.add(job)
        session.commit()

        fetched_job = session.scalar(
            select(AnalysisJob).where(
                AnalysisJob.id == job.id,
                AnalysisJob.organization_id == organization.id,
            )
        )
        if fetched_job is None:
            print("analysis job read failed")
            return 1

        print(f"created analysis_job id={fetched_job.id} organization_id={fetched_job.organization_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
