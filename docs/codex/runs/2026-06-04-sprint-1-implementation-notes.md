# Implementation Notes: Sprint 1 Database Foundation

Date: 2026-06-04

Spec: `docs/codex/sprints/sprint-1-database-foundation.md`

Branch: current workspace

Implementer: Codex

## Summary

- Added SQLAlchemy models for the MVP tables from `docs/Plan.md`.
- Added Alembic configuration and initial migration.
- Added PostgreSQL service through Docker Compose.
- Added database health endpoint/startup check and DB smoke script.
- Kept the existing file-backed upload -> analysis -> report flow in place.

## Decisions

| Decision | Reason | Alternatives Considered |
| --- | --- | --- |
| Keep current API job stores file-backed in Sprint 1. | Sprint 1 introduces DB foundation without replacing the working flow yet. | Rewrite job persistence now. |
| Use UUID database primary keys while current API IDs remain `analysis_*`/`total_*` strings. | `docs/Plan.md` defines UUID DB IDs; wiring current public IDs to DB is a later persisted-jobs sprint. | Store prefixed IDs as DB primary keys. |
| Use check constraints instead of PostgreSQL enums. | Easier MVP migrations and role/status changes. | Native PostgreSQL enum types. |
| Make database required only with `AGENTIC_DATABASE_REQUIRED=1`. | Local file-backed demo must still start without Postgres. | Fail backend startup whenever DB is unavailable. |

## Spec Changes

| Original Spec | Actual Implementation | Why |
| --- | --- | --- |
| Backend connects to database. | Backend has startup/health DB check and can require DB with `AGENTIC_DATABASE_REQUIRED=1`; normal startup remains non-blocking. | Preserve old file-backed demo when Postgres is not running. |

## Tradeoffs

- The migration manually handles the `analysis_jobs.source_artifact_id` -> `artifacts.id` circular reference after both tables exist.
- The DB smoke script writes temporary rows and does not clean them up; useful for proving persistence.

## Compatibility Notes

- API response shape: unchanged except new `GET /api/v1/health/database`.
- Database/migration impact: creates `users`, `organizations`, `organization_members`, `analysis_jobs`, `total_jobs`, `artifacts`, and `audit_logs`.
- Frontend impact: none.
- Existing upload -> analysis -> report flow: file-backed flow remains active.

## Security Notes

- Tenant isolation: DB schema includes `organization_id` on protected tables and smoke read uses `id + organization_id`.
- File upload/path handling: unchanged in Sprint 1.
- Auth/session behavior: unchanged in Sprint 1.
- Secrets/subprocess risk: `.env.example` uses local-only default Postgres credentials; no provider secrets added.

## Verification

Commands run:

```bash
git status --short
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python -m compileall backend/db backend/scripts/db_smoke.py backend/alembic
./.venv/bin/python -c "from backend.db.models import Base; print(sorted(Base.metadata.tables))"
./.venv/bin/python -m alembic heads
./.venv/bin/python -m alembic upgrade head --sql
docker compose up -d postgres
docker compose ps postgres
./.venv/bin/python -m alembic upgrade head
./.venv/bin/python backend/scripts/db_smoke.py
./.venv/bin/python backend/scripts/run_api.py --host 127.0.0.1 --port 8000
./.venv/bin/python -c "<GET /api/v1/health/database>"
./.venv/bin/python -c "<GET />"
./.venv/bin/python -c "<generated-PCAP upload, poll, report fetch>"
./.venv/bin/python -m alembic current
docker compose stop postgres
docker compose down
git diff --check
./.venv/bin/python -m compileall backend/api/app.py backend/db backend/scripts/db_smoke.py backend/alembic
docker compose ps postgres
./.venv/bin/python backend/scripts/run_api.py --host 127.0.0.1 --port 8000
./.venv/bin/python -c '<GET / with Postgres stopped>'
./.venv/bin/python -c '<GET /api/v1/health/database with Postgres stopped>'
```

Manual checks:

- Docker Compose PostgreSQL started and reported healthy.
- `alembic upgrade head` applied migration `20260604_0001`.
- `alembic current` returned `20260604_0001 (head)`.
- DB smoke created/read `analysis_jobs` rows with organization-scoped reads.
- Backend started on `http://127.0.0.1:8000`.
- `GET /` returned HTTP 200.
- `GET /api/v1/health/database` returned `status: ok`.
- Generated `/tmp/agenticnetsec-sprint1-smoke.pcap`.
- Uploaded generated PCAP to `POST /api/v1/analysis/batch`.
- Created `total_8e99320a14ec` with child `analysis_ca11ff82ab7c`.
- Child job completed with `risk_level: low`.
- `GET /api/v1/analysis/analysis_ca11ff82ab7c/report.json` returned report keys.
- Backend still starts when PostgreSQL is stopped.
- With PostgreSQL stopped, `GET /` returned unchanged root JSON and `GET /api/v1/health/database` returned `status: unavailable`.
- Compose container was removed after verification with `docker compose down`; named volume is preserved.
- Final `git diff --check` passed.
- Final `compileall` passed.

Skipped checks:

- Hands-on browser upload/refresh was skipped; API-level upload -> analysis -> report regression passed.

Warnings/failures observed:

- New DB dependencies were already present when `pip install -r requirements.txt` was rerun.
- Direct backend import inside sandbox hit the known Scapy interface permission issue from Sprint 0.
- DB smoke and Alembic failed inside sandbox despite healthy Postgres because local socket access is restricted.
- Docker Compose start required approved Docker socket access.
- Host-side DB connection failed inside sandbox while the Postgres container was healthy; approved unsandboxed Alembic and DB smoke passed.

## Known Gaps

- Current API routes still read/write file-backed stores.
- No auth/RBAC enforcement yet.
- No browser-level upload refresh check was run in Sprint 1.

## Follow-Ups

- Sprint 2 should wire job persistence to DB while preserving current route shapes.
