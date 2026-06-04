# Sprint 1: Database Foundation

## Goal

Introduce PostgreSQL without replacing the working file-based flow yet.

## Subagents

- `database-engineer`
- `backend-developer`
- `test-engineer`
- `security-reviewer`

## Develop

- add SQLAlchemy setup
- add Alembic migrations
- create MVP tables from `docs/Plan.md`
- add PostgreSQL service to Docker Compose
- add migration docs/command
- add database health/startup check

## Done

- [x] migrations create all MVP tables
- [x] backend connects to database
- [x] test/script can create/read job rows
- [x] existing file-based analysis still works

Notes:

- DB verification used Docker Compose PostgreSQL plus `backend/scripts/db_smoke.py`.
- The current upload -> analysis -> report flow remains file-backed; Sprint 1 only adds the database foundation.

## Verification

```bash
alembic upgrade head
./.venv/bin/python backend/scripts/run_api.py
```

Manual:

- run old upload flow
- confirm no current API regression
