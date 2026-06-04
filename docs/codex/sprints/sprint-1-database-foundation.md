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

- migrations create all MVP tables
- backend connects to database
- tests can create/read job rows
- existing file-based analysis still works

## Verification

```bash
alembic upgrade head
./.venv/bin/python backend/scripts/run_api.py
```

Manual:

- run old upload flow
- confirm no current API regression

