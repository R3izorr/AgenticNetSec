# Implementation Notes: Sprint 2 Persisted Job State

Date: 2026-06-04

Spec: `docs/codex/sprints/sprint-2-persisted-jobs.md`

Branch: current workspace

Implementer: Codex

## Summary

- Added Sprint 2 migration fields for public job IDs and API-facing job metadata.
- Made `JobStore` and `TotalJobStore` database-backed while preserving their dataclass contracts and local artifact files.
- Kept manifest writes as a compatibility/cache path and fallback when the DB is unavailable.
- Verified single upload -> analysis -> report and batch total-job state survive backend restart.

## Decisions

| Decision | Reason | Alternatives Considered |
| --- | --- | --- |
| Add nullable `public_id` columns to `analysis_jobs` and `total_jobs`. | Public API IDs are `analysis_*`/`total_*`, while Sprint 1 DB primary keys are UUIDs. | Expose UUIDs to frontend; store prefixed strings as primary keys. |
| Keep `JobRecord` and `TotalJobRecord` as the route-facing contract. | Preserves response shape and minimizes route churn. | Rewrite route serializers around SQLAlchemy models. |
| Use a local default user/org for unauthenticated MVP persistence. | `organization_id` is non-null and all protected job DB queries must be org-scoped, while auth is out of scope for Sprint 2. | Make org nullable; add auth early. |
| Continue writing `job.json` and `total_job.json`. | Keeps local artifact compatibility and allows fallback startup when DB is unavailable. | Remove manifests entirely. |

## Spec Changes

| Original Spec | Actual Implementation | Why |
| --- | --- | --- |
| Move job and total-job metadata into the database. | Metadata is persisted to DB and also mirrored to local manifests. | Preserve existing local artifact/report flow and no-DB demo fallback. |

## Tradeoffs

- The store disables DB writes for the current process after a DB exception, then continues with local manifests. A backend restart reattempts DB persistence.
- Total-job child refs are persisted as JSON to preserve the exact current response shape without introducing an extra child-link table in Sprint 2.
- Test smoke rows created through API remain in local Postgres and normal `outputs/` artifacts; one temporary direct-store smoke row was removed because its artifact directory was under `/tmp`.

## Compatibility Notes

- API response shape: unchanged for `GET /api/v1/analysis`, `GET /api/v1/analysis/{id}`, `GET /api/v1/total-jobs`, and `GET /api/v1/total-jobs/{id}`.
- Database/migration impact: adds public IDs, artifact paths, progress metadata, child JSON, and API-facing metadata columns to `analysis_jobs`/`total_jobs`.
- Frontend impact: none expected; existing snake_case transport fields are preserved.
- Existing upload -> analysis -> report flow: verified through local API before and after backend restart.

## Security Notes

- Tenant isolation: DB reads/writes for jobs filter by the local default `organization_id`.
- File upload/path handling: artifact lookup still uses server-generated `artifacts_dir`; no client-supplied artifact paths added.
- Auth/session behavior: unchanged; no auth/RBAC added in Sprint 2.
- Secrets/subprocess risk: no new provider secrets or subprocess behavior added.

## Verification

Commands run:

```bash
sed -n '1,220p' AGENTS.md
sed -n '1,260p' docs/Plan.md
sed -n '1,260p' docs/codex/README.md
sed -n '1,260p' docs/codex/HARNESS.md
sed -n '1,260p' docs/codex/IMPLEMENTATION_NOTES.md
sed -n '1,280p' docs/codex/runs/2026-06-04-sprint-1-implementation-notes.md
sed -n '1,320p' docs/codex/sprints/sprint-2-persisted-jobs.md
sed -n '1,280p' docs/codex/prompts/new-chat-bootstrap.md
sed -n '1,260p' docs/codex/prompts/goal-driven-double-agent.md
git status --short
python -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python -m compileall backend/api backend/db backend/alembic
./.venv/bin/python -c "from backend.api.job_store import JobStore; from backend.api.total_job_store import TotalJobStore; from backend.db.models import AnalysisJob, TotalJob; print('imports ok')"
./.venv/bin/python -m alembic heads
docker compose ps postgres
./.venv/bin/python -m alembic upgrade head --sql
docker compose up -d postgres
./.venv/bin/python -m alembic upgrade head
./.venv/bin/python - <<'PY'  # direct store DB persistence smoke
PY
./.venv/bin/python backend/scripts/run_api.py --host 127.0.0.1 --port 8000
./.venv/bin/python - <<'PY'  # single upload, poll, report fetch
PY
./.venv/bin/python - <<'PY'  # batch upload, poll total job
PY
kill <api_pid>
./.venv/bin/python backend/scripts/run_api.py --host 127.0.0.1 --port 8000
./.venv/bin/python - <<'PY'  # restarted API persisted analysis/total-job checks
PY
kill <api_pid>
./.venv/bin/python -m alembic current
git diff --check
./.venv/bin/python - <<'PY'  # remove temporary direct-store smoke rows
PY
```

Manual checks:

- Docker Compose PostgreSQL started and reported healthy.
- Alembic current returned `20260604_0002 (head)`.
- Direct store smoke persisted and reloaded `analysis_4e4e8a8c3a0b` under `total_762bffa1eb17`; temporary DB rows were removed after verification.
- Uploaded generated PCAP to `POST /api/v1/analysis`; created `analysis_808d865d400f`; job completed and report JSON was available.
- Uploaded generated PCAP to `POST /api/v1/analysis/batch`; created `total_594b4b79dfae`; total job completed with one child.
- Restarted backend and confirmed `analysis_808d865d400f` remained `completed`, report JSON still loaded, `total_594b4b79dfae` remained `completed`, and total-job children reloaded.

Skipped checks:

- Browser-level frontend reload was not run; API-level history/detail/report restart checks passed.
- Frontend lint/build was not run because no frontend files changed.

Warnings/failures observed:

- Initial sandboxed read/edit attempts failed with `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`; approved unsandboxed commands were used.
- The patch helper failed with the same sandbox error, so scoped scripted edits were used and verified by diff/compile.
- The documented `.venv` did not exist initially; it was created and dependencies were installed.
- Generated PCAP creation emitted Scapy MAC lookup warnings in this environment; Scapy used broadcast and the API smoke still completed.

## Known Gaps

- Persistence is still synchronous inside the in-process stores; no Redis/background worker migration yet.
- The local default organization is an MVP bridge until auth/RBAC sprints assign real organization context.

## Follow-Ups

- Add focused automated tests once a backend test harness is introduced.
- Later auth/RBAC sprint should replace the local default principal with request-derived user/org context.
