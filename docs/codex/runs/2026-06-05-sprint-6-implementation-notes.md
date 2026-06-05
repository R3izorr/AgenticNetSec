# Implementation Notes: Sprint 6 Worker Queue

Date: 2026-06-05

Spec: `docs/codex/sprints/sprint-6-worker-queue.md`

Branch: current workspace

Implementer: Codex

## Summary

- Added Redis/RQ queue adapter and worker command.
- Single upload, batch upload, and total-job enrichment now enqueue worker jobs instead of starting in-process API background tasks.
- Persisted analysis request options on server-created job records so workers reconstruct work from trusted job metadata.
- Added worker entrypoints for analysis, total-job deterministic processing, and total-job enrichment with organization-scoped loading.
- Added focused worker queue tests and updated frontend polling for queued enrichment.

## Decisions

| Decision | Reason | Alternatives Considered |
| --- | --- | --- |
| Use RQ over Celery. | Sprint needs a small Redis-backed local worker without introducing broker/result-backend complexity. | Celery. |
| Queue IDs plus `organization_id`, not paths. | Workers must reload server-generated paths and persisted options from job records. | Put full `AnalysisRequest` payloads on Redis. |
| Keep existing DB schema. | Current analysis and total-job tables already persist status, progress, and error fields. | Add queue observability columns such as `worker_job_id` or heartbeat timestamps. |
| Fail API enqueue requests with 503 when Redis is unavailable. | New work cannot run without the Sprint 6 queue, and silent inline fallback would hide worker failures. | Fall back to `asyncio.create_task`. |

## Spec Changes

| Original Spec | Actual Implementation | Why |
| --- | --- | --- |
| Add Redis service. | Added `redis` to `compose.yaml`; API/worker use `REDIS_URL`. | Keeps local services explicit and reproducible. |
| Enqueue analysis jobs. | Single upload enqueues one analysis job; batch enqueues one total-job worker that processes child jobs sequentially. | Preserves total-job orchestration and response compatibility with less queue coordination complexity. |

## Tradeoffs

- Batch child analysis no longer uses the API process pool; the parent worker processes children in the worker process. Multiple RQ workers can still run multiple queued jobs concurrently, but one total job is currently handled by one worker at a time.
- Queue observability is in Redis/RQ and user-visible status remains in the existing job tables/manifests.

## Compatibility Notes

- API response shape: existing job and total-job response fields are preserved, including `accepted_file_count` and `skipped_files`.
- Database/migration impact: no Alembic migration required.
- Frontend impact: total-job detail polling now treats queued/running enrichment as active; enrichment buttons treat queued as in progress.
- Existing upload -> analysis -> report flow: preserved when backend, Redis, and worker are running.

## Security Notes

- Tenant isolation: enqueue payloads include organization ID and worker entrypoints load records with organization scope before mutating.
- File upload/path handling: workers reload server-created `source_path` and persisted request metadata; queue callers do not provide arbitrary artifact paths.
- Auth/session behavior: protected routes still use existing `analysis:create` and `analysis:read` permissions; no auth bypass was added.
- Secrets/subprocess risk: no OAuth, API keys, email, billing, S3/MinIO, or new subprocess execution was added.

## Verification

Commands run:

```bash
./.venv/bin/python -m compileall backend/api backend/db backend/tests
docker compose up -d postgres redis
./.venv/bin/python -m alembic upgrade head
./.venv/bin/python -m unittest discover -s backend/tests -p 'test_*.py' -v
cd frontend && npm run lint
cd frontend && npm run build
git diff --check
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python -c "import redis, rq; from backend.api.app import app; print('app and queue deps import ok')"
./.venv/bin/python backend/scripts/run_worker.py --help
```

Manual checks:

- Backend tests use real registered users and auth cookies for protected routes.
- Queue enqueue calls were patched in tests; worker lifecycle was exercised by direct worker entrypoint calls.
- RQ enqueue smoke check succeeded against local Redis and removed the temporary smoke job.

Skipped checks:

- Browser upload -> analysis -> report with a live worker processing a real PCAP was not run in this turn.

## Known Gaps

- No durable Postgres queue heartbeat/retry metadata yet.
- All-total-jobs summary still uses the existing API background task path; Sprint 6 focused on analysis and total-job enrichment.

## Follow-Ups

- Consider parallel child-job fan-out for large total jobs after queue stability is proven.
- Add operational docs for retrying failed RQ jobs if deployment moves beyond local MVP.
