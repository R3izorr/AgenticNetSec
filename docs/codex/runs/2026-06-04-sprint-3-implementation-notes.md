# Implementation Notes: Sprint 3 Artifact Service

Date: 2026-06-04

Spec: `docs/codex/sprints/sprint-3-artifact-service.md`

Branch: current workspace

Implementer: Codex

## Summary

- Added a local artifact service for server-owned upload paths, artifact metadata, upload validation, and soft-delete checks.
- Stored artifact rows for uploaded PCAPs and generated analysis/total-job artifacts using existing `artifacts` table columns.
- Preserved existing API response shapes for upload, status, history, report, and total-job routes.
- Added `DELETE /api/v1/analysis/{job_id}` as a soft-delete path for analysis artifacts without deleting local files.

## Decisions

| Decision | Reason | Alternatives Considered |
| --- | --- | --- |
| Reuse existing `artifacts` table without a Sprint 3 migration. | Sprint 1 schema already has `storage_path`, `content_type`, `size_bytes`, `sha256`, job FKs, and `deleted_at`. | Add a uniqueness migration for `(organization_id, storage_path, artifact_type)`. |
| Save uploads under `outputs/artifacts/uploads/<uuid>/<filename>`. | Ensures path ownership is server-generated while retaining the original safe basename for display. | Continue timestamped `outputs/uploads` paths. |
| Reject path-component filenames instead of normalizing traversal. | Sprint requires user-supplied paths are never trusted; rejection is clearer than silent basename stripping. | Silently use `Path(filename).name`. |
| Keep report endpoints unchanged and enforce soft delete inside store read methods. | Preserves frontend response shape while blocking deleted artifacts. | Add new artifact download routes and migrate frontend. |

## Spec Changes

| Original Spec | Actual Implementation | Why |
| --- | --- | --- |
| Add soft-delete behavior. | Added analysis artifact soft-delete via `DELETE /api/v1/analysis/{job_id}` and read blocking through `ensure_readable`. | No delete endpoint existed before Sprint 3; adding one is the smallest externally verifiable behavior. |

## Tradeoffs

- Direct `pcap_path` analysis remains separate from uploaded PCAP artifact ownership; Sprint 3 hardens uploaded files only.
- Artifact service falls back to local file behavior if DB writes fail, matching Sprint 2’s demo-preserving approach.
- All-scans summary helper artifacts still use direct file writes because they are not tied to a single job row; analysis and total-job artifacts are covered.

## Compatibility Notes

- API response shape: unchanged for existing upload/status/history/report endpoints. New delete endpoint is additive.
- Database/migration impact: no new migration; `artifacts` rows are now populated for uploads and generated reports.
- Frontend impact: no frontend files changed. Existing report JSON/Markdown endpoints still return the same shapes.
- Existing upload -> analysis -> report flow: verified through API smoke after implementation.

## Security Notes

- Tenant isolation: artifact DB reads/writes use the local default `organization_id` and job lookups filter by organization.
- File upload/path handling: uploads accept only `.pcap`/`.pcapng`; empty names, path separators, Windows path parts, traversal-style names, and other extensions are rejected with HTTP 400.
- Auth/session behavior: unchanged; no auth/RBAC added in Sprint 3.
- Secrets/subprocess risk: no new secrets, external object stores, or provider integrations added.

## Verification

Commands run:

```bash
sed -n '1,220p' AGENTS.md
sed -n '1,260p' docs/Plan.md
sed -n '1,260p' docs/codex/README.md
sed -n '1,260p' docs/codex/HARNESS.md
sed -n '1,260p' docs/codex/IMPLEMENTATION_NOTES.md
sed -n '1,260p' docs/codex/runs/2026-06-04-sprint-0-implementation-notes.md
sed -n '1,300p' docs/codex/runs/2026-06-04-sprint-1-implementation-notes.md
sed -n '1,360p' docs/codex/runs/2026-06-04-sprint-2-implementation-notes.md
sed -n '1,320p' docs/codex/sprints/sprint-3-artifact-service.md
sed -n '1,280p' docs/codex/prompts/new-chat-bootstrap.md
sed -n '1,260p' docs/codex/prompts/goal-driven-double-agent.md
git status --short
./.venv/bin/python -m compileall backend/api backend/db backend/alembic
./.venv/bin/python -c "from backend.api.artifact_service import ArtifactService; from backend.api.job_store import JobStore; from backend.api.total_job_store import TotalJobStore; print('imports ok')"
./.venv/bin/python -m alembic heads
docker compose up -d postgres
./.venv/bin/python -m alembic upgrade head --sql
docker compose ps postgres
./.venv/bin/python -m alembic upgrade head
./.venv/bin/python -m alembic current
./.venv/bin/python backend/scripts/run_api.py --host 127.0.0.1 --port 8000
./.venv/bin/python - <<'PY'  # direct upload filename validation
PY
./.venv/bin/python - <<'PY'  # upload -> analysis -> report + artifact DB row assertions
PY
./.venv/bin/python - <<'PY'  # invalid filename/extension API checks
PY
./.venv/bin/python - <<'PY'  # soft-delete and blocked report access check
PY
./.venv/bin/python - <<'PY'  # batch upload smoke, initially exposed bug
PY
./.venv/bin/python -m compileall backend/api backend/db
./.venv/bin/python -c "from backend.api.app import app; print('app import ok')"
kill <api_pid>
./.venv/bin/python backend/scripts/run_api.py --host 127.0.0.1 --port 8000
./.venv/bin/python - <<'PY'  # final single upload/report/artifact DB row smoke
PY
./.venv/bin/python - <<'PY'  # final batch upload smoke
PY
./.venv/bin/python - <<'PY'  # final invalid filename/extension API checks
PY
./.venv/bin/python - <<'PY'  # final soft-delete check
PY
kill <api_pid>
```

Manual checks:

- Direct validator accepted `sample.pcap` and `sample.pcapng`.
- Direct validator rejected `evil.txt`, `../evil.pcap`, `..\evil.pcap`, and `nested/evil.pcap`.
- Final single upload created `analysis_09a6a7dbd6b1`, completed successfully, and report JSON/Markdown loaded with existing response shapes.
- Final single upload produced 6 artifact rows, including 1 `source_pcap` row and report rows; every checked row had nonzero `size_bytes`, 64-char `sha256`, and `content_type`.
- API rejected `../evil.pcap`, `..\evil.pcap`, and `evil.txt` with HTTP 400.
- Final batch upload created `total_75ee15797def`, completed successfully, and child `analysis_9206b2b35091` had artifact rows including `source_pcap`.
- Soft delete on `analysis_09a6a7dbd6b1` marked 6 artifact rows deleted and blocked report access with HTTP 409.

Skipped checks:

- Browser-level frontend report load was not run; API report JSON/Markdown endpoints returned the same shapes used by the frontend.
- Frontend lint/build was not run because no frontend files changed.

Warnings/failures observed:

- Generated PCAP creation emitted Scapy MAC lookup warnings in this environment; Scapy used broadcast and the smoke tests completed.
- First batch smoke failed with `name 'source_artifact_id' is not defined` due to a misplaced scripted insertion inside the process-pool worker. The line was removed, compile/import checks passed, API was restarted, and final batch smoke passed.

## Known Gaps

- No automated test harness exists yet for artifact service validation and DB row assertions.
- All-scans summary artifacts are still file-only because they are not linked to one analysis or total-job row.

## Follow-Ups

- Add focused tests for `ArtifactService.validate_upload_filename`, `save_upload`, report artifact row creation, and soft-delete read blocking.
- Consider a later uniqueness migration on `(organization_id, storage_path, artifact_type)` if duplicate artifact rows become a practical issue.
