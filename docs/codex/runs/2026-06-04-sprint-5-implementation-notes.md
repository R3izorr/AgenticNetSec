# Implementation Notes: Sprint 5 RBAC and Tenant Isolation

Date: 2026-06-04

Spec: `docs/codex/sprints/sprint-5-rbac-tenant-isolation.md`

Branch: current workspace

Implementer: Codex

## Summary

- Added role-to-permission enforcement for analysis creation, analysis/report reads, enrichment/delete writes, and member management.
- Added an owner-only organization member role update endpoint with audit logging and last-owner protection.
- Hardened tenant isolation for all-total-jobs summary artifacts by moving status/artifact files under organization-specific directories.
- Threaded `organization_id` through total-job enrichment helper paths and total-job JSONL artifact metadata writes.
- Added role-aware frontend behavior so viewers cannot access upload/create/enrichment controls.
- Added focused backend RBAC and cross-tenant negative tests using real registered users and auth cookies.

## Decisions

| Decision | Reason | Alternatives Considered |
| --- | --- | --- |
| Keep RBAC mapping in `backend/api/auth.py`. | Roles are currently session-derived there, and Sprint 5 only needs MVP permissions. | Add a separate policy service/module. |
| Use `PATCH /api/v1/organization/members/{member_id}/role` for minimal role updates. | Keeps member management scoped and explicit without adding a full admin/member listing UI. | Put the route under `/auth`; build a full members API. |
| Treat enrichment and delete actions as `analysis:create`. | Viewer is read-only in the MVP permission model; these actions mutate job/artifact state. | Add new `analysis:write` permission. |
| Store all-total-jobs summary files under `outputs/total_jobs/__all_jobs_summary/<organization_id>/`. | The previous single shared directory could leak one organization’s generated summary to another. | Persist these artifacts only through DB artifact rows; remove all-scans summary. |
| Gate server-side `pcap_path` creation behind `AGENTIC_ALLOW_SERVER_PCAP_PATHS`. | Sprint rules require server-generated artifact paths and the frontend upload flow does not need raw server paths. | Remove `pcap_path` support entirely; leave path support always enabled for legacy scripts. |

## Spec Changes

| Original Spec | Actual Implementation | Why |
| --- | --- | --- |
| Add minimal owner role update path. | Added owner-only PATCH endpoint by membership ID; no frontend member-management form. | There is no member listing/invite surface in Sprint 5, and tests can target the endpoint directly. |
| Preserve API compatibility unless sprint requires otherwise. | Upload API response shape is unchanged; server-side `pcap_path` inputs now require `AGENTIC_ALLOW_SERVER_PCAP_PATHS=1`. | This is a security hardening change needed to satisfy server-generated artifact path rules. |

## Tradeoffs

- Store methods still allow unscoped reads for internal/background compatibility, but protected routes and risky helpers now pass `organization_id`.
- The role update endpoint does not create or invite members; it only changes an existing membership role.
- Frontend hides/disables viewer write actions, but backend RBAC remains the source of truth.

## Compatibility Notes

- API response shape: successful job, total-job, report, and auth payload shapes are preserved; unauthorized role attempts now return 403.
- Database/migration impact: no migration required; existing `organization_members.role` constraint and `audit_logs` are used.
- Frontend impact: viewers no longer see New Analysis navigation/CTAs and cannot use enrichment controls from the UI.
- Existing upload -> analysis -> report flow: preserved for owner/analyst users using file upload.

## Security Notes

- Tenant isolation: protected reads and writes are permission-gated and organization-scoped; all-total-jobs summary artifacts are now organization-specific.
- File upload/path handling: file uploads remain server-generated artifacts; raw server `pcap_path` inputs are disabled unless explicitly enabled for local/dev use.
- Auth/session behavior: `get_current_principal` still reloads membership role on every request, so role changes take effect without issuing a new cookie.
- Secrets/subprocess risk: no OAuth, API keys, email, billing, S3/MinIO, or subprocess behavior was added.

## Verification

Commands run:

```bash
./.venv/bin/python -m compileall backend/api backend/db
./.venv/bin/python -m compileall backend/api backend/db backend/tests
./.venv/bin/python -B -c "from backend.api.app import app; print('app import ok')"
./.venv/bin/python -m unittest discover -s backend/tests -p 'test_*.py' -v
cd frontend && npm run lint
cd frontend && npm run build
git diff --check
cd frontend && npm run lint
cd frontend && npm run build
```

Manual checks:

- Backend tests registered real local users through `/api/v1/auth/register`, used their auth cookies, then changed roles through real DB membership rows.
- Verified viewer upload attempts return 403 and analyst batch upload succeeds without bypassing auth.
- Verified cross-tenant job, report, total-job, and all-total-jobs summary access does not leak another organization’s records/artifacts.

Skipped checks:

- Browser-level viewer/analyst manual login was not run; frontend lint/build and backend API tests passed.
- Full upload -> analysis -> report browser run was not repeated in this sprint; owner/analyst upload API shape remains covered by tests and frontend build.

## Known Gaps

- No member listing or invite endpoint/UI exists yet, so owners need a known membership ID to call the role update path.
- Store-level methods still support internal unscoped access for legacy/background flows; further hardening could split protected repositories from internal worker helpers.
- `AGENTIC_ALLOW_SERVER_PCAP_PATHS=1` is available for legacy local scripts, but should remain off for normal MVP protected usage.

## Follow-Ups

- Add a small owner settings member-management UI after member listing/invite requirements are defined.
- Consider database-level composite constraints to enforce same-organization relationships between jobs, total jobs, and artifacts.
- Add browser manual checks for viewer read-only UI and analyst upload flow in Sprint 7 polish.
