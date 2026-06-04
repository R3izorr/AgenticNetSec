# Implementation Notes: Sprint 4 Simple Auth

Date: 2026-06-04

Spec: `docs/codex/sprints/sprint-4-simple-auth.md`

Branch: current workspace

Implementer: Codex

## Summary

- Added MVP email/password auth endpoints under `/api/v1/auth`.
- Added HttpOnly cookie session tokens and frontend session state.
- Added login/register pages and client-side protected app routing.
- Threaded authenticated `user_id` and `organization_id` through job, total-job, and artifact persistence paths.

## Decisions

| Decision | Reason | Alternatives Considered |
| --- | --- | --- |
| Use bcrypt-compatible password hashes, with the declared `bcrypt` package and a local `crypt.METHOD_BLOWFISH` fallback. | Sprint requires bcrypt or Argon2id; current venv lacks bcrypt, but target dependencies now declare it. | Add Argon2id only; add passlib. |
| Use stdlib HMAC-SHA256 JWT-style cookies. | Avoids adding a JWT dependency while preserving signed expiry claims. | Add PyJWT/python-jose. |
| Protect existing analysis and total-job API routes in Sprint 4. | Logout/protected-route verification requires anonymous access to be blocked; store scoping was added to prevent cross-tenant leakage. | Leave API unprotected until Sprint 5 and protect only frontend routes. |
| Keep `ensure_default_principal` only as a legacy fallback for pre-auth filesystem recovery. | Existing demo artifacts can still load, but authenticated writes use the current org. | Remove demo principal entirely. |

## Spec Changes

| Original Spec | Actual Implementation | Why |
| --- | --- | --- |
| JWT/session in HttpOnly cookie. | HMAC-signed JWT-style token in an HttpOnly cookie. | Keeps dependency surface small; still includes `sub`, `org_id`, `iat`, `exp`, and `jti`. |

## Tradeoffs

- Auth secret has a local-dev fallback so the app can boot from a fresh checkout; `.env.example` documents `AGENTIC_AUTH_SECRET`.
- All-jobs summary status files remain filesystem-backed, but record loading is organization-scoped.

## Compatibility Notes

- API response shape: existing successful analysis/total-job/report payloads are unchanged; anonymous calls now return 401.
- Database/migration impact: no schema migration; existing Sprint 1 users/orgs/members tables are used.
- Frontend impact: auth provider wraps the existing shell; all API fetches include credentials.
- Existing upload -> analysis -> report flow: must now be run after register/login.

## Security Notes

- Tenant isolation: protected job, total-job, and artifact reads/writes pass authenticated `organization_id`.
- File upload/path handling: unchanged Sprint 3 upload validation remains in place.
- Auth/session behavior: passwords are bcrypt-compatible; session cookie is HttpOnly, SameSite=Lax by default, and finite-lived.
- Secrets/subprocess risk: no OAuth, reset email, API key, billing, S3/MinIO, or subprocess changes added.

## Verification

Commands run:

```bash
sed -n '1,220p' AGENTS.md
sed -n '1,1040p' docs/Plan.md
sed -n '1,260p' docs/codex/README.md
sed -n '1,320p' docs/codex/HARNESS.md
sed -n '1,260p' docs/codex/IMPLEMENTATION_NOTES.md
sed -n '1,320p' docs/codex/runs/2026-06-04-sprint-3-implementation-notes.md
sed -n '1,320p' docs/codex/sprints/sprint-4-simple-auth.md
sed -n '1,340p' docs/codex/prompts/new-chat-bootstrap.md
sed -n '1,360p' docs/codex/prompts/run-sprint.md
git status --short
./.venv/bin/python -m compileall backend/api backend/db backend/alembic
./.venv/bin/python -c "from backend.api.app import app; print('app import ok')"
docker compose up -d postgres
./.venv/bin/python -m alembic upgrade head
./.venv/bin/python -m alembic current
./.venv/bin/python backend/scripts/run_api.py --host 127.0.0.1 --port 8000
./.venv/bin/python - <<'PY'  # auth API smoke: anonymous 401, register, me, logout, login
PY
./.venv/bin/python - <<'PY'  # verify user/org/member rows and non-plaintext password hash
PY
./.venv/bin/python - <<'PY'  # disabled user login returns 401
PY
./.venv/bin/python - <<'PY'  # authenticated upload -> analysis -> report JSON/Markdown
PY
cd frontend && npm run lint
cd frontend && npm run build
./.venv/bin/python -m unittest discover -s backend/tests -p 'test_*.py' -v
kill <api_pid>
```

Manual checks:

- Anonymous `GET /api/v1/analysis` returned 401.
- Register returned 201, set an HttpOnly cookie, normalized email to lowercase, and `/auth/me` returned owner org membership.
- Logout returned 204, cleared the cookie, and `/auth/me` returned 401 afterward.
- Login returned 200, set an HttpOnly cookie, and `/auth/me` returned 200 afterward.
- DB inspection confirmed user, default organization, owner membership, and non-plaintext password hash.
- Disabled user login returned 401.
- Authenticated upload smoke created `analysis_33f62c198374`, completed, and returned report JSON/Markdown with HTTP 200.

Skipped checks:

- Browser-level register -> dashboard -> logout redirect -> login was not run; API auth flow and frontend lint/build passed.
- No full cross-tenant browser test was run; store methods now filter by authenticated `organization_id`.

Warnings/failures observed:

- Initial FastAPI import failed in the sandbox because Scapy probes network interfaces; import passed outside sandbox.
- Initial Docker/Alembic/localhost checks failed in the sandbox; they passed outside sandbox against local Docker Postgres.
- First logout smoke exposed an unset-status `Response` return; logout was fixed and final smoke passed.
- First frontend build failed because `next/font/google` tried to fetch Geist with network disabled; layout now uses a local system font variable and build passes.
- Frontend lint still reports one warning in `frontend/app/analysis/history/data-table.tsx` for TanStack Table and React Compiler compatibility; no lint errors.

## Known Gaps

- No automated pytest suite existed before Sprint 4; verification uses compile/import/API smoke and frontend lint/build.
- CSRF token protection is not added; MVP relies on explicit CORS origins and SameSite=Lax local cookie behavior.

## Follow-Ups

- Sprint 5 should add RBAC permissions and cross-user negative tests around guessed job/report IDs.
- Consider per-organization all-summary artifact directories if all-summary becomes multi-tenant critical.
