# Implementation Notes: Sprint 8 Tests, Compose, and Portfolio Finish

Date: 2026-06-05

Spec: `docs/codex/sprints/sprint-8-tests-compose-portfolio.md`

Branch: `codex-mvp-framework`

Implementer: Codex

## Summary

- Added Docker app services for backend, worker, frontend, migration, PostgreSQL, and Redis.
- Added backend/frontend Dockerfiles and a root `.dockerignore`.
- Added focused backend API tests for auth session behavior, upload validation, server path rejection, artifact-not-ready lifecycle states, and viewer mutation denial.
- Formalized the browser E2E fixture requirement and added a UI assertion on total-job detail.
- Updated reviewer docs with quick start, architecture diagram, demo path, tests, manual checklist, and security notes.

## Decisions

| Decision | Reason | Alternatives Considered |
| --- | --- | --- |
| Use one backend image for API, migrate, and worker. | Keeps Python dependencies and analysis tools identical across backend processes. | Separate worker image. |
| Run Alembic through a one-shot `migrate` Compose service. | Reviewers can use `docker compose up --build` without a separate migration step. | Entrypoint migration inside API container. |
| Share `app_outputs` between API and worker. | Uploads are written by API and consumed by the worker through server-generated artifact paths. | External object storage, out of MVP scope. |
| Keep E2E fixture missing as a hard failure. | Sprint 8 wants a reviewable test path, not a silent skip. | Preserve optional skip behavior. |

## Spec Changes

| Original Spec | Actual Implementation | Why |
| --- | --- | --- |
| Docker Compose for full stack. | Added full app stack plus migration service; docs use `docker compose up --build`. | First run needs image build and migrations. |
| Frontend manual checklist. | Added `docs/Manual_Test_Checklist.md` and linked it from README. | Stable doc is easier for reviewers than run notes. |

## Tradeoffs

- Backend Docker image installs `tshark`, increasing image size but matching packet-inspection expectations.
- Compose publishes PostgreSQL and Redis ports for local debugging; README marks this local-only.
- Frontend image bakes `NEXT_PUBLIC_API_BASE_URL` at build time and defaults to `http://localhost:8000` for browser access.

## Compatibility Notes

- API response shape: unchanged.
- Database/migration impact: no new migration; Compose now runs existing Alembic migrations.
- Frontend impact: E2E test fails if the default PCAP fixture is missing.
- Existing upload -> analysis -> report flow: preserved and covered by Playwright E2E.

## Security Notes

- Tenant isolation: existing organization-scoped backend reads/writes unchanged; added tests around mutation denial and not-ready artifacts.
- File upload/path handling: added API tests for unsafe filenames and disabled server `pcap_path` inputs.
- Auth/session behavior: added API tests for duplicate registration, logout, anonymous protected routes, and tampered cookies.
- Secrets/subprocess risk: README documents local-only secrets; no OAuth, Stripe, API keys, S3/MinIO, password reset, or email verification added.

## Verification

Commands run:

```bash
./.venv/bin/python -m unittest discover -s backend/tests -p 'test_*.py' -v
cd frontend && npm run lint
cd frontend && npm run build
docker compose config
docker compose up --build -d
docker compose ps
cd frontend && npm run test:e2e
docker compose up -d
git diff --check
```

Manual checks:

- `docker compose up --build -d` built and started PostgreSQL, Redis, migrate, backend, worker, and frontend.
- `docker compose ps` showed backend healthy, frontend running on `:3000`, backend on `:8000`, PostgreSQL/Redis healthy, and worker running.
- Playwright browser journey passed against Compose with a real registered account and `pcap/CredAccess/DCSync_krbtgt_dcerpc_smb.pcapng`.

Skipped checks:

- Plain follow-up `docker compose up -d` was not completed because the escalation request was rejected by the environment usage limit after `docker compose up --build -d` had already passed.

## Known Gaps

- Backend API still serializes server paths to authenticated users in raw API payloads; Sprint 7 hid paths in UI. Documented as a local MVP limitation in security notes.

## Follow-Ups

- Consider a production compose/profile later with unpublished DB/Redis ports and externally managed secrets.
