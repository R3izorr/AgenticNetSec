# AgenticNetSec Internship MVP Plan

## Goal

Build AgenticNetSec into an internship-grade full-stack security product without losing the current working demo.

The project should prove:

- real database design
- authentication
- authorization
- persistent job state
- background processing
- secure file handling
- clear frontend workflows
- testable software engineering

This is not a full SaaS launch plan. Commercial features are treated as future-ready design, not first-build scope.

## Product Summary

AgenticNetSec is a network forensic web app.

Users upload PCAP files, run automated analysis, track jobs, and review structured reports. The existing forensic engine remains the core differentiator. The MVP adds the missing software engineering layer around it.

## MVP Boundary

Build only what is needed for a credible internship portfolio.

In scope:

- PostgreSQL database
- SQLAlchemy models
- Alembic migrations
- local artifact storage abstraction
- email/password auth
- HttpOnly cookie JWT/session
- default organization per user
- simple RBAC
- Redis-backed worker queue
- protected frontend app
- job dashboard/history/report views
- Docker Compose
- focused tests
- updated README/demo docs

Out of scope for MVP:

- OAuth 2.0
- Stripe
- real billing
- API keys
- password reset
- email verification
- S3/MinIO
- full admin portal
- public SaaS deployment

These stay as stretch goals.

## Non-Negotiable Rule

Do not break the current upload -> analysis -> report flow.

Every milestone must preserve this path:

1. user uploads PCAP
2. backend creates job
3. worker runs analysis
4. progress is visible
5. report artifacts are available
6. job state survives backend restart

## Target Architecture

```text
Next.js frontend
  |
  | authenticated API requests
  v
FastAPI backend
  |
  | SQLAlchemy
  v
PostgreSQL
  |
  | enqueue long work
  v
Redis Queue worker
  |
  | local artifact service
  v
outputs/<org_id>/<job_id>/
  |
  | existing engine
  v
Scapy / tshark / AI fallback reports
```

## Current Reference Code

Keep these pieces:

- `backend/src/analysis_engine.py`
- `backend/src/detectors.py`
- `backend/src/planner.py`
- `backend/src/report_ai.py`
- `backend/src/payload_carver.py`
- `backend/src/sandbox_verifier.py`
- `frontend/app/analysis/*`
- `frontend/app/total-jobs/*`
- `frontend/lib/api/analysis.ts`

Refactor these later:

- `backend/api/app.py`
- `backend/api/job_store.py`
- `backend/api/total_job_store.py`

## MVP Data Model

Use PostgreSQL.

Recommended libraries:

- SQLAlchemy 2.x
- Alembic
- asyncpg or psycopg

### users

Fields:

- `id uuid primary key`
- `email text unique not null`
- `password_hash text not null`
- `display_name text`
- `created_at timestamptz not null`
- `updated_at timestamptz not null`
- `disabled_at timestamptz null`

Indexes:

- unique lower email

Rules:

- email normalized to lowercase
- disabled users cannot log in

### organizations

Fields:

- `id uuid primary key`
- `name text not null`
- `slug text unique not null`
- `created_by_user_id uuid references users(id)`
- `plan text not null default 'free'`
- `created_at timestamptz not null`
- `updated_at timestamptz not null`

Rules:

- each registered user gets one default organization
- `plan` is billing-ready only, no Stripe in MVP

### organization_members

Fields:

- `id uuid primary key`
- `organization_id uuid references organizations(id) on delete cascade`
- `user_id uuid references users(id) on delete cascade`
- `role text not null`
- `created_at timestamptz not null`

Constraints:

- unique `(organization_id, user_id)`
- role enum/check: `owner`, `analyst`, `viewer`

Permissions:

- owner: manage members, create/read jobs
- analyst: create/read jobs
- viewer: read jobs/reports only

### analysis_jobs

Fields:

- `id uuid primary key`
- `organization_id uuid references organizations(id) on delete cascade`
- `created_by_user_id uuid references users(id)`
- `total_job_id uuid null references total_jobs(id) on delete set null`
- `source_type text not null`
- `source_name text not null`
- `source_artifact_id uuid null references artifacts(id)`
- `status text not null`
- `current_phase text not null`
- `progress numeric not null default 0`
- `analysis_profile text not null`
- `risk_level text null`
- `attack_type text null`
- `confidence_score numeric null`
- `error text null`
- `created_at timestamptz not null`
- `updated_at timestamptz not null`
- `completed_at timestamptz null`

Indexes:

- `(organization_id, created_at desc)`
- `(organization_id, status)`
- `(total_job_id)`

Status enum/check:

- `queued`
- `running`
- `completed`
- `failed`
- `cancelled`

Rules:

- all queries must filter by `organization_id`
- job progress must be between `0` and `1`
- completed jobs must have `completed_at`

### total_jobs

Fields:

- `id uuid primary key`
- `organization_id uuid references organizations(id) on delete cascade`
- `created_by_user_id uuid references users(id)`
- `status text not null`
- `current_stage text not null`
- `progress numeric not null default 0`
- `enrichment_status text not null default 'not_started'`
- `enrichment_progress numeric not null default 0`
- `analysis_profile text not null`
- `worker_count integer not null default 2`
- `file_count integer not null default 0`
- `created_at timestamptz not null`
- `updated_at timestamptz not null`
- `completed_at timestamptz null`

Indexes:

- `(organization_id, created_at desc)`
- `(organization_id, status)`

### artifacts

Fields:

- `id uuid primary key`
- `organization_id uuid references organizations(id) on delete cascade`
- `analysis_job_id uuid null references analysis_jobs(id) on delete cascade`
- `total_job_id uuid null references total_jobs(id) on delete cascade`
- `artifact_type text not null`
- `storage_path text not null`
- `content_type text not null`
- `size_bytes bigint not null`
- `sha256 text not null`
- `created_at timestamptz not null`
- `deleted_at timestamptz null`

Indexes:

- `(organization_id, analysis_job_id)`
- `(organization_id, total_job_id)`
- `(sha256)`

Rules:

- storage path generated by server only
- path format: `outputs/<organization_id>/<job_id>/<artifact_name>`
- soft-delete first, physical cleanup later
- never use user-supplied path directly

### audit_logs

Fields:

- `id uuid primary key`
- `organization_id uuid references organizations(id) on delete cascade`
- `user_id uuid references users(id)`
- `action text not null`
- `target_type text not null`
- `target_id uuid null`
- `metadata_json jsonb not null default '{}'`
- `created_at timestamptz not null`

MVP audit actions:

- user registered
- user logged in
- job created
- report viewed
- artifact downloaded
- member role changed

## Tenant Isolation Policy

Every protected query must be organization-scoped.

Bad:

```sql
select * from analysis_jobs where id = :job_id;
```

Good:

```sql
select * from analysis_jobs
where id = :job_id
and organization_id = :current_org_id;
```

Acceptance test:

- user A cannot fetch user B job by guessing UUID
- user A cannot download user B artifact
- user A cannot view user B total job

## Auth MVP

Use email/password only.

Endpoints:

```text
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

Rules:

- password hashing with Argon2id or bcrypt
- JWT stored in HttpOnly cookie
- access token lifetime: 30-60 minutes for MVP
- logout clears cookie
- `/auth/me` returns user and default organization

Skip until stretch:

- OAuth
- password reset
- email verification
- refresh token rotation

Acceptance criteria:

- new user can register
- default organization is created
- owner membership is created
- user can log in
- user can log out
- protected routes reject anonymous requests
- disabled user cannot log in

### Test Account Policy

After authentication is implemented, protected verification must use real registered or seeded test accounts.

Do not bypass authentication, disable route protection, inject fake request principals, or call internal store methods only to make a protected-flow check pass.

If a sprint requires protected-flow verification and no suitable test account exists, stop and notify the user. Ask the user to create accounts manually or approve a local-only seed script before continuing.

Recommended local-only test accounts:

- `owner@example.test`
- `analyst@example.test`
- `viewer@example.test`
- `disabled@example.test`
- `other-owner@example.test`

## RBAC MVP

Roles:

- `owner`
- `analyst`
- `viewer`

Permissions:

```text
analysis:create   owner, analyst
analysis:read     owner, analyst, viewer
members:manage    owner
settings:read     owner, analyst, viewer
```

Acceptance criteria:

- viewer cannot create analysis
- analyst can create analysis
- owner can change member role
- all report access stays organization-scoped

## Artifact MVP

Keep local filesystem first.

Add artifact service:

```python
save_artifact(...)
read_artifact(...)
delete_artifact(...)
get_artifact_metadata(...)
```

Artifact service must:

- generate paths
- calculate sha256
- store size
- store content type
- create database row
- reject path traversal

PCAP-specific controls:

- max upload size
- allowed extensions: `.pcap`, `.pcapng`
- magic/header validation where possible
- quarantine-style upload path before analysis
- no archive extraction in MVP
- retention policy documented

Retention MVP:

- keep uploaded PCAPs and reports until user deletes job
- delete job marks artifacts deleted
- cleanup command can physically remove deleted artifacts later

Acceptance criteria:

- uploaded PCAP metadata is stored
- report artifact metadata is stored
- artifact sha256 is present
- job deletion prevents future artifact access
- path traversal attempt fails

## Worker Queue MVP

Use Redis Queue or Celery.

Recommendation:

- RQ + Redis for fastest MVP

Worker jobs:

- `run_analysis_job(job_id)`
- `run_total_job_enrichment(total_job_id)`

Flow:

1. API creates DB job row with `queued`
2. API saves upload artifact
3. API enqueues worker job
4. worker marks job `running`
5. worker calls existing `AnalysisEngine.run`
6. worker saves artifacts through artifact service
7. worker marks job `completed` or `failed`

Acceptance criteria:

- API returns quickly after upload
- long analysis does not block API server
- job progress is persisted in DB
- failed worker stores error
- backend restart does not erase job state
- worker restart can continue with queued jobs

## Frontend MVP

Routes:

```text
/login
/register
/dashboard
/analysis/new
/analysis/history
/analysis/[jobId]
/total-jobs
/total-jobs/[totalJobId]
/settings
```

Required UI behavior:

- unauthenticated users redirect to login
- authenticated app shell shows user/org
- upload page creates analysis
- dashboard shows recent jobs
- history page shows persisted jobs
- report page shows markdown/json artifacts
- loading, empty, error states exist

Acceptance criteria:

- register -> dashboard works
- login -> dashboard works
- logout blocks protected routes
- upload from UI still works
- completed report can be opened after page refresh

## API MVP

Keep current route shape where possible.

Protected endpoints:

```text
POST /api/v1/analysis
POST /api/v1/analysis/batch
GET  /api/v1/analysis
GET  /api/v1/analysis/{job_id}
GET  /api/v1/analysis/{job_id}/report.json
GET  /api/v1/analysis/{job_id}/report.md
GET  /api/v1/analysis/{job_id}/metrics
GET  /api/v1/analysis/{job_id}/guardrail-audit
GET  /api/v1/total-jobs
GET  /api/v1/total-jobs/{total_job_id}
POST /api/v1/total-jobs/{total_job_id}/enrich
```

Acceptance criteria:

- old frontend analysis flow still maps to API
- anonymous calls return 401
- wrong-role calls return 403
- wrong-organization IDs return 404 or 403 consistently

## Testing MVP

Backend tests:

- register creates user/org/member
- login sets auth cookie
- anonymous protected route fails
- viewer cannot create analysis
- cross-tenant job access fails
- upload creates artifact row
- job lifecycle: queued -> running -> completed
- failed analysis stores error

Frontend tests/manual checks:

- login page
- register page
- protected route redirect
- upload flow
- job history reload
- report page reload

Security tests:

- invalid JWT
- missing cookie
- disabled user
- path traversal filename
- oversized upload
- cross-org artifact download

## Docker Compose MVP

Services:

- backend
- frontend
- postgres
- redis
- worker

Nice-to-have:

- pgadmin optional

Acceptance criteria:

- `docker compose up` starts the app
- migrations run
- user can register
- analysis job can complete

## Milestones

### Milestone 1: Database Foundation

Tasks:

- add SQLAlchemy setup
- add Alembic
- create tables: users, organizations, organization_members, analysis_jobs, total_jobs, artifacts, audit_logs
- add Docker Compose PostgreSQL
- add migration command

Acceptance:

- migrations create all tables
- app boots with database connection
- job rows can be created/read in tests
- current file-based analysis code is not broken

### Milestone 2: Simple Auth

Tasks:

- register/login/logout/me
- password hashing
- HttpOnly JWT cookie
- default org creation
- owner membership creation
- frontend login/register pages

Acceptance:

- user can register and log in
- protected routes require auth
- frontend auth state survives refresh
- logout works

### Milestone 3: Org Scope and RBAC

Tasks:

- current user dependency
- current organization dependency
- permission dependency
- org-scoped job queries
- owner/analyst/viewer roles

Acceptance:

- analyst can create jobs
- viewer cannot create jobs
- users cannot access other org jobs/artifacts

### Milestone 4: Artifact Service

Tasks:

- local artifact service
- artifact metadata table writes
- upload validation
- report artifact metadata
- soft delete behavior

Acceptance:

- uploaded PCAP and generated reports are tracked in DB
- sha256/size/content type are stored
- artifact paths are server-generated
- traversal filenames are rejected/sanitized

### Milestone 5: Worker Queue

Tasks:

- add Redis
- add RQ/Celery worker
- move analysis execution out of API request
- persist job progress/errors
- update frontend polling if needed

Acceptance:

- upload API returns without waiting for analysis
- worker completes analysis
- backend restart does not erase job
- failed jobs show error

### Milestone 6: Frontend MVP Polish

Tasks:

- protected app shell
- dashboard
- job history
- report detail
- settings page
- empty/loading/error states

Acceptance:

- complete user journey works from browser
- report opens after refresh
- UI clearly shows job status and errors

### Milestone 7: Portfolio Finish

Tasks:

- README
- architecture diagram
- Docker Compose guide
- demo seed or demo instructions
- focused tests
- security notes

Acceptance:

- reviewer can run project locally
- demo path is documented
- tests cover auth, tenant isolation, upload, job lifecycle

## Sprint Development Plan

Use short sprints. Each sprint must leave the app runnable.

Recommended cadence:

- 1 sprint = 3-5 focused development days
- each sprint ends with a browser/manual demo
- do not start stretch goals until Sprint 8 is done

### Sprint 0: Baseline and Safety Net

Goal:

- preserve the current working demo before large changes

Develop:

- document current backend/frontend run commands
- verify current upload -> analysis -> report flow
- add or update minimal smoke test script/manual checklist
- identify current API endpoints used by frontend
- add `.env.example` values needed for local development

Done:

- backend starts locally
- frontend starts locally
- existing PCAP upload flow works
- current API route map is documented
- known limitations are written down

Verification:

- run backend
- run frontend
- upload one small PCAP
- open report page
- refresh report page

### Sprint 1: Database Foundation

Goal:

- introduce PostgreSQL without replacing the working file-based flow yet

Develop:

- add SQLAlchemy database setup
- add Alembic migrations
- create tables: `users`, `organizations`, `organization_members`, `analysis_jobs`, `total_jobs`, `artifacts`, `audit_logs`
- add PostgreSQL service to Docker Compose
- add migration command/docs
- add DB health check endpoint or startup check

Done:

- migrations create all MVP tables
- app can connect to database
- tests can create/read job rows
- existing file-based analysis still works

Verification:

- run migrations from empty database
- run backend
- create/read DB job row in test or script
- run old upload flow

### Sprint 2: Persist Job State

Goal:

- move job and total-job metadata into database while keeping artifacts local

Develop:

- replace or wrap `job_store.py` with DB-backed repository
- replace or wrap `total_job_store.py` with DB-backed repository
- persist job status, phase, progress, error, timestamps
- persist total-job status and enrichment fields
- keep compatibility with current frontend API response shape

Done:

- jobs survive backend restart
- history page reads persisted jobs
- job detail page reads persisted status
- old frontend still works

Verification:

- upload PCAP
- restart backend
- reload job/history pages
- confirm job status remains visible

### Sprint 3: Artifact Service

Goal:

- centralize upload/report file handling and record artifact metadata

Develop:

- add local artifact service
- generate server-owned artifact paths
- store artifact rows for uploaded PCAPs and generated reports
- calculate `sha256`, size, and content type
- validate `.pcap`/`.pcapng` extension and max size
- reject/sanitize path traversal filenames
- add soft-delete behavior

Done:

- uploaded PCAP artifact metadata is stored
- report artifact metadata is stored
- frontend can still download/view reports
- user-supplied paths are never trusted

Verification:

- upload valid PCAP
- try traversal filename
- open report
- inspect artifact DB rows
- delete job and confirm artifact access is blocked

### Sprint 4: Simple Auth

Goal:

- add MVP authentication with default organization creation

Develop:

- implement `register`, `login`, `logout`, `me`
- hash passwords with Argon2id or bcrypt
- store JWT/session in HttpOnly cookie
- create default organization on registration
- create owner membership on registration
- add frontend login/register pages
- add frontend session state

Done:

- user can register
- user can log in
- user can log out
- auth state survives refresh
- disabled user cannot log in

Verification:

- register -> dashboard
- logout -> protected route blocked
- login -> dashboard
- call `/api/v1/auth/me`

### Sprint 5: RBAC and Tenant Isolation

Goal:

- protect data by organization and role

Develop:

- add current-user dependency
- add current-organization dependency
- add permission dependency
- enforce org-scoped queries for jobs, total jobs, artifacts
- protect analysis creation with `analysis:create`
- protect report reads with `analysis:read`
- add minimal member role update path for owner

Done:

- analyst can create jobs
- viewer cannot create jobs
- users cannot access another organization job
- users cannot access another organization artifact

Verification:

- create two users/orgs
- user A attempts user B job fetch
- user A attempts user B artifact fetch
- viewer attempts upload
- analyst uploads successfully

### Sprint 6: Worker Queue

Goal:

- move long analysis work out of the API request path

Develop:

- add Redis service
- add RQ or Celery worker
- enqueue `run_analysis_job(job_id)`
- enqueue `run_total_job_enrichment(total_job_id)`
- update worker to persist progress/errors in database
- keep frontend polling compatible
- document worker run command

Done:

- upload API returns quickly
- worker runs analysis
- job progresses through queued -> running -> completed
- failed jobs store error
- backend restart does not erase state

Verification:

- start backend/frontend/redis/worker
- upload PCAP
- observe queued/running/completed states
- stop backend during job and restart
- force one failed job and confirm error display

### Sprint 7: Frontend Product Polish

Goal:

- make the app feel like a coherent authenticated product

Develop:

- protected app shell
- dashboard with recent jobs
- persisted job history
- report detail reload support
- total-job detail cleanup
- settings page with user/org info
- loading, empty, and error states
- role-aware navigation

Done:

- complete browser journey works
- UI clearly shows job status and failures
- report opens after refresh
- anonymous users are redirected to login

Verification:

- register
- upload PCAP
- watch progress
- open report
- refresh report
- logout
- confirm protected route redirect

### Sprint 8: Tests, Compose, and Portfolio Finish

Goal:

- make the project reviewable by an internship reviewer

Develop:

- Docker Compose for backend, frontend, postgres, redis, worker
- migration startup docs
- backend tests for auth, RBAC, tenant isolation, artifact validation, job lifecycle
- frontend manual test checklist
- README update
- architecture diagram
- demo instructions
- security notes

Done:

- reviewer can run the app locally
- tests cover core security and job flow
- demo path is documented
- MVP pitch is clear

Verification:

- run backend tests
- run frontend lint/build
- run `docker compose up`
- register user
- upload PCAP
- complete analysis
- open report

## Sprint Dependency Map

```text
Sprint 0 baseline
  -> Sprint 1 database
  -> Sprint 2 persisted jobs
  -> Sprint 3 artifacts
  -> Sprint 4 auth
  -> Sprint 5 RBAC/tenant isolation
  -> Sprint 6 worker queue
  -> Sprint 7 frontend polish
  -> Sprint 8 tests/docs/compose
```

Parallel work allowed:

- frontend visual polish can start after Sprint 4
- README/demo notes can be updated every sprint
- tests should be added during each sprint, then consolidated in Sprint 8

Do not parallelize:

- RBAC before auth
- worker queue before persisted jobs
- artifact deletion before artifact metadata exists

## Stretch Goals

Add only after MVP works.

### OAuth 2.0

- Google login
- account linking
- OAuth callback security

### Refresh Tokens

- refresh token table
- rotation
- revocation

### Password Reset and Email Verification

- email provider
- signed reset token
- rate limiting
- abuse controls

### S3 or MinIO

- S3-compatible storage adapter
- signed download URLs
- object lifecycle rules

### API Keys

- hashed API keys
- scopes
- last-used tracking

### Billing

- Stripe customer/subscription sync
- webhook handler
- plan enforcement

### Admin Surface

- user management
- system metrics
- worker dashboard

## PCAP-Specific Security Risks

PCAPs may contain sensitive data.

Controls:

- warn users before upload
- store under organization-isolated paths
- never expose raw paths to frontend
- document retention policy
- allow job/artifact deletion
- limit file size
- limit analysis runtime
- timeout forensic tools
- avoid archive extraction
- treat carved payloads as unsafe
- never auto-execute carved files

## Final MVP Pitch

AgenticNetSec is a full-stack forensic analysis platform with authenticated users, organization-scoped job history, persistent database records, secure artifact handling, and background PCAP analysis.

It demonstrates software engineering depth while preserving the original cybersecurity value of the project.
