# AgenticNetSec

AgenticNetSec is a network forensic analysis platform for turning large PCAP collections into structured investigation records, per-file reports, and campaign-level incident summaries.

It is designed for ransomware and intrusion triage where analysts need to answer:

- How did the attacker get initial access?
- How did they discover and move through the network?
- Did data leave the environment?
- How was the payload deployed?

The project uses a FastAPI backend, a Next.js frontend, and a two-stage analysis workflow.

## What It Does

AgenticNetSec accepts one or more PCAP files and creates a parent batch job with one child analysis job per file.

The backend extracts deterministic network evidence from each PCAP, stores report artifacts, and can later enrich the whole batch into a campaign-level summary.

The frontend provides pages for upload, batch progress, per-file inspection, total-job enrichment, and all-scans summaries.

## Repository Extras

This repository also includes a committed Understand Anything graph snapshot under `.understand-anything/`.

Included files:

- `.understand-anything/knowledge-graph.json`
- `.understand-anything/fingerprints.json`
- `.understand-anything/meta.json`
- `.understand-anything/.understandignore`

Use this when you want a fast architecture walkthrough without re-running a full scan first.

## Reviewer Quick Start

This is the preferred internship-review path. It starts PostgreSQL, Redis, the FastAPI backend, the RQ worker, and the Next.js frontend.

```bash
cp .env.example .env
docker compose up --build
```

Then open:

```text
http://localhost:3000
```

The Compose stack runs Alembic migrations before the backend and worker start. Browser requests use `http://localhost:8000` for the API.

For later runs after the images are built:

```bash
docker compose up
```

Stop the stack:

```bash
docker compose down
```

Reset local database and runtime artifacts:

```bash
docker compose down -v
```

## Accounts And Keys You Need

For local Docker Compose use, you do not need to create a hosted PostgreSQL account or a hosted Redis account.

- PostgreSQL account:
  Compose creates the local database user from `.env`.
  Default local values are `POSTGRES_DB=agenticnetsec`, `POSTGRES_USER=agenticnetsec`, and `POSTGRES_PASSWORD=agenticnetsec`.
- Redis account:
  None for local Compose use. The app uses the local Redis container through `REDIS_URL`.
- App login account:
  Required.
  Create it in the UI at `http://localhost:3000/register`.
  Registration creates the user, default organization, and owner membership.
- Auth secret:
  Required.
  Set `AGENTIC_AUTH_SECRET` in `.env`.
  The sample value in `.env.example` is only for local demos.
- AI provider account or API key:
  Optional.
  Deterministic Stage 1 analysis and the authenticated upload -> analysis -> report flow work without AI keys.
  Add one only if you want AI-backed summaries or follow-up reasoning.

Supported optional AI providers:

- `OPENROUTER_API_KEY`
- `OPENAI_API_KEY`
- `GEMINI_API_KEY` or `GOOGLE_API_KEY`
- `GROQ_API_KEY`
- local Ollama via `OLLAMA_BASE_URL` and `OLLAMA_MODEL`

Recommended first local account:

```text
email: owner+demo-<timestamp>@example.test
password: Password123!
```

## Architecture

```text
Browser
  |
  | HttpOnly cookie auth
  v
Next.js frontend :3000
  |
  | authenticated API requests
  v
FastAPI backend :8000
  |
  | SQLAlchemy
  v
PostgreSQL :5432
  |
  | enqueue job IDs
  v
Redis :6379
  |
  | RQ worker loads trusted DB/artifact metadata
  v
Shared outputs volume
  |
  | existing forensic engine
  v
Scapy / tshark / deterministic fallback reports
```

Runtime upload and report files live in the shared `app_outputs` Docker volume so the API container and worker container see the same server-generated artifact paths.

## Demo Path

Use a real local account. Do not bypass auth.

1. Open `http://localhost:3000/register`.
2. Register `owner+demo-<timestamp>@example.test` with password `Password123!`.
3. Open New Analysis.
4. Upload `pcap/CredAccess/DCSync_krbtgt_dcerpc_smb.pcapng`.
5. Start the batch with the default `standard` profile.
6. Watch the Total Job page until deterministic analysis completes.
7. Open the child analysis report.
8. Refresh the report page and confirm it reloads.
9. Log out.
10. Open `/dashboard` directly and confirm redirect to login.

Full checklist: `docs/Manual_Test_Checklist.md`.

## Architecture Graph

The repo includes a committed knowledge graph snapshot for the current codebase.

Graph files:

```text
.understand-anything/knowledge-graph.json
.understand-anything/fingerprints.json
.understand-anything/meta.json
```

To regenerate it later, run the Understand Anything flow from the repository root and commit the refreshed snapshot.

To view the graph in the interactive dashboard, start the dashboard against this repo and open the tokenized URL it prints. The graph is intended for source understanding and reviewer onboarding, not for runtime application behavior.

## How The Workflow Works

### Stage 1: Deterministic PCAP Analysis

Stage 1 runs once per uploaded PCAP.

It extracts repeatable evidence such as:

- external ingress indicators
- RDP activity
- SMB/RPC activity
- scanning and discovery behavior
- large outbound transfer candidates
- suspicious protocol patterns
- per-file report data

Stage 1 supports three profiles:

- `fast`: quickest triage path with minimal expensive work
- `standard`: recommended default for normal analysis
- `full`: heavier deterministic analysis path

The normal `standard` profile keeps Stage 1 fast and defers heavier payload-carving work to Stage 2.

### Stage 2: Campaign Enrichment

Stage 2 runs at the parent total-job level after Stage 1 child jobs finish.

It combines completed child records and performs:

- record deduplication
- initial AI campaign summary
- sandbox-style verification
- targeted follow-up checks
- delayed payload-carving enrichment
- final campaign report generation

The goal is to connect individual PCAP findings into a single incident narrative.

## Repository Layout

```text
backend/
  api/          FastAPI app, routes, job stores
  config/       local settings template
  scripts/      run helpers and batch submission helpers
  src/          analysis engine, detectors, enrichment, AI report logic

frontend/
  app/          Next.js routes
  components/   UI components
  lib/          frontend API helpers

docs/           architecture notes and project documentation
script.txt      demo narration script
```

Runtime artifacts are generated under `outputs/` when the app runs. The repository does not need bundled PCAP datasets or generated analysis results.

## Requirements

- Python 3.10+
- Node.js and npm
- Docker and Docker Compose for the reviewer quick start
- Redis for the background worker queue
- PostgreSQL for durable auth/job state
- `tshark` for packet inspection features
- Optional AI provider keys for AI-backed summaries

The deterministic Stage 1 workflow can run without AI keys.

## Setup

Create the Python environment:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt
```

Install frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

Optional local settings:

```bash
cp backend/config/local_settings.example.py backend/config/local_settings.py
```

Then edit `backend/config/local_settings.py` with local-only provider keys if needed. Do not commit that file.

## Run The Backend And Worker

Manual local fallback, useful while developing without containerized app services.

Start Redis and PostgreSQL:

```bash
docker compose up -d redis postgres
```

Run migrations:

```bash
set -a
. ./.env
set +a
./.venv/bin/python -m alembic upgrade head
```

Run the API:

```bash
./.venv/bin/python backend/scripts/run_api.py
```

Run the worker in a second terminal:

```bash
./.venv/bin/python backend/scripts/run_worker.py
```

With API auto-reload:

```bash
./.venv/bin/python backend/scripts/run_api.py --reload
```

Backend URLs:

- API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`

## Run The Database And Queue

PostgreSQL stores durable job state and Redis backs the worker queue.

Start local PostgreSQL and Redis:

```bash
docker compose up -d postgres redis
```

Run migrations from the repository root:

```bash
./.venv/bin/python -m alembic upgrade head
```

Verify the backend can create and read one database job row:

```bash
./.venv/bin/python backend/scripts/db_smoke.py
```

Default local database URL:

```text
postgresql+psycopg://agenticnetsec:agenticnetsec@localhost:5432/agenticnetsec
```

Override it with `DATABASE_URL` if needed.

PostgreSQL is required for the MVP reviewer path. `AGENTIC_DATABASE_REQUIRED=1` is set in `.env.example` so startup fails loudly if the database is unavailable. Redis is required for API enqueue routes to start new analysis work.

## Run The Frontend

Development mode:

```bash
cd frontend
npm run dev
```

Production-style local run:

```bash
cd frontend
npm run build
npm run start
```

Frontend URL:

```text
http://localhost:3000
```

If needed, set the backend URL in `frontend/.env.local`:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

## Tests

Backend tests:

```bash
set -a
. ./.env
set +a
./.venv/bin/python -m alembic upgrade head
./.venv/bin/python -m unittest discover -s backend/tests -p 'test_*.py' -v
```

Frontend static checks:

```bash
cd frontend
npm run lint
npm run build
```

Browser E2E:

```bash
cd frontend
npx playwright install chromium
npm run test:e2e
```

`npm run test:e2e` expects the backend, frontend, PostgreSQL, Redis, and worker to be running. It registers a real local user, uploads `pcap/CredAccess/DCSync_krbtgt_dcerpc_smb.pcapng`, waits for analysis completion, opens and refreshes the report, logs out, and verifies protected-route redirect.

## How To Use

1. Start the backend.
2. Start the frontend.
3. Open `http://localhost:3000`.
4. Go to New Analysis.
5. Upload one or more PCAP files.
6. Choose an analysis profile, usually `standard`.
7. Start the scan.
8. Monitor the parent batch in Total Jobs.
9. Open child reports to inspect per-file findings.
10. Run enrichment on the total job.
11. Review the final campaign report.

For large local corpora, use the backend batch helper:

```bash
./.venv/bin/python backend/scripts/submit_batch_to_api.py /path/to/pcaps --workers 4 --analysis-profile standard
```

## Generated Artifacts

During runtime, AgenticNetSec writes generated files under `outputs/`, including:

- uploaded PCAP cache
- child analysis job records
- per-file reports
- parent total-job summaries
- enrichment artifacts
- all-scans summary artifacts

These files are runtime data, not source code. They are ignored by git and should not be committed unless you intentionally want to archive a specific investigation result.

## AI Provider Notes

AI-backed summaries are optional.

Configuration is loaded from environment variables and `backend/config/local_settings.py`, with environment variables taking priority.

The report path is provider-specific:

- Gemini requests use Gemini only.
- OpenRouter requests use OpenRouter only.
- The report path does not silently cross-fallback into a different provider.

If no provider is callable, the system can still produce deterministic fallback reporting.

## Security Notes

- Authentication uses email/password with an HttpOnly session cookie.
- Every protected API route reloads the current user membership and enforces role permissions.
- Roles are `owner`, `analyst`, and `viewer`; viewers can read jobs/reports but cannot upload, delete, or trigger enrichment.
- Protected job and artifact reads are scoped by `organization_id`.
- Browser uploads are stored through the server artifact service under server-generated paths.
- Raw server `pcap_path` inputs are disabled unless `AGENTIC_ALLOW_SERVER_PCAP_PATHS=1` is explicitly set.
- Upload filenames reject path separators and only accept `.pcap` or `.pcapng`.
- Authenticated API payloads may include local server artifact paths for debugging; the frontend hides these paths from reviewer workflows.
- `.env.example` secrets and database passwords are local-demo defaults only. Replace `AGENTIC_AUTH_SECRET` before any shared or deployed environment.
- PostgreSQL and Redis ports are published for local reviewer convenience; this Compose file is not a production deployment.
- Do not commit `.env`, `frontend/.env.local`, `backend/config/local_settings.py`, or generated `outputs/`.

## Deployment Notes

Current production posture:

- Good enough for local review, demo, and single-server hosting.
- Not yet a hardened multi-tenant production deployment.

If you want to host it:

- use hosted PostgreSQL via `DATABASE_URL`
- use hosted Redis via `REDIS_URL`
- set a strong `AGENTIC_AUTH_SECRET`
- run the frontend, backend, and worker on a server with Docker Compose or equivalent
- keep HTTPS in front of the app and set secure cookie settings

Current limitation:

- uploaded PCAPs and generated report artifacts still live on server disk / shared volume
- there is no S3, Blob, or MinIO integration yet
- if you need fully remote durable artifact storage, add object storage in a later phase

## Demo

Use `script.txt` as the demo narration.

The recommended demo story:

1. Explain that the dataset contains many PCAP files.
2. Show Stage 1 deterministic per-file analysis.
3. Open one or two per-file reports.
4. Show the Total Jobs view.
5. Run or open Stage 2 enrichment.
6. Show the final AI campaign summary.
7. Point out both findings and gaps.

The key message:

```text
AgenticNetSec does not just summarize packets. It helps analysts understand what is known, what is suspected, and what still cannot be proven.
```

## Project Hygiene

This repository intentionally excludes:

- raw PCAP datasets
- generated `outputs/` artifacts
- local virtual environments
- local secrets
- temporary test/cache files

Keep `backend/config/local_settings.py` local only.
