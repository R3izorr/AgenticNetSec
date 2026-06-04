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

## Run The Backend

```bash
./.venv/bin/python backend/scripts/run_api.py
```

With auto-reload:

```bash
./.venv/bin/python backend/scripts/run_api.py --reload
```

Backend URLs:

- API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`

## Run The Database

Sprint 1 adds PostgreSQL for the MVP persistence foundation. The current upload -> analysis -> report path still uses the existing file-backed job stores until later sprints.

Start local PostgreSQL:

```bash
docker compose up -d postgres
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

PostgreSQL is optional for the legacy file-backed analysis flow unless `AGENTIC_DATABASE_REQUIRED=1` is set.

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
