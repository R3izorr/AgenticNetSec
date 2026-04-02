# AgenticNetSec

AgenticNetSec is a read-only network forensic analysis system with a FastAPI backend and a Next.js frontend.

The current product flow is batch-first:

- users submit one or more PCAP files from the frontend
- the backend creates one parent `total_job`
- the backend creates one child `analysis_job` per file
- stage 1 runs deterministic analysis only
- stage 2 runs later, on demand, for parent-level AI summary and sandbox enrichment

The system writes artifacts and analysis metadata only. It does not execute containment actions or mutate analyst environments.

## Current State

As of the current implementation:

- batch-first submission is implemented through `POST /api/v1/analysis/batch`
- the frontend uses `/analysis/new` as the submission page
- the frontend uses `/total-jobs` and `/total-jobs/[totalJobId]` for batch monitoring
- deterministic stage 1 does not use AI or sandbox
- parent enrichment can be triggered later from the UI
- parent enrichment now:
  - supports run, retry, and rerun
  - deduplicates duplicate completed PCAPs before AI and sandbox processing
  - exposes dedupe metadata in the total-job detail page
  - surfaces partial-batch warnings when some child jobs fail

## Repository Layout

- `backend/src/`: analysis engine, planner, detectors, report generation, guardrails
- `backend/api/`: FastAPI app and job persistence
- `backend/scripts/`: CLI helpers such as `run.py` and `run_api.py`
- `backend/config/`: local configuration templates
- `backend/tests/`: backend tests
- `frontend/`: Next.js frontend
- `outputs/`: uploads, job artifacts, and parent batch artifacts
- `docs/`: architecture, plans, testing notes, and change logs

## Prerequisites

Required:

- Python 3.10+ with `venv`
- Node.js and npm

Optional:

- AI provider credentials if you want provider-backed enrichment
- sandbox environment setup if you want real sandbox verification behavior

You can still run the system without external AI credentials. The deterministic stage works without them.

## Setup

### Windows

From the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
cd frontend
cmd /c npm install
cd ..
```

### Linux

From the repository root:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt
cd frontend
npm install
cd ..
```

## Start The Backend

The backend API is served by `backend/scripts/run_api.py`.

### Windows

```powershell
.\.venv\Scripts\python backend/scripts/run_api.py
```

Optional auto-reload:

```powershell
.\.venv\Scripts\python backend/scripts/run_api.py --reload
```

### Linux

```bash
./.venv/bin/python backend/scripts/run_api.py
```

Optional auto-reload:

```bash
./.venv/bin/python backend/scripts/run_api.py --reload
```

Backend URLs:

- API base: `http://localhost:8000`
- FastAPI docs: `http://localhost:8000/docs`
- `http://localhost:8000/` returning `404 Not Found` is expected

## Start The Frontend

Use production mode for demos, UAT, and normal testing. Use dev mode only for active frontend development.

### Windows

Production mode:

```powershell
cd frontend
cmd /c npm run build
cmd /c npm run start
```

Development mode:

```powershell
cd frontend
cmd /c npm run dev
```

### Linux

Production mode:

```bash
cd frontend
npm run build
npm run start
```

Development mode:

```bash
cd frontend
npm run dev
```

Frontend URL:

- `http://localhost:3000`

Backend base URL expected by the frontend:

- `http://localhost:8000`

If you need to override it, use `frontend/.env.local` with:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

## Recommended Startup For Full System Testing

1. Start the backend on `:8000`
2. Start the frontend on `:3000` using production mode
3. Open `http://localhost:3000`
4. Submit one or more PCAP files from `/analysis/new`
5. Watch the batch in `/total-jobs/{totalJobId}`
6. Trigger AI enrichment later from:
   - `/total-jobs`
   - or `/total-jobs/{totalJobId}`

## Current Frontend Flow

### Submission

- Route: `/analysis/new`
- Input: one or more PCAP files
- Worker count: required, minimum `2`
- Output: redirect to a parent total-job page

### Batch Monitoring

- Route: `/total-jobs`
- Route: `/total-jobs/[totalJobId]`
- Shows:
  - parent total-job status
  - file count
  - worker count
  - child-job progress
  - partial-batch warnings when applicable

### Enrichment

- Trigger labels include:
  - `Run AI`
  - `Retry AI`
  - `Re-run AI`
  - `Run AI Summary + Sandbox`
  - `Retry AI Summary + Sandbox`
  - `Re-run AI Summary + Sandbox`
- Enrichment runs at the parent total-job level only
- Duplicate completed PCAPs are removed before parent AI/sandbox processing

## API Surface

### Child-job APIs

- `POST /api/v1/analysis`
- `GET /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`
- `GET /api/v1/analysis/{job_id}/guardrail-audit`

### Total-job APIs

- `POST /api/v1/analysis/batch`
- `GET /api/v1/total-jobs`
- `GET /api/v1/total-jobs/{total_job_id}`
- `POST /api/v1/total-jobs/{total_job_id}/enrich`
- `GET /api/v1/total-jobs/{total_job_id}/summary.json`
- `GET /api/v1/total-jobs/{total_job_id}/summary.md`
- `GET /api/v1/total-jobs/{total_job_id}/sandbox`

## Output Layout

### Child-job artifacts

Stored under:

- `outputs/analysis_jobs/<analysis_job_id>/`

Common files:

- `job.json`
- `report.json`
- `report.md`
- `metrics.json`
- `guardrail_audit.json`
- `analysis_record.json`

### Total-job artifacts

Stored under:

- `outputs/total_jobs/<total_job_id>/`

Common files:

- `total_job.json`
- `summary.json`
- `summary.md`
- `sandbox.json`

## Useful Verification Commands

### Backend compile check

Windows:

```powershell
.\.venv\Scripts\python -m compileall backend
```

Linux:

```bash
./.venv/bin/python -m compileall backend
```

### Frontend validation

Windows:

```powershell
cd frontend
cmd /c npm run lint
cmd /c npm run build
```

Linux:

```bash
cd frontend
npm run lint
npm run build
```

## Troubleshooting

### Backend root returns `404`

That is expected. Use `http://localhost:8000/docs` instead.

### Frontend dev mode is noisy

`npm run dev` is more sensitive than `npm run start`. If localhost looks stale, clear site data for `http://localhost:3000`, remove any old service worker on that origin, restart the dev server, and hard refresh.

### No AI provider configured

That is acceptable for deterministic batch analysis. Parent enrichment may still fall back depending on your provider configuration and runtime behavior.

### Sandbox is not active

Sandbox behavior is backend-controlled. If you want sandbox verification available for enrichment flows, review the backend sandbox configuration and environment settings in `backend/README.md`.

## More Detailed Guides

- `README_RUN_TEST.md`
- `backend/README.md`
- `frontend/README.md`
- `docs/Architecture.md`
- `docs/Batch_Total_Job_Plan.md`
