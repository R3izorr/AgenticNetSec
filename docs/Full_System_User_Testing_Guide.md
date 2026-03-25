# Full System User Testing Guide

This guide explains how to run the AgenticNetSec backend and frontend together for end-to-end user testing.

It is aimed at the actual product flow:

- start the FastAPI backend
- start the Next.js frontend
- submit a PCAP through the UI
- watch the job progress through the dashboard and analysis pages
- validate the generated artifacts

## What You Will Run

The full system has two live processes:

- Backend API: `http://localhost:8000`
- Frontend UI: `http://localhost:3000`

The frontend talks to the backend through the REST API under `/api/v1/analysis`.

Important backend note:

- visiting `http://localhost:8000/` will return `404 Not Found`, and that is expected
- the backend does not expose a root landing page at `/`
- use `http://localhost:8000/docs` for FastAPI docs
- use `http://localhost:8000/api/v1/analysis` for the analysis API surface

## Prerequisites

Recommended local setup on Windows:

- Python virtual environment already created at `.venv`
- Backend dependencies installed from `requirements.txt`
- Node.js and npm installed
- Frontend dependencies installed in `frontend/node_modules`

If you still need to install dependencies:

```powershell
.\.venv\Scripts\python -m pip install -r requirements.txt
cd frontend
cmd /c npm install
cd ..
```

## Optional AI Configuration

You can test the system without any external AI provider.

For backend-only CLI testing, use `--no-ai`.

For the web API flow, the system behavior depends on your local backend configuration. If you want AI-backed generation, configure provider settings from:

- `backend/config/local_settings.example.py`

If no provider is configured, keep user testing focused on connectivity, job lifecycle, persistence, and artifact availability unless your current backend fallback path is already configured.

## Terminal 1: Start the Backend

From the repository root:

```powershell
.\.venv\Scripts\python backend/scripts/run_api.py
```

Expected result:

- the API starts on `http://localhost:8000`
- the backend exposes analysis endpoints under `/api/v1/analysis`
- opening `http://localhost:8000/` directly will show `404 Not Found`, which is normal for this app

Useful note:

- auto-reload is intentionally off by default for Windows stability
- if you explicitly want dev reload, use `--reload`

Example:

```powershell
.\.venv\Scripts\python backend/scripts/run_api.py --reload
```

## Terminal 2: Start the Frontend for UAT or Demo

For user acceptance testing, stakeholder walkthroughs, and demo runs, use the production frontend path from the repository root:

```powershell
cd frontend
cmd /c npm run build
cmd /c npm run start
```

Expected result:

- the UI starts on `http://localhost:3000`
- this is the preferred frontend mode for UAT because it avoids most dev-only hydration noise

The frontend defaults to `http://localhost:8000` for the backend API.

If you need to override that, create `frontend/.env.local` with:

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

## Development Frontend Mode

Use dev mode only for active frontend development:

```powershell
cd frontend
cmd /c npm run dev
```

Important dev-mode warning:

- hydration warnings can appear in `npm run dev` even when `npm run build` and `npm run start` work correctly
- this repo does not register a service worker, so service-worker errors are usually caused by stale browser state from another project running on `http://localhost:3000`
- hot reload and cached localhost assets make dev mode much more sensitive than the production start path

## Recommended User Testing Flow

Open:

- `http://localhost:3000`

Then use this route sequence:

1. `/dashboard`
2. `/analysis/new`
3. `/analysis/[jobId]`
4. `/analysis/[jobId]/report`
5. `/analysis/[jobId]/raw`
6. `/analysis/history`

### What to Verify on Each Screen

`/dashboard`

- recent jobs load successfully
- summary cards show total, running, completed, and failed jobs
- top risk/confidence jobs show report and raw links
- refresh works without page reload

`/analysis/new`

- file upload submission works
- path-based submission works if the file exists on the backend machine
- the form returns a valid `analysis_job_id`

`/analysis/[jobId]`

- status changes from `queued` to `running` to `completed` or `failed`
- backend phase labels appear correctly
- source metadata appears when available
- runtime, risk, confidence, and artifact readiness update correctly

`/analysis/[jobId]/report`

- the report page loads after completion
- if opened too early, the page recovers once the artifact becomes ready
- findings, timeline, evidence, and recommendations render cleanly

`/analysis/[jobId]/raw`

- `report.json`, `report.md`, `metrics`, and `guardrail audit` appear when ready
- not-ready states recover automatically without forcing a full navigation

`/analysis/history`

- persisted jobs appear after refresh
- search and status filters work
- restarting the backend does not erase completed job history

## Good Test Inputs

Repo-local smoke inputs are available in:

- `outputs/smoke_inputs/benign_small.pcap`
- `outputs/smoke_inputs/suspicious_scan_small.pcap`
- `outputs/smoke_inputs/corrupt_input.pcap`

Recommended manual test set:

1. Benign sample
   - expected to complete cleanly
   - useful for validating the success path and normal report rendering
2. Suspicious sample
   - expected to produce stronger findings, risk, and evidence content
   - useful for dashboard and report walkthroughs
3. Corrupt sample
   - expected to fail or surface an error state cleanly
   - useful for validating failure UX and history behavior

## Suggested End-to-End Test Script

1. Start the backend.
2. Start the frontend with `npm run build` and `npm run start`.
3. Open `/dashboard` and confirm the page loads.
4. Submit `outputs/smoke_inputs/benign_small.pcap` from `/analysis/new`.
5. Watch the job page until the status is final.
6. Open the report page and raw page.
7. Return to `/analysis/history` and confirm the job is listed.
8. Submit `outputs/smoke_inputs/suspicious_scan_small.pcap` and repeat.
9. Submit `outputs/smoke_inputs/corrupt_input.pcap` and confirm failure handling is clear.
10. Stop and restart the backend.
11. Reload `/dashboard` and `/analysis/history` and confirm previous jobs are still present.

## Backend API Checks

If you want to confirm the backend independently while the UI is running, these are the main endpoints:

- `http://localhost:8000/docs`
- `http://localhost:8000/api/v1/analysis`
- `POST /api/v1/analysis`
- `GET /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`
- `GET /api/v1/analysis/{job_id}/guardrail-audit`

## Expected Output Location

Completed analysis jobs persist under:

- `outputs/analysis_jobs/<job_id>/`

Typical artifacts include:

- `job.json`
- `report.json`
- `report.md`
- `metrics.json`
- `guardrail_audit.json`

## Troubleshooting

### `http://localhost:8000/` shows `404 Not Found`

That is expected. This backend does not define a root `/` page.

Use one of these instead:

- `http://localhost:8000/docs`
- `http://localhost:8000/api/v1/analysis`
- `http://localhost:3000`

### `npm run dev` shows hydration or service-worker problems

This is usually an environment issue rather than an AgenticNetSec bug.

Key points:

- `npm run dev` is more sensitive than `npm run start`
- this repo does not register a service worker
- another project previously served on `http://localhost:3000` can leave behind stale service workers or cached assets
- production mode can work cleanly even when dev mode is noisy

Recommended cleanup steps:

1. Open browser site settings or devtools for `http://localhost:3000`.
2. Unregister any service worker for that origin.
3. Clear site data and cache for `http://localhost:3000`.
4. Restart the frontend server.
5. Hard refresh the page.

For UAT, prefer:

```powershell
cd frontend
cmd /c npm run build
cmd /c npm run start
```

### Frontend loads but shows API errors

Check:

- the backend is running on `http://localhost:8000`
- `NEXT_PUBLIC_API_BASE_URL` is correct
- the backend terminal did not exit with an import or dependency error

### Backend starts but frontend cannot submit

Check:

- CORS or API base URL overrides were not changed unexpectedly
- the request payload matches either file upload or `pcap_path`
- the selected PCAP path exists on the backend machine if using path submission

### PowerShell blocks npm scripts

Use `cmd /c`:

```powershell
cd frontend
cmd /c npm run dev
```

### Backend restart loses jobs

That should no longer happen for completed or active API jobs. Check whether `outputs/analysis_jobs/<job_id>/job.json` exists.

### Windows reload issues

If `--reload` causes watcher or permission issues, use the default startup command without reload:

```powershell
.\.venv\Scripts\python backend/scripts/run_api.py
```

## Related Files

- `README.md`
- `README_RUN_TEST.md`
- `backend/README.md`
- `frontend/README.md`
- `docs/Changes_2026-03-25.md`
