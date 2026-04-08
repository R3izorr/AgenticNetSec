# AgenticNetSec Run And Test Guide

This guide explains how to set up, start, and test the current AgenticNetSec system from a fresh checkout.

AgenticNetSec is a read-only network forensic platform. It analyzes PCAP evidence and writes artifacts only.

## Current Product Flow

The current system is batch-first:

1. Submit one or more PCAP files from the frontend
2. Backend creates one parent `total_job`
3. Backend creates one child `analysis_job` per file
4. Stage 1 runs deterministic analysis only
5. Stage 2 runs later, on demand, for parent-level AI summary and sandbox enrichment

Important current behavior:

- stage 1 does not use AI
- stage 1 does not use sandbox
- stage 1 supports `fast`, `standard`, and `full` deterministic profiles
- `standard` is the default, only runs deep dive when evidence exists, and skips deterministic payload carving
- payload-deployment follow-up is deferred to stage-2 sandbox enrichment unless you explicitly use `full`
- AI and sandbox run only at parent total-job enrichment time
- duplicate completed PCAPs are removed before parent enrichment
- partial child-job failures are surfaced in the total-job UI

## Prerequisites

Required:

- Python 3.10+
- Node.js and npm

Optional:

- AI provider credentials if you want provider-backed enrichment
- sandbox environment setup if you want real sandbox verification behavior

## Setup

### Windows

From the repository root:

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

### Windows

```powershell
.\.venv\Scripts\python backend/scripts/run_api.py
```

Auto-reload if you need it:

```powershell
.\.venv\Scripts\python backend/scripts/run_api.py --reload
```

### Linux

```bash
./.venv/bin/python backend/scripts/run_api.py
```

Auto-reload if you need it:

```bash
./.venv/bin/python backend/scripts/run_api.py --reload
```

Backend URLs:

- API: `http://localhost:8000`
- Docs: `http://localhost:8000/docs`
- `http://localhost:8000/` returning `404` is expected

## Start The Frontend

Use production mode for testing and demos.

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

## Quick End-To-End Smoke Test

Use the smoke inputs already in the repo if available:

- `outputs/smoke_inputs/suspicious_scan_small.pcap`
- `outputs/smoke_inputs/benign_small.pcap`
- `outputs/smoke_inputs/corrupt_input.pcap`

### Recommended full-system test

1. Start the backend
2. Start the frontend in production mode
3. Open `http://localhost:3000`
4. Go to `/analysis/new`
5. Upload one or more PCAPs
6. Set worker count to `2` or more
7. Select a stage-1 profile
8. Submit
9. Confirm redirect to `/total-jobs/{totalJobId}`
10. Wait for deterministic child analysis to finish
11. Trigger enrichment from:
   - `/total-jobs`
   - or `/total-jobs/{totalJobId}`
12. Verify parent artifacts and dedupe summary

## What To Verify In The UI

### Submission

On `/analysis/new`:

- multi-file input works
- one file and many files use the same flow
- worker count minimum is `2`
- stage-1 profile selector shows `fast`, `standard`, and `full`
- submission redirects to a total-job page

### Total-job list

On `/total-jobs`:

- parent jobs appear
- file counts and worker counts appear
- partial-batch warnings appear if some child jobs failed
- direct enrichment actions appear:
  - `Run AI`
  - `Retry AI`
  - `Re-run AI`

### Total-job detail

On `/total-jobs/{totalJobId}`:

- child jobs appear with status and progress
- selected stage-1 profile appears on the parent total-job summary
- child rows show deep-dive and payload-carving execution state
- failed children are clearly called out
- enrichment actions appear:
  - `Run AI Summary + Sandbox`
  - `Retry AI Summary + Sandbox`
  - `Re-run AI Summary + Sandbox`
- parent artifacts load after enrichment:
  - markdown summary
  - summary JSON
  - sandbox JSON
- dedupe summary appears after enrichment

## Output Artifacts

### Child jobs

Stored under:

- `outputs/analysis_jobs/<analysis_job_id>/`

Expected files:

- `job.json`
- `report.json`
- `report.md`
- `metrics.json`
- `guardrail_audit.json`
- `analysis_record.json`

### Total jobs

Stored under:

- `outputs/total_jobs/<total_job_id>/`

Expected files after submit:

- `total_job.json`

Expected files after enrichment:

- `summary.json`
- `summary.md`
- `sandbox.json`

## Dedupe Test

To test duplicate-PCAP dedupe behavior, use two identical files plus one unique file.

### Linux example

```bash
cp outputs/smoke_inputs/suspicious_scan_small.pcap /tmp/dup_a.pcap
cp outputs/smoke_inputs/suspicious_scan_small.pcap /tmp/dup_b.pcap
cp outputs/smoke_inputs/benign_small.pcap /tmp/unique_c.pcap
```

### Windows example

```powershell
Copy-Item outputs\smoke_inputs\suspicious_scan_small.pcap $env:TEMP\dup_a.pcap
Copy-Item outputs\smoke_inputs\suspicious_scan_small.pcap $env:TEMP\dup_b.pcap
Copy-Item outputs\smoke_inputs\benign_small.pcap $env:TEMP\unique_c.pcap
```

Submit all three files in one batch, then run enrichment.

Expected result:

- all child jobs still exist
- parent enrichment uses only unique completed PCAPs
- dedupe metadata appears in:
  - `summary.json`
  - `sandbox.json`
- dedupe summary appears on the total-job detail page

## Verification Commands

### Path-based batch helper smoke test

Linux:

```bash
python backend/scripts/submit_batch_to_api.py outputs/smoke_inputs --workers 2 --analysis-profile standard
```

Re-run the same command to confirm skip-existing behavior.

### Backend compile check

Windows:

```powershell
.\.venv\Scripts\python -m compileall backend
```

Linux:

```bash
./.venv/bin/python -m compileall backend
```

### Backend tests

Windows:

```powershell
.\.venv\Scripts\python -m unittest discover -s backend\tests -v
```

Linux:

```bash
./.venv/bin/python -m unittest discover -s backend/tests -v
```

### Frontend checks

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

Current note:

- frontend lint still reports one existing warning from TanStack Table / React Compiler compatibility in `frontend/app/analysis/history/data-table.tsx`

## Troubleshooting

### Backend root shows `404`

That is expected. Use `http://localhost:8000/docs`.

### Frontend dev mode behaves strangely

`npm run dev` is more sensitive than `npm run start`. If localhost looks stale:

1. clear site data for `http://localhost:3000`
2. unregister any old service worker for that origin
3. restart the frontend server
4. hard refresh the browser

### PowerShell blocks npm or npx

Use `cmd /c`:

```powershell
cmd /c npm run lint
cmd /c npm run build
```

### No AI provider configured

That is fine for deterministic testing. Parent enrichment behavior may fall back depending on your provider configuration.

### Sandbox is unavailable

Review sandbox-related setup and environment details in `backend/README.md`.

### Frontend cannot reach backend

Check:

- backend is running on `http://localhost:8000`
- frontend is running on `http://localhost:3000`
- `NEXT_PUBLIC_API_BASE_URL` is correct if overridden
