# AgenticNetSec Run and Test Guide

This guide explains how to set up, run, and test AgenticNetSec from a fresh checkout.

AgenticNetSec is a read-only network forensic analysis system. It analyzes PCAP evidence and writes report artifacts, but it does not execute containment actions or change analyst environments.

## Prerequisites

Recommended Windows setup:

- Python 3.14 or compatible Python 3 environment
- Node.js and npm
- PowerShell or Command Prompt

Optional for AI-backed report generation:

- Gemini, OpenAI, Groq, or Ollama configuration

You can still run and test the system without AI by using `--no-ai`.

## Backend Setup

From the repository root:

```powershell
python -m virtualenv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

If you already created the environment, just reuse:

```powershell
.\.venv\Scripts\python -m pip install -r requirements.txt
```

## Frontend Setup

From the repository root:

```powershell
cd frontend
cmd /c npm install
cd ..
```

## Optional AI Provider Configuration

If you want AI-assisted report generation, start from:

`backend/config/local_settings.example.py`

You can define provider keys and model settings there, for example:

- `GEMINI_API_KEY`
- `OPENAI_API_KEY`
- `GROQ_API_KEY`
- `OLLAMA_BASE_URL`

If you do not configure any provider, you can still test the system with deterministic local reporting by using `--no-ai`.

## Run CLI Analysis

To run a direct backend analysis from the command line:

```powershell
.\.venv\Scripts\python backend/scripts/run.py outputs/smoke_inputs/suspicious_scan_small.pcap --no-ai
```

This is the easiest way to verify the backend works without starting the web stack.

You can also analyze any other PCAP path:

```powershell
.\.venv\Scripts\python backend/scripts/run.py path\to\capture.pcap --no-ai
```

## Run the FastAPI Backend

From the repository root:

```powershell
.\.venv\Scripts\python backend/scripts/run_api.py
```

The backend API runs on:

- `http://localhost:8000`

Important backend note:

- opening `http://localhost:8000/` will return `404 Not Found`
- that is expected because the backend does not define a root `/` page
- use `http://localhost:8000/docs` for FastAPI docs
- use `http://localhost:8000/api/v1/analysis` for the API surface

Supported REST endpoints:

- `POST /api/v1/analysis`
- `GET /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`
- `GET /api/v1/analysis/{job_id}/guardrail-audit`

## Frontend Startup Modes

### User Acceptance Testing / Demo

Use the stable production frontend path:

```powershell
cd frontend
cmd /c npm run build
cmd /c npm run start
```

This is the preferred path for:

- demo runs
- stakeholder walkthroughs
- UAT validation

### Development Only

Use dev mode only for active frontend development:

```powershell
cd frontend
cmd /c npm run dev
```

Important dev-mode warning:

- hydration warnings can appear in dev mode even when production works
- this repo does not register a service worker
- stale service workers or cached assets from another project on `http://localhost:3000` can interfere with dev mode

## Test the Backend

Run the backend unit tests from the repository root:

```powershell
d:\AgenticNetSec\.venv\Scripts\python.exe -m unittest discover -s d:\AgenticNetSec\backend\tests -v
```

This covers:

- forensic schema checks
- guardrail checks
- report AI usage parsing
- evidence reference generation
- API artifact endpoint coverage

Run the backend compile check:

```powershell
d:\AgenticNetSec\.venv\Scripts\python.exe -m compileall d:\AgenticNetSec\backend\src d:\AgenticNetSec\backend\scripts\run_benchmark.py
```

## Test the Frontend

From the `frontend` directory, run:

```powershell
cmd /c npm run lint
cmd /c npx tsc --noEmit
```

These checks validate the current frontend source, including the report view, raw artifacts page, and API contract types.

## Quick Smoke / Demo Run

Use the repo-local smoke inputs in:

- `outputs/smoke_inputs/suspicious_scan_small.pcap`
- `outputs/smoke_inputs/benign_small.pcap`
- `outputs/smoke_inputs/corrupt_input.pcap`

Recommended quick verification path:

1. Start the backend:

```powershell
.\.venv\Scripts\python backend/scripts/run_api.py
```

2. Start the frontend in a second terminal with the production path:

```powershell
cd frontend
cmd /c npm run build
cmd /c npm run start
```

3. Open `http://localhost:3000` and submit a smoke PCAP through the UI.

4. If you want to inspect the backend directly, use `http://localhost:8000/docs` instead of `http://localhost:8000/`.

5. Or run a smoke file directly through CLI:

```powershell
.\.venv\Scripts\python backend/scripts/run.py outputs/smoke_inputs/suspicious_scan_small.pcap --no-ai
```

6. Verify artifacts were produced.

## Output Artifacts

Async analysis jobs write artifacts to:

- `outputs/analysis_jobs/<job_id>/`

Expected artifacts:

- `report.json`
- `report.md`
- `metrics.json`
- `guardrail_audit.json`

Additional project outputs may also appear under:

- `outputs/`

## Troubleshooting

### `http://localhost:8000/` shows `404 Not Found`

That is expected. This backend does not expose a root landing page.

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

Recommended cleanup steps:

1. Open browser site settings or devtools for `http://localhost:3000`.
2. Unregister any service worker for that origin.
3. Clear site data and cache for `http://localhost:3000`.
4. Restart the frontend server.
5. Hard refresh the page.

### Python packages missing

Reinstall backend requirements:

```powershell
.\.venv\Scripts\python -m pip install -r requirements.txt
```

### npm or npx blocked in PowerShell

If PowerShell blocks script execution, run Node commands through `cmd /c`:

```powershell
cmd /c npm run lint
cmd /c npx tsc --noEmit
```

### No AI provider configured

Use `--no-ai` for CLI testing, or start the API and submit jobs knowing the system may fall back to deterministic report generation depending on configuration.

### Frontend cannot reach backend

Check:

- backend is running on `http://localhost:8000`
- frontend is running on `http://localhost:3000`
- `NEXT_PUBLIC_API_BASE_URL` is correct if overridden

### Corrupt PCAP testing

`outputs/smoke_inputs/corrupt_input.pcap` is useful for input/guardrail testing and error handling, not for a successful analysis path.
