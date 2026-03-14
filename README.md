# AgenticNetSec

Backend-first forensic analyzer with a Next.js frontend shell.

## Structure

- `backend/src/`: analysis, guardrails, planner, schema, observability
- `backend/api/`: REST API (`/api/v1/analysis` async job flow)
- `backend/scripts/`: CLI tools (`run.py`, `batch_analyze.py`, `summarize_results.py`, `verify_findings.py`, `run_api.py`)
- `backend/config/`: local settings template
- `backend/tests/`: schema/guardrail tests
- `frontend/`: Next.js + React + Tailwind UI
- `outputs/`: reports, metrics, and analysis job artifacts
- `docs/`: project requirements and checklist

## Setup (recommended)

```bash
python -m virtualenv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

## Run

CLI analysis:

```bash
.\.venv\Scripts\python backend/scripts/run.py /path/to/file.pcap --no-ai
```

Run REST API service:

```bash
.\.venv\Scripts\python backend/scripts/run_api.py
```

### REST endpoints

- `POST /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`

## Output Location

Generated outputs are stored in `outputs/`.
