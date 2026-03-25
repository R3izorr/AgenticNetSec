# AgenticNetSec

Backend-first forensic analyzer with a Next.js frontend shell.

The agent is read-only by design: it analyzes PCAP evidence and writes report artifacts only. It does not execute containment actions or mutate analyst environments.

## Structure

- `backend/src/`: analysis, guardrails, planner, schema, observability
- `backend/api/`: REST API (`/api/v1/analysis` async job flow)
- `backend/scripts/`: CLI tools (`run.py`, `batch_analyze.py`, `summarize_results.py`, `verify_findings.py`, `run_api.py`)
- `backend/config/`: local settings template
- `backend/tests/`: schema/guardrail/API tests
- `frontend/`: Next.js + React + Tailwind UI
- `outputs/`: reports, metrics, and analysis job artifacts
- `docs/`: project requirements and checklist

## Setup (recommended)

```bash
python -m virtualenv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

For a full Windows-first setup, run, and verification walkthrough, see [README_RUN_TEST.md](/d:/Github%20Projects/AgenticNetSec/README_RUN_TEST.md) and [Full_System_User_Testing_Guide.md](/d:/Github%20Projects/AgenticNetSec/docs/Full_System_User_Testing_Guide.md).

## Run

CLI analysis:

```bash
.\.venv\Scripts\python backend/scripts/run.py /path/to/file.pcap --no-ai
```

Run REST API service:

```bash
.\.venv\Scripts\python backend/scripts/run_api.py
```

Dev auto-reload is now opt-in:

```bash
.\.venv\Scripts\python backend/scripts/run_api.py --reload
```

Backend URL note:

- `http://localhost:8000/` returns `404 Not Found` by design
- use `http://localhost:8000/docs` for FastAPI docs
- use `http://localhost:3000` for the actual frontend user-testing flow

Frontend UAT note:

- prefer `npm run build` followed by `npm run start` for demos, stakeholder walkthroughs, and UAT
- keep `npm run dev` for active frontend development only because localhost cache or stale service-worker state from another project can make dev mode noisy

### REST endpoints

- `POST /api/v1/analysis`
- `GET /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`
- `GET /api/v1/analysis/{job_id}/guardrail-audit`

## Output Location

Generated outputs are stored in `outputs/`. Each analysis job also persists `job.json` alongside its artifacts in `outputs/analysis_jobs/<job_id>/` so history survives API restarts.

## Demo-Ready Additions

- Evidence-backed findings include MITRE ATT&CK mappings, evidence reference IDs, sampled frame numbers, and Wireshark filters.
- Guardrail decisions emit `guardrail_audit.json` with consistency checks, contradictions, and explicit read-only mode.
- Runtime metrics capture provider/model, fallback state, artifact sizes, and token-aware LLM cost when provider metadata is available.
- Job status/history responses now include persisted source metadata, artifact readiness, runtime summary, confidence, and risk context.
- Benchmark planning material lives in `docs/BenchmarkManifest.json`, and `backend/scripts/run_benchmark.py` can generate demo-friendly benchmark summaries.
