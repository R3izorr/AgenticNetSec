# AgenticNetSec v1 Architecture (REST + Async Jobs)

## Data Flow

1. `POST /api/v1/analysis` accepts either:
   - `file` upload (multipart), or
   - `pcap_path` (multipart/json)
2. Service creates `analysis_job_id`, persists `job.json`, and queues background execution.
3. Job runs autonomous pipeline with persisted phase updates:
   - ingest/pre-check + metadata
   - parse summary
   - forensic findings
   - optional deep dive + zero-day heuristics
   - reasoning/report generation
   - guardrail/policy enforcement
4. Artifacts are stored in `outputs/analysis_jobs/<job_id>/`:
   - `job.json`
   - `report.json`
   - `report.md`
   - `metrics.json`
   - `guardrail_audit.json`
5. Client polls status/history and downloads artifacts via REST.

## Endpoints

- `POST /api/v1/analysis`
- `GET /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`
- `GET /api/v1/analysis/{job_id}/guardrail-audit`

## Core Components

- `backend/src/analysis_engine.py`
  - Orchestrates end-to-end autonomous run and emits real phase/progress callbacks.
- `backend/src/planner.py`
  - Selects pipeline depth and reasoning mode.
- `backend/src/tool_executor.py`
  - Enforces allowlist, timeout, retry, fallback.
- `backend/src/guardrails.py`
  - Input/tool/policy guardrail decisions plus contradiction checks and audit trace generation.
- `backend/src/forensic_schema.py`
  - Forensic report schema with evidence references, MITRE mappings, uncertainty fields, and richer job metadata.
- `backend/src/observability.py`
  - Per-phase timings plus token-aware cost and artifact-size assumptions.
- `backend/api/app.py`
  - FastAPI async-job endpoints.
- `backend/api/job_store.py`
  - Persistent job state + artifact metadata storage.

## Notes

- WebSocket streaming is intentionally deferred to a later phase.
- The system is intentionally read-only: it produces analysis artifacts and never executes host/network containment actions.
- `backend/scripts/run_api.py` defaults to `reload=False`; use `--reload` only for local development.
