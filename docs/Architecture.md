# AgenticNetSec v1 Architecture (REST + Async Jobs)

## Data Flow

1. `POST /api/v1/analysis` accepts either:
   - `file` upload (multipart), or
   - `pcap_path` (multipart/json)
2. Service creates `analysis_job_id` and queues background execution.
3. Job runs autonomous pipeline:
   - ingest/pre-check + metadata
   - parse summary
   - forensic findings
   - optional deep dive + zero-day heuristics
   - reasoning/report generation
   - guardrail/policy enforcement
4. Artifacts are stored in `outputs/analysis_jobs/<job_id>/`:
   - `report.json`
   - `report.md`
   - `metrics.json`
   - `guardrail_audit.json`
5. Client polls status and downloads artifacts via REST.

## Endpoints

- `POST /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`
- `GET /api/v1/analysis/{job_id}/guardrail-audit`

## Core Components

- `backend/src/analysis_engine.py`
  - Orchestrates end-to-end autonomous run.
- `backend/src/planner.py`
  - Selects pipeline depth and reasoning mode.
- `backend/src/tool_executor.py`
  - Enforces allowlist, timeout, retry, fallback.
- `backend/src/guardrails.py`
  - Input/tool/policy guardrail decisions plus contradiction checks and audit trace generation.
- `backend/src/forensic_schema.py`
  - Forensic report schema with evidence references, MITRE mappings, and uncertainty fields.
- `backend/src/observability.py`
  - Per-phase timings plus token-aware cost and artifact-size assumptions.
- `backend/api/app.py`
  - FastAPI async-job endpoints.
- `backend/api/job_store.py`
  - In-memory job state + artifact persistence.

## Notes

- WebSocket streaming is intentionally deferred to phase 2.
- The system is intentionally read-only: it produces analysis artifacts and never executes host/network containment actions.
