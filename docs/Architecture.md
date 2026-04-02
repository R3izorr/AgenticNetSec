# AgenticNetSec Architecture

## Overview

AgenticNetSec currently has two execution paths in the codebase:

1. Single-file analysis job
- `POST /api/v1/analysis`
- accepts one upload or one `pcap_path`
- runs the existing `AnalysisEngine`
- can still use AI and sandbox depending on request flags and backend runtime settings

2. Batch-first total-job analysis
- `POST /api/v1/analysis/batch`
- accepts one or more uploaded PCAP files
- creates one parent `total_job`
- creates one child analysis job per file
- runs deterministic code-only analysis first
- supports a later parent-level enrichment trigger for AI summary and sandbox

The current direction of the system is:
- deterministic first pass per file
- parent job tracks the batch
- AI summary and sandbox are deferred until explicitly triggered later

## Current Code Structure

### Frontend

- `frontend/app/analysis/new/page.tsx`
  - batch-first submission UI
  - accepts one or more PCAP files
  - sends `worker_count` with a minimum UI value of `2`
- `frontend/lib/api/analysis.ts`
  - frontend HTTP client for child-job and total-job APIs
- `frontend/lib/transport/analysis.ts`
  - raw transport contracts shaped like backend API responses
- `frontend/lib/adapters/analysis.ts`
  - transport-to-UI model mapping
- `frontend/lib/types/analysis.ts`
  - frontend domain types
- `frontend/hooks/use-total-jobs.ts`
  - total-job list polling
- `frontend/hooks/use-total-job-status.ts`
  - single total-job polling
- `frontend/components/layout/app-shell.tsx`
  - navigation now includes `Total Jobs`

Current frontend state:
- batch submission is implemented
- total-job API integration is implemented at the data layer
- legacy child-job pages still exist
- a dedicated total-job page is the next UX layer to finish

### Backend API

- `backend/api/app.py`
  - FastAPI entrypoint
  - single-job routes
  - batch-first total-job routes
  - background orchestration for child analysis and later enrichment
- `backend/api/job_store.py`
  - child analysis job persistence
- `backend/api/total_job_store.py`
  - parent total-job persistence

### Backend Analysis Core

- `backend/src/analysis_engine.py`
  - main analysis pipeline
  - now persists an internal `analysis_record` for later total-job enrichment
- `backend/src/planner.py`
  - request planning
  - supports request-level `enable_sandbox`
- `backend/src/analyzer.py`
  - packet summary and metadata extraction
- `backend/src/detectors.py`
  - rule-based network findings
- `backend/src/deep_dive.py`
  - deeper evidence interpretation for richer captures
- `backend/src/report_ai.py`
  - deterministic or provider-backed report rendering
- `backend/src/guardrails.py`
  - report validation and review signaling

### Backend Enrichment Helpers

- `backend/build_aggregate.py`
  - aggregate record building across analyzed files
- `backend/generate_results_report.py`
  - parent-level markdown summary generation
- `backend/enrich_record.py`
  - sandbox-oriented enrichment helpers used during delayed parent enrichment

## Current Mermaid Diagram

```mermaid
flowchart TD
    A[Frontend Batch Submit\n/analysis/new] --> B[POST /api/v1/analysis/batch]
    B --> C[FastAPI app.py]
    C --> D[Create total_job\noutputs/total_jobs/<total_job_id>/total_job.json]
    C --> E[Create child analysis jobs\noutputs/analysis_jobs/<analysis_job_id>/job.json]
    E --> F[ProcessPoolExecutor\nmin 2 workers]
    F --> G[AnalysisEngine.run\nuse_ai=false\nenable_sandbox=false]
    G --> H[analyzer.py\ndetectors.py\ndeep_dive.py\nreport_ai fallback/code path]
    H --> I[Child artifacts\nreport.json\nreport.md\nmetrics.json\nguardrail_audit.json\nanalysis_record.json]
    I --> J[Total job stage = ready_for_enrichment]
    J --> K[Frontend Total Job Page\nplanned consumer of total-job APIs]
    K --> L[POST /api/v1/total-jobs/{id}/enrich]
    L --> M[Load child analysis_record.json files]
    M --> N[build_aggregate + generate_results_report]
    M --> O[enrich_record / sandbox enrichment]
    N --> P[summary.json + summary.md]
    O --> Q[sandbox.json]
    P --> R[Total job stage = enrichment_completed]
    Q --> R
```

## Main Runtime Flow

### 1. Ingestion

#### Single-file path
- `POST /api/v1/analysis`
- receives one file or one `pcap_path`
- creates one `analysis_job`
- starts one async background run

#### Batch-first path
- `POST /api/v1/analysis/batch`
- receives one or more uploaded files
- validates worker count with a minimum of `2`
- creates:
  - one `total_job`
  - one child `analysis_job` per file
- dispatches child work through a `ProcessPoolExecutor`

## 2. Child Analysis Pipeline

Each child job runs through `backend/src/analysis_engine.py`.

Current pipeline stages:
- input validation
- metadata extraction
- packet summary analysis
- heuristic detections
- optional deep dive for larger captures
- report construction
- metrics generation
- guardrail audit generation
- internal `analysis_record` generation for later batch enrichment

Core modules involved:
- `backend/src/analyzer.py`
  - compact packet and protocol summary
- `backend/src/detectors.py`
  - rule-based findings such as:
    - external remote access indicators
    - external scanning
    - SMB/RPC scanning
    - DCERPC account activity
    - exfiltration indicators
    - payload deployment indicators
- `backend/src/deep_dive.py`
  - additional narrative and A/B/C/D attack-stage interpretation
- `backend/src/report_ai.py`
  - report generation
  - can produce provider-backed AI output or deterministic fallback text
- `backend/src/guardrails.py`
  - output consistency and human-review decisioning

## 3. Deterministic-First Batch Behavior

The current batch-first path forces stage 1 child analysis to run with:
- `use_ai = false`
- `enable_sandbox = false`

This means the initial batch execution is designed to:
- produce baseline per-file artifacts quickly
- avoid AI cost in the first pass
- avoid sandbox execution in the first pass
- preserve enough structured information for later enrichment

The additional persisted artifact that enables this is:
- `analysis_record.json`

Stored per child job in:
- `outputs/analysis_jobs/<analysis_job_id>/`

## 4. Parent Total Job

The parent job is persisted by `backend/api/total_job_store.py`.

It tracks:
- total job ID
- batch file count
- worker count
- child job references
- deterministic stage progress
- enrichment stage progress
- enrichment error state

Stored in:
- `outputs/total_jobs/<total_job_id>/total_job.json`

Current parent stages in code:
- `queued`
- `deterministic_analysis`
- `ready_for_enrichment`
- `enrichment_running`
- `enrichment_completed`
- `failed`

## 5. Delayed Enrichment Flow

Parent-level enrichment is currently triggered by:
- `POST /api/v1/total-jobs/{total_job_id}/enrich`

This flow currently does the following:
- loads completed child `analysis_record.json` artifacts
- enriches records with sandbox-oriented follow-up using `enrich_record`
- builds aggregate signals with `build_aggregate`
- generates batch summary markdown with `generate_results_report`
- writes parent-level artifacts

Parent-level output artifacts:
- `summary.json`
- `summary.md`
- `sandbox.json`

Stored in:
- `outputs/total_jobs/<total_job_id>/`

## 6. Current API Surface

### Child analysis APIs
- `POST /api/v1/analysis`
- `GET /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`
- `GET /api/v1/analysis/{job_id}/guardrail-audit`

### Parent total-job APIs
- `POST /api/v1/analysis/batch`
- `GET /api/v1/total-jobs`
- `GET /api/v1/total-jobs/{total_job_id}`
- `POST /api/v1/total-jobs/{total_job_id}/enrich`
- `GET /api/v1/total-jobs/{total_job_id}/summary.json`
- `GET /api/v1/total-jobs/{total_job_id}/summary.md`
- `GET /api/v1/total-jobs/{total_job_id}/sandbox`

## 7. Storage Model

### Child job artifacts
Stored in:
- `outputs/analysis_jobs/<analysis_job_id>/`

Current files:
- `job.json`
- `report.json`
- `report.md`
- `metrics.json`
- `guardrail_audit.json`
- `analysis_record.json`

### Parent total-job artifacts
Stored in:
- `outputs/total_jobs/<total_job_id>/`

Current files:
- `total_job.json`
- `summary.json` after enrichment
- `summary.md` after enrichment
- `sandbox.json` after enrichment

### Offline script artifacts
Still present for script-based workflows:
- `outputs/scan_results.jsonl`
- `outputs/scan_results.ai-tshark.jsonl`
- `outputs/aggregate_summary.json`
- `outputs/incident_report.md`

## 8. Frontend Structure

The frontend is currently a Next.js app under `frontend/`.

Current frontend responsibilities in code:
- submit batch uploads from `/analysis/new`
- send worker count with a minimum UI value of `2`
- keep legacy child-job views for per-file artifacts
- move navigation toward total-job-based monitoring

Current frontend integration points:
- `frontend/lib/api/analysis.ts`
- `frontend/lib/transport/analysis.ts`
- `frontend/lib/types/analysis.ts`
- `frontend/lib/adapters/analysis.ts`

The frontend is in transition from a child-job-first UX to a total-job-first UX.

## 9. Execution Boundaries

### What deterministic stage 1 is allowed to do
- parse PCAPs locally
- run rule-based analysis
- build deterministic reports
- persist structured artifacts for later enrichment

### What stage 1 does not do in the batch-first path
- no AI summary
- no sandbox verification

### What parent enrichment is allowed to do
- read child artifacts
- build aggregate summary context
- run AI summary generation
- run sandbox-oriented enrichment helpers

### What AI is not allowed to do
- execute arbitrary shell commands
- operate outside bounded backend flows
- access unrestricted raw environment tooling directly

### What the sandbox path is allowed to do
- run bounded `tshark` queries
- inspect one PCAP at a time
- return compact structured results

## 10. Current Limitations

- The architecture doc previously described the older offline-summary-first model and is now being updated to reflect the live batch-first API structure.
- The backend currently supports both the legacy single-file API path and the new total-job batch path, so the system is in an overlap phase rather than a fully simplified final state.
- The frontend total-job UX is not yet fully complete even though the backend total-job APIs now exist.
- The enrichment path currently reuses offline enrichment helpers and should later be tightened into a more explicit parent-job service layer.
- The base detection logic remains somewhat RDP-biased and may still under-detect some WinRM or VPN-centric access patterns.

## 11. Recommended Near-Term Direction

1. Finish the total-job-first frontend pages.
2. Keep child-job pages as drill-down views only.
3. Treat `analysis_record.json` as the stable bridge between deterministic stage 1 and enrichment stage 2.
4. Keep AI summary and sandbox as explicit second-step operations.
5. Continue moving shared batch logic into reusable backend services instead of duplicating script behavior and API behavior.
