# Batch-First Total Job Plan

## Current Status

Last reviewed against the codebase on `2026-04-06` after adding the combined all-total-jobs summary flow.

### Implemented

- Batch-first submission exists through `POST /api/v1/analysis/batch`.
- The submission UI at `frontend/app/analysis/new/page.tsx` accepts one or more files.
- Worker count is exposed in the frontend and validated with a minimum of `2`.
- The backend creates one parent `total_job` and one child `analysis_job` per file.
- Stage 1 child jobs are forced to run with:
  - `use_ai = false`
  - `enable_sandbox = false`
- The planner now supports request-level sandbox control instead of env-only control.
- Child jobs persist the normal artifacts plus `analysis_record.json`.
- Parent total-job APIs exist:
  - `GET /api/v1/total-jobs`
  - `GET /api/v1/total-jobs/{total_job_id}`
  - `POST /api/v1/total-jobs/{total_job_id}/enrich`
  - `GET /api/v1/total-jobs/{total_job_id}/summary.json`
  - `GET /api/v1/total-jobs/{total_job_id}/summary.md`
  - `GET /api/v1/total-jobs/{total_job_id}/sandbox`
- Frontend routes exist:
  - `/total-jobs`
  - `/total-jobs/[totalJobId]`
- The total-job detail page can trigger enrichment, rerun enrichment, and render parent-level artifacts.
- The total-job detail page now includes a dedicated batch summary action for the whole parent job.
- The `/total-jobs` list page can trigger enrichment directly.
- The `/total-jobs` list page now exposes a `Summary` action for completed parent jobs.
- The `/total-jobs` page now also exposes one combined all-scans summary action that analyzes all completed child scans across all total jobs in one artifact set.
- Combined all-total-jobs summary APIs now exist:
  - `GET /api/v1/total-jobs/summary/status`
  - `POST /api/v1/total-jobs/summary/enrich`
  - `GET /api/v1/total-jobs/summary/json`
  - `GET /api/v1/total-jobs/summary/markdown`
  - `GET /api/v1/total-jobs/summary/sandbox`
- The combined all-scans summary route now runs:
  - initial AI campaign summary
  - sandbox verification across the campaign records
  - targeted AI-authored tshark follow-up for weak sections
  - final AI report over the enriched evidence
- The per-total-job enrichment route now runs the same campaign AI flow:
  - initial AI campaign summary
  - sandbox verification across that total job's deduplicated records
  - targeted AI-authored tshark follow-up for weak sections
  - final AI report over the enriched evidence
- Total-job enrichment now deduplicates duplicate PCAPs before AI and sandbox processing.
- Total-job enrichment now persists richer campaign artifacts alongside the final report:
  - `aggregate_summary.json`
  - `scan_results.json`
  - `scan_results.jsonl`
  - `scan_results.ai-tshark.jsonl`
  - `initial_summary.md`
  - `campaign_plan.json`
  - `summary.json`
  - `summary.md`
  - `sandbox.json`
- The total-job detail page now shows:
  - dedupe summary
  - removed duplicate files
  - partial-batch warnings when child jobs fail
- The total-job list page now shows a partial-batch warning when some child jobs failed.

### Verified

- Frontend `npm run lint` passes for the current implementation.
- Frontend `npm run build` passes in production mode when font/network access is available.
- The new total-job routes compile:
  - `/total-jobs`
  - `/total-jobs/[totalJobId]`

### Not Yet Implemented

- There is still no dedicated retry policy or backend-side retry history for enrichment attempts.
- The parent enrichment UX still renders aggregate outputs mainly as raw JSON and markdown rather than a more structured analyst view.
- The batch-job docs outside this plan are not all updated yet to describe the total-job-first workflow.

### Important Truth About Current Behavior

- AI is only triggered at the total-job enrichment stage, not during stage-1 batch submission.
- Sandbox is also only triggered at the total-job enrichment stage, not during stage-1 batch submission.
- The total-job detail page supports:
  - `Run AI Summary + Sandbox`
  - `Retry AI Summary + Sandbox`
  - `Re-run AI Summary + Sandbox`
- The total-job list page supports:
  - `Run AI`
  - `Retry AI`
  - `Re-run AI`
- Parent enrichment deduplicates duplicate completed PCAPs before AI and sandbox processing and persists dedupe metadata in:
  - `summary.json`
  - `sandbox.json`
- Parent enrichment now also persists the initial campaign summary and follow-up planning artifacts in:
  - `initial_summary.md`
  - `campaign_plan.json`

## Goal

Move the product from a mixed single-file and per-file-first submission model to a batch-first model:

1. The frontend always submits one batch of files.
2. A batch may contain one file or many files.
3. The backend creates one `total_job` for the batch.
4. The backend creates one child analysis job per file inside that `total_job`.
5. Stage 1 runs deterministic code-only analysis.
6. Stage 2 is triggered later by the user to run AI summary and sandbox enrichment across the finished batch.

This keeps the first run fast, deterministic, and cheaper, while making AI and sandbox a deliberate second step.

## Product Rules

### Submission

- The frontend input should support multiple files by default.
- If the user wants to analyze one file, they still use the same batch flow with one file selected.
- The frontend should expose a worker-count input.
- Worker count must have a minimum value of `2`.
- The worker count should be passed to the backend batch execution path.

### Stage 1: Deterministic Analysis

- Every submitted file becomes one child analysis job.
- Stage 1 must not use AI summary.
- Stage 1 must not use sandbox verification.
- Stage 1 should use the existing deterministic analyzer, detectors, deep-dive logic, and code-generated report flow only.
- Stage 1 writes normal per-file job artifacts as it does today.

### Stage 2: Delayed Enrichment

- After the child jobs are done, the user can trigger batch enrichment from the new total-job page.
- This enrichment stage runs:
  - aggregate AI summary
  - sandbox verification
- This stage works from existing finished child job outputs rather than re-running all initial parsing unless truly necessary.
- For large multi-day imports, such as a 9-day PCAP split into 129 child files, the primary summary control should live on the total-job page and summarize the whole parent batch rather than encouraging per-child summary review.
- For repeated or rolling imports, the `/total-jobs` page should also support one combined summary across all completed child scans from all total jobs so the analyst can summarize the full body of completed scans in one run.

## Core Domain Model

### Child Analysis Job

Existing concept, still needed.

Purpose:

- Represents one analyzed PCAP file.
- Stores per-file artifacts and status.

Expected artifacts:

- `report.json`
- `report.md`
- `metrics.json`
- `guardrail_audit.json`

### Total Job

New parent concept.

Purpose:

- Represents one batch submission from the frontend.
- Tracks all included files and all child analysis jobs.
- Holds batch-level enrichment state and aggregate artifacts.

Suggested storage:

- `outputs/total_jobs/<total_job_id>/total_job.json`
- `outputs/total_jobs/<total_job_id>/summary.json`
- `outputs/total_jobs/<total_job_id>/summary.md`
- `outputs/total_jobs/<total_job_id>/sandbox.json`

Suggested `total_job.json` shape:

```json
{
  "total_job_id": "total_123",
  "status": "running",
  "stage": "deterministic_analysis",
  "created_at": "2026-04-03T00:00:00Z",
  "updated_at": "2026-04-03T00:00:00Z",
  "worker_count": 4,
  "file_count": 3,
  "children": [
    {
      "analysis_job_id": "analysis_a",
      "filename": "a.pcap",
      "status": "completed"
    }
  ],
  "deterministic_complete": false,
  "enrichment_status": "not_started"
}
```

## End-to-End Flow

### Flow A: Batch Submit

1. User opens the analysis submission page.
2. User selects one or more files.
3. User chooses worker count, minimum `2`.
4. Frontend sends one batch request.
5. Backend creates one `total_job`.
6. Backend creates child analysis jobs for each file.
7. Backend runs deterministic analysis only for each child.
8. Frontend redirects to the new total-job page.

### Flow B: Batch Completion

1. Child jobs continue running.
2. Total-job page polls parent status.
3. Parent status is derived from child statuses.
4. When all child jobs reach terminal state, the total job is marked ready for enrichment.

### Flow C: AI Summary and Sandbox Trigger

1. User clicks `Run AI Summary + Sandbox`.
2. Backend validates that the total job is in a suitable state.
3. Backend loads completed child-job artifacts.
4. Backend builds aggregate batch context.
5. Backend runs AI summary.
6. Backend runs sandbox verification flow.
7. Backend writes total-job-level artifacts.
8. Frontend shows enriched outputs on the total-job page.

Current implementation note:

- This flow exists today from both:
  - the total-job detail page
  - the total-job list page
- Duplicate completed PCAPs are removed before parent-level AI and sandbox processing.
- The detail page surfaces dedupe metadata after enrichment so the reduced record count is explicit.

## Backend Plan

### New or Changed API Endpoints

#### Submission

- `POST /api/v1/analysis/batch`

Responsibilities:

- accept one or more uploaded files
- accept `worker_count`
- create one `total_job`
- create one child analysis job per file
- force deterministic mode for child runs

#### Total Job Read APIs

- `GET /api/v1/total-jobs`
- `GET /api/v1/total-jobs/{total_job_id}`

Responsibilities:

- list total jobs
- show file count
- show child job states
- show enrichment readiness and progress

#### Total Job Enrichment APIs

- `POST /api/v1/total-jobs/{total_job_id}/enrich`
- `GET /api/v1/total-jobs/{total_job_id}/summary.json`
- `GET /api/v1/total-jobs/{total_job_id}/summary.md`
- `GET /api/v1/total-jobs/{total_job_id}/sandbox`

Responsibilities:

- trigger stage-2 AI summary and sandbox
- serve total-job-level artifacts

### Execution Model

#### Batch Worker Control

- Use the batch-analysis worker model for deterministic execution.
- Worker count comes from the frontend.
- Minimum worker count is `2`.
- Backend must validate and clamp invalid worker values.

Suggested rule:

- if frontend sends less than `2`, backend resets to `2`
- optionally apply a safe upper bound

#### Deterministic Mode

Current single-file analysis must be made request-driven instead of environment-driven only.

Needed behavior for stage 1:

- `use_ai = false`
- `enable_sandbox = false`

This means the backend planner and engine should support explicit run-mode flags rather than only reading environment state.

#### Enrichment Mode

Stage 2 should be separate from stage 1.

It should:

- read completed child artifacts
- build aggregate context
- generate the AI summary
- run sandbox verification
- write parent-level artifacts

This should be orchestrated as total-job work, not as another normal child analysis job.

## Frontend Plan

### Submission Page

Route:

- `/analysis/new`

Changes:

- make multi-file input the default and only file-based flow
- treat one file and many files the same
- add worker count input
- worker input minimum is `2`
- remove stage-1 AI and sandbox choices from the submission UI
- submission success should redirect to `/total-jobs/{totalJobId}`

### Total Job Page

New route:

- `/total-jobs/[totalJobId]`

Main content:

- total job ID
- total file count
- worker count used
- aggregate job counts:
  - queued
  - running
  - completed
  - failed
- file table with:
  - filename
  - child analysis job ID
  - status
  - runtime
  - risk
  - confidence

Actions:

- `Run AI Summary + Sandbox`
- disable while deterministic analysis is not ready
- show enrichment progress once triggered

Suggested sections:

- Overview
- Files
- Child Jobs
- Aggregate Summary
- Sandbox Results

## Persistence Plan

### Existing Child Jobs

Keep:

- `outputs/analysis_jobs/<analysis_job_id>/...`

### New Total Jobs

Add:

- `outputs/total_jobs/<total_job_id>/total_job.json`

Optional additional artifacts:

- `summary.json`
- `summary.md`
- `sandbox.json`

The parent manifest should be the source of truth for:

- batch composition
- worker count
- current stage
- child references
- enrichment status

## Status Model

### Total Job Status

Suggested values:

- `queued`
- `running`
- `completed`
- `failed`

### Total Job Stage

Suggested values:

- `deterministic_analysis`
- `ready_for_enrichment`
- `enrichment_running`
- `enrichment_completed`
- `enrichment_failed`

### Child Job Status

Reuse current values:

- `queued`
- `running`
- `completed`
- `failed`

## Edge Cases

### Partial Failure

If some child jobs fail:

- the total job should still be visible
- file-level failure should be explicit
- enrichment policy must be defined

Recommended default:

- allow enrichment if at least one child completed
- show a clear warning that enrichment is partial

### Re-run Enrichment

Recommended default:

- allow rerun from the total-job page
- overwrite the current canonical parent artifacts
- optionally archive older versions later if needed

### Large Batches

Recommended behavior:

- backend validates worker count
- total-job page avoids loading massive embedded artifacts up front
- detailed artifact fetches stay on demand

## Acceptance Criteria

The feature is done when:

1. The frontend can submit one or more files in one batch flow.
2. The frontend can send worker count with a minimum of `2`.
3. The backend creates one total job plus child jobs for each file.
4. Initial child analysis runs without AI and without sandbox.
5. The system persists a total-job JSON manifest containing all analyzed files in that batch.
6. A new frontend total-job page lists the files and file count.
7. That page includes a button to trigger AI summary and sandbox.
8. The batch enrichment flow writes parent-level summary and sandbox artifacts.

## Build Order

1. Add total-job persistence model and store.
2. Implement `POST /api/v1/analysis/batch`.
3. Add deterministic-only child-run controls.
4. Add total-job read APIs.
5. Build the total-job frontend page.
6. Add total-job enrichment trigger API.
7. Show parent-level AI summary and sandbox outputs in the frontend.
