# Batch-First Total Job Implementation Checklist

## Current Status Snapshot

Last reviewed against the codebase on `2026-04-06` after adding the combined all-total-jobs summary flow.

- `[done]` Phase 1: Data model and persistence
- `[done]` Phase 2: Batch submission backend
- `[done]` Phase 3: Deterministic child runs
- `[done]` Phase 4: Worker execution path
- `[done]` Phase 5: Total job read APIs
- `[done]` Phase 6: Frontend submission flow
- `[done]` Phase 7: Total job frontend page
- `[done]` Phase 8: Enrichment trigger backend
- `[done]` Phase 9: Enrichment frontend UX
- `[pending]` Phase 10: Error handling and retry rules

### What is now done for Phase 9

- The total-job detail page can trigger enrichment.
- The total-job detail page can rerun or retry enrichment.
- The `/total-jobs` list page can trigger enrichment directly.
- The `/total-jobs` list page now has a dedicated `Summary` action for completed parent jobs.
- The `/total-jobs` list page now has a top-level all-scans summary action for all completed child scans across all total jobs.
- The backend now exposes combined all-total-jobs summary artifacts and status under `/api/v1/total-jobs/summary/...`.
- The combined all-scans summary now uses the campaign AI route:
  - initial AI summary
  - sandbox verification
  - targeted AI-authored tshark follow-up
  - final AI report
- The total-job detail page can render:
  - `summary.md`
  - `summary.json`
  - `sandbox.json`
- The total-job detail page now includes a clear parent-level batch summary action instead of pushing users toward child-by-child summary review.
- The total-job detail page now surfaces dedupe metadata.
- The total-job detail page now surfaces partial-batch warnings when child jobs fail.
- The `/total-jobs` list page now surfaces partial-batch warnings when some child jobs fail.

### What remains for Phase 10

- define a clearer backend retry policy beyond rerunning the same enrichment endpoint
- add richer structured rendering for parent artifacts if desired
- decide whether enrichment attempts should be versioned or audited separately

## Scope

This checklist translates the batch-first total-job plan into a build order for the current repository.

## Phase 1: Data Model and Persistence

- Status: `[done]`

- Add a `TotalJobRecord` model.
- Add a `TotalJobStore`.
- Create storage under `outputs/total_jobs/`.
- Persist:
  - `total_job_id`
  - `worker_count`
  - `file_count`
  - `children`
  - status
  - stage
  - timestamps
  - enrichment state

Definition of done:

- a total-job manifest can be created, loaded after restart, updated, and listed

## Phase 2: Batch Submission Backend

- Status: `[done]`

- Add `POST /api/v1/analysis/batch`.
- Accept:
  - `files[]`
  - `worker_count`
  - optional provider/model fields for later enrichment defaults if still desired
- Validate:
  - at least one file
  - `worker_count >= 2`
- Create one total job.
- Create one child analysis job per file.
- Associate each child analysis job with its total job.

Definition of done:

- backend returns one total job plus child-job references for a batch submit

## Phase 3: Deterministic Child Runs

- Status: `[done]`

- Force stage-1 child jobs to run with:
  - `use_ai = false`
  - `enable_sandbox = false`
- Refactor planner and engine so sandbox is request-controlled, not env-only.
- Keep normal deterministic reporting outputs.

Definition of done:

- a batch submit never triggers AI summary or sandbox during initial analysis

## Phase 4: Worker Execution Path

- Status: `[done]`

- Reuse or align with `batch_analyze.py` worker model.
- Ensure the batch execution path uses at least `2` workers.
- Ensure worker count is visible in logs/metrics/manifest.
- Decide and implement a safe upper bound.

Definition of done:

- submitted worker count changes actual batch concurrency within validated limits

## Phase 5: Total Job Read APIs

- Status: `[done]`

- Add `GET /api/v1/total-jobs`.
- Add `GET /api/v1/total-jobs/{total_job_id}`.
- Return:
  - total job metadata
  - file count
  - worker count
  - child-job list
  - derived counts by status
  - enrichment status

Definition of done:

- frontend can fully render a total-job page using backend responses only

## Phase 6: Frontend Submission Flow

- Status: `[done]`

- Update `/analysis/new`.
- Keep file upload batch-first.
- Remove the need to think in terms of separate single-file mode.
- Add worker count UI.
- Set frontend minimum to `2`.
- Remove stage-1 AI/sandbox toggles from submission.
- Redirect to the new total-job page after submit.

Definition of done:

- submitting one file or many files follows the same path and lands on a total-job page

## Phase 7: Total Job Frontend Page

- Status: `[done]`

- Add route:
  - `/total-jobs/[totalJobId]`
- Show:
  - total job ID
  - file count
  - worker count
  - child-job counts by status
  - file list
  - child-job links
- Add polling while deterministic child jobs are active.

Definition of done:

- user can monitor a whole submitted batch from one page

## Phase 8: Enrichment Trigger Backend

- Status: `[done]`

- Add `POST /api/v1/total-jobs/{total_job_id}/enrich`.
- Validate:
  - total job exists
  - enough child outputs exist
  - enrichment is not already running
- Read child outputs.
- Build aggregate context.
- Run:
  - AI summary
  - sandbox verification
- Save:
  - `summary.json`
  - `summary.md`
  - `sandbox.json`

Definition of done:

- one backend endpoint can kick off the second-stage enrichment for a batch

## Phase 9: Enrichment Frontend UX

- Status: `[done]`

- Add button:
  - `Run AI Summary + Sandbox`
- Disable button until deterministic stage is ready.
- Show enrichment progress.
- Add tabs or sections for:
  - aggregate summary
  - sandbox outputs

Definition of done:

- user can trigger and review second-stage enrichment from the total-job page

## Phase 10: Error Handling and Retry Rules

- Status: `[pending]`

- Define partial-failure messaging.
- Handle rerun of enrichment.
- Handle child-job failures gracefully.
- Surface total-job warnings in the UI.

Recommended default:

- enrichment allowed if at least one child completed
- UI must show that some files failed or were skipped

Definition of done:

- failures are visible and do not make the workflow confusing

## API Contract Notes

### Batch Submit Response

Suggested shape:

```json
{
  "total_job_id": "total_123",
  "status": "queued",
  "stage": "deterministic_analysis",
  "worker_count": 4,
  "file_count": 3,
  "children": [
    {
      "analysis_job_id": "analysis_a",
      "filename": "a.pcap",
      "status": "queued"
    }
  ]
}
```

### Total Job Read Response

Suggested shape:

```json
{
  "total_job_id": "total_123",
  "status": "running",
  "stage": "deterministic_analysis",
  "worker_count": 4,
  "file_count": 3,
  "counts": {
    "queued": 0,
    "running": 1,
    "completed": 2,
    "failed": 0
  },
  "children": [
    {
      "analysis_job_id": "analysis_a",
      "filename": "a.pcap",
      "status": "completed"
    }
  ],
  "enrichment_status": "not_started"
}
```

## Repository Touchpoints

Likely backend files to change:

- `backend/api/app.py`
- `backend/api/job_store.py`
- new total-job store module under `backend/api/`
- `backend/src/analysis_engine.py`
- `backend/src/planner.py`
- batch orchestration module or script reuse path

Likely frontend files to change:

- `frontend/app/analysis/new/page.tsx`
- `frontend/lib/api/analysis.ts`
- `frontend/lib/transport/analysis.ts`
- `frontend/lib/types/analysis.ts`
- `frontend/lib/adapters/analysis.ts`
- new route under `frontend/app/total-jobs/[totalJobId]/`

## Out of Scope For This Change

- redesigning the existing report page
- replacing the current child analysis artifacts
- changing the forensic detector logic itself
- introducing user-configurable sandbox parameters beyond the one enrichment trigger

## Final Delivery Check

- `[done]` one-file and many-file submissions both work through batch
- `[done]` worker count exists on frontend and is validated with minimum `2`
- `[done]` deterministic stage never uses AI or sandbox
- `[done]` total-job manifest persists all analyzed files in the batch
- `[done]` new total-job page lists files and file count
- `[done]` enrichment button triggers AI summary and sandbox later
- `[done]` duplicate completed PCAPs are removed before parent enrichment
- `[done]` partial child-job failures are surfaced in the total-job UI
