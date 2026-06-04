# Sprint 2: Persisted Job State

## Goal

Move job and total-job metadata into the database while keeping artifacts local.

## Subagents

- `backend-developer`
- `database-engineer`
- `test-engineer`
- `integration-lead`

## Develop

- wrap or replace `backend/api/job_store.py`
- wrap or replace `backend/api/total_job_store.py`
- persist job status, phase, progress, error, timestamps
- persist total-job state and enrichment fields
- keep frontend API response shape compatible

## Done

- jobs survive backend restart
- history page reads persisted jobs
- job detail page reads persisted status
- old frontend still works

## Verification

Manual:

- upload PCAP
- restart backend
- reload history page
- reload job detail page
- confirm job state remains visible

