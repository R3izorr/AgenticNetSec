# Sprint 6: Worker Queue

## Goal

Move long analysis work out of the API request path.

## Subagents

- `backend-developer`
- `integration-lead`
- `test-engineer`
- `security-reviewer`

## Develop

- add Redis service
- add RQ or Celery worker
- enqueue `run_analysis_job(job_id)`
- enqueue `run_total_job_enrichment(total_job_id)`
- persist worker progress/errors in database
- keep frontend polling compatible
- document worker command

## Done

- upload API returns quickly
- worker runs analysis
- job progresses queued -> running -> completed
- failed jobs store error
- backend restart does not erase job state

## Verification

Manual:

- start backend/frontend/redis/worker
- upload PCAP
- observe queued/running/completed states
- stop backend during job and restart
- force one failed job and confirm error display

