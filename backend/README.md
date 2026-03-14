# Backend

Core forensic analysis code lives here.

## Layout

- `src/`: analyzers, detectors, planner, guardrails, reporting schema, observability
- `api/`: REST API for async analysis jobs
- `scripts/`: CLI entrypoints
- `config/`: local configuration templates
- `tests/`: tests

## Common Commands

From repository root:

```bash
python backend/scripts/run.py /path/to/capture.pcap --no-ai
python backend/scripts/batch_analyze.py --start 1 --end 10 --workers 2
python backend/scripts/summarize_results.py outputs/scan_results.jsonl --no-ai --print-json
python backend/scripts/verify_findings.py temp-sh
python backend/scripts/run_api.py
```

API base URL: `http://localhost:8000`

### REST Endpoints (v1)

- `POST /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`

Generated job artifacts are written to `outputs/analysis_jobs/<job_id>/`.
