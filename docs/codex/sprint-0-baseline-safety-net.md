# Sprint 0 Baseline Safety Net

Date: 2026-06-04

Scope: preserve the current upload -> analysis -> report demo path before larger MVP changes.

## Run Commands

Backend:

```bash
./.venv/bin/python backend/scripts/run_api.py
```

Backend with reload:

```bash
./.venv/bin/python backend/scripts/run_api.py --reload
```

Frontend:

```bash
cd frontend
npm run dev
```

Frontend production-style local run:

```bash
cd frontend
npm run build
npm run start
```

Dependency setup:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
cd frontend
npm ci
```

## Current API Route Map

Backend routes from `backend/api/app.py`:

| Method | Route | Purpose | Frontend use |
| --- | --- | --- | --- |
| `GET` | `/` | API health/root JSON | manual check |
| `POST` | `/api/v1/analysis` | create single analysis from upload or backend-local path | legacy/API helper, not current New Analysis UI |
| `POST` | `/api/v1/analysis/batch` | create parent total job with child analysis jobs | `/analysis/new` |
| `GET` | `/api/v1/analysis` | list child analysis jobs | dashboard/history |
| `GET` | `/api/v1/analysis/{job_id}` | child job status | child job page/polling |
| `GET` | `/api/v1/analysis/{job_id}/report.json` | structured child report | report/raw pages |
| `GET` | `/api/v1/analysis/{job_id}/report.md` | Markdown child report | raw page |
| `GET` | `/api/v1/analysis/{job_id}/metrics` | runtime metrics artifact | raw page |
| `GET` | `/api/v1/analysis/{job_id}/guardrail-audit` | guardrail audit artifact | raw page |
| `GET` | `/api/v1/total-jobs` | list parent total jobs | total jobs page |
| `GET` | `/api/v1/total-jobs/{total_job_id}` | parent total job status | total job page/polling |
| `POST` | `/api/v1/total-jobs/{total_job_id}/enrich` | run parent enrichment | total job page |
| `GET` | `/api/v1/total-jobs/{total_job_id}/summary.json` | parent summary JSON | total job page |
| `GET` | `/api/v1/total-jobs/{total_job_id}/summary.md` | parent summary Markdown | total job page |
| `GET` | `/api/v1/total-jobs/{total_job_id}/sandbox` | parent sandbox artifact | total job page |
| `GET` | `/api/v1/total-jobs/summary/status` | all-total-jobs summary status | total jobs page |
| `POST` | `/api/v1/total-jobs/summary/enrich` | run all-total-jobs summary | total jobs page |
| `GET` | `/api/v1/total-jobs/summary/json` | all-total-jobs summary JSON | total jobs page |
| `GET` | `/api/v1/total-jobs/summary/markdown` | all-total-jobs summary Markdown | total jobs page |
| `GET` | `/api/v1/total-jobs/summary/sandbox` | all-total-jobs sandbox artifact | total jobs page |

Frontend API wrapper: `frontend/lib/api/analysis.ts`.

Frontend base URL default: `http://localhost:8000`, overridable with `NEXT_PUBLIC_API_BASE_URL`.

## Manual Smoke Checklist

Use one known-small PCAP from outside the repo. Runtime artifacts under `outputs/` are ignored and may not exist in a fresh checkout.

- [ ] Start backend with `./.venv/bin/python backend/scripts/run_api.py`.
- [ ] Confirm `http://localhost:8000/` returns API JSON.
- [ ] Confirm `http://localhost:8000/docs` loads.
- [ ] Start frontend with `cd frontend && npm run dev`.
- [ ] Open `http://localhost:3000/analysis/new`.
- [ ] Upload one small PCAP.
- [ ] Submit with profile `standard` and worker count `2` or higher.
- [ ] Confirm redirect to `/total-jobs/{totalJobId}`.
- [ ] Wait until deterministic child analysis completes or fails cleanly.
- [ ] Open the first child job from the total-job page.
- [ ] Open `/analysis/{jobId}/report`.
- [ ] Refresh the report page and confirm it still loads.
- [ ] Open `/analysis/{jobId}/raw` and confirm report/metrics/guardrail artifacts load when ready.
- [ ] Open `/analysis/history` and confirm the job is listed.
- [ ] Restart backend and refresh `/analysis/history` to confirm file-backed job state survives restart.

## Known Limitations

- Fresh checkouts do not include repo-local PCAP fixtures; manual upload verification needs an external small PCAP.
- Runtime state is file-backed under `outputs/`, not database-backed yet.
- API routes are unauthenticated until later MVP auth/RBAC sprints.
- Current API list endpoints are global, not tenant-scoped yet.
- Uploaded files are saved server-side under `outputs/uploads/`; the current route has no configured upload size limit.
- Backend-local `pcap_path` requests are still supported for local demos and scripts. Do not expose that mode to untrusted users without the later artifact/storage hardening.
- AI provider keys are optional for deterministic Stage 1. Enrichment quality depends on environment variables or `backend/config/local_settings.py`.
- `tshark`/sandbox verification is optional and environment-dependent.
