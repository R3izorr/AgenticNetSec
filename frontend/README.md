# Frontend (AgenticNetSec v1)

Next.js App Router frontend aligned to the current backend async REST contract.

## Stack

- Next.js 16
- React 19
- TypeScript
- Tailwind CSS 4
- shadcn/ui primitives

## Run

From repository root:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

## Build Checks

```bash
npm run lint
npm run build
```

## Environment Variables

- `NEXT_PUBLIC_API_BASE_URL` (default in code: `http://localhost:8000`)

Create `.env.local` from `.env.example` when needed.

## Routes (v1 scope)

- `/` overview/landing
- `/analysis/new` submit PCAP file or `pcap_path`
- `/analysis/[jobId]` async status + polling
- `/analysis/[jobId]/report` analyst-facing structured report
- `/analysis/[jobId]/raw` raw artifacts (`report.json`, `report.md`, metrics)

## API Contract Assumptions

Only these backend endpoints are used:

- `POST /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`

### Behavior notes

- `analysis_job_id` is treated as canonical identifier.
- Artifact `409` means "not ready yet" and is handled as a retryable UI state.
- `404` and failed job states are surfaced as explicit error states.
- Polling interval for job status is 3 seconds while status is `queued` or `running`.

## Deferred (Phase 2)

- Dashboard aggregate analytics
- Server-backed job history listing
- Settings page for runtime configuration
