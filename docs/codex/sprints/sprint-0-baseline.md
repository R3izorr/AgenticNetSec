# Sprint 0: Baseline and Safety Net

## Goal

Preserve the current working demo before large changes.

## Subagents

- `integration-lead`
- `backend-developer`
- `frontend-developer`
- `test-engineer`

## Develop

- document backend/frontend run commands
- verify current upload -> analysis -> report flow
- identify API endpoints used by frontend
- add or update smoke/manual checklist
- add `.env.example` values if missing

## Done

- [x] backend starts locally
- [x] frontend starts locally
- [x] existing PCAP upload flow works
- [x] current API route map is documented
- [x] known limitations are written down

Notes:

- API-level upload smoke used a generated one-packet PCAP and completed through report artifact fetch.
- Hands-on browser upload was not performed in this run; frontend report route returned HTTP 200 for the completed smoke job.

## Verification

```bash
./.venv/bin/python backend/scripts/run_api.py
cd frontend
npm run dev
```

Manual:

- upload one small PCAP
- open report page
- refresh report page
