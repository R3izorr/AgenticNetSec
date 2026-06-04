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

- backend starts locally
- frontend starts locally
- existing PCAP upload flow works
- current API route map is documented
- known limitations are written down

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

