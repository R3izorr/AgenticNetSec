# AgenticNetSec Codex Instructions

## First Reads

Before implementation work, read:

- `docs/Plan.md`
- `docs/codex/README.md`
- `docs/codex/HARNESS.md`
- `docs/codex/IMPLEMENTATION_NOTES.md`
- the active sprint file under `docs/codex/sprints/`

## Non-Negotiable

Do not break the current upload -> analysis -> report flow.

Preserve:

- FastAPI backend
- Next.js frontend
- existing forensic engine under `backend/src/`
- current report/history/total-job user journey

## Subagent Policy

Use subagents only when the user asks for parallel agents or sprint harness execution.

Good parallel work:

- codebase exploration
- security review
- test planning
- frontend/backend impact review
- docs review

Avoid parallel writes to the same files.

Main agent owns:

- final implementation decisions
- patch integration
- conflict resolution
- verification commands
- final summary

Subagents return summaries, not noisy logs.

## Development Rules

- Keep edits scoped to the active sprint.
- Preserve API response compatibility unless the sprint says otherwise.
- Add tests near risky backend/auth/security changes.
- After auth exists, do not bypass auth to make verification pass. If a protected flow needs an account and no seeded/demo account exists, stop and ask the user to create or approve test accounts before running that verification.
- Use server-generated artifact paths only.
- All protected database queries must include `organization_id`.
- Never trust user-supplied file paths.
- Do not add OAuth, Stripe, API keys, S3/MinIO, password reset, or email verification during MVP sprints.
- Keep a running implementation notes file under `docs/codex/runs/` for sprint/task decisions, spec changes, tradeoffs, skipped checks, and follow-ups.

## Local Commands

Backend:

```bash
./.venv/bin/python backend/scripts/run_api.py
```

Frontend:

```bash
cd frontend
npm run dev
```

Frontend checks:

```bash
cd frontend
npm run lint
npm run build
```

Python dependencies:

```bash
./.venv/bin/python -m pip install -r requirements.txt
```
