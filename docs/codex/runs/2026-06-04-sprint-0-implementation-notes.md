# Implementation Notes: Sprint 0 Baseline and Safety Net

Date: 2026-06-04

Spec: `docs/codex/sprints/sprint-0-baseline.md`

Branch: current workspace

Implementer: Codex

## Summary

- Documented the current backend/frontend run commands, API route map, manual smoke checklist, and known limitations.
- Added root and frontend `.env.example` files for local defaults.
- Corrected stale docs that said `GET /` returns 404; the backend currently returns health JSON.

## Decisions

| Decision | Reason | Alternatives Considered |
| --- | --- | --- |
| Keep Sprint 0 changes documentation/config-only. | Sprint 0 is baseline preservation before larger MVP changes. | Add runtime tests or app changes now. |
| Document missing PCAP fixture instead of inventing one in source. | No committed PCAP exists; runtime `outputs/` is ignored. | Commit a tiny generated PCAP fixture. |
| Use `docs/codex/sprint-0-baseline-safety-net.md` for the route map and checklist. | Keeps sprint safety net near Codex sprint docs without changing product behavior. | Expand older broad testing docs only. |

## Spec Changes

| Original Spec | Actual Implementation | Why |
| --- | --- | --- |
| Verify upload with one small PCAP. | API-level upload/report smoke used a generated one-packet PCAP; hands-on browser upload was skipped. | Fresh checkout has no committed PCAP fixture; generated `/tmp` PCAP was enough to verify backend upload -> analysis -> report artifact path. |

## Tradeoffs

- `.env.example` documents optional provider keys as comments so secrets are not implied or required for deterministic Stage 1.
- The checklist names current risks that later sprints are expected to fix instead of changing them in Sprint 0.

## Compatibility Notes

- API response shape: unchanged.
- Database/migration impact: none.
- Frontend impact: no UI/runtime code changed.
- Existing upload -> analysis -> report flow: unchanged; documented as the baseline path.

## Security Notes

- Tenant isolation: not implemented yet; current list endpoints are global and documented as a known limitation.
- File upload/path handling: current upload path and `pcap_path` local-path behavior documented as limitations.
- Auth/session behavior: unauthenticated API documented as a known limitation for later sprints.
- Secrets/subprocess risk: `.env.example` contains no secrets; sandbox/tshark is optional and environment-dependent.

## Verification

Commands run:

```bash
git status --short
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
npm install
npm ci --cache /tmp/agenticnetsec-npm-cache
./.venv/bin/python backend/scripts/run_api.py --host 127.0.0.1 --port 8000
npm run dev -- --hostname 127.0.0.1 --port 3000
./.venv/bin/python -c '<local backend/frontend HTTP checks>'
./.venv/bin/python -c '<generate one-packet PCAP, upload to /api/v1/analysis/batch, poll child, fetch report.json>'
npm run lint
npm run build
```

Manual checks:

- Backend started on `http://127.0.0.1:8000` outside sandbox after sandbox Scapy interface discovery failed.
- Frontend dev server started on `http://127.0.0.1:3000` outside sandbox after sandbox port bind failed.
- `GET /` returned `{"message":"AgenticNetSec API is running","version":"1.0.0"}`.
- Frontend `/` returned HTTP 200.
- Generated `/tmp/agenticnetsec-sprint0-smoke.pcap`.
- Uploaded generated PCAP to `POST /api/v1/analysis/batch`.
- Created `total_8641c4224cac` with child `analysis_2dbb03996402`.
- Child job completed with `risk_level: low` and all artifacts ready.
- `GET /api/v1/analysis/analysis_2dbb03996402/report.json` returned report keys.
- Frontend `/analysis/analysis_2dbb03996402/report` returned HTTP 200.

Skipped checks:

- Hands-on browser upload and report refresh were skipped; API-level upload/report smoke and frontend report-route HTTP check passed.

Warnings/failures observed:

- Initial Python dependency install failed under restricted network, then passed with approved network access.
- Initial `npm install`/`npm ci` failed under restricted network/cache behavior, then `npm ci --cache /tmp/agenticnetsec-npm-cache` passed with approved network access.
- `npm ci` reported 8 dependency vulnerabilities: 6 moderate, 2 high.
- Backend start inside sandbox failed with Scapy `PermissionError: Operation not permitted`; unsandboxed start passed.
- Frontend start inside sandbox failed with `listen EPERM`; unsandboxed start passed.
- First `npm run build` failed because restricted network blocked Google Fonts fetch; approved-network build passed.
- `npm run lint` passed with one warning in `frontend/app/analysis/history/data-table.tsx` from React Compiler/TanStack Table incompatible-library detection.

## Known Gaps

- Need hands-on browser upload smoke with an external small PCAP.
- Fresh checkout still lacks a committed PCAP fixture.

## Follow-Ups

- Consider adding a tiny committed PCAP fixture or a script that generates one for repeatable Sprint 0 smoke checks.
