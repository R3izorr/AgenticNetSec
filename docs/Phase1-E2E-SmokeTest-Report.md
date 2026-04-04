# Phase 1 E2E Smoke-Test Report (Frontend <-> Backend)

Date: 2026-03-17

## Environment

- Backend base URL: http://127.0.0.1:8000
- Frontend base URL: http://127.0.0.1:3000
- Polling interval target: 3s (frontend)
- Deferred routes remain out of scope: /dashboard, /jobs, /settings

## Test Inputs

- outputs/smoke_inputs/benign_small.pcap
- outputs/smoke_inputs/suspicious_scan_small.pcap
- outputs/smoke_inputs/corrupt_input.pcap
- Invalid path case: outputs/smoke_inputs/does_not_exist.pcap

## Scenario Results

### API-level smoke checks

Source: outputs/smoke_logs/api_smoke_results.json

- 400 no input: PASS
- 404 invalid job ID: PASS
- 409 artifact-not-ready race: PASS
- Network error simulation (backend unavailable endpoint): PASS
- Benign case (queued -> running -> completed): PASS
- Suspicious/attack-like case (queued -> running -> completed): PASS
- Invalid path failure case (failed): PASS
- Corrupt file failure case (failed): PASS

### Captured Job IDs

- Benign job ID: analysis_53748274c674
- Attack job ID: analysis_c24c2a433310
- Invalid-path failure job ID: analysis_727c99ee2bf0
- Corrupt-file failure job ID: analysis_8b61aa014440

### Frontend route availability checks

Source: outputs/smoke_logs/frontend_route_results.json

- /: HTTP 200 (content length: 51441)
- /analysis/new: HTTP 200 (content length: 26084)
- /analysis/analysis_53748274c674: HTTP 200 (content length: 23419)
- /analysis/analysis_53748274c674/report: HTTP 200 (content length: 24359)
- /analysis/analysis_53748274c674/raw: HTTP 200 (content length: 27193)
- /analysis/analysis_nonexistent_123456: HTTP 200 (content length: 23664)

## Findings and Gaps

- No backend contract gaps were observed for the Phase 1 scope.
- Report JSON includes checklist-critical fields: observation, inference, recommendation, and guardrail verification block.
- Metrics payload includes runtime and phase timing fields.
- Route checks confirm pages load for valid and invalid job IDs; invalid-job data handling remains client-side fetch behavior.
- Browser screenshot capture was not automated in this run; use these logs plus manual recording for demo visuals.

## Artifacts Produced

- outputs/smoke_logs/api_smoke_results.json
- outputs/smoke_logs/frontend_route_results.json
- outputs/smoke_logs/frontend.out.log
- outputs/smoke_logs/frontend.err.log
- docs/Phase1-E2E-SmokeTest-Report.md
