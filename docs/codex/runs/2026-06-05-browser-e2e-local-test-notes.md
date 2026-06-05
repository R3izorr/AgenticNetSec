# Browser E2E Local Test Notes

Date: 2026-06-05

## Purpose

Record the local browser verification setup used after Sprint 4 so future agents can run real authenticated UI checks instead of stopping at API-only smokes.

## Local State

- Playwright is now the committed browser E2E runner. Install browsers locally with:

```bash
cd frontend
npx playwright install chromium
```

- The committed test is:

```text
frontend/e2e/authenticated-analysis.spec.ts
```

- The committed config is:

```text
frontend/playwright.config.ts
```

- Run it with:

```bash
cd frontend
npm run test:e2e
```

- `frontend/package.json` and `frontend/package-lock.json` include `@playwright/test`.
- `frontend/package-lock.json` was normalized when Playwright was formalized, so its diff may be larger than the dependency change alone.

## Required Services

Use local Postgres from `compose.yaml`; no cloud Postgres account is required.

```bash
docker compose up -d postgres
set -a
. ./.env
set +a
./.venv/bin/python -m alembic upgrade head
```

Start backend:

```bash
set -a
. ./.env
set +a
./.venv/bin/python backend/scripts/run_api.py
```

Start frontend:

```bash
cd frontend
npm run dev
```

Expected URLs:

- frontend: `http://localhost:3000`
- backend: `http://localhost:8000`
- DB health: `http://localhost:8000/api/v1/health/database`

## Test Account Policy

After auth exists, do not bypass auth to pass verification. Use a real registered or seeded local account.

Register through UI:

```text
http://localhost:3000/register
```

Recommended local account:

```text
email: owner@example.test
password: Password123!
```

For repeated automated tests, prefer unique emails:

```text
owner+e2e-<timestamp>@example.test
```

## PCAP Fixtures

The committed local `pcap/` directory contains test captures from PCAP-ATTACK, grouped by tactic. It is useful for browser upload tests and realistic report checks.

Known examples:

```text
pcap/Command and Control/C2_Foudre_Backdoor_DGA.pcapng
pcap/CredAccess/DCSync_krbtgt_dcerpc_smb.pcapng
pcap/Discovery/discovery_scan_dcerpc_endpoint_mapper.pcapng
pcap/Lateral Movement/LM_psexec_smb_dcerpc_epm_svcctl.pcapng
pcap/PrivEsc/CVE-2020-0796_SMBGhost_PrivEsc_Loopback_traffic.pcapng
```

The Playwright test defaults to:

```text
pcap/CredAccess/DCSync_krbtgt_dcerpc_smb.pcapng
```

Override with:

```bash
E2E_PCAP_PATH=/path/to/file.pcapng npm run test:e2e
```

## Browser Journey To Verify

Minimum Sprint 7 browser journey:

1. Register or login.
2. Open dashboard.
3. Go to New Analysis.
4. Upload one `.pcap` or `.pcapng` from `pcap/`.
5. Wait for total job completion.
6. Open child analysis report.
7. Refresh report page and confirm it reloads.
8. Logout.
9. Confirm protected route redirects to login.

## Known Warnings

- Anonymous session checks can produce expected `401 Unauthorized` console/network logs.
- Treat unexpected UI console errors, failed report loads, stuck total jobs, and cross-tenant access as blockers.
- Do not commit `.env` or local secrets.
