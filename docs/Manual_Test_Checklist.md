# Manual Test Checklist

Use this checklist after starting the full stack with Docker Compose or the manual local commands in `README.md`.

## Required Services

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000`
- Database health: `http://localhost:8000/api/v1/health/database`
- Worker: running and listening on the `agenticnetsec` RQ queue

## Authenticated Upload Journey

1. Open `http://localhost:3000/register`.
2. Register a real local account:
   - Email: `owner+manual-<timestamp>@example.test`
   - Password: `Password123!`
3. Confirm the app redirects to `/dashboard`.
4. Open New Analysis.
5. Upload:
   - `pcap/CredAccess/DCSync_krbtgt_dcerpc_smb.pcapng`
6. Keep the default `standard` profile and start the batch.
7. Confirm the app opens `/total-jobs/<id>`.
8. Wait for deterministic progress to reach completed.
9. Open the child analysis job.
10. Open the report.
11. Refresh the report page and confirm the report reloads from the backend.
12. Open History and confirm the job is listed.
13. Open Settings and confirm user, organization, and role are visible.
14. Log out.
15. Open `http://localhost:3000/dashboard` directly and confirm redirect to `/login?next=%2Fdashboard`.

## Negative Checks

- Anonymous `GET /api/v1/analysis` returns `401`.
- A viewer account cannot upload, delete jobs, or trigger enrichment.
- Bad upload filenames such as `../evil.pcap` and `notes.txt` return `400`.
- Cross-organization job/report reads return `404`.

## Expected Warnings

- Browser dev tools may show `401 Unauthorized` for anonymous session checks after logout.
- AI provider keys are optional; deterministic fallback reports should still be generated without them.
