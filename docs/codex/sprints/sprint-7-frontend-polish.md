# Sprint 7: Frontend Product Polish

## Goal

Make the app feel like a coherent authenticated security product.

## Subagents

- `frontend-developer`
- `backend-developer`
- `test-engineer`
- `security-reviewer`

## Develop

- protected app shell
- dashboard with recent jobs
- persisted job history
- report detail reload support
- total-job detail cleanup
- settings page with user/org info
- loading, empty, error states
- role-aware navigation

## Done

- complete browser journey works
- UI clearly shows job status and failures
- report opens after refresh
- anonymous users redirect to login

## Verification

```bash
cd frontend
npm run lint
npm run build
```

Manual:

- register
- upload PCAP
- watch progress
- open report
- refresh report
- logout
- confirm protected route redirect

