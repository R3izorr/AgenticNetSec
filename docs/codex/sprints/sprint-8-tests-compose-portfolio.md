# Sprint 8: Tests, Compose, and Portfolio Finish

## Goal

Make the project reviewable by an internship reviewer.

## Subagents

- `test-engineer`
- `integration-lead`
- `docs-maintainer`
- `security-reviewer`

## Develop

- Docker Compose for backend, frontend, postgres, redis, worker
- migration startup docs
- backend tests for auth, RBAC, tenant isolation, artifact validation, job lifecycle
- frontend manual test checklist
- README update
- architecture diagram
- demo instructions
- security notes

## Done

- reviewer can run the app locally
- tests cover core security and job flow
- demo path is documented
- MVP pitch is clear

## Verification

```bash
cd frontend
npm run lint
npm run build
docker compose up
```

Manual:

- register user
- upload PCAP
- complete analysis
- open report

