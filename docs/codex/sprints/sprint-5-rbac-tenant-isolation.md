# Sprint 5: RBAC and Tenant Isolation

## Goal

Protect data by organization and role.

## Subagents

- `backend-developer`
- `database-engineer`
- `security-reviewer`
- `test-engineer`
- `frontend-developer`

## Develop

- add current-user dependency
- add current-organization dependency
- add permission dependency
- enforce org-scoped job/total-job/artifact queries
- protect analysis creation with `analysis:create`
- protect report reads with `analysis:read`
- add minimal owner role update path
- show role-aware navigation where needed

## Done

- analyst can create jobs
- viewer cannot create jobs
- users cannot access another organization job
- users cannot access another organization artifact

## Verification

Manual/test:

- create two users/orgs
- user A attempts user B job fetch
- user A attempts user B artifact fetch
- viewer attempts upload
- analyst uploads successfully

