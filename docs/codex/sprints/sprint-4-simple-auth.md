# Sprint 4: Simple Auth

## Goal

Add MVP email/password authentication with default organization creation.

## Subagents

- `backend-developer`
- `frontend-developer`
- `security-reviewer`
- `test-engineer`

## Develop

- implement register/login/logout/me
- hash passwords with Argon2id or bcrypt
- store JWT/session in HttpOnly cookie
- create default organization on registration
- create owner membership on registration
- add frontend login/register pages
- add frontend session state

## Done

- user can register
- user can log in
- user can log out
- auth state survives refresh
- disabled user cannot log in

## Verification

Manual:

- register -> dashboard
- logout -> protected route blocked
- login -> dashboard
- call `/api/v1/auth/me`

