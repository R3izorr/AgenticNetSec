# Codex Sprint Harness

## Purpose

Run each sprint as a bounded development loop:

1. understand current code
2. split investigation across subagents
3. implement one coordinated patch
4. verify
5. update docs/checklists
6. maintain implementation notes

## Required Context

Read in order:

1. `AGENTS.md`
2. `docs/Plan.md`
3. active sprint file in `docs/codex/sprints/`
4. files named by the active sprint
5. `docs/codex/IMPLEMENTATION_NOTES.md`

## Main Agent Duties

The main agent must:

- choose the active sprint scope
- spawn subagents only for independent work
- wait for subagent summaries
- decide final implementation order
- edit files coherently
- run verification
- maintain implementation notes during implementation
- report final status

## Subagent Duties

Subagents must:

- stay inside their role
- avoid unrelated refactors
- summarize findings compactly
- cite file paths and line numbers when possible
- say when they did not run tests

## Default Subagent Split

For backend-heavy sprints:

- `database-engineer`: schema/migrations/repositories
- `backend-developer`: API/services/integration
- `test-engineer`: focused regression tests
- `security-reviewer`: auth, tenant, upload, subprocess risk

For frontend-heavy sprints:

- `frontend-developer`: UI/API-client flow
- `backend-developer`: contract compatibility
- `test-engineer`: frontend checks/manual checklist
- `security-reviewer`: route/auth exposure

For docs/portfolio sprint:

- `docs-maintainer`: README/demo/security docs
- `integration-lead`: run path and verification
- `test-engineer`: final test coverage map

## Edit Coordination

Use this rule:

- subagents may inspect freely
- only one agent should edit a file family at a time
- main agent owns final integration

File families:

- backend API/services/models/migrations
- frontend app/components/lib
- docs
- Docker/compose/env
- tests

## Sprint Loop

1. Baseline check:
   - current git status
   - relevant files
   - current run/test commands

2. Spawn:
   - exploration/review agents first
   - implementation agents only when scope is clear

3. Integrate:
   - apply smallest coherent change
   - preserve existing API shape where possible
   - add tests for risky paths
   - update implementation notes when decisions, tradeoffs, or spec changes happen

4. Verify:
   - run relevant backend tests
   - run frontend lint/build when frontend changed
   - manually verify upload -> analysis -> report when possible
   - record skipped checks and reasons in implementation notes

5. Close:
   - summarize changed files
   - list commands run
   - list failed/skipped checks
   - update sprint checklist if needed
   - ensure implementation notes capture decisions and gaps

## Completion Contract

A sprint is done only when:

- active sprint `Done` items are satisfied
- verification commands pass or skipped checks are justified
- current demo path is still valid
- no stretch goal leaked into MVP
- implementation notes exist if any decision, spec change, tradeoff, skipped check, or known gap occurred

## Implementation Notes

For each sprint or task, create a running notes file from `docs/codex/IMPLEMENTATION_NOTES.md`.

Preferred path:

```text
docs/codex/runs/<YYYY-MM-DD>-sprint-<N>-implementation-notes.md
```

Use task slug instead of sprint number for one-off tasks.

Track:

- decisions not obvious from code
- spec changes
- tradeoffs
- compatibility impact
- security notes
- verification commands
- skipped checks
- follow-ups
