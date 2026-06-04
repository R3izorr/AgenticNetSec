# Implementation Notes

Use this file as the running engineering log for a sprint or task.

Codex should keep a copy named:

```text
docs/codex/runs/<YYYY-MM-DD>-sprint-<N>-implementation-notes.md
```

For a single task:

```text
docs/codex/runs/<YYYY-MM-DD>-<task-slug>-implementation-notes.md
```

## Purpose

While implementing a spec, keep track of anything important that was not fully captured in the spec:

- decisions made during implementation
- requirements that had to change
- tradeoffs
- risks
- assumptions
- follow-up work
- test or verification gaps
- compatibility notes

This is not a diary. Keep it concise and useful for the next developer or reviewer.

## Rule

If the implementation differs from the sprint/task spec, write it here before final response.

## Template

```md
# Implementation Notes: <Sprint or Task Name>

Date:

Spec:

Branch:

Implementer:

## Summary

- 

## Decisions

| Decision | Reason | Alternatives Considered |
| --- | --- | --- |
|  |  |  |

## Spec Changes

| Original Spec | Actual Implementation | Why |
| --- | --- | --- |
|  |  |  |

## Tradeoffs

- 

## Compatibility Notes

- API response shape:
- Database/migration impact:
- Frontend impact:
- Existing upload -> analysis -> report flow:

## Security Notes

- Tenant isolation:
- File upload/path handling:
- Auth/session behavior:
- Secrets/subprocess risk:

## Verification

Commands run:

```bash

```

Manual checks:

- 

Skipped checks:

- 

## Known Gaps

- 

## Follow-Ups

- 
```

