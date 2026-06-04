# New Chat Bootstrap Prompt

Use this prompt when starting a new Codex CLI chat for AgenticNetSec development.

Replace:

- `<SPRINT_NUMBER>`
- `<SPRINT_FILE>`
- `<GOAL>`
- `<MODE>`

Suggested modes:

- `plan-only`
- `review-only`
- `implement`
- `implement-with-double-agent`
- `implement-with-sprint-subagents`

```text
You are working in the AgenticNetSec repository.

Mode:
<MODE>

Goal:
<GOAL>

Active sprint:
Sprint <SPRINT_NUMBER>

Active sprint file:
<SPRINT_FILE>

First, read these files in order:
- AGENTS.md
- docs/Plan.md
- docs/codex/README.md
- docs/codex/HARNESS.md
- docs/codex/IMPLEMENTATION_NOTES.md
- <SPRINT_FILE>

Rules to follow:
- Preserve upload -> analysis -> report.
- Stay inside the active sprint scope.
- Do not implement stretch goals.
- Keep API response compatibility unless the sprint requires a change.
- Main agent owns final integration.
- Subagents are used only when explicitly requested by this prompt or by the user.
- Use subagents for exploration, review, testing, and focused implementation support.
- Avoid parallel writes to the same file family.
- Maintain implementation notes under docs/codex/runs/.
- Record decisions, spec changes, tradeoffs, skipped checks, and follow-ups.

Model/reasoning policy:
- Let Codex auto-select model/reasoning by default.
- Use high reasoning for security, auth, RBAC, tenant isolation, DB migrations, and architecture-risky decisions.
- Lower/mini is acceptable for read-only exploration, docs, checklists, and simple UI polish.
- Do not hard-pin every agent unless the task needs it.

If mode is plan-only:
- do not edit files
- summarize current sprint scope
- propose task order
- list likely files and risks

If mode is review-only:
- do not edit files
- use docs/codex/prompts/review-only.md
- return blockers, risks, missing tests, and next patch order

If mode is implement:
- implement without subagents unless useful and explicitly allowed by the user
- create/update implementation notes
- run sprint verification

If mode is implement-with-double-agent:
- use docs/codex/prompts/goal-driven-double-agent.md
- create exactly one subagent best suited for the active sprint
- wait for subagent summary before final integration
- continue until success criteria are met or a real blocker is reached

If mode is implement-with-sprint-subagents:
- use docs/codex/prompts/run-sprint.md
- spawn the subagents listed in the sprint file
- wait for summaries
- main agent integrates one coherent patch

Before editing:
- report the active sprint
- report selected mode
- report subagent plan, if any
- report implementation notes path

Final response must include:
- goal status
- implementation notes path
- changed files
- commands run
- checks passed/failed/skipped
- remaining risks
- next recommended step
```

## Example: Start Sprint 1 With Double Agent

```text
You are working in the AgenticNetSec repository.

Mode:
implement-with-double-agent

Goal:
Implement Sprint 1 database foundation.

Active sprint:
Sprint 1

Active sprint file:
docs/codex/sprints/sprint-1-database-foundation.md

First, read these files in order:
- AGENTS.md
- docs/Plan.md
- docs/codex/README.md
- docs/codex/HARNESS.md
- docs/codex/IMPLEMENTATION_NOTES.md
- docs/codex/sprints/sprint-1-database-foundation.md

Follow all rules in docs/codex/prompts/new-chat-bootstrap.md.
Use high reasoning only if the migration/schema design becomes risky.
```

