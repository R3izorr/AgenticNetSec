# Codex Development Harness

This folder gives Codex CLI a repeatable way to develop AgenticNetSec sprint by sprint.

## Files

- `HARNESS.md`: main workflow for sprint execution.
- `IMPLEMENTATION_NOTES.md`: template for running notes during implementation.
- `TASK_TEMPLATE.md`: template for new implementation tasks.
- `prompts/run-sprint.md`: pasteable prompt to run a full sprint with subagents.
- `prompts/run-task.md`: pasteable prompt to run one task with subagents.
- `prompts/goal-driven-double-agent.md`: 1 master + 1 subagent goal-driven loop.
- `prompts/new-chat-bootstrap.md`: starting prompt for a fresh Codex CLI chat.
- `prompts/review-only.md`: pasteable prompt for parallel review without edits.
- `sprints/`: sprint-specific development contracts.
- `runs/`: per-sprint/task implementation notes created while building.

## Agent Files

Custom subagents live in `.codex/agents/`:

- `backend-developer`
- `database-engineer`
- `frontend-developer`
- `test-engineer`
- `security-reviewer`
- `integration-lead`
- `docs-maintainer`

Codex CLI only spawns subagents when explicitly asked.

## Standard Use

From repo root:

```text
Use docs/codex/prompts/run-sprint.md for Sprint N.
Spawn the listed subagents, wait for them, then implement and verify.
```

Main rule:

- parallelize exploration/review/testing
- serialize code edits
- main agent integrates final patch
- keep implementation notes for decisions, changes, tradeoffs, and gaps
