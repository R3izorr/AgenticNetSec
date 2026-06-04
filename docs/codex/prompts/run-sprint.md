# Run Sprint Prompt

Use this prompt from the repo root.

```text
Run Sprint <N> using the Codex sprint harness.

Read:
- AGENTS.md
- docs/Plan.md
- docs/codex/HARNESS.md
- docs/codex/IMPLEMENTATION_NOTES.md
- docs/codex/sprints/sprint-<N>-*.md

Spawn subagents listed in the sprint file.
Use read/review agents in parallel first.
Wait for all subagent summaries.
Then implement the smallest coherent patch.
Create and maintain:
docs/codex/runs/<YYYY-MM-DD>-sprint-<N>-implementation-notes.md

Rules:
- preserve upload -> analysis -> report
- no stretch goals
- avoid parallel writes to the same file family
- main agent owns final integration
- run verification listed in the sprint file
- record decisions, spec changes, tradeoffs, skipped checks, and follow-ups in implementation notes

Final response:
- changed files
- commands run
- checks passed/failed/skipped
- implementation notes path
- remaining risks
- next sprint recommendation
```
