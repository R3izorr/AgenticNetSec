# Run Task Prompt

```text
Run this task using the Codex task harness.

Task:
<paste task>

Read:
- AGENTS.md
- docs/Plan.md
- docs/codex/HARNESS.md
- docs/codex/IMPLEMENTATION_NOTES.md
- docs/codex/TASK_TEMPLATE.md
- relevant sprint file under docs/codex/sprints/

Spawn only the subagents needed for this task.
Use subagents for exploration/review/testing.
Main agent owns edits and final integration.
Create and maintain a task implementation notes file under docs/codex/runs/.

Do not implement out-of-scope features.
Run relevant verification before final response.
Final response must include the implementation notes path.
```
