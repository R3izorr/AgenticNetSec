# Understand Anything Snapshot

This directory contains a committed architecture snapshot for the current repository.

Files:

- `knowledge-graph.json`: graph used by the interactive dashboard
- `fingerprints.json`: structural baseline for future incremental refreshes
- `meta.json`: snapshot metadata
- `.understandignore`: scan exclusions / overrides

Notes:

- This snapshot was generated from the repository root worktree.
- It is meant for code understanding, onboarding, and reviewer walkthroughs.
- Refresh it when the codebase changes materially and commit the updated snapshot.
- Do not store runtime app data here. Runtime outputs still belong under `outputs/`.
