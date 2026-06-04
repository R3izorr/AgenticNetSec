# Sprint 3: Artifact Service

## Goal

Centralize upload/report file handling and record artifact metadata.

## Subagents

- `backend-developer`
- `database-engineer`
- `security-reviewer`
- `test-engineer`

## Develop

- add local artifact service
- generate server-owned artifact paths
- store artifact rows for uploaded PCAPs and reports
- calculate sha256, size, content type
- validate `.pcap` and `.pcapng`
- reject path traversal filenames
- add soft-delete behavior

## Done

- uploaded PCAP metadata is stored
- report metadata is stored
- frontend can still view reports
- user-supplied paths are never trusted

## Verification

Manual:

- upload valid PCAP
- try traversal filename
- open generated report
- inspect artifact DB rows
- delete job and confirm artifact access blocked

