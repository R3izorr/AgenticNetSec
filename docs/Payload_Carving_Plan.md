# Payload Carving Plan

## Goal

Implement Requirement D payload carving for AgenticNetSec in a way that:

- stays deterministic for the MVP
- does not require sandbox as the primary extraction engine
- avoids carving every file or every flow
- recovers real transferred payload artifacts when possible
- upgrades reporting to distinguish heuristic evidence from recovered artifacts

## Agreed MVP Scope

- Protocol scope:
  - SMB
  - HTTP
- Output scope:
  - save carved bytes
  - save `carved_manifest.json`
  - compute `md5`, `sha1`, `sha256`
  - detect file magic and MIME type
  - extract lightweight PE metadata when parseable
- Reporting scope:
  - heuristic deployment only
  - confirmed transferred payload with recovered artifact
  - partial/hash-only evidence
- Execution scope:
  - run carving after `collect_all_findings`
  - run carving before report generation
  - do not make sandbox the primary carving engine

## Key Design Decision

The carving module should not carve all files blindly.

Instead, the system should:

- run normal deterministic analysis across all PCAPs
- use existing Requirement D heuristics to triage files and flows
- carve only suspicious SMB or HTTP candidate flows

This keeps runtime bounded and preserves the current batch-first architecture.

## Why Not Make Sandbox the Main Carving Engine

Sandbox is useful for follow-up verification, but it is the wrong primary place for MVP carving because:

- carving is deterministic byte reconstruction, not exploratory verification
- stage 1 is intentionally batch-first, no-AI, no-sandbox
- pushing carving into sandbox would make the primary extraction path slower and more fragile
- sandbox availability should not decide whether transferred payload evidence can be recovered

Recommended role of sandbox in MVP:

- optional corroboration
- optional follow-up for ambiguous or partial evidence
- not the core extractor

## Runtime Strategy

### File-Level Gating

Only attempt carving for files that have at least one strong payload-deployment signal.

Initial gating signals:

- non-empty `manual_payload_deployment_candidates`
- suspicious SMB/admin-share activity
- suspicious remote-exec markers over SMB/DCERPC
- suspicious HTTP upload/body indicators

### Flow-Level Gating

Within a flagged file, only carve a capped set of high-value candidate flows.

Initial candidate sources:

- `manual_payload_deployment_candidates`
  - prioritize targets with `admin_share_markers`
  - prioritize targets with `remote_exec_markers`
  - then targets with correlated SMB/RPC ports
- suspicious SMB/admin-share activity inferred from Requirement D detectors
- suspicious HTTP uploads or HTTP bodies from `large_http_posts`

### Safety / Performance Caps

The MVP should include simple limits so carving remains predictable:

- cap candidate flows per file
- cap bytes reconstructed per file
- skip obviously tiny or low-signal payload fragments
- emit partial evidence instead of forcing full reconstruction

## Planned Insertion Points

### 1. New Backend Module

Add a new module under `backend/src/` for payload carving.

Suggested responsibilities:

- candidate selection from existing findings
- SMB and HTTP payload reconstruction
  - current SMB MVP implementation focuses on SMB2 write-payload extraction plus filename hints recovered from SMB paths/create traffic
- file type and hash extraction
- optional PE metadata parsing
- manifest creation

### 2. Analysis Engine

Insert carving in `backend/src/analysis_engine.py`:

- after `collect_all_findings`
- before `generate_report_result`

The engine should:

- call the new carving module
- merge carve results into findings and the flattened `analysis_record`
- expose carve evidence to structured report generation

### 3. Job Artifact Persistence

Persist carve outputs under each analysis job artifact directory:

- carved payload bytes in a dedicated subdirectory
- `carved_manifest.json`

This likely requires one of two approaches:

- pass the job artifact directory into the analysis pipeline
- or have the API layer persist returned carve outputs after engine completion

The implementation should prefer the least disruptive option to current architecture.

### 4. Aggregate and Report Path

Update:

- `backend/src/report_ai.py`
- `backend/scripts/summarize_results.py`
- batch/parent enrichment artifact generation

So aggregate outputs can distinguish:

- heuristic-only payload deployment
- confirmed recovered payload artifact
- partial or hash-only payload evidence

## Data Model Changes

Extend structured artifacts with:

- `carved_payloads`
- `payload_iocs`
- `payload_deployment_confidence`

Recommended semantics:

- `carved_payloads`
  - recovered or partially recovered payload artifacts with metadata
- `payload_iocs`
  - hashes, filenames, PE traits, MIME/type indicators, execution-relevant paths if present
- `payload_deployment_confidence`
  - normalized confidence reflecting whether evidence is heuristic, partial, or confirmed

## Expected Artifact Shape

### Per Recovered Artifact

Each carved payload record should ideally include:

- artifact ID
- protocol
- source IP
- destination IP
- destination port
- candidate basis
- recovery status
  - `confirmed_artifact`
  - `partial_evidence`
  - `hash_only`
- relative saved path if bytes were written
- recovered filename if available
- size in bytes
- `md5`
- `sha1`
- `sha256`
- file magic
- MIME type
- lightweight PE metadata if present

### Manifest

`carved_manifest.json` should include:

- job ID or source file context
- carve execution summary
- candidate counts
- recovered artifact entries
- skipped candidates
- errors or parsing limitations

## Reporting Changes

The report should stop treating all Requirement D evidence the same.

It should explicitly distinguish:

### Heuristic Deployment Only

Use when:

- manual-drop or admin-share heuristics exist
- no payload bytes or artifact metadata were recovered

### Confirmed Transferred Payload With Recovered Artifact

Use when:

- bytes were successfully reconstructed
- a saved artifact exists
- hashes and type metadata are available

### Partial / Hash-Only Evidence

Use when:

- a strong transfer signal exists
- enough bytes exist for type/hash evidence
- but full artifact reconstruction is incomplete or not safe to claim

## Performance Expectations

If we only carve suspicious SMB/HTTP candidates:

- baseline detector performance should remain mostly unchanged
- runtime increase should be focused on a smaller set of flagged files
- the cost should be far lower than full-PCAP full-stream reconstruction

If later needed, carving can be made configurable behind a runtime flag.

## Verification Plan

Verify the MVP with focused checks:

- one SMB-like suspicious sample that triggers candidate selection
- one HTTP upload/body suspicious sample
- one benign or low-signal sample that should skip carving
- aggregate/report output checks to confirm the new evidence categories appear correctly

## Non-Goals for MVP

- full protocol coverage beyond SMB and HTTP
- using sandbox as the default extraction engine
- universal extraction of all binary content in every PCAP
- advanced malware unpacking
- deep file-format reverse engineering beyond lightweight metadata

## Suggested Implementation Order

1. Add carving module and candidate-selection logic.
2. Add per-job artifact persistence for carved bytes and manifest.
3. Extend `analysis_record` and structured artifacts.
4. Update report and aggregate rollups.
5. Add focused smoke checks and sample validation.
