# AgenticNetSec Architecture

## Overview

AgenticNetSec now has two analysis layers:

1. Base forensic analysis
- deterministic packet parsing and heuristic detection over each PCAP
- produces structured per-file findings in JSONL

2. Optional AI-guided verification
- reuses the structured findings and existing report
- decides which incident sections are still weak
- runs targeted `tshark` follow-up only on related PCAPs

The important architectural idea is:
- AI plans
- the sandbox executes
- the packet tooling stays local and bounded

This mirrors the safer tool-use pattern used by systems like `verialabs/ctf-agent`: the model is a coordinator, not a raw shell operator.

## Main Data Flow

1. PCAP ingestion
- `POST /api/v1/analysis` accepts either file upload or `pcap_path`
- local and batch scripts can also analyze PCAPs directly

2. Base analyzer
- `backend/src/analyzer.py` builds lightweight packet and metadata summaries
- `backend/src/detectors.py` extracts rule-based findings:
  - remote-access ingress
  - SMB/RPC scanning
  - DCERPC markers
  - exfiltration hints
  - internal RDP / manual deployment patterns
- `backend/src/deep_dive.py` turns those findings into a per-PCAP A/B/C/D-oriented narrative

3. Structured result output
- results are written to `outputs/scan_results.jsonl`
- each record stores:
  - file name
  - PCAP path
  - structured findings
  - deep-dive narrative
  - optional sandbox verification artifacts

4. Aggregate reporting
- `backend/scripts/summarize_results.py` builds `outputs/aggregate_summary.json`
- `backend/src/report_ai.py` generates `outputs/incident_report.md`
- report generation can use AI providers or deterministic fallback text

5. Optional sandbox verification
- `backend/src/sandbox_verifier.py` runs bounded `tshark` queries on selected PCAPs
- can use host `tshark` or the Docker sandbox image
- returns compact JSON, not packet dumps

6. Optional AI-guided sandbox follow-up
- `backend/scripts/enrich_results_with_sandbox.py` reads existing JSONL results
- it does not need to rerun the base analyzer
- it can work in three modes:
  - fixed verification profiles
  - heuristic weak-section planning
  - AI+tshark planning

## AI-Guided Verification Flow

The new AI idea is report-driven, not file-order-driven.

1. Case summary stage
- either:
  - generate a report with Gemini or another summary provider, or
  - reuse an existing report with `--summary-file`

2. Campaign planner stage
- OpenRouter reads the incident report plus aggregate signals
- it decides which of the incident sections are still weak:
  - `A` Initial Access
  - `B` Lateral Movement & Discovery
  - `C` Exfiltration
  - `D` Payload Deployment

3. Related-file selection
- the planner does not run across all records blindly
- `backend/src/ai_tshark_planner.py` maps weak sections to related files from the aggregate summary
- examples:
  - `A` uses patient-zero and external-ingress related files
  - `B` uses scan / DCERPC related files
  - `C` uses exfil / upload / temp.sh related files
  - `D` uses internal spread / manual deployment related files

4. Per-file planner stage
- OpenRouter reads:
  - the relevant report excerpt
  - compact aggregate context
  - one per-PCAP finding record
- it generates compact, bounded `tshark` plans for only the unresolved sections for that file

5. Sandbox execution stage
- `backend/src/sandbox_verifier.py` sanitizes the AI-authored query plan
- only allowed fields are passed through
- `tshark` runs locally against the referenced PCAP
- results are written back into:
  - `ai_verification_plan`
  - `ai_tshark_review`
  - `sandbox_verification`

## Components

### Core analysis

- `backend/src/analysis_engine.py`
  - orchestrates end-to-end local or API-driven analysis runs
- `backend/src/analyzer.py`
  - packet summary and metadata extraction
- `backend/src/detectors.py`
  - primary rule-based forensic detectors
- `backend/src/deep_dive.py`
  - per-file attack narrative and flow hypothesis
- `backend/src/flow_analysis.py`
  - aggregate attack-flow builder

### Reporting and AI

- `backend/src/report_ai.py`
  - provider routing, prompts, fallback reports, and sectioned report generation
- `backend/src/verification_planner.py`
  - heuristic weak-section planner
- `backend/src/ai_tshark_planner.py`
  - AI planner for campaign weak sections and per-file `tshark` plans

### Sandbox verification

- `backend/src/sandbox_verifier.py`
  - bounded `tshark` execution and query sanitation
- `backend/sandbox/Dockerfile`
  - forensic sandbox image
- `backend/sandbox/bin/build-sandbox.sh`
  - builds the sandbox image
- `backend/sandbox/bin/run-tshark.sh`
  - ad hoc `tshark` execution helper

### API and job persistence

- `backend/api/app.py`
  - FastAPI endpoints
- `backend/api/job_store.py`
  - persistent job artifacts and state

## Storage Model

### Per-job REST analysis artifacts

Stored in `outputs/analysis_jobs/<job_id>/`:

- `job.json`
- `report.json`
- `report.md`
- `metrics.json`
- `guardrail_audit.json`

### Offline corpus artifacts

Stored in `outputs/`:

- `scan_results.jsonl`
- `scan_results.ai-tshark.jsonl`
- `aggregate_summary.json`
- `incident_report.md`

## Execution Boundaries

### What AI is allowed to do

- choose weak incident sections
- choose which related files deserve follow-up
- propose compact `tshark` query plans

### What AI is not allowed to do

- execute arbitrary shell
- dump large raw packet content into context
- run unrestricted tools against the environment

### What the sandbox is allowed to do

- run bounded `tshark` with a known field allowlist
- inspect a single PCAP at a time
- return compact structured rows

This keeps token cost and execution risk under control.

## Current Limitations

- the base analyzer is still RDP-biased in several places and can under-detect WinRM/VPN ingress
- AI-authored `tshark` filters are improved but still less reliable than code-generated filters
- the current planner is stronger at reinforcing `B/D` than discovering new `A/C` evidence unless prompted by the report
- the best long-term design is:
  - AI outputs investigation intent
  - code translates that intent into valid `tshark` filters

## Recommended Operating Model

1. Run the base analyzer across the full corpus.
2. Deduplicate and summarize results.
3. Generate the incident report.
4. Reuse that report for AI-guided sandbox follow-up.
5. Target only weak A/B/C/D sections on related files.
6. Regenerate the aggregate summary and report after enrichment if the new evidence is useful.
