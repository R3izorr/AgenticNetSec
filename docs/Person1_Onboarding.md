# Person 1 Onboarding: Forensics + AI Engine

## Role Summary

Person 1 owns the analysis brain of AgenticNetSec.

Core ownership:

- PCAP ingestion logic
- Packet parsing
- Flow and session reconstruction
- Rule-based detectors
- Deep-dive logic
- Attack-flow building
- Structured findings and report quality
- Detector tuning and validation
- Speed and artifact quality for local analysis workflows

Primary files in scope:

- `backend/src/analyzer.py`
- `backend/src/detectors.py`
- `backend/src/deep_dive.py`
- `backend/src/flow_analysis.py`
- `backend/src/report_ai.py`
- `backend/src/analysis_engine.py`
- `backend/src/forensic_schema.py`
- `backend/src/guardrails.py`
- `backend/scripts/run.py`
- `backend/scripts/batch_analyze.py`
- `backend/scripts/summarize_results.py`
- `backend/scripts/verify_findings.py`

Reference teammate update:

- `docs/Changes_2026-03-17.md`
- `docs/FirstFeedback.md`

---

## What Changed From Teammate Update

The current Person 1 doc must be read against the new 2026-03-17 backend update.

Already implemented by teammate:

- Evidence references were added to the forensic report schema.
- MITRE ATT&CK mappings were added to structured report output.
- Direct evidence, evidence reference IDs, and uncertainty fields were added.
- Guardrail consistency checks and contradiction checks were added.
- A new `guardrail_audit.json` artifact and API endpoint were added.
- Metrics were extended with provider, model, fallback-used state, artifact sizes, and cost assumptions.
- Backend tests were expanded for schema, guardrails, evidence refs, API audit endpoint, and report AI usage parsing.
- Benchmark support files were added for later demo and evaluation work.

This means Person 1 should no longer treat MITRE, evidence refs, and guardrail audit as future proposals.
They are now part of the current baseline and should be treated as existing surfaces to maintain, refine, and extend.

---

## Current System Structure

The project is a backend-first network forensic analyzer with a thin Next.js frontend.

### Backend analysis pipeline

- `backend/src/analysis_engine.py`
  Orchestrates the autonomous run:
  ingest -> parse -> analysis -> reason -> report.
- `backend/src/analyzer.py`
  Produces compact per-PCAP summary statistics.
- `backend/src/detectors.py`
  Runs the main one-pass detection logic over packet evidence.
- `backend/src/deep_dive.py`
  Builds per-PCAP narrative pivots around a focus host.
- `backend/src/flow_analysis.py`
  Correlates many per-file records into a likely attack flow.
- `backend/src/report_ai.py`
  Generates final Markdown reports and fallback reports.
- `backend/src/forensic_schema.py`
  Defines the structured report schema, evidence refs, MITRE fields, and run metrics.
- `backend/src/guardrails.py`
  Performs input validation, consistency checks, contradiction checks, and guardrail audit generation.

### API and artifacts

- `backend/api/app.py`
  Supports both upload and filesystem path ingestion.
- `outputs/analysis_jobs/<job_id>/`
  Stores:
  - `report.json`
  - `report.md`
  - `metrics.json`
  - `guardrail_audit.json`

### Local script workflow

- `backend/scripts/run.py`
  Single-PCAP local analysis.
- `backend/scripts/batch_analyze.py`
  Batch local analysis over a PCAP directory.
- `backend/scripts/summarize_results.py`
  Aggregates batch JSONL into summary JSON and incident report.
- `backend/scripts/verify_findings.py`
  Analyst verification helper.

### Frontend role

- `frontend/`
  Demo UI for submitting jobs and reading artifacts.
  It is not the primary performance path for large local PCAP analysis.

---

## Current Assessment After The Update

### Requirement compliance

Current status against the project core objective:

- Must ingest PCAP files: Pass
- Must autonomously perform analysis: Pass
- Must generate structured findings and a report: Pass
- Must run without manual step-by-step guidance: Pass

### Deliverable 3 status

#### 2.1 Agent Effectiveness & Forensic Quality

Current status:

- Better than the original baseline
- Still not finished

What is now good:

- Multi-phase pipeline exists and is stable.
- Structured report schema now includes evidence refs and MITRE fields.
- Report output now separates direct evidence, uncertainties, and references better than before.
- Tests exist for schema and evidence-ref generation.

What is still weak:

1. Detector evidence provenance is still built mainly at report-assembly level, not deeply from detector-native output.
2. Detector thresholds remain mostly static and challenge-shaped.
3. Batch result artifacts are still loose and bulky rather than schema-versioned and profile-aware.
4. Validation is improved, but detector-family verification coverage is still narrow.
5. There is still no true external FP/FN evaluation dataset.

#### 2.2 Guardrails & Safety Controls

Current status:

- Stronger than before
- Still partial

What is now good:

- Input validation exists.
- Tool allowlist, timeout, retry, and fallback exist.
- Contradiction checks now exist.
- Guardrail audit trail now exists.
- System is explicitly read-only.

What is still weak:

1. Hallucination control is still mostly consistency-based, not a deeper claim verifier.
2. Report drift protection should remain a priority whenever report generation changes.
3. Guardrails are stronger for final report assembly than for batch artifact quality.

#### 2.3 Cost & Efficiency

Current status:

- Improved
- Still partial

What is now good:

- Runtime, phase timings, provider, model, artifact sizes, and fallback-used state are tracked.
- Benchmark manifest and benchmark script exist.

What is still weak:

1. Batch scripts are still not optimized around lean/full output profiles.
2. Local scripts still default to AI-enabled behavior rather than speed-first deterministic mode.
3. Batch JSONL remains heavy and repetitive for large corpus analysis.

---

## What Person 1 Owns Now

Person 1 no longer owns the original "add evidence refs and MITRE to the report schema" task.
That work is already done.

Person 1 now owns the next layer:

### Workstream 1: Move from report-level evidence refs to detector-native provenance

Goal:

- Make detectors emit stronger, more reusable provenance instead of relying mainly on report-time reference construction.

Target outcomes:

- More precise supporting evidence
- Better analyst trust
- Easier validation and testing

Concrete tasks:

1. Review each detector in `backend/src/detectors.py` and identify what its strongest supporting packet or flow references should be.
2. Add richer source-level evidence where practical, such as:
   - timestamps
   - src and dst IPs
   - ports
   - representative frame numbers
   - protocol
   - correlation basis
   - Wireshark or `tshark` filters
3. Ensure the current evidence refs in `analysis_engine.py` consume detector-native evidence rather than rebuilding too much context from summarized findings.
4. Keep the detector pipeline one-pass and avoid expensive second reads.

### Workstream 2: Rework batch artifacts for speed-first local analysis

Goal:

- Make the batch path cleaner, lighter, and more stable for local use.

Current problem:

- `outputs/scan_results.jsonl` is still a loose, repeated, presentation-heavy structure.

Concrete tasks:

1. Define a versioned batch artifact contract for per-file results.
2. Add:
   - `schema_version`
   - explicit artifact profile
   - clearer separation between summary fields and heavy narrative fields
3. Introduce `lean` and `full` output modes:
   - `lean` for routine speed-first local analysis
   - `full` for demo or deep review
4. Update:
   - `backend/scripts/batch_analyze.py`
   - `backend/scripts/summarize_results.py`
   - `backend/src/report_ai.py`
   to consume the new artifact shape cleanly.
5. Keep API compatibility for the frontend path unless a later frontend change is agreed by the team.

### Workstream 3: Make local scripts truly speed-first

Goal:

- Align the implementation with the project’s local-first, not-online, demo-focused reality.

Concrete tasks:

1. Review `backend/scripts/run.py` and `backend/scripts/summarize_results.py`.
2. Decide and implement a clearer deterministic local default path.
3. Keep direct filesystem path ingestion as the preferred large-PCAP workflow.
4. Reduce unnecessary artifact size and avoid deep-dive-heavy defaults for routine runs.
5. Update docs and benchmark notes to clearly state the recommended run mode for demo.

### Workstream 4: Expand detector validation coverage

Goal:

- Make detector quality claims more defensible in the demo and report.

Concrete tasks:

1. Expand `backend/scripts/verify_findings.py` beyond:
   - inbound RDP
   - `temp.sh`
2. Add verification support for:
   - SMB/RPC scanning
   - DCERPC account markers
   - outbound exfiltration
   - internal RDP spread
   - manual payload deployment
3. Add or improve backend tests around detector quality using:
   - smoke PCAPs
   - synthetic PCAP generation where needed
4. Capture likely false-positive and false-negative boundaries in brief notes for the demo.

### Workstream 5: Tune confidence scoring and detector assumptions

Goal:

- Improve reasoning quality without losing the explainability of the current heuristic system.

Concrete tasks:

1. Review current confidence scoring in `backend/src/analysis_engine.py`.
2. Reduce generic additive scoring where it overstates certainty.
3. Make contradictions, weak corroboration, and sparse support lower confidence more clearly.
4. Isolate scenario-shaped detector thresholds and assumptions so they are easier to tune and explain.
5. Document which detector logic is challenge-specific and which is more general.

---

## Updated Priority Order

Person 1 should now work in this order:

1. Detector-native provenance improvements
2. Batch artifact contract and lean/full output profiles
3. Speed-first local script defaults and workflow cleanup
4. Verification and detector-quality coverage
5. Confidence and threshold tuning
6. Benchmark execution and demo evidence packaging

This order reflects the fact that teammate work already covered a large part of schema, guardrails, and structured reporting.

---

## Recommended Commands

Fastest current local path:

```bash
python backend/scripts/run.py /path/to/file.pcap --no-ai
```

Batch local analysis:

```bash
python backend/scripts/batch_analyze.py --pcap-dir /path/to/pcaps --workers 4
python backend/scripts/summarize_results.py outputs/scan_results.jsonl --no-ai
```

Verification helper:

```bash
python backend/scripts/verify_findings.py rdp --results-file outputs/scan_results.jsonl
python backend/scripts/verify_findings.py temp-sh --results-file outputs/scan_results.jsonl
```

Benchmark support:

```bash
python backend/scripts/run_benchmark.py
```

---

## First Deliverables For Person 1 After This Update

Person 1 should now produce:

1. A short note listing which feedback items from `docs/FirstFeedback.md` are already resolved by teammate work.
2. A detector provenance gap list showing what is still missing at the detector-output level.
3. A proposal for `lean` and `full` batch artifact profiles.
4. A speed-first local workflow recommendation for large PCAPs.
5. A validation roadmap for SMB/RPC, DCERPC, exfiltration, and payload-deployment findings.
6. A detector-threshold tuning note describing where current heuristics may be brittle.

---

## Definition Of Done For Person 1

Person 1 is considered correctly reconfigured and onboarded when they can:

- Explain the current post-update backend architecture accurately
- Distinguish already-completed teammate work from still-open Person 1 work
- Run the local path-based workflow without depending on frontend upload
- Explain where evidence refs and MITRE now exist in the system
- Identify the next high-value gaps in provenance, artifact design, validation, and speed
- Present a realistic, current-state-aligned roadmap for improving the analysis engine
