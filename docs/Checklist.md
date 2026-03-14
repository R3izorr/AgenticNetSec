**Checklist 1: Adhere to Original Requirements (Pass/Fail)**

1. Agent must ingest PCAPs

- [ ] Has a direct PCAP input module.
- [ ] Supports both small and long files (test at least 3 sizes).
- [ ] Clearly logs metadata: filename, size, capture time, number of flows/packets.
- [ ] Handles errors when PCAP is corrupted or lacks read permissions.

2. Agent must perform automated analysis using tools

- [ ] No step-by-step manual operation required from the user.
- [ ] Has a planner that automatically selects the pipeline: parse → feature extraction → detection → reasoning.
- [ ] Clear tool-calling (e.g., tshark/scapy/SIFT tools).
- [ ] Has timeout, retry, and fallback when a tool fails.

3. Agent must generate structured findings + report

- [ ] Standardized JSON findings.
- [ ] Analyst-friendly summary.
- [ ] IOC mapping + timeline + confidence score.
- [ ] Clearly distinguishes between observation, inference, and recommendation.

4. Agent must run autonomously

- [ ] Requires only a single input command.
- [ ] Has short-term memory for context within the same analysis session.
- [ ] Does not require the user to guide it step-by-step.

5. Allowed technologies

- [ ] Can run locally.
- [ ] Clearly states which components are cloud-based (if using LLM APIs).
- [ ] If using SIFT/Security Onion: describes integration or replacement modes.

---

**Checklist 2: Proposed Architecture for Your Submission (NetMoniAI+)**

Objective: Keep the NetMoniAI backbone, add forensic + guardrails + explainability.

1. Ingestion Layer

- [ ] PCAP Loader.
- [ ] Metadata Extractor.
- [ ] Pre-check validator (file integrity, format).

2. Forensic Processing Layer

- [ ] Packet parser (Scapy/TShark).
- [ ] Flow/session reconstruction.
- [ ] Feature extraction: protocol, src/dst, port, burst, entropy, failed handshakes.
- [ ] Event timeline builder.

3. Detection Layer

- [ ] Rule-based detector (baseline, explainable).
- [ ] ML/LLM-assisted detector (if applicable).
- [ ] Zero-day heuristic detector (in the spirit of ThreatFormer: drift/anomaly robustness).

4. Agentic Reasoning Layer

- [ ] Planner creates automated analysis plans.
- [ ] Tool executor calls appropriate modules.
- [ ] Summarizer generates a forensic narrative.

5. Guardrails Layer (Strong Selling Point)

- [ ] Input guardrail: checks prompt/file/path.
- [ ] Tool guardrail: tool whitelisting, blocks dangerous commands.
- [ ] Output guardrail: anti-hallucination + mandates evidence citation.
- [ ] Policy guardrail: no conclusions when confidence is low.

6. Reporting Layer

- [ ] Structured JSON report.
- [ ] Human-readable report (markdown/pdf-ready).
- [ ] Incident severity + MITRE mapping (if any).

7. Observability Layer

- [ ] Runtime logs.
- [ ] Cost/time metrics.
- [ ] Error traces for demonstrating challenges.

---

**Checklist 3: Forensic Report Format (Should freeze schema)**

1. Header

- [ ] Case ID.
- [ ] Timestamp.
- [ ] Analyst mode: Autonomous Agent.
- [ ] Data source list.

2. Evidence

- [ ] Key packets/flows.
- [ ] IOC list.
- [ ] Suspicious sessions.
- [ ] Correlated events by timeline.

3. Findings

- [ ] Primary finding.
- [ ] Supporting evidence.
- [ ] Confidence score.
- [ ] Alternative hypotheses.

4. Impact

- [ ] Affected assets.
- [ ] Attack type (DoS, scan, brute-force, exfiltration, etc.).
- [ ] Risk level.

5. Recommended Actions

- [ ] Immediate containment.
- [ ] Validation steps.
- [ ] Longer-term hardening.

6. Guardrail Verification Block

- [ ] Data validity check pass/fail.
- [ ] Tool-output validation pass/fail.
- [ ] Human-review required (Yes/No).

---

**Checklist 4: Video Demo < 30 minutes (Follow rubric)**

1. Segment 1: Agent Architecture (6-8 mins)

- [ ] Present components + data flow.
- [ ] Highlight the actual toolset.
- [ ] Explain the autonomous decision loop.
- [ ] Clearly state what is inherited from NetMoniAI and the forensic extensions.

2. Segment 2: Live Demo (8-10 mins)

- [ ] Run 1 benign PCAP.
- [ ] Run 1 attack PCAP.
- [ ] Run 1 edge/failure case.
- [ ] Show full report output.

3. Segment 3: Key Challenges (4-5 mins)

- [ ] False positives.
- [ ] Missed detections.
- [ ] Tool limitations.
- [ ] Scale/performance bottlenecks.

4. Segment 4: Guardrails & Safety Controls (5-6 mins)

- [ ] Hallucination detection strategy.
- [ ] Constraints on actions.
- [ ] Validation before drawing conclusions.
- [ ] Human-in-the-loop trigger conditions.

5. Segment 5: Cost & Efficiency (3-4 mins)

- [ ] Cost per run.
- [ ] Runtime breakdown.
- [ ] Speed vs. accuracy vs. cost trade-offs.

Target Total Duration: 26-29 mins.

---

**Checklist 5: Guardrails (Syncing AgentDoG + Securing Agentic AI)**

1. Risk Sources to Cover

- [ ] User input risk.
- [ ] Environmental misinformation.
- [ ] Tool/API risk.
- [ ] Internal reasoning failures.

2. Failure Modes to Check

- [ ] Over-privileged actions.
- [ ] Improper tool use.
- [ ] Failure to validate tool outputs.
- [ ] Inefficient/wasteful execution.
- [ ] Misleading/inaccurate output.

3. Harm Mapping Before Conclusion

- [ ] Privacy/confidentiality.
- [ ] Security/system integrity.
- [ ] Financial/operational impact.
- [ ] Functional harm.

4. Validation Pipeline

- [ ] Schema check (input/tool/output).
- [ ] Evidence consistency check.
- [ ] Confidence thresholding.
- [ ] Inter-module contradiction check.
- [ ] Human approval gate for high-risk actions.

---

**Checklist 6: Key Challenges (Include in slides/report for points)**

1. Technical Challenges

- [ ] Large PCAPs causing parsing bottlenecks.
- [ ] Lack of forensic ground-truth labels.
- [ ] Unstable session reconstruction with complex traffic.
- [ ] LLM latency/token costs.

2. False Positives / Missed Detections

- [ ] FP due to valid but rare spikes.
- [ ] FN due to low-and-slow behaviors.
- [ ] FN when attacker mimics normal traffic.

3. Tool Limitations

- [ ] Inconsistent tool outputs.
- [ ] Parser failures with malformed PCAPs.
- [ ] Dependency version conflicts.

4. Scaling/Performance

- [ ] Massive CPU/RAM spikes during high-speed replays.
- [ ] Queue backlogs in multi-step analysis.
- [ ] Increased latency if multiple validations are enabled.

---

**Checklist 7: Cost & Efficiency (Include figures for points)**

1. Required Metrics to Log

- [ ] Total runtime per case.
- [ ] Time per phase: ingest, parse, detect, reason, report.
- [ ] CPU%, RAM peak.
- [ ] API tokens (if using cloud LLMs).
- [ ] Estimated cost per run.

2. Reporting Formulas

- [ ] Run Cost: $C_{run} = C_{compute} + C_{llm} + C_{storage}$.
- [ ] Run Time: $T_{run} = T_{ingest} + T_{analysis} + T_{reason} + T_{report}$.
- [ ] If using APIs: $C_{llm} = \frac{tok_{in}}{10^6} \times p_{in} + \frac{tok_{out}}{10^6} \times p_{out}$.

3. Mandatory Trade-offs to Discuss

- [ ] Faster execution reduces reasoning depth.
- [ ] Higher accuracy increases compute/token costs.
- [ ] Stricter guardrails increase latency but reduce hallucinations/risky actions.

---

**Checklist 8: Submission Packaging (Correct format, avoid deductions)**

1. Submission Structure

- [ ] Create `Part2` folder.
- [ ] Inside: Deliverable 3 (PDF).
- [ ] Inside: README.txt.
- [ ] Inside: `Agent` folder.

2. Mandatory README.txt Content

- [ ] Brief architecture description.
- [ ] How to run locally.
- [ ] Dependencies and versions.
- [ ] API keys/configuration instructions.
- [ ] Video demo link.
- [ ] Basic troubleshooting.

3. Packaging Rules

- [ ] Zip as `Part2.zip`.
- [ ] Do not use RAR.
- [ ] Do not add a password.
- [ ] Test extraction before submitting.

---

**Checklist 9: PDF Deliverable 3 Outline (Complete Suggested Structure)**

1. Executive Summary

- [ ] Objectives.
- [ ] Novelty compared to Part 1.
- [ ] Key results.

2. Architecture

- [ ] General diagram.
- [ ] Data flow.
- [ ] Decision logic.

3. Agent Workflow

- [ ] PCAP Input.
- [ ] Autonomous analysis loop.
- [ ] Structured reporting.

4. Demo Results

- [ ] Benign case.
- [ ] Attack case.
- [ ] Stress/failure case.

5. Challenges and Failure Analysis

- [ ] FPs/FNs.
- [ ] Tool limits.
- [ ] Performance bottlenecks.

6. Guardrails & Safety

- [ ] Taxonomy-based risk control.
- [ ] Validation gates.
- [ ] Human-in-the-loop.

7. Cost & Efficiency

- [ ] Runtime table.
- [ ] Cost table.
- [ ] Trade-off discussion.

8. Conclusion and Future Work

- [ ] Planned upgrades.
- [ ] Path to production expansion.

---

**Checklist 10: What to Say When Challenged During Q&A**

1. Why choose NetMoniAI as the core?

- [ ] Clear agent + controller architecture is already in place.
- [ ] Has local + simulation experimental setups.
- [ ] Easy to extend for forensic automation.

2. Why add AgentDoG-style guardrails?

- [ ] Shifts from binary safe/unsafe to root-cause diagnosis.
- [ ] Useful for forensic audits and remediation.
- [ ] Reduces risks of hallucinations and tool misuse.

3. Why use MAESTRO-style risk modeling?

- [ ] Mapping threats by layers enables comprehensive control.
- [ ] Provides a basis for defense-in-depth design.
- [ ] Makes mitigation choices easier to justify.
