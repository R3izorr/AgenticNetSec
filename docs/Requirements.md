College of Computing and Data Science

# CCDS, 50 Nanyang Avenue, North Spine Block N4, Singapore 639798 http://www.ntu.edu.sg

### SC4063 NETWORK FORENSIC FINAL PROJECT

## PROJECT OVERVIEW AND LEARNING OBJECTIVES

This project is designed to simulate real-world network incident response and forensic investigation, followed by an

exploration of agentic, AI-assisted forensic analysis, which represents the emerging future of cybersecurity
operations.

By completing this project, students will:

1. Apply network forensic techniques to real packet capture data
2. Practice structured incident response reporting aligned with industry standards
3. Develop analytical thinking under uncertainty and incomplete information
4. Experience the limitations of automation and AI in security investigations
5. Design guardrails to manage AI hallucination and decision risk
6. Communicate technical findings clearly to both technical and non-technical audiences

Students are expected to demonstrate technical rigor, investigative reasoning, teamwork, and professional

communication.

**Team Structure:**

- Students will be randomly group into 10 - 11 members group.
- Each team member must contribute meaningfully and visibly to the project
- Clear role allocation and accountability is required and will be assessed

## PART 1 : NETWORK FORENSIC INVESTIGATION

**Scenario:**

You are a network incident response team engaged by a client during Phase 1 of a cybersecurity investigation.
The client has detected suspicious activity and has provided one or more packet capture (PCAP) files.

At this stage:

- No endpoint telemetry is available
- No host images are provided

Your task is to analyze the PCAP(s), identify malicious or anomalous behavior, and produce a formal Phase 1
Investigation Report suitable for executive and technical stakeholders.

**Deliverable 1: Formal Investigation Report ( 30 % of total marks)**
Your report must be professionally written and structured as follows:

1. Title/Cover Page, clearly indicating each student’s name and matriculation number.
2. Table of Contents
3. Executive summary written for C-suite stakeholders detailing the root cause, impact and
   recommendations.
4. Detailed Findings including MITRE ATT&CK tactics, techniques and sub-techniques observed, tools
   used, assumptions and scope.

5. Conclusion and Recommendation, provide prioritized recommendations to address gaps (if any) and
   defensive controls to prevent recurrence
6. Appendix – Timeline
7. Appendix – Timesheet and work breakdown, detailing the responsibility of each consultant
8. Appendix – Any other details you deem necessary

**Deliverable 2: In Class Presentation ( 30 % of total marks)**
Prepare a presentation to present in class. You have 10 minutes to present your findings and another 5 minutes for
Q&A.

**Evaluation criteria:**

1. Quality, Completeness and accuracy of report
2. Marks will be awarded for quality questions asked and answered during Q&A.
3. Fee incurred. Client will negotiate for discount following your presentation. Marks will be awarded
   depending on the outcome.
4. Q&A

**Submission Criteria:**
Follow the following submission criteria **closely** , failure to do so would result in marks deducted.

1. Do not use any space in your file names. Should it be required, use underscore “\_”.
2. All submission should be in PDF. If you include visual effects in your presentation, ensure that the
   slides remain coherence in PDF form.
3. Name your Deliverable 1 as follow _Group<x>\_NetworkForensicReport.pdf_ where x is your group
   number.
4. Name your Deliverable 2 as follow _Group<x>\_Presentation.pdf_ where x is your group number.
5. Create a folder named “Part1”, containing both Deliverable 1 and 2. Zip up the folder and name the file
   “Part1.zip”.
6. Do not use RAR or any other archival tools. Do not put a password on your zip file. Marks will be
   deducted if your file cannot be accessed.

## PART 2 : AGENTIC NETWORK FORENSIC (Focus on this)

Modern cyber espionage and advanced threats increasingly operate at machine speed.
Human-only analysis does not scale.

Refer to AI Orchestrated cyber espionage campaign and Protocol SIFT.

**Objective:**
Design and build a network forensic agent capable of autonomously analyzing PCAP files and producing a forensic
report comparable to your **Part 1** findings.

**Requirements:**
Your agent:

1. Must ingest PCAP files
2. Must autonomously perform analysis using available tools
3. Must generate structured findings and a report
4. Must operate without manual step-by-step guidance

You may use:

- Security Onion
- SIFT Workstation
- Custom Python tooling
- LLMs and orchestration frameworks
- Local or cloud-based execution environments

You are free to design the architecture.

**Deliverable 3 : Agent Demo and Presentation (40% of total marks)**

Prepare a video demo presentation for submission. Video length should be less than 30 minutes.

Your video demo presentation must include the following:

1. Agent Architecture
   - Components and data flow
   - Tools available to the agent
   - Decision-making logic
2. Demo
   - Show how the agent analyzes PCAPs
   - Show generated outputs
3. Key Challenges
   - Technical challenges
   - False positives or missed detections
   - Tool limitations
   - Scaling or performance issues
4. Guardrails and Safety Controls
   - How hallucination is prevented or detected
   - Constraints placed on agent actions
   - Validation steps before conclusions
   - Human-in-the-loop considerations
5. Cost and Efficiency
   - Compute cost per run (estimated or measured)
   - Time to complete analysis
   - Trade-offs between speed, accuracy, and cost

**Evaluation criteria:**

1. Agent Effectiveness & Forensic Quality
2. Guardrails & Safety Controls
3. Cost & Efficiency
4. Demo Quality

**Submission Criteria:**
Follow the following submission criteria **closely** , failure to do so would result in marks deducted.

1. Prepare a README.txt that is comprehensive and contains all keys and repositories required to run your
   agent.
2. Include the recorded video link in your README.txt.
3. Deliverable 3 submission should be in PDF. If you include visual effects in your presentation, ensure that
   the slides remain coherent in PDF form.
4. Create a folder named “Part 2 ”, containing Deliverable 3, README.txt and a folder named “Agent”.
5. If your agent is able to run locally (with Internet), put all related files in “Agent” folder. Any folder
   dependencies should be clearly stated in README.txt.
6. Zip up the folder and name the file “Part 2 .zip”.
7. Do not use RAR or any other archival tools. Do not put a password on your zip file. Marks will be deducted
   if your file cannot be accessed.
