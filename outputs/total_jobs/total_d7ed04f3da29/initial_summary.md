> Initial Campaign Summary AI Status
> AI requested: yes
> AI callable: yes
> Fallback used: no
> Status: ai_generated
> Provider used: gemini
> Model used: gemini-2.5-flash
>
> If `AI callable: no`, this markdown came from the deterministic fallback report.
# Incident Report

Attack Flow:
Initial Access -> Payload Deployment -> Discovery -> Exfiltration

## Initial Access
Initial access was established via Remote Desktop Protocol (RDP) connections to the internal host `10.128.239.57`. Direct evidence from PCAP analysis confirms 20 distinct external-to-internal RDP sessions, characterized by complete TCP and RDP handshakes, followed by significant RDP application traffic.

The primary external IP addresses observed initiating these connections include:
*   `195.211.190.189`
*   `141.98.11.170`
*   `141.98.11.190`
*   `141.98.11.81`
*   `185.147.125.13`

These connections demonstrate successful RDP session establishment, indicated by the presence of RDP application packets flowing in both directions, confirming post-handshake activity. Heuristic analysis further suggests successful authentication and interaction, as lateral movement (e.g., internal RDP spread) and discovery activities were observed originating from `10.128.239.57` shortly after these initial RDP accesses. While the specific credentials used for initial RDP login are not directly observable in the provided PCAP, the immediate follow-on activity from `10.128.239.57` strongly indicates compromise through these RDP sessions. There is no direct evidence of external port scanning preceding these successful RDP connections within the provided data.

## Lateral Movement & Discovery
Lateral Movement & Discovery

Evidence directly indicates the compromised host `10.128.239.57` engaged in significant internal discovery and lateral movement activities.

**Discovery:**
The host `10.128.239.57` performed extensive SMB/RPC scanning on at least two distinct occasions:
*   On 2025-12-17, `10.128.239.57` scanned 149 unique internal targets via SMB/RPC, spanning over 38 hours (PCAP: `upload_1775748864_34936-sensor-250301-00002370_redacted.pcap`). This is direct evidence of internal network reconnaissance.
*   On 2026-01-05, `10.128.239.57` scanned 147 unique internal targets via SMB/RPC, over approximately 31 hours (PCAP: `upload_1775748864_34936-sensor-250301-00002371_redacted.pcap`). This is also direct evidence of internal network reconnaissance.

Additionally, internal SMB/RPC scanning activity was observed originating from `10.128.239.39`, targeting 20 unique hosts in two separate instances (PCAPs: `upload_1775748866_34936-sensor-250302-00002376_redacted.pcap`, `upload_1775748866_34936-sensor-250302-00002377_redacted.pcap`). While this is direct evidence of scanning, the relationship of `10.128.239.39` to the primary focus host `10.128.239.57` or the overall campaign is not explicitly established from the provided PCAP findings.

No direct evidence of external port scanning targeting internal hosts (beyond initial access points) was identified.

**Lateral Movement:**
Extensive lateral movement was observed, primarily originating from `10.128.239.57`:
*   **Internal RDP Spread:** `10.128.239.57` initiated RDP connections to a large number of internal systems, indicating RDP-based lateral movement. Specific instances show RDP spreading to 12, 16, 21, 21, 17, 12 targets, and broader activities categorized as RDP spread to 74 and 80 targets (aggregate across multiple PCAPs). This is direct evidence.
*   **Manual Payload Deployment Candidates:** There is direct evidence of `10.128.239.57` engaging in activities consistent with manual payload deployment across multiple internal targets:
    *   Deployment to 61 unique targets, with one target showing direct evidence of an admin share (`admin$`) being accessed for deployment (PCAP: `upload_1775748864_34936-sensor-250301-00002370_redacted.pcap`).
    *   Deployment to 74 unique targets (PCAP: `upload_1775748864_34936-sensor-250301-00002371_redacted.pcap`).
    These activities imply lateral movement to facilitate payload distribution.

No evidence of DCE/RPC account changes (e.g., password resets, new user creation) was identified, meaning privilege escalation via these specific network indicators cannot be confirmed from the PCAPs.

## Exfiltration
On 2026-01-06 at 07:34:38 UTC, the focus host `10.128.239.57` initiated an outbound data transfer totaling 14.5 MB to external IP `195.211.190.189` on port `52946`. This constitutes direct evidence of a bulk outbound flow. Heuristic analysis of the flow indicates the presence of 147 GZIP archive hits, strongly suggesting the exfiltration of compressed data.

The destination IP `195.211.190.189` was also identified as the source for an initial access event via RDP to `10.128.239.57` at a timestamp immediately preceding the observed exfiltration, suggesting it functions as a command-and-control (C2) and exfiltration endpoint.

**Confidence / Gaps:**
The presence of a significant outbound data flow to an actor-controlled IP, combined with heuristic indicators of compressed content, provides medium confidence for exfiltration. The specific content of the exfiltrated data remains unknown as payload carving was skipped per policy, preventing identification of file types or sensitive information.

## Payload Deployment
The internal host 10.128.239.57 demonstrated significant activity consistent with payload deployment across eight distinct PCAP captures. This activity primarily consists of two observed patterns:

1.  **Internal RDP Spread:** The host 10.128.239.57 initiated numerous RDP connections to internal targets. This was observed spreading to 12 targets (upload\_1775748867\_34936-sensor-250303-00002380\_redacted.pcap), 16 targets (upload\_1775748861\_34936-sensor-250301-00002364\_redacted.pcap), 21 targets (upload\_1775748867\_34936-sensor-250303-00002381\_redacted.pcap and upload\_1775748865\_34936-sensor-250302-00002372\_redacted.pcap), 17 targets (upload\_1775748862\_34936-sensor-250301-00002365\_redacted.pcap), and 12 targets (upload\_1775748865\_34936-sensor-250302-00002373\_redacted.pcap). This RDP activity is classified as payload deployment in the incident timeline, indicating a heuristic inference that RDP access was leveraged for subsequent actions.

2.  **Manual Payload Deployment Traits:** Direct evidence of "manual-drop traits" was identified from 10.128.239.57. Specifically, in `upload_1775748864_34936-sensor-250301-00002370_redacted.pcap`, manual-drop traits were observed across 61 targets, with one target showing specific administrative share markers. Similarly, in `upload_1775748864_34936-sensor-250301-00002371_redacted.pcap`, manual-drop traits were observed across 74 targets. These traits, characterized by SMB/RPC activity consistent with file transfer, are strong indicators of an attacker pushing files to compromised hosts.

**Carved Payloads & IOCs:** Despite the observed deployment activity, **no payload artifacts were successfully carved from the PCAP data, and no specific payload IOCs (hashes, filenames, or file-type indicators) were recovered.** The payload carving status for relevant files indicates "skipped\_profile\_policy," meaning that automated carving did not yield results. This absence of direct payload evidence limits our ability to identify the specific malware or tools deployed.

**Confidence:** While network traffic patterns strongly suggest payload deployment activities (e.g., manual-drop traits with SMB/RPC, and internal RDP for lateral tool execution), the **absence of carved payload artifacts or specific IOCs means that the nature of the deployed payloads remains unconfirmed.** The confidence in observing *deployment activity* is high, but the confidence in *identifying the specific payload* is absent based on the provided network captures.

## Confidence / Gaps
Confidence in the overall attack flow, including Initial Access, Lateral Movement via RDP, and Discovery via SMB/RPC, is high. Direct network evidence confirms multiple external RDP connections to `10.128.239.57` from numerous unique external IPs, followed by extensive internal RDP spreading to multiple targets (up to 80 unique hosts observed in one file) and significant internal SMB/RPC scanning activities (up to 149 targets). This clearly establishes `10.128.239.57` as the initial beachhead and pivot point.

Exfiltration is directly evidenced by a substantial outbound data transfer (14.5MB with gzip indicators) from `10.128.239.57` to an external IP (`195.211.190.189`) that was also involved in initial access. This constitutes strong heuristic evidence of data theft, though the specific content of the exfiltrated data remains unconfirmed due to redaction.

The payload deployment phase is observed through "manual-drop traits" across a significant number of internal targets (up to 74 hosts), implying interactive file transfers or command execution via RDP sessions. However, a critical gap exists as *no payload artifacts were carved*, and consequently, no specific payload IOCs (hashes, filenames) could be recovered. The `payload_carving_status` indicates "skipped_profile_policy", meaning the full content was not analyzed or extracted. Therefore, while deployment activity is heuristically evident, the nature of the deployed malware is unknown.

Finally, there is an absence of direct evidence for external port scanning activities against internal hosts and no explicit DCERPC markers indicating account changes or administrative activity within the provided PCAP files. This does not mean these activities did not occur, only that the available network captures did not contain explicit traces. The `ai_tshark_review` status is null for all representative records, indicating that targeted follow-up analysis on specific weak sections was either not performed or its results are not reflected in this summary.
