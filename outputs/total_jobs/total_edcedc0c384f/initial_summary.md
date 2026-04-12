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
Initial Access -> Discovery -> Payload Deployment -> Exfiltration

## Initial Access
Initial access to the network was confirmed via multiple external-to-internal Remote Desktop Protocol (RDP) sessions targeting the internal host `10.128.239.57` (Direct Evidence: RDP handshakes and application packets observed).

Throughout the campaign, `10.128.239.57` was accessed by several suspicious external IP addresses, including `77.90.153.30`, `179.60.146.32`, `45.135.232.124`, and `179.60.146.34`. These RDP sessions consistently show a complete TCP and RDP handshake, followed by extensive application-layer traffic, indicating successful interactive logon and activity (Direct Evidence: Packet captures confirm full RDP session establishment and data exchange).

A total of 20 PCAP files demonstrate distinct external RDP connections to `10.128.239.57`. The highest confidence initial access events (Confidence Score: 80) include:
*   `77.90.153.30` connected at `1768065860.572567` (duration 88448 seconds, 90,400 application packets).
*   `179.60.146.32` connected at `1768965491.400755` (duration 133077 seconds, 67,862 application packets).
*   `45.135.232.124` connected at `1765296995.663519` (duration 151170 seconds, 53,131 application packets).
*   `179.60.146.34` connected at `1768695192.523322` (duration 142593 seconds, 48,031 application packets).

Following these initial access points, `10.128.239.57` was observed engaging in post-login lateral activity targeting numerous internal hosts (Heuristic Inference: "post_login_unique_internal_targets" counts indicate significant internal network interaction following RDP establishment).

There is no direct evidence of prior external port scanning activities specifically targeting `10.128.239.57` that led to these RDP accesses. The mechanism by which the RDP service was compromised (e.g., brute-force, stolen credentials) cannot be determined solely from the provided PCAP findings. No VPN-like ingress was detected.

## Lateral Movement & Discovery
Evidence strongly indicates active internal discovery and lateral movement originating from host `10.128.239.57`.

**Discovery**:
Direct evidence from PCAP findings shows `10.128.239.57` extensively scanning internal targets via SMB/RPC. This activity is observed across fifteen distinct PCAP files, indicating persistent and repeated network reconnaissance. Specific instances include:
- Scanning 21 targets over SMB/RPC (`upload_1775799216_34936-sensor-250308-00002455_redacted.pcap`, `upload_1775799212_34936-sensor-250307-00002447_redacted.pcap`, `upload_1775799214_34936-sensor-250308-00002452_redacted.pcap`, `upload_1775799214_34936-sensor-250307-00002451_redacted.pcap`, `upload_1775799209_34936-sensor-250307-00002445_redacted.pcap`, `upload_1775799212_34936-sensor-250307-00002448_redacted.pcap`).
- Scanning 20 targets over SMB/RPC (`upload_1775799212_34936-sensor-250307-00002446_redacted.pcap`).
- Scanning 22 targets over SMB/RPC (`upload_1775799216_34936-sensor-250308-00002456_redacted.pcap`, `upload_1775799213_34936-sensor-250307-00002449_redacted.pcap`, `upload_1775799214_34936-sensor-250308-00002453_redacted.pcap`, `upload_1775799213_34936-sensor-250307-00002450_redacted.pcap`, `upload_1775799215_34936-sensor-250308-00002454_redacted.pcap`).
- Larger-scale scans targeting 148, 153, and 151 systems over SMB/RPC are also observed (`upload_1775799218_34936-sensor-250308-00002457_redacted.pcap`, `upload_1775799218_34936-sensor-250308-00002458_redacted.pcap`, `upload_1775799218_34936-sensor-250308-00002459_redacted.pcap`).

**Lateral Movement**:
Direct evidence shows `10.128.239.57` initiating RDP connections to multiple internal hosts, indicating attempts at lateral movement:
- Spread internal RDP to 14 targets (`upload_1775799216_34936-sensor-250308-00002455_redacted.pcap`).
- Spread internal RDP to 12 targets (`upload_1775799209_34936-sensor-250307-00002445_redacted.pcap`).

Additionally, related to payload deployment but implying lateral movement, `10.128.239.57` exhibited "manual-drop traits" for payload deployment across 75 targets (`upload_1775799218_34936-sensor-250308-00002457_redacted.pcap`), 93 targets (`upload_1775799218_34936-sensor-250308-00002458_redacted.pcap`), and 73 targets (`upload_1775799218_34936-sensor-250308-00002459_redacted.pcap`). The exact mechanism for these "manual-drop traits" is heuristic, as no `admin_share_targets` or `remote_exec_targets` were identified in these instances. This suggests either interactive remote access or other unobserved lateral movement vectors were employed for these deployments.

**Gaps**:
There is no direct evidence of DCE/RPC account changes. This indicates that either such activity did not occur during the capture period, or the specific methods used for account manipulation (if any) did not trigger the current DCE/RPC account marker detection. No external port scanning was observed.

## Exfiltration
A single high-severity outbound exfiltration flow was observed from the compromised host 10.128.239.57 to the external IP 77.90.153.30, destination port 53632. This flow, captured in `upload_1775799218_34936-sensor-250308-00002458_redacted.pcap` at timestamp 1768066037.343378, directly involved the transfer of 25,606,848 bytes (approximately 24.4 MB).

Heuristic analysis of this flow identified 328 `gzip` archive hits, which strongly suggests the exfiltrated data was compressed. This is a common tactic for reducing data size and potentially evading detection. The destination IP (77.90.153.30) is also directly associated with an initial access event to 10.128.239.57 within the same PCAP file, indicating a direct connection between adversary ingress and data egress. No other outbound exfiltration candidates were observed across the entire multi-file PCAP campaign.

## Payload Deployment
Deployment activities originating from `10.128.239.57` were identified across five distinct PCAP files. Direct evidence confirms that host `10.128.239.57` extensively used internal RDP to spread to multiple targets within the network. Specifically, this RDP spread targeted 14 hosts (in `upload_1775799216_...2455_redacted.pcap`), 12 hosts (in `upload_1775799209_...2445_redacted.pcap`), 99 hosts (in `upload_1775799218_...2457_redacted.pcap`), 110 hosts (in `upload_1775799218_...2458_redacted.pcap`), and 81 hosts (in `upload_1775799218_...2459_redacted.pcap`). This indicates successful lateral movement and control over these systems.

Heuristic evidence, labeled as "manual-drop traits," was observed in three of these files. This activity involved SMB/RPC communications from `10.128.239.57` to 75, 93, and 73 unique targets respectively, suggesting possible manual file transfers or command execution. However, direct indicators of administrative share usage or remote execution command markers were absent in the observed traffic for these "manual-drop traits," making this a heuristic inference rather than confirmed direct payload deployment.

Crucially, no payload artifacts have been successfully carved from any of the PCAP files, and consequently, no specific payload IOCs (hashes, filenames, or file types) have been identified. The payload carving process was noted as "skipped_profile_policy," indicating that artifact recovery was not attempted due to policy configurations, rather than a failure to find identifiable data. The specific nature or identity of any deployed malware or tools remains unknown.

## Confidence / Gaps
Initial Access to host `10.128.239.57` is confirmed with high confidence, based on numerous successful RDP connections from multiple distinct external IP addresses over an extended period. Direct evidence includes RDP handshake completion and subsequent internal activity (`post_login_targets`). The specific credentials or method of compromise (e.g., brute-force, stolen credentials) leading to this RDP access is not ascertainable from the provided PCAP data.

Lateral Movement and Discovery activities originating from `10.128.239.57` are observed with high confidence. This includes extensive internal SMB/RPC scanning targeting many hosts, indicating host enumeration and service discovery. Internal RDP spread from `10.128.239.57` to multiple internal targets is also directly observed, indicating attempted or successful lateral movement. No direct evidence of account changes via DCERPC has been observed.

Exfiltration is directly evidenced by a single, high-severity outbound flow of approximately 25.6 MB from `10.128.239.57` to an external IP (`77.90.153.30`). The specific content or nature of the exfiltrated data is not available from the PCAP.

Payload Deployment activity is inferred from observed "manual-drop traits" across numerous internal targets, often following internal RDP spread. However, no specific payload artifacts have been carved or identified (i.e., `carved_payloads` is empty, `payload_iocs` are absent, and `payload_carving_status` was `skipped_profile_policy` for reviewed files). Therefore, while deployment activity is heuristically indicated, the exact malware or tools used are unknown.

Overall, the attack flow (Initial Access -> Discovery -> Payload Deployment -> Exfiltration) is well-supported by network traffic. The primary gaps relate to the absence of recovered payload artifacts, the specific content of exfiltrated data, and the initial compromise vector (e.g., credentials) for RDP access. Further host-based forensic analysis would be required to identify deployed payloads, user accounts, and specific commands executed. No external port scanning activity was explicitly detected in the provided PCAP files prior to initial RDP access.
