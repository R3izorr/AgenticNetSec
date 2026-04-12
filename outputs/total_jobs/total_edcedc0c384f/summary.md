> Final Campaign Report AI Status
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
Initial access to the network was predominantly observed via Remote Desktop Protocol (RDP) connections targeting internal host **10.128.239.57** on TCP port 3389.

**Direct evidence** indicates successful establishment of RDP sessions from multiple external IP addresses:
*   **77.90.153.30**
*   **179.60.146.32**
*   **45.135.232.124** (multiple instances)
*   **179.60.146.34** (multiple instances)
*   **141.98.11.109** (multiple instances)
*   **179.60.146.30** (multiple instances)
*   **179.60.146.36** (multiple instances)
*   **141.98.11.170**
*   **45.227.254.3**

Each of these connections exhibits a complete TCP three-way handshake followed by a sustained exchange of RDP application-layer packets, confirming active RDP sessions.

**Heuristic inference** of successful authentication and compromise is derived from the high volume of post-login activity originating from 10.128.239.57 shortly after these RDP connections. This includes significant internal discovery (SMB/RPC scanning) and payload deployment activities targeting numerous internal hosts (ranging from 5 to 153 unique targets), strongly suggesting interactive access and control of the initial access point. The confidence scores associated with these RDP sessions range from 65 to 80, reflecting the strength of this evidence.

**Gaps:** While successful RDP sessions are confirmed, the specific authentication methods and credentials utilized for these accesses are not discernible from the provided PCAP findings. There is no direct evidence to determine how initial RDP credentials were obtained (e.g., brute-force, stolen credentials, phishing). No evidence of external port scanning activity preceding these RDP connections was identified in the provided context, suggesting either pre-existing knowledge of the RDP service or reconnaissance conducted outside the monitored scope.

## Lateral Movement & Discovery
The internal host 10.128.239.57 engaged in extensive network discovery and lateral movement activities following initial access.

**Discovery:** Direct evidence from 15 separate PCAP files confirms that host 10.128.239.57 initiated numerous internal SMB/RPC scans. This includes identifying 20-35 unique targets in multiple instances, with more extensive scans observed in `upload_1775799218_34936-sensor-250308-00002457_redacted.pcap` (148 targets) and `upload_1775799218_34936-sensor-250308-00002458_redacted.pcap` (153 targets). No external reconnaissance (port scanning) targeting internal assets was observed.

**Lateral Movement:** Direct evidence indicates host 10.128.239.57 attempted to establish internal RDP connections to other hosts. This "internal RDP spread" was observed in `upload_1775799216_34936-sensor-250308-00002455_redacted.pcap` targeting 14 hosts, and in `upload_1775799209_34936-sensor-250307-00002445_redacted.pcap` targeting 12 hosts. Additionally, heuristic analysis flags "manual-drop traits" (e.g., across 75, 93, and 73 targets in `upload_1775799218_34936-sensor-250308-00002457_redacted.pcap`, `_00002458_redacted.pcap`, and `_00002459_redacted.pcap` respectively). While these "manual-drop traits" are a strong indicator of intent for lateral payload deployment, no direct evidence of file transfers via administrative shares or remote execution over SMB/RPC was explicitly identified within these specific flagged instances.

**Account Changes:** There is no evidence of DCE/RPC account changes or other administrative account activity observed in the provided PCAP data.

## Exfiltration
Host `10.128.239.57` engaged in an outbound data transfer event classified as exfiltration.

**Direct Evidence:**
A high-volume outbound flow was observed from `10.128.239.57` to external IP `77.90.153.30` on destination port `53632`. This transfer involved `25,606,848` bytes (approximately 25.6 MB) and occurred at `1768066037.343378` (recorded within `upload_1775799218_34936-sensor-250308-00002458_redacted.pcap`).

**Heuristic Inference:**
The flow is categorized with a "high" severity, and `328` mentions of `gzip` were detected within the traffic, strongly suggesting the use of data compression, a common technique for exfiltration. This specific exfiltration event occurred shortly after `10.128.239.57` established initial access from `77.90.153.30`, indicating a direct link between the external attacker IP and the exfiltration destination. No specific file names or content of the exfiltrated data have been directly identified from the PCAP at this stage.

## Payload Deployment
Payload deployment activities were observed originating from the focus host `10.128.239.57`. Direct evidence indicates `10.128.239.57` initiated internal RDP connections, spreading to 14 distinct targets (in `upload_1775799216_34936-sensor-250308-00002455_redacted.pcap`) and an additional 12 targets (in `upload_1775799209_34936-sensor-250307-00002445_redacted.pcap`).

Heuristic evidence suggests manual payload deployment traits by `10.128.239.57` across numerous internal targets. Specifically, three PCAP files (`upload_1775799218_34936-sensor-250308-00002457_redacted.pcap`, `upload_1775799218_34936-sensor-250308-00002458_redacted.pcap`, and `upload_1775799218_34936-sensor-250308-00002459_redacted.pcap`) show activity consistent with manual drops to 75, 93, and 73 targets respectively. This inference is based on observed SMB/RPC activity to these targets without clear indications of admin share usage or remote execution markers, resulting in a low payload deployment confidence score of 0.35 for these instances. The provided `payload_iocs` for these events are limited to SMB/RPC port and source/target IP addresses, which are indicators of network protocols used rather than specific payload identifiers.

Critically, **no direct payload artifacts (e.g., file hashes, filenames, or carved binaries) have been recovered** from any of the PCAP files, despite identified carving candidates. The payload carving status across all relevant files is "heuristic_only," meaning the specific nature and content of any deployed payloads remain unknown. There is no partial or confirmed artifact evidence.

## Confidence / Gaps
Confidence in the initial access is high, based on numerous external RDP connections from multiple distinct IP addresses to host 10.128.239.57 with strong confidence scores (e.g., 80%). The specific method of initial compromise (e.g., brute-force, stolen credentials, RDP vulnerability) cannot be determined from PCAP data alone and remains a gap.

Lateral movement and discovery are well-evidenced. Direct observations confirm extensive SMB/RPC scanning and internal RDP spread from 10.128.239.57 to a significant number of internal targets (up to 153 for SMB/RPC scans, and multiple RDP connections to 12-14 targets). There is no direct evidence of account changes or privilege escalation via DCERPC.

A single, high-severity exfiltration event of approximately 25MB from 10.128.239.57 to an external IP (77.90.153.30:53632) is directly observed. The content of this exfiltrated data is unknown, representing a gap in the evidence.

Payload deployment is largely heuristic. While "manual-drop traits" were identified across numerous targets (e.g., 73-93 targets), indicating potential manual file transfer or execution, no confirmed payload artifacts (hashes, filenames, or full binaries) were successfully carved from the PCAPs. The `payload_carving_status` is either `skipped_profile_policy`, `no_candidates`, or `heuristic_payload_only`. Therefore, the specific nature of the deployed payload(s) and the exact mechanism (e.g., via admin shares, remote execution) beyond manual interaction over RDP is a significant gap, relying only on heuristic inference.
