## Incident Report: Apex Global Logistics

**Date:** March 15, 2024
**Analyst:** Senior Network Forensic Analyst
**Affected Entity:** Apex Global Logistics
**Focus Host:** 10.128.239.57

### 1. Initial Access

Direct evidence indicates that the initial access was primarily facilitated through external Remote Desktop Protocol (RDP) connections to the internal host `10.128.239.57`. A total of 121 PCAP files show evidence of external RDP activity.

The strongest patient zero candidate is associated with the PCAP file `34936-sensor-250306-00002436_redacted.pcap`. This file records an RDP session from external IP `195.211.190.189` to internal IP `10.128.239.57` with a high confidence score of 80. This session was active for over 32 hours and notably targeted 153 unique internal hosts post-login.

Further initial access points were observed from various external IPs to `10.128.239.57`, including `77.90.153.30`, `149.50.116.107`, `179.60.146.33`, `141.98.11.170`, `45.135.232.124`, and others, all with high confidence (80). No VPN-like ingress was identified in the provided evidence.

### 2. Lateral Movement & Discovery

Evidence strongly suggests extensive lateral movement and discovery activities originating from the initial access point `10.128.239.57`.

*   **SMB/RPC Scanning:** The host `10.128.239.57` engaged in significant SMB/RPC scanning, observed in 35 PCAP files. For instance, `34936-sensor-250309-00002481_redacted.pcap` shows `10.128.239.57` scanning 150 unique internal targets. Other instances include scanning 149 targets in `34936-sensor-250301-00002370_redacted.pcap` and 147 targets in `34936-sensor-250301-00002371_redacted.pcap`. This is direct evidence of network reconnaissance.
*   **DCERPC Account Markers:** Five PCAP files contain DCERPC account markers, indicating activity related to account enumeration or manipulation. Examples include `34936-sensor-250306-00002436_redacted.pcap`, `34936-sensor-250306-00002437_redacted.pcap`, and `34936-sensor-250306-00002438_redacted.pcap`, where internal IPs like `10.128.239.34`, `10.128.239.176`, and `10.128.239.37` are involved in communications with `10.128.239.57`. The specific "marker" content is not detailed in the provided evidence, making this a heuristic inference of account activity rather than direct proof of a specific account compromise.

The likely attack flow indicates Discovery occurred directly after Initial Access, which is consistent with the observed SMB/RPC scanning and DCERPC activity from the compromised host.

### 3. Exfiltration

Outbound exfiltration candidates were identified in 9 PCAP files, indicating data egress from the network.

*   **Direct Exfiltration:** Multiple high-severity exfiltration events were observed from `10.128.239.57`. For example, `34936-sensor-250306-00002439_redacted.pcap` shows `240,443,403 bytes` being exfiltrated from `10.128.239.57` to `51.91.79.17` over port `443`. Another significant exfiltration occurred in `34936-sensor-250306-00002441_redacted.pcap` where `576,532,595 bytes` were sent to the same destination `51.91.79.17:443`.
*   **Archive Hits:** Many exfiltration flows showed a high number of 'gzip' archive hits (e.g., 3495 in `34936-sensor-250306-00002439_redacted.pcap`, 3077 in `34936-sensor-250306-00002440_redacted.pcap`), suggesting compressed data was being transferred.
*   **Temp.sh Hits:** Two files (`34936-sensor-250306-00002439_redacted.pcap`, `34936-sensor-250306-00002440_redacted.pcap`) explicitly recorded "temp_sh_hits" and "temp_sh_mentions" (e.g., 6 mentions in the former, 5 in the latter) in conjunction with high-severity outbound exfiltration to `51.91.79.17`. This is a strong heuristic indicator of potential staging or data transfer activities using temporary shell scripts, reinforcing the malicious nature of the exfiltration.
*   **Absence of Large HTTP Uploads:** No large HTTP uploads were detected in the provided PCAP evidence.

Exfiltration is positioned after Payload Deployment and Discovery in the likely attack flow, which aligns with the observed sequence of events where reconnaissance and internal spread would precede data collection and egress.

### 4. Payload Deployment

Evidence of payload deployment, specifically internal RDP spread, was found in 27 PCAP files.

*   **Internal RDP Spread:** The compromised host `10.128.239.57` was observed spreading RDP connections to numerous other internal targets. Notable examples include spreading to 89 unique targets in `34936-sensor-250309-00002477_redacted.pcap`, 77 targets in `34936-sensor-250309-00002481_redacted.pcap`, and 74 targets in `34936-sensor-250301-00002370_redacted.pcap`. This indicates the attacker leveraged the initial access to establish persistence and expand control within the internal network via RDP.

This internal RDP spread is categorized as "Payload Deployment" and is observed in the timeline after initial access and discovery, suggesting a progression of the attack to establish a broader foothold.

### 5. Confidence / Gaps

**Confidence:**
Overall confidence in the identified attack chain is high.
*   **Direct Evidence:** Initial access via external RDP, SMB/RPC scanning, internal RDP spread, and outbound exfiltration flows with byte counts and destinations are directly observed in the PCAP data. The correlation between `temp_sh_hits` and high-volume exfiltration adds strong contextual confidence.
*   **Consistency:** The consistent identification of `10.128.239.57` as the central focus host across all stages of the attack flow (`initial_access`, `discovery`, `payload_deployment`, `exfiltration`) further solidifies the findings.

**Gaps / Heuristic Evidence:**
*   **DCERPC Account Markers:** While the presence of DCERPC account markers strongly suggests account-related activity (e.g., enumeration, authentication attempts), the provided evidence does not detail the specific "marker" content, such as exact account names or actions. This remains a heuristic inference regarding the *type* of administrative activity, but the *occurrence* of the activity is directly observed.
*   **Payload Specifics:** Although internal RDP spread points to payload deployment for lateral movement, the exact nature of any initial payload (e.g., malware, credential stealer) used to gain initial RDP access or to facilitate the spread is not explicitly detailed in the PCAP summaries. Further deep-dive analysis of the RDP streams themselves would be required to potentially uncover this.
*   **Root Cause of Initial RDP Access:** The report confirms external RDP was the vector, but it doesn't specify if this was due to compromised credentials, an exposed RDP server vulnerability, or other means. This would require host-based forensics or login/authentication logs not provided in the PCAP.
*   **Full Scope of Internal Compromise:** While `10.128.239.57` scanned and spread RDP to many targets, the extent of compromise on those secondary targets is not fully detailed within this PCAP summary.
