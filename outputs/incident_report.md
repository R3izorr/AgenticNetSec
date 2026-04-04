## Incident Report: Apex Global Logistics

**Date:** [Current Date]
**Affected Organization:** Apex Global Logistics
**Focus Host:** 10.128.239.57
**Overview:**
Analysis of PCAP data indicates a sophisticated multi-stage incident originating from external RDP access to an internal host (10.128.239.57). This initial compromise led to extensive internal discovery, lateral movement, payload deployment, and significant exfiltration of compressed data.

---

### 1. Initial Access

The primary method of initial access was identified as **Remote Desktop Protocol (RDP)**. The strongest patient-zero candidate is internal IP **10.128.239.57**, which was accessed externally from multiple suspicious IP addresses.

The most prominent initial access event, based on duration and packet activity, is observed in **34936-sensor-250306-00002436_redacted.pcap**, where external IP **195.211.190.189** initiated a long-duration RDP session with `10.128.239.57`. This session exhibited a complete RDP handshake and extensive application-layer traffic. Similar suspicious external-to-internal RDP sessions (121 in total) were detected across all analyzed PCAP files, indicating widespread RDP exposure or compromise.

No external port scans or VPN-like ingress activities were identified in the provided evidence.

---

### 2. Lateral Movement & Discovery

Following initial access, the compromised host **10.128.239.57** engaged in significant internal reconnaissance and lateral movement activities:

*   **SMB/RPC Scanning:** Host `10.128.239.57` performed extensive SMB/RPC scanning, observed in 35 PCAP files. For instance, in **34936-sensor-250301-00002370_redacted.pcap**, `10.128.239.57` scanned 149 unique internal targets over SMB/RPC. This is direct evidence of discovery activity to map the internal network.
*   **Internal RDP Spread:** `10.128.239.57` was involved in spreading internal RDP connections, detected in 27 PCAP files. This indicates attempts to establish control or further access to other internal hosts using RDP. For example, in **34936-sensor-250309-00002477_redacted.pcap**, `10.128.239.57` spread internal RDP to 89 unique targets. This is direct evidence of lateral movement.
*   **DCERPC Account Markers:** DCERPC account markers were detected in 5 PCAP files, involving `10.128.239.57`. The `attack_flow` indicates "Administrative Activity" as a stage performed by `10.128.239.57`. However, the detailed `dcerpc_account_records` show other internal IPs (e.g., `10.128.239.34`, `10.128.239.176`, `10.128.239.37`) as source IPs communicating with `10.128.239.57` as the destination for these markers. This is a heuristic inference suggesting potential credential access attempts or other administrative actions targeting `10.128.239.57` or actions from other compromised hosts involving `10.128.239.57`.

No external reconnaissance was observed.

---

### 3. Exfiltration

Significant outbound data exfiltration was detected from **10.128.239.57** to multiple external destinations, appearing in 9 PCAP files:

*   **High-Severity Exfiltration:** Large volumes of compressed data were exfiltrated.
    *   In **34936-sensor-250306-00002439_redacted.pcap**, `10.128.239.57` exfiltrated **240 MB** (240,443,403 bytes) to **51.91.79.17** over port 443 (HTTPS), with 3495 gzip archive hits. This is classified as high severity.
    *   In **34936-sensor-250306-00002441_redacted.pcap**, `10.128.239.57` exfiltrated **576 MB** (576,532,595 bytes) to **51.91.79.17** over port 443, also classified as high severity.
    *   In **34936-sensor-250306-00002440_redacted.pcap**, `10.128.239.57` exfiltrated **216 MB** (216,753,753 bytes) to **51.91.79.17** over port 443, with 3077 gzip hits and 1 zip hit, classified as high severity.
*   **Medium-Severity Exfiltration:** Additional exfiltration flows were observed to other external IPs:
    *   In **34936-sensor-250301-00002371_redacted.pcap**, `10.128.239.57` exfiltrated **14.5 MB** to **195.211.190.189** (the initial access external IP) on port 52946, with 147 gzip hits.
    *   In **34936-sensor-250306-00002438_redacted.pcap**, `10.128.239.57` exfiltrated **12.9 MB** to **195.211.190.189** on port 53789, with 166 gzip hits.
    *   In **34936-sensor-250309-00002477_redacted.pcap**, `10.128.239.57` exfiltrated **11.7 MB** to **77.90.153.30** on port 55613, with 156 gzip hits.
    *   In **34936-sensor-250309-00002482_redacted.pcap**, `10.128.239.57` exfiltrated **22.1 MB** to **77.90.153.30** on port 55613, with 289 gzip hits.

The presence of numerous gzip/zip archive hits strongly suggests the exfiltration of compressed data. No large HTTP uploads were identified.

---

### 4. Payload Deployment

Payload deployment activities by `10.128.239.57` were identified across 8 PCAP files, using both manual and likely automated methods:

*   **Manual Payload Deployment:** Evidence of "manual-drop traits" from `10.128.239.57` was found, indicating interactive or manual deployment of malicious tools/scripts. For example, in **34936-sensor-250301-00002370_redacted.pcap**, `10.128.239.57` showed manual-drop traits across 61 targets, with 1 target exhibiting admin share markers. This implies direct file transfer or command execution.
*   **`temp_sh` Hits:** Heuristic indicators for temporary shell script activity (`temp_sh_hits`) were observed in 2 PCAP files (**34936-sensor-250306-00002439_redacted.pcap** and **34936-sensor-250306-00002440_redacted.pcap**), linking `10.128.239.57` to the exfiltration destination `51.91.79.17`. This suggests the execution of short-lived scripts, potentially for data collection or C2.

---

### 5. Confidence / Gaps

**Confidence:** High. The evidence paints a clear picture of a successful compromise originating from external RDP to host `10.128.239.57`, followed by comprehensive internal discovery (SMB/RPC scanning), lateral movement (internal RDP spread), manual payload deployment, and significant data exfiltration. The correlation of multiple suspicious activities from the same internal host and external IPs, coupled with high confidence scores for RDP sessions and specific indicators like compressed data exfiltration and `temp_sh_hits`, strongly supports this attack narrative. The `attack_flow` timeline consistently shows stages of initial access, discovery, payload deployment, and exfiltration.

**Gaps:**
*   The initial RDP compromise vector (e.g., brute-force, leaked credentials, RDP exploit) is not specified by the PCAP analysis.
*   The specific content of the exfiltrated data is unknown, though its compression (gzip/zip) is noted.
*   Detailed command execution for "manual-drop traits" or "temp_sh_hits" is not provided, making it impossible to identify specific malware or post-exploitation tools.
*   The exact nature and initiation of activities related to `dcerpc_account_markers` are slightly ambiguous. While the overall `attack_flow` attributes administrative activity to `10.128.239.57`, the detailed records show other internal IPs as sources for these markers, suggesting either `10.128.239.57` was targeted or these were actions by other already compromised hosts.
*   No external port scans or VPN-like ingress activities were explicitly observed, which could indicate a targeted RDP compromise rather than opportunistic scanning.
