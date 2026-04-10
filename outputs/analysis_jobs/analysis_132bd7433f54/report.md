# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 195.211.190.189 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (153 targets)

## Exfiltration
No direct temp.sh indicator was found. Additional outbound transfer spikes were observed from 10.128.239.57 -> 195.211.190.189:53789 (42750302 bytes).

## Payload Deployment
Heuristic deployment evidence is present through correlated RDP plus SMB/DCERPC admin-share activity from 10.128.239.57 to 65 hosts (admin_share_targets=2, remote_exec_targets=1). Confidence=0.00.

## Confidence / Gaps
Total packets analyzed: 1117712. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery -> Administrative Activity -> Exfiltration -> Payload Deployment

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery -> Administrative Activity -> Exfiltration -> Payload Deployment
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-10T15:50:10.393525+00:00 evidence=External RDP from 195.211.190.189 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-10T15:50:32.092414+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 153 internal targets.
- administrative_activity: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-10T17:54:15.093592+00:00 evidence=DCERPC/account-administration markers were observed near the focus host.
- exfiltration: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-11T22:09:33.914086+00:00 evidence=Outbound upload or transfer evidence exists and should be treated as potential exfiltration.
- payload_deployment: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-12T01:40:26.909597+00:00 evidence=Internal RDP plus SMB/DCERPC correlations are consistent with manual payload deployment.
Best ingress candidate: external `195.211.190.189` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 195.211.190.189 -> 10.128.239.57 packets=128313 app_packets=91808 post_login_targets=153 suspicious=True
- 141.98.83.70 -> 10.128.239.57 packets=80191 app_packets=51400 post_login_targets=153 suspicious=True
- 179.60.146.37 -> 10.128.239.57 packets=66903 app_packets=43069 post_login_targets=153 suspicious=True
- 91.238.181.10 -> 10.128.239.57 packets=42166 app_packets=25745 post_login_targets=153 suspicious=True
- 92.255.85.173 -> 10.128.239.57 packets=48725 app_packets=23188 post_login_targets=153 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=153 attempts=229 duration=127106.2
- Internal RDP spread source 10.128.239.57 unique_targets=73 sessions=73 duration=6705.27

### Administrative Activity Pivot
Possible account or group administration markers were observed over SMB/DCERPC.
- DCERPC markers 10.128.239.34 -> 10.128.239.57 markers={'c$': 220, 'administrators': 6}
- DCERPC markers 10.128.239.176 -> 10.128.239.57 markers={'c$': 9}
- DCERPC markers 10.128.239.20 -> 10.128.239.57 markers={'c$': 7}

### Exfiltration Pivot
Outbound HTTP upload or temp.sh evidence exists and should be reviewed for archive staging and data loss.
- Outbound exfil candidate 10.128.239.57 -> 195.211.190.189:53789 total_bytes=42750302 payload_bytes=38633270 archive_hits={'gzip': 609}

### Payload Deployment Pivot
RDP fan-out from the focus host overlapped with SMB/DCERPC admin-share or remote-exec markers on the same internal targets, which is consistent with manual payload drop activity.
- Manual-drop candidate 10.128.239.57 targets=65 smb_targets=65 admin_share_targets=2 remote_exec_targets=1 score=100
- Internal RDP spread source 10.128.239.57 unique_targets=73 sessions=73 duration=6705.27


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 195.211.190.189 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- Internal RDP spread from the focus host is consistent with manual operator-driven lateral movement or payload staging.
- RDP fan-out from the focus host overlaps with SMB/DCERPC admin-share or remote-exec indicators on the same targets, which is stronger evidence of manual payload drop behavior.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
