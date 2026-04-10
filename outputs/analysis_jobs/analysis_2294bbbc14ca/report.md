# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 195.211.190.189 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (147 targets)

## Exfiltration
No direct temp.sh indicator was found. Additional outbound transfer spikes were observed from 10.128.239.57 -> 195.211.190.189:52946 (14582215 bytes).

## Payload Deployment
Heuristic deployment evidence is present through correlated RDP plus SMB/DCERPC admin-share activity from 10.128.239.57 to 74 hosts (admin_share_targets=0, remote_exec_targets=0). Confidence=0.00.

## Confidence / Gaps
Total packets analyzed: 1790189. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery -> Exfiltration -> Payload Deployment

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery -> Exfiltration -> Payload Deployment
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-05T03:39:18.459193+00:00 evidence=External RDP from 195.211.190.189 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-05T03:39:35.541778+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 147 internal targets.
- administrative_activity: supported=False weakly_supported=True confidence=0.35 first_seen=None evidence=Generic SMB/DCERPC marker strings were observed near the focus host, but they did not meet the account-change threshold.
- exfiltration: supported=True weakly_supported=False confidence=0.65 first_seen=2026-01-06T07:34:38.112303+00:00 evidence=Outbound upload or transfer evidence exists and should be treated as potential exfiltration.
- payload_deployment: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-06T09:44:19.645720+00:00 evidence=Internal RDP plus SMB/DCERPC correlations are consistent with manual payload deployment.
Best ingress candidate: external `195.211.190.189` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 195.211.190.189 -> 10.128.239.57 packets=109182 app_packets=72391 post_login_targets=147 suspicious=True
- 141.98.11.170 -> 10.128.239.57 packets=97602 app_packets=58237 post_login_targets=147 suspicious=True
- 194.0.234.17 -> 10.128.239.57 packets=94208 app_packets=56902 post_login_targets=147 suspicious=True
- 45.135.232.124 -> 10.128.239.57 packets=60774 app_packets=36496 post_login_targets=147 suspicious=True
- 141.98.83.70 -> 10.128.239.57 packets=35721 app_packets=22857 post_login_targets=147 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=147 attempts=159 duration=113519.66
- Internal RDP spread source 10.128.239.57 unique_targets=80 sessions=80 duration=46398.28

### Administrative Activity Pivot
Possible account or group administration markers were observed over SMB/DCERPC.
- DCERPC markers 10.128.239.176 -> 10.128.239.57 markers={'c$': 2}

### Exfiltration Pivot
Outbound HTTP upload or temp.sh evidence exists and should be reviewed for archive staging and data loss.
- Outbound exfil candidate 10.128.239.57 -> 195.211.190.189:52946 total_bytes=14582215 payload_bytes=11764075 archive_hits={'gzip': 147}

### Payload Deployment Pivot
RDP fan-out from the focus host overlapped with SMB/DCERPC admin-share or remote-exec markers on the same internal targets, which is consistent with manual payload drop activity.
- Manual-drop candidate 10.128.239.57 targets=74 smb_targets=74 admin_share_targets=0 remote_exec_targets=0 score=100
- Internal RDP spread source 10.128.239.57 unique_targets=80 sessions=80 duration=46398.28


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
