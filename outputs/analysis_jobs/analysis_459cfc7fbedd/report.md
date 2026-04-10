# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 141.98.11.170 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (149 targets)

## Exfiltration
No direct temp.sh indicator was found.

## Payload Deployment
Heuristic deployment evidence is present through correlated RDP plus SMB/DCERPC admin-share activity from 10.128.239.57 to 61 hosts (admin_share_targets=1, remote_exec_targets=0). Confidence=0.00.

## Confidence / Gaps
Total packets analyzed: 1442537. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery -> Payload Deployment

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery -> Payload Deployment
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-17T12:55:32.620737+00:00 evidence=External RDP from 141.98.11.170 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-17T12:56:27.812818+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 149 internal targets.
- administrative_activity: supported=False weakly_supported=True confidence=0.35 first_seen=2025-12-18T06:14:56.480920+00:00 evidence=Generic SMB/DCERPC marker strings were observed near the focus host, but they did not meet the account-change threshold.
- exfiltration: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No direct exfiltration indicator was isolated in this file.
- payload_deployment: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-19T01:55:08.227476+00:00 evidence=Internal RDP plus SMB/DCERPC correlations are consistent with manual payload deployment.
Best ingress candidate: external `141.98.11.170` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 141.98.11.170 -> 10.128.239.57 packets=105713 app_packets=63122 post_login_targets=151 suspicious=True
- 194.0.234.17 -> 10.128.239.57 packets=94830 app_packets=57213 post_login_targets=151 suspicious=True
- 45.135.232.124 -> 10.128.239.57 packets=45798 app_packets=27446 post_login_targets=151 suspicious=True
- 179.60.146.33 -> 10.128.239.57 packets=33327 app_packets=21348 post_login_targets=151 suspicious=True
- 141.98.83.70 -> 10.128.239.57 packets=31865 app_packets=20367 post_login_targets=151 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=149 attempts=159 duration=138866.88
- Internal RDP spread source 10.128.239.57 unique_targets=74 sessions=74 duration=43915.58

### Administrative Activity Pivot
Possible account or group administration markers were observed over SMB/DCERPC.
- DCERPC markers 10.128.239.176 -> 10.128.239.57 markers={'c$': 19}
- DCERPC markers 10.128.239.57 -> 10.128.239.29 markers={'c$': 3}
- DCERPC markers 10.128.239.57 -> 10.128.239.23 markers={'c$': 2}

### Exfiltration Pivot
No direct exfiltration indicator was observed in this file.

### Payload Deployment Pivot
RDP fan-out from the focus host overlapped with SMB/DCERPC admin-share or remote-exec markers on the same internal targets, which is consistent with manual payload drop activity.
- Manual-drop candidate 10.128.239.57 targets=61 smb_targets=61 admin_share_targets=1 remote_exec_targets=0 score=100
- Internal RDP spread source 10.128.239.57 unique_targets=74 sessions=74 duration=43915.58


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 141.98.11.170 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- Internal RDP spread from the focus host is consistent with manual operator-driven lateral movement or payload staging.
- RDP fan-out from the focus host overlaps with SMB/DCERPC admin-share or remote-exec indicators on the same targets, which is stronger evidence of manual payload drop behavior.
- This PCAP does not currently show the challenge's expected exfiltration indicators, so exfil may be elsewhere in the capture set or via another protocol.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
