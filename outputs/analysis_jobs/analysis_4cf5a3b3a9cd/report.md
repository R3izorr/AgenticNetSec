# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 149.50.116.107 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (21 targets)

## Exfiltration
No direct temp.sh indicator was found.

## Payload Deployment
Heuristic deployment evidence is present through correlated RDP plus SMB/DCERPC admin-share activity from 10.128.239.57 to 3 hosts (admin_share_targets=0, remote_exec_targets=0). Confidence=0.00.

## Confidence / Gaps
Total packets analyzed: 1137660. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery -> Payload Deployment

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery -> Payload Deployment
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-11T14:14:23.900008+00:00 evidence=External RDP from 149.50.116.107 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-11T14:15:11.565653+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 21 internal targets.
- administrative_activity: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No clear account/group administration markers were isolated in this file.
- exfiltration: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No direct exfiltration indicator was isolated in this file.
- payload_deployment: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-11T19:53:12.094225+00:00 evidence=Internal RDP plus SMB/DCERPC correlations are consistent with manual payload deployment.
Best ingress candidate: external `149.50.116.107` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 149.50.116.107 -> 10.128.239.57 packets=113952 app_packets=74406 post_login_targets=41 suspicious=True
- 179.60.146.32 -> 10.128.239.57 packets=80726 app_packets=52089 post_login_targets=41 suspicious=True
- 179.60.146.30 -> 10.128.239.57 packets=74414 app_packets=48048 post_login_targets=41 suspicious=True
- 185.42.12.42 -> 10.128.239.57 packets=66350 app_packets=37784 post_login_targets=41 suspicious=True
- 92.255.85.173 -> 10.128.239.57 packets=48354 app_packets=23147 post_login_targets=41 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=21 attempts=23 duration=127606.96
- Internal RDP spread source 10.128.239.57 unique_targets=20 sessions=20 duration=16871.97

### Administrative Activity Pivot
No account-creation or group-modification marker was observed in this file.

### Exfiltration Pivot
No direct exfiltration indicator was observed in this file.

### Payload Deployment Pivot
RDP fan-out from the focus host overlapped with SMB/DCERPC admin-share or remote-exec markers on the same internal targets, which is consistent with manual payload drop activity.
- Manual-drop candidate 10.128.239.57 targets=3 smb_targets=3 admin_share_targets=0 remote_exec_targets=0 score=30
- Internal RDP spread source 10.128.239.57 unique_targets=20 sessions=20 duration=16871.97


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 149.50.116.107 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- Internal RDP spread from the focus host is consistent with manual operator-driven lateral movement or payload staging.
- RDP fan-out from the focus host overlaps with SMB/DCERPC admin-share or remote-exec indicators on the same targets, which is stronger evidence of manual payload drop behavior.
- This PCAP does not currently show the challenge's expected exfiltration indicators, so exfil may be elsewhere in the capture set or via another protocol.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
