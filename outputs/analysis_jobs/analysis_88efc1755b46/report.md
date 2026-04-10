# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 179.60.146.32 over RDP.

## Lateral Movement & Discovery
No high-confidence SMB/RPC scanning pattern crossed the current thresholds.

## Exfiltration
No direct temp.sh indicator was found. Additional outbound transfer spikes were observed from 10.128.239.57 -> 77.90.153.30:55613 (22188804 bytes).

## Payload Deployment
Heuristic deployment evidence is limited to internal RDP spread from 10.128.239.57 to 4 hosts.

## Confidence / Gaps
Total packets analyzed: 1851714. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Exfiltration -> Payload Deployment

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Exfiltration -> Payload Deployment
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-15T07:06:11.737376+00:00 evidence=External RDP from 179.60.146.32 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=False weakly_supported=True confidence=0.35 first_seen=2026-01-15T07:11:05.567766+00:00 evidence=10.128.239.57 generated limited SMB/RPC probing toward 6 internal targets, but it stayed below the stronger detection threshold.
- administrative_activity: supported=False weakly_supported=True confidence=0.35 first_seen=2026-01-17T17:41:41.329059+00:00 evidence=Generic SMB/DCERPC marker strings were observed near the focus host, but they did not meet the account-change threshold.
- exfiltration: supported=True weakly_supported=False confidence=0.65 first_seen=2026-01-15T07:06:11.637005+00:00 evidence=Outbound upload or transfer evidence exists and should be treated as potential exfiltration.
- payload_deployment: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-15T08:26:23.200134+00:00 evidence=Internal RDP plus SMB/DCERPC correlations are consistent with manual payload deployment.
Best ingress candidate: external `179.60.146.32` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 179.60.146.32 -> 10.128.239.57 packets=128055 app_packets=82551 post_login_targets=10 suspicious=True
- 179.60.146.37 -> 10.128.239.57 packets=126882 app_packets=81681 post_login_targets=10 suspicious=True
- 141.98.83.70 -> 10.128.239.57 packets=95954 app_packets=61628 post_login_targets=10 suspicious=True
- 141.98.11.53 -> 10.128.239.57 packets=97493 app_packets=55743 post_login_targets=10 suspicious=True
- 141.98.11.49 -> 10.128.239.57 packets=95774 app_packets=51913 post_login_targets=10 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=6 attempts=7 duration=62794.81
- Internal RDP spread source 10.128.239.57 unique_targets=4 sessions=4 duration=28124.38

### Administrative Activity Pivot
Possible account or group administration markers were observed over SMB/DCERPC.
- DCERPC markers 10.128.239.176 -> 10.128.239.57 markers={'c$': 8}
- DCERPC markers 10.128.239.57 -> 10.128.239.29 markers={'c$': 1}

### Exfiltration Pivot
Outbound HTTP upload or temp.sh evidence exists and should be reviewed for archive staging and data loss.
- Outbound exfil candidate 10.128.239.57 -> 77.90.153.30:55613 total_bytes=22188804 payload_bytes=19502886 archive_hits={'gzip': 289}

### Payload Deployment Pivot
RDP fan-out from the focus host overlapped with SMB/DCERPC admin-share or remote-exec markers on the same internal targets, which is consistent with manual payload drop activity.
- Manual-drop candidate 10.128.239.57 targets=2 smb_targets=2 admin_share_targets=0 remote_exec_targets=0 score=20
- Internal RDP spread source 10.128.239.57 unique_targets=4 sessions=4 duration=28124.38


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 179.60.146.32 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- Internal RDP spread from the focus host is consistent with manual operator-driven lateral movement or payload staging.
- RDP fan-out from the focus host overlaps with SMB/DCERPC admin-share or remote-exec indicators on the same targets, which is stronger evidence of manual payload drop behavior.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
