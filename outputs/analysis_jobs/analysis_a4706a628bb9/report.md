# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 77.90.153.30 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (153 targets)

## Exfiltration
No direct temp.sh indicator was found. Additional outbound transfer spikes were observed from 10.128.239.57 -> 77.90.153.30:53632 (25606848 bytes).

## Payload Deployment
Heuristic deployment evidence is present through correlated RDP plus SMB/DCERPC admin-share activity from 10.128.239.57 to 93 hosts (admin_share_targets=0, remote_exec_targets=0). Confidence=0.00.

## Confidence / Gaps
Total packets analyzed: 980613. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery -> Exfiltration -> Payload Deployment

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery -> Exfiltration -> Payload Deployment
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-10T16:13:09.009359+00:00 evidence=External RDP from 77.90.153.30 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-10T16:13:14.497660+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 153 internal targets.
- administrative_activity: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No clear account/group administration markers were isolated in this file.
- exfiltration: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-10T17:27:17.343378+00:00 evidence=Outbound upload or transfer evidence exists and should be treated as potential exfiltration.
- payload_deployment: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-10T16:16:00.063437+00:00 evidence=Internal RDP plus SMB/DCERPC correlations are consistent with manual payload deployment.
Best ingress candidate: external `77.90.153.30` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 77.90.153.30 -> 10.128.239.57 packets=129494 app_packets=90400 post_login_targets=153 suspicious=True
- 141.98.11.109 -> 10.128.239.57 packets=39821 app_packets=24311 post_login_targets=153 suspicious=True
- 141.98.11.8 -> 10.128.239.57 packets=35301 app_packets=18728 post_login_targets=153 suspicious=True
- 45.227.254.3 -> 10.128.239.57 packets=26842 app_packets=16273 post_login_targets=153 suspicious=True
- 92.255.85.173 -> 10.128.239.57 packets=28317 app_packets=13627 post_login_targets=153 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=153 attempts=166 duration=124631.32
- Internal RDP spread source 10.128.239.57 unique_targets=110 sessions=110 duration=92512.23

### Administrative Activity Pivot
No account-creation or group-modification marker was observed in this file.

### Exfiltration Pivot
Outbound HTTP upload or temp.sh evidence exists and should be reviewed for archive staging and data loss.
- Outbound exfil candidate 10.128.239.57 -> 77.90.153.30:53632 total_bytes=25606848 payload_bytes=22057308 archive_hits={'gzip': 328}

### Payload Deployment Pivot
RDP fan-out from the focus host overlapped with SMB/DCERPC admin-share or remote-exec markers on the same internal targets, which is consistent with manual payload drop activity.
- Manual-drop candidate 10.128.239.57 targets=93 smb_targets=93 admin_share_targets=0 remote_exec_targets=0 score=100
- Internal RDP spread source 10.128.239.57 unique_targets=110 sessions=110 duration=92512.23


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 77.90.153.30 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- Internal RDP spread from the focus host is consistent with manual operator-driven lateral movement or payload staging.
- RDP fan-out from the focus host overlaps with SMB/DCERPC admin-share or remote-exec indicators on the same targets, which is stronger evidence of manual payload drop behavior.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
