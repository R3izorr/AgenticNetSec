# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 179.60.146.33 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (150 targets)

## Exfiltration
No direct temp.sh indicator was found. Additional outbound transfer spikes were observed from 10.128.239.57 -> 77.90.153.30:55613 (11786184 bytes).

## Payload Deployment
Heuristic deployment evidence is present through correlated RDP plus SMB/DCERPC admin-share activity from 10.128.239.57 to 68 hosts (admin_share_targets=0, remote_exec_targets=0). Confidence=0.00.

## Confidence / Gaps
Total packets analyzed: 1797338. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery -> Exfiltration -> Payload Deployment

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery -> Exfiltration -> Payload Deployment
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-14T17:15:54.187362+00:00 evidence=External RDP from 179.60.146.33 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-14T17:16:42.321459+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 150 internal targets.
- administrative_activity: supported=False weakly_supported=True confidence=0.35 first_seen=2025-12-14T19:41:20.972270+00:00 evidence=Generic SMB/DCERPC marker strings were observed near the focus host, but they did not meet the account-change threshold.
- exfiltration: supported=True weakly_supported=False confidence=0.65 first_seen=2025-12-17T05:59:19.961983+00:00 evidence=Outbound upload or transfer evidence exists and should be treated as potential exfiltration.
- payload_deployment: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-16T20:11:09.461677+00:00 evidence=Internal RDP plus SMB/DCERPC correlations are consistent with manual payload deployment.
Best ingress candidate: external `179.60.146.33` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 179.60.146.33 -> 10.128.239.57 packets=87262 app_packets=56182 post_login_targets=151 suspicious=True
- 141.98.11.53 -> 10.128.239.57 packets=99398 app_packets=56404 post_login_targets=151 suspicious=True
- 77.90.153.30 -> 10.128.239.57 packets=49895 app_packets=35756 post_login_targets=151 suspicious=True
- 141.98.11.100 -> 10.128.239.57 packets=96112 app_packets=49129 post_login_targets=151 suspicious=True
- 141.98.11.114 -> 10.128.239.57 packets=82529 app_packets=48328 post_login_targets=151 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=150 attempts=162 duration=227744.13
- Internal RDP spread source 10.128.239.57 unique_targets=89 sessions=89 duration=47474.65

### Administrative Activity Pivot
Possible account or group administration markers were observed over SMB/DCERPC.
- DCERPC markers 10.128.239.57 -> 10.128.239.23 markers={'c$': 4}
- DCERPC markers 10.128.239.33 -> 10.128.239.57 markers={'c$': 1}

### Exfiltration Pivot
Outbound HTTP upload or temp.sh evidence exists and should be reviewed for archive staging and data loss.
- Outbound exfil candidate 10.128.239.57 -> 77.90.153.30:55613 total_bytes=11786184 payload_bytes=10343832 archive_hits={'gzip': 156}

### Payload Deployment Pivot
RDP fan-out from the focus host overlapped with SMB/DCERPC admin-share or remote-exec markers on the same internal targets, which is consistent with manual payload drop activity.
- Manual-drop candidate 10.128.239.57 targets=68 smb_targets=68 admin_share_targets=0 remote_exec_targets=0 score=100
- Internal RDP spread source 10.128.239.57 unique_targets=89 sessions=89 duration=47474.65


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 179.60.146.33 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- Internal RDP spread from the focus host is consistent with manual operator-driven lateral movement or payload staging.
- RDP fan-out from the focus host overlaps with SMB/DCERPC admin-share or remote-exec indicators on the same targets, which is stronger evidence of manual payload drop behavior.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
