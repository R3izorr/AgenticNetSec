# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 179.60.146.37 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (20 targets)

## Exfiltration
Evidence supports outbound exfiltration to temp.sh from 10.128.239.57 -> 51.91.79.17, 10.128.239.57 -> 51.91.79.17, 10.128.239.57 -> 51.91.79.17, 10.128.239.57 -> 51.91.79.17, 10.128.239.57 -> 51.91.79.17 Additional outbound transfer spikes were observed from 10.128.239.57 -> 51.91.79.17:443 (240443403 bytes).

## Payload Deployment
The current packet evidence does not strongly prove RDP-based internal deployment or transferred payload recovery.

## Confidence / Gaps
Total packets analyzed: 989808. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery -> Administrative Activity -> Exfiltration

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery -> Administrative Activity -> Exfiltration
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2025-11-20T13:07:07.233687+00:00 evidence=External RDP from 179.60.146.37 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2025-11-20T13:06:45.996081+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 20 internal targets.
- administrative_activity: supported=True weakly_supported=False confidence=0.9 first_seen=None evidence=DCERPC/account-administration markers were observed near the focus host.
- exfiltration: supported=True weakly_supported=False confidence=0.9 first_seen=2025-11-21T08:14:41.257181+00:00 evidence=Outbound upload or transfer evidence exists and should be treated as potential exfiltration.
- payload_deployment: supported=False weakly_supported=False confidence=0.0 first_seen=2025-11-22T00:28:24.293588+00:00 evidence=No strong internal RDP payload-deployment pattern was isolated in this file.
Best ingress candidate: external `179.60.146.37` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 179.60.146.37 -> 10.128.239.57 packets=39432 app_packets=25346 post_login_targets=22 suspicious=True
- 185.147.124.43 -> 10.128.239.57 packets=29195 app_packets=17779 post_login_targets=21 suspicious=True
- 91.238.181.10 -> 10.128.239.57 packets=23323 app_packets=14239 post_login_targets=21 suspicious=True
- 92.255.85.173 -> 10.128.239.57 packets=25143 app_packets=11978 post_login_targets=22 suspicious=True
- 91.238.181.7 -> 10.128.239.57 packets=19201 app_packets=11687 post_login_targets=22 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=20 attempts=21 duration=68880.24
- Internal RDP spread source 10.128.239.57 unique_targets=1 sessions=1 duration=1.79

### Administrative Activity Pivot
Possible account or group administration markers were observed over SMB/DCERPC.
- DCERPC markers 10.128.239.37 -> 10.128.239.57 markers={'c$': 323, 'samr': 8}

### Exfiltration Pivot
Outbound HTTP upload or temp.sh evidence exists and should be reviewed for archive staging and data loss.
- temp.sh candidate 10.128.239.57 -> 51.91.79.17 host=None method=None
- temp.sh candidate 10.128.239.57 -> 51.91.79.17 host=None method=None
- temp.sh candidate 10.128.239.57 -> 51.91.79.17 host=None method=None
- Outbound exfil candidate 10.128.239.57 -> 51.91.79.17:443 total_bytes=240443403 payload_bytes=231835299 archive_hits={'gzip': 3495}

### Payload Deployment Pivot
Internal RDP fan-out from the focus host is consistent with hands-on-keyboard deployment.
- Internal RDP spread source 10.128.239.57 unique_targets=1 sessions=1 duration=1.79


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 179.60.146.37 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- Internal RDP spread from the focus host is consistent with manual operator-driven lateral movement or payload staging.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
