# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 185.147.125.13 over RDP.

## Lateral Movement & Discovery
No high-confidence SMB/RPC scanning pattern crossed the current thresholds.

## Exfiltration
No direct temp.sh indicator was found.

## Payload Deployment
Heuristic deployment evidence is limited to internal RDP spread from 10.128.239.57 to 21 hosts.

## Confidence / Gaps
Total packets analyzed: 1621606. Findings are heuristic and packet-based.
Likely path for this file: Initial Access

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-03T22:30:00.670198+00:00 evidence=External RDP from 185.147.125.13 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=False weakly_supported=True confidence=0.35 first_seen=2026-01-03T22:29:55.521111+00:00 evidence=10.128.239.57 generated limited SMB/RPC probing toward 5 internal targets, but it stayed below the stronger detection threshold.
- administrative_activity: supported=False weakly_supported=True confidence=0.35 first_seen=2026-01-03T23:12:42.200312+00:00 evidence=Generic SMB/DCERPC marker strings were observed near the focus host, but they did not meet the account-change threshold.
- exfiltration: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No direct exfiltration indicator was isolated in this file.
- payload_deployment: supported=False weakly_supported=True confidence=0.35 first_seen=2026-01-06T06:18:26.621411+00:00 evidence=Internal RDP fan-out suggests operator-driven payload staging, but no stronger correlated payload-drop indicator was isolated.
Best ingress candidate: external `185.147.125.13` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 185.147.125.13 -> 10.128.239.57 packets=73013 app_packets=44510 post_login_targets=30 suspicious=True
- 45.135.232.124 -> 10.128.239.57 packets=57801 app_packets=34914 post_login_targets=31 suspicious=True
- 45.141.87.46 -> 10.128.239.57 packets=43427 app_packets=26323 post_login_targets=30 suspicious=True
- 179.60.146.30 -> 10.128.239.57 packets=34250 app_packets=22028 post_login_targets=30 suspicious=True
- 45.141.87.83 -> 10.128.239.57 packets=39594 app_packets=23937 post_login_targets=30 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=5 attempts=6 duration=216438.89
- Internal RDP spread source 10.128.239.57 unique_targets=21 sessions=21 duration=11307.16

### Administrative Activity Pivot
Possible account or group administration markers were observed over SMB/DCERPC.
- DCERPC markers 10.128.239.57 -> 10.128.239.29 markers={'c$': 1}

### Exfiltration Pivot
No direct exfiltration indicator was observed in this file.

### Payload Deployment Pivot
Internal RDP fan-out from the focus host is consistent with hands-on-keyboard deployment.
- Internal RDP spread source 10.128.239.57 unique_targets=21 sessions=21 duration=11307.16


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 185.147.125.13 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- Internal RDP spread from the focus host is consistent with manual operator-driven lateral movement or payload staging.
- This PCAP does not currently show the challenge's expected exfiltration indicators, so exfil may be elsewhere in the capture set or via another protocol.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
