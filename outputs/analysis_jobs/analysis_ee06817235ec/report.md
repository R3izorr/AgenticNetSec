# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 179.60.146.30 over RDP.

## Lateral Movement & Discovery
No high-confidence SMB/RPC scanning pattern crossed the current thresholds.

## Exfiltration
No direct temp.sh indicator was found.

## Payload Deployment
The current packet evidence does not strongly prove RDP-based internal deployment or transferred payload recovery.

## Confidence / Gaps
Total packets analyzed: 11395222. Findings are heuristic and packet-based.
Likely path for this file: Initial Access

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-19T05:15:14.495377+00:00 evidence=External RDP from 179.60.146.30 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=False weakly_supported=True confidence=0.35 first_seen=2025-12-19T05:57:51.422210+00:00 evidence=10.128.239.57 generated limited SMB/RPC probing toward 3 internal targets, but it stayed below the stronger detection threshold.
- administrative_activity: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No clear account/group administration markers were isolated in this file.
- exfiltration: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No direct exfiltration indicator was isolated in this file.
- payload_deployment: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong internal RDP payload-deployment pattern was isolated in this file.
Best ingress candidate: external `179.60.146.30` -> internal `10.128.239.57` with confidence `59`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 179.60.146.30 -> 10.128.239.57 packets=30777 app_packets=19812 post_login_targets=3 suspicious=True
- 91.224.92.23 -> 10.128.239.57 packets=24797 app_packets=14006 post_login_targets=3 suspicious=True
- 141.98.11.49 -> 10.128.239.57 packets=22152 app_packets=12022 post_login_targets=3 suspicious=True
- 45.135.232.19 -> 10.128.239.57 packets=8891 app_packets=5194 post_login_targets=3 suspicious=True
- 141.98.11.81 -> 10.128.239.57 packets=7225 app_packets=4368 post_login_targets=3 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=3 attempts=5 duration=920561.32

### Administrative Activity Pivot
No account-creation or group-modification marker was observed in this file.

### Exfiltration Pivot
No direct exfiltration indicator was observed in this file.

### Payload Deployment Pivot
No strong internal RDP fan-out suggesting payload deployment was observed in this file.


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 179.60.146.30 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- This PCAP does not currently show the challenge's expected exfiltration indicators, so exfil may be elsewhere in the capture set or via another protocol.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
