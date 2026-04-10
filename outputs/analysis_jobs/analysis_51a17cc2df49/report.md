# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 179.60.146.34 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (22 targets)

## Exfiltration
No direct temp.sh indicator was found.

## Payload Deployment
The current packet evidence does not strongly prove RDP-based internal deployment or transferred payload recovery.

## Confidence / Gaps
Total packets analyzed: 1278632. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-18T00:13:11.695401+00:00 evidence=External RDP from 179.60.146.34 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-18T00:13:26.586032+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 22 internal targets.
- administrative_activity: supported=False weakly_supported=True confidence=0.35 first_seen=2026-01-19T08:42:05.813528+00:00 evidence=Generic SMB/DCERPC marker strings were observed near the focus host, but they did not meet the account-change threshold.
- exfiltration: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No direct exfiltration indicator was isolated in this file.
- payload_deployment: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong internal RDP payload-deployment pattern was isolated in this file.
Best ingress candidate: external `179.60.146.34` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 179.60.146.34 -> 10.128.239.57 packets=74460 app_packets=48031 post_login_targets=23 suspicious=True
- 179.60.146.33 -> 10.128.239.57 packets=72451 app_packets=46636 post_login_targets=23 suspicious=True
- 45.135.232.124 -> 10.128.239.57 packets=54125 app_packets=31436 post_login_targets=23 suspicious=True
- 92.255.85.173 -> 10.128.239.57 packets=53608 app_packets=25810 post_login_targets=23 suspicious=True
- 141.98.11.8 -> 10.128.239.57 packets=36726 app_packets=19083 post_login_targets=23 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=22 attempts=25 duration=97362.7

### Administrative Activity Pivot
Possible account or group administration markers were observed over SMB/DCERPC.
- DCERPC markers 10.128.239.57 -> 10.128.239.23 markers={'c$': 1}

### Exfiltration Pivot
No direct exfiltration indicator was observed in this file.

### Payload Deployment Pivot
No strong internal RDP fan-out suggesting payload deployment was observed in this file.


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 179.60.146.34 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- This PCAP does not currently show the challenge's expected exfiltration indicators, so exfil may be elsewhere in the capture set or via another protocol.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
