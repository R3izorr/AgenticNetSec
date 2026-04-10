# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 194.165.17.11 over RDP.

## Lateral Movement & Discovery
No high-confidence SMB/RPC scanning pattern crossed the current thresholds.

## Exfiltration
No direct temp.sh indicator was found.

## Payload Deployment
The current packet evidence does not strongly prove RDP-based internal deployment or transferred payload recovery.

## Confidence / Gaps
Total packets analyzed: 106936. Findings are heuristic and packet-based.
Likely path for this file: Initial Access

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-04T11:09:49.149645+00:00 evidence=External RDP from 194.165.17.11 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong SMB/RPC discovery pattern was isolated in this file.
- administrative_activity: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No clear account/group administration markers were isolated in this file.
- exfiltration: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No direct exfiltration indicator was isolated in this file.
- payload_deployment: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong internal RDP payload-deployment pattern was isolated in this file.
Best ingress candidate: external `194.165.17.11` -> internal `10.128.239.57` with confidence `50`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 194.165.17.11 -> 10.128.239.57 packets=594 app_packets=357 post_login_targets=0 suspicious=True
- 88.214.25.123 -> 10.128.239.57 packets=373 app_packets=229 post_login_targets=0 suspicious=True
- 91.238.181.91 -> 10.128.239.57 packets=236 app_packets=144 post_login_targets=0 suspicious=True
- 88.214.25.115 -> 10.128.239.57 packets=205 app_packets=121 post_login_targets=0 suspicious=True
- 98.159.33.51 -> 10.128.239.57 packets=112 app_packets=72 post_login_targets=0 suspicious=True

### Lateral Movement & Discovery Pivot
No strong internal discovery or lateral spread pattern was isolated for the focus host in this file.

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
- `ip.addr == 194.165.17.11 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- This PCAP does not currently show the challenge's expected exfiltration indicators, so exfil may be elsewhere in the capture set or via another protocol.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
