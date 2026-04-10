# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 45.135.232.124 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (22 targets)

## Exfiltration
No direct temp.sh indicator was found.

## Payload Deployment
The current packet evidence does not strongly prove RDP-based internal deployment or transferred payload recovery.

## Confidence / Gaps
Total packets analyzed: 7061828. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-15T19:22:24.344187+00:00 evidence=External RDP from 45.135.232.124 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-15T19:23:00.008472+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 22 internal targets.
- administrative_activity: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No clear account/group administration markers were isolated in this file.
- exfiltration: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No direct exfiltration indicator was isolated in this file.
- payload_deployment: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong internal RDP payload-deployment pattern was isolated in this file.
Best ingress candidate: external `45.135.232.124` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 45.135.232.124 -> 10.128.239.57 packets=83336 app_packets=48451 post_login_targets=23 suspicious=True
- 179.60.146.34 -> 10.128.239.57 packets=67207 app_packets=43350 post_login_targets=23 suspicious=True
- 179.60.146.33 -> 10.128.239.57 packets=65534 app_packets=42192 post_login_targets=23 suspicious=True
- 141.98.11.8 -> 10.128.239.57 packets=45549 app_packets=23815 post_login_targets=23 suspicious=True
- 141.98.11.127 -> 10.128.239.57 packets=46389 app_packets=22294 post_login_targets=23 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=22 attempts=25 duration=70859.62

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
- `ip.addr == 45.135.232.124 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- This PCAP does not currently show the challenge's expected exfiltration indicators, so exfil may be elsewhere in the capture set or via another protocol.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
