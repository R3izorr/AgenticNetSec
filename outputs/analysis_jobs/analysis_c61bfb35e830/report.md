# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 179.60.146.37 over RDP.

## Lateral Movement & Discovery
No high-confidence SMB/RPC scanning pattern crossed the current thresholds.

## Exfiltration
No direct temp.sh indicator was found.

## Payload Deployment
Heuristic deployment evidence is limited to internal RDP spread from 10.128.239.57 to 13 hosts.

## Confidence / Gaps
Total packets analyzed: 11145111. Findings are heuristic and packet-based.
Likely path for this file: Initial Access

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2026-01-08T00:22:23.435635+00:00 evidence=External RDP from 179.60.146.37 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=False weakly_supported=True confidence=0.35 first_seen=2026-01-08T00:30:23.635780+00:00 evidence=10.128.239.57 generated limited SMB/RPC probing toward 6 internal targets, but it stayed below the stronger detection threshold.
- administrative_activity: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No clear account/group administration markers were isolated in this file.
- exfiltration: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No direct exfiltration indicator was isolated in this file.
- payload_deployment: supported=False weakly_supported=True confidence=0.35 first_seen=2026-01-18T14:16:57.101218+00:00 evidence=Internal RDP fan-out suggests operator-driven payload staging, but no stronger correlated payload-drop indicator was isolated.
Best ingress candidate: external `179.60.146.37` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 179.60.146.37 -> 10.128.239.57 packets=25613 app_packets=16507 post_login_targets=24 suspicious=True
- 179.60.146.32 -> 10.128.239.57 packets=24215 app_packets=15633 post_login_targets=22 suspicious=True
- 141.98.11.53 -> 10.128.239.57 packets=25659 app_packets=14579 post_login_targets=24 suspicious=True
- 141.98.11.100 -> 10.128.239.57 packets=19394 app_packets=9969 post_login_targets=24 suspicious=True
- 141.98.83.70 -> 10.128.239.57 packets=11759 app_packets=7560 post_login_targets=22 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=6 attempts=8 duration=161019.16
- Internal RDP spread source 10.128.239.57 unique_targets=13 sessions=13 duration=187181.18

### Administrative Activity Pivot
No account-creation or group-modification marker was observed in this file.

### Exfiltration Pivot
No direct exfiltration indicator was observed in this file.

### Payload Deployment Pivot
Internal RDP fan-out from the focus host is consistent with hands-on-keyboard deployment.
- Internal RDP spread source 10.128.239.57 unique_targets=13 sessions=13 duration=187181.18


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
- This PCAP does not currently show the challenge's expected exfiltration indicators, so exfil may be elsewhere in the capture set or via another protocol.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
