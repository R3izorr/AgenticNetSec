# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 179.60.146.37 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (21 targets)

## Exfiltration
No direct temp.sh indicator was found. Additional outbound transfer spikes were observed from 10.128.239.57 -> 51.91.79.17:443 (576532595 bytes).

## Payload Deployment
The current packet evidence does not strongly prove RDP-based internal deployment or transferred payload recovery.

## Confidence / Gaps
Total packets analyzed: 1189946. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery -> Exfiltration

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery -> Exfiltration
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-18T18:51:15.016983+00:00 evidence=External RDP from 179.60.146.37 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-18T19:29:38.775156+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 21 internal targets.
- administrative_activity: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No clear account/group administration markers were isolated in this file.
- exfiltration: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-18T18:50:39.473619+00:00 evidence=Outbound upload or transfer evidence exists and should be treated as potential exfiltration.
- payload_deployment: supported=False weakly_supported=False confidence=0.0 first_seen=2025-12-19T02:08:36.423282+00:00 evidence=No strong internal RDP payload-deployment pattern was isolated in this file.
Best ingress candidate: external `179.60.146.37` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 179.60.146.37 -> 10.128.239.57 packets=45264 app_packets=29249 post_login_targets=24 suspicious=True
- 185.147.124.43 -> 10.128.239.57 packets=38518 app_packets=23473 post_login_targets=22 suspicious=True
- 92.255.85.173 -> 10.128.239.57 packets=30560 app_packets=14563 post_login_targets=24 suspicious=True
- 91.238.181.8 -> 10.128.239.57 packets=23767 app_packets=14463 post_login_targets=24 suspicious=True
- 149.50.116.107 -> 10.128.239.57 packets=20639 app_packets=13531 post_login_targets=22 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=21 attempts=23 duration=208557.74
- Internal RDP spread source 10.128.239.57 unique_targets=2 sessions=2 duration=91355.73

### Administrative Activity Pivot
No account-creation or group-modification marker was observed in this file.

### Exfiltration Pivot
Outbound HTTP upload or temp.sh evidence exists and should be reviewed for archive staging and data loss.
- Outbound exfil candidate 10.128.239.57 -> 51.91.79.17:443 total_bytes=576532595 payload_bytes=555917123 archive_hits={'gzip': 8511}

### Payload Deployment Pivot
Internal RDP fan-out from the focus host is consistent with hands-on-keyboard deployment.
- Internal RDP spread source 10.128.239.57 unique_targets=2 sessions=2 duration=91355.73


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
