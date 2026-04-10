# Incident Report

## Initial Access
Most likely patient zero is 10.128.239.57 after ingress from 91.238.181.8 over RDP.

## Lateral Movement & Discovery
Rapid SMB/RPC scanning was observed from 10.128.239.57 (21 targets)

## Exfiltration
No direct temp.sh indicator was found. Additional outbound transfer spikes were observed from 10.128.239.57 -> 195.211.190.189:53789 (12960266 bytes).

## Payload Deployment
The current packet evidence does not strongly prove RDP-based internal deployment or transferred payload recovery.

## Confidence / Gaps
Total packets analyzed: 819948. Findings are heuristic and packet-based.
Likely path for this file: Initial Access -> Discovery -> Administrative Activity -> Exfiltration

## Deep Dive

Focus host: `10.128.239.57`

### Structured Flow Hypothesis
Likely path for this file: Initial Access -> Discovery -> Administrative Activity -> Exfiltration
- reconnaissance: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong external reconnaissance signal was isolated in this file.
- initial_access: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-15T09:26:59.877999+00:00 evidence=External RDP from 91.238.181.8 into 10.128.239.57 shows handshake/application evidence and post-login behavior change.
- discovery: supported=True weakly_supported=False confidence=0.9 first_seen=2025-12-15T09:28:04.457117+00:00 evidence=10.128.239.57 generated SMB/RPC scanning toward 21 internal targets.
- administrative_activity: supported=True weakly_supported=False confidence=0.9 first_seen=None evidence=DCERPC/account-administration markers were observed near the focus host.
- exfiltration: supported=True weakly_supported=False confidence=0.65 first_seen=2025-12-15T09:26:59.236761+00:00 evidence=Outbound upload or transfer evidence exists and should be treated as potential exfiltration.
- payload_deployment: supported=False weakly_supported=False confidence=0.0 first_seen=None evidence=No strong internal RDP payload-deployment pattern was isolated in this file.
Best ingress candidate: external `91.238.181.8` -> internal `10.128.239.57` with confidence `80`.

### Reconnaissance Pivot
No strong external reconnaissance pattern was isolated in this file.

### Initial Access Pivot
External RDP into 10.128.239.57 is the strongest initial-access hypothesis.
- 91.238.181.8 -> 10.128.239.57 packets=6634 app_packets=3938 post_login_targets=21 suspicious=True
- 179.60.146.37 -> 10.128.239.57 packets=4946 app_packets=3052 post_login_targets=21 suspicious=True
- 91.238.181.7 -> 10.128.239.57 packets=3995 app_packets=2380 post_login_targets=21 suspicious=True
- 45.130.145.40 -> 10.128.239.57 packets=4099 app_packets=2422 post_login_targets=21 suspicious=True
- 92.255.85.173 -> 10.128.239.57 packets=2730 app_packets=1287 post_login_targets=21 suspicious=True

### Lateral Movement & Discovery Pivot
The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario.
- SMB/RPC scan source 10.128.239.57 unique_targets=21 attempts=21 duration=11408.55

### Administrative Activity Pivot
Possible account or group administration markers were observed over SMB/DCERPC.
- DCERPC markers 10.128.239.37 -> 10.128.239.57 markers={'c$': 6417, 'administrators': 6, 'ipc$': 1, 'samr': 1}
- DCERPC markers 10.128.239.176 -> 10.128.239.57 markers={'c$': 3703, 'administrators': 5}
- DCERPC markers 10.128.239.32 -> 10.128.239.57 markers={'c$': 1}

### Exfiltration Pivot
Outbound HTTP upload or temp.sh evidence exists and should be reviewed for archive staging and data loss.
- Outbound exfil candidate 10.128.239.57 -> 195.211.190.189:53789 total_bytes=12960266 payload_bytes=11329406 archive_hits={'gzip': 166}

### Payload Deployment Pivot
No strong internal RDP fan-out suggesting payload deployment was observed in this file.


### Recommended Filters
- `ip.addr == 10.128.239.57 and tcp.port == 3389`
- `ip.src == 10.128.239.57 and tcp.dstport in {135,445,3389,5985,5986}`
- `ip.addr == 10.128.239.57 and tcp.port == 445`
- `ip.addr == 10.128.239.57 and dcerpc`
- `ip.addr == 91.238.181.8 and ip.addr == 10.128.239.57 and tcp.port == 3389`
- `http.request.method == "POST"`
- `http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"`

### Notes
- The challenge hypothesis fits an external-to-internal RDP compromise focused on 10.128.239.57.
- The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping.
- PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service.
