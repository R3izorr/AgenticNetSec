> Initial Campaign Summary AI Status
> AI requested: yes
> AI callable: no
> Fallback used: yes
> Status: fallback_report
> Provider requested: gemini
> Model requested: gemini-2.5-flash
>
> If `AI callable: no`, this markdown came from the deterministic fallback report.
# Incident Report

Attack Flow:
Initial Access -> Discovery -> Payload Deployment -> Exfiltration

## Initial Access
Strongest patient-zero candidate is 10.128.239.57 from external 179.60.146.33 in file upload_1775809333_34936-sensor-250309-00002477_redacted.pcap.

## Lateral Movement & Discovery
No external reconnaissance evidence is currently present in the results file. Possible SMB/RPC scanning appears in upload_1775809333_34936-sensor-250309-00002477_redacted.pcap, upload_1775809338_34936-sensor-250309-00002481_redacted.pcap, upload_1775809343_34936-sensor-250309-00002487_redacted.pcap, upload_1775809346_34936-sensor-250309-00002490_redacted.pcap.

## Exfiltration
No temp.sh indicator is currently present in the results file. Outbound transfer spike candidates appear in upload_1775809333_34936-sensor-250309-00002477_redacted.pcap, upload_1775809339_34936-sensor-250309-00002482_redacted.pcap.

## Payload Deployment
Manual RDP/SMB deployment candidates appear in upload_1775809333_34936-sensor-250309-00002477_redacted.pcap, upload_1775809338_34936-sensor-250309-00002481_redacted.pcap.

## Confidence / Gaps
Files analyzed in results file: 29. Targeted AI-authored tshark follow-up ran on 0 file(s). This report is based on aggregated per-file scan results and remains heuristic.
