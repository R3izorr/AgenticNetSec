> Final Campaign Report AI Status
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
Initial Access -> Payload Deployment

## Initial Access
Strongest patient-zero candidate is 10.128.239.57 from external 179.60.146.37 in file upload_1775784848_34936-sensor-250304-00002389_redacted.pcap.

## Lateral Movement & Discovery
No external reconnaissance evidence is currently present in the results file. Possible SMB/RPC scanning appears in upload_1775784844_34936-sensor-250303-00002384_redacted.pcap, upload_1775784845_34936-sensor-250303-00002385_redacted.pcap.

## Exfiltration
No temp.sh indicator is currently present in the results file.

## Payload Deployment
Internal RDP spread appears in upload_1775784848_34936-sensor-250304-00002389_redacted.pcap, upload_1775784849_34936-sensor-250304-00002390_redacted.pcap.

## Confidence / Gaps
Files analyzed in results file: 20. Targeted AI-authored tshark follow-up ran on 0 file(s). This report is based on aggregated per-file scan results and remains heuristic.
