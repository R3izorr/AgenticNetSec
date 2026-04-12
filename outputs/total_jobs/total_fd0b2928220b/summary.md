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
Initial Access -> Payload Deployment -> Discovery -> Exfiltration -> Administrative Activity

## Initial Access
Strongest patient-zero candidate is 10.128.239.57 from external 141.98.11.53 in file upload_1775796404_34936-sensor-250305-00002429_redacted.pcap.

## Lateral Movement & Discovery
No external reconnaissance evidence is currently present in the results file. Possible SMB/RPC scanning appears in upload_1775796406_34936-sensor-250306-00002436_redacted.pcap, upload_1775796407_34936-sensor-250306-00002437_redacted.pcap, upload_1775796407_34936-sensor-250306-00002438_redacted.pcap, upload_1775796409_34936-sensor-250306-00002439_redacted.pcap, upload_1775796410_34936-sensor-250306-00002440_redacted.pcap. DCERPC or account/group markers appear in upload_1775796406_34936-sensor-250306-00002436_redacted.pcap, upload_1775796407_34936-sensor-250306-00002437_redacted.pcap, upload_1775796407_34936-sensor-250306-00002438_redacted.pcap, upload_1775796409_34936-sensor-250306-00002439_redacted.pcap, upload_1775796410_34936-sensor-250306-00002440_redacted.pcap.

## Exfiltration
temp.sh indicators appear in upload_1775796409_34936-sensor-250306-00002439_redacted.pcap, upload_1775796410_34936-sensor-250306-00002440_redacted.pcap Outbound transfer spike candidates appear in upload_1775796406_34936-sensor-250306-00002436_redacted.pcap, upload_1775796407_34936-sensor-250306-00002438_redacted.pcap, upload_1775796409_34936-sensor-250306-00002439_redacted.pcap, upload_1775796410_34936-sensor-250306-00002440_redacted.pcap, upload_1775796411_34936-sensor-250306-00002441_redacted.pcap.

## Payload Deployment
Heuristic-only payload deployment evidence appears in upload_1775796406_34936-sensor-250306-00002436_redacted.pcap, upload_1775796407_34936-sensor-250306-00002437_redacted.pcap, upload_1775796411_34936-sensor-250307-00002444_redacted.pcap (3 file(s)).

## Confidence / Gaps
Files analyzed in results file: 20. Targeted AI-authored tshark follow-up ran on 0 file(s). This report is based on aggregated per-file scan results and remains heuristic.
