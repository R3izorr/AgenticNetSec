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
Initial Access -> Payload Deployment -> Discovery -> Exfiltration

## Initial Access
Strongest patient-zero candidate is 10.128.239.57 from external 141.98.11.81 in file upload_1775748861_34936-sensor-250301-00002364_redacted.pcap.

## Lateral Movement & Discovery
No external reconnaissance evidence is currently present in the results file. Possible SMB/RPC scanning appears in upload_1775748864_34936-sensor-250301-00002370_redacted.pcap, upload_1775748864_34936-sensor-250301-00002371_redacted.pcap, upload_1775748866_34936-sensor-250302-00002376_redacted.pcap, upload_1775748866_34936-sensor-250302-00002377_redacted.pcap, upload_1775748866_34936-sensor-250302-00002378_redacted.pcap.

## Exfiltration
No temp.sh indicator is currently present in the results file. Outbound transfer spike candidates appear in upload_1775748864_34936-sensor-250301-00002371_redacted.pcap.

## Payload Deployment
Heuristic-only payload deployment evidence appears in upload_1775748864_34936-sensor-250301-00002370_redacted.pcap, upload_1775748864_34936-sensor-250301-00002371_redacted.pcap (2 file(s)).

## Confidence / Gaps
Files analyzed in results file: 20. Targeted AI-authored tshark follow-up ran on 0 file(s). This report is based on aggregated per-file scan results and remains heuristic.
