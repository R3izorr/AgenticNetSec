# Incident Report

Attack Flow:
Initial Access -> Discovery -> Payload Deployment -> Exfiltration -> Administrative Activity

## Initial Access
Strongest patient-zero candidate is 10.128.239.57 from external 141.98.11.81 in file 34936-sensor-250301-00002364_redacted.pcap.

## Lateral Movement & Discovery
No external reconnaissance evidence is currently present in the results file. Possible SMB/RPC scanning appears in 34936-sensor-250301-00002370_redacted.pcap, 34936-sensor-250301-00002371_redacted.pcap, 34936-sensor-250302-00002376_redacted.pcap, 34936-sensor-250302-00002377_redacted.pcap, 34936-sensor-250302-00002378_redacted.pcap. DCERPC or account/group markers appear in 34936-sensor-250306-00002436_redacted.pcap, 34936-sensor-250306-00002437_redacted.pcap, 34936-sensor-250306-00002438_redacted.pcap, 34936-sensor-250306-00002439_redacted.pcap, 34936-sensor-250306-00002440_redacted.pcap.

## Exfiltration
temp.sh indicators appear in 34936-sensor-250306-00002439_redacted.pcap, 34936-sensor-250306-00002440_redacted.pcap Outbound transfer spike candidates appear in 34936-sensor-250301-00002371_redacted.pcap, 34936-sensor-250306-00002436_redacted.pcap, 34936-sensor-250306-00002438_redacted.pcap, 34936-sensor-250306-00002439_redacted.pcap, 34936-sensor-250306-00002440_redacted.pcap.

## Payload Deployment
Manual RDP/SMB deployment candidates appear in 34936-sensor-250301-00002370_redacted.pcap, 34936-sensor-250301-00002371_redacted.pcap, 34936-sensor-250306-00002436_redacted.pcap, 34936-sensor-250306-00002437_redacted.pcap, 34936-sensor-250307-00002444_redacted.pcap

## Confidence / Gaps
Files analyzed in results file: 121. This report is based on aggregated per-file scan results and remains heuristic.
