python3 batch_analyze.py --start 61 --end 80 --workers 4 --dive
python3 report_ai.py
python3 verify_findings.py temp-sh --run-tshark
python3 verify_findings.py rdp --run-tshark
