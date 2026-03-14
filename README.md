# PCAP AI Analyzer

This project is a stripped-down forensic analyzer built from the useful PCAP summary logic in `NetMoniAI`, specifically the reference function from `backend/tools/pcap_analyzer.py`.

The goal is to keep only three layers:

1. PCAP parser
2. Feature and finding extractor
3. AI report generator

## Files

- `analyzer.py`: deterministic PCAP summary extraction
- `detectors.py`: incident-focused evidence extraction
- `report_ai.py`: prompt building and AI/fallback reporting
- `run.py`: CLI entrypoint
- `summarize_results.py`: summarize `scan_results.jsonl` and generate a report
- `requirements.txt`: minimal dependencies

## Incident Focus

The detector layer is built for the Apex Global Logistics ransomware case and targets:

- external RDP ingress
- VPN-like ingress
- SMB/RPC scanning
- DCERPC account or group modification markers
- `temp.sh` exfiltration
- large outbound HTTP POST uploads
- internal RDP spread for payload deployment

## Usage

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run with local deterministic reporting:

```bash
python3 run.py /path/to/file.pcap --no-ai
```

Run a file range and append one result per file into the default JSONL results file:

```bash
python3 batch_analyze.py --start 1 --end 10 --workers 2
```

Continue later with the next range using the same results file:

```bash
python3 batch_analyze.py --start 11 --end 20 --workers 2
```

Add the attack-focused deep dive to each batch result:

```bash
python3 batch_analyze.py --start 21 --end 30 --workers 2 --dive
```

Run from a start file to the end:

```bash
python3 batch_analyze.py --start 1 --workers 2
```

Defaults used by `batch_analyze.py`:

- PCAP folder: `/mnt/c/Users/az100/1-PROJECT/network/network/pcap`
- results file: `/home/kuri/4063_project/pcap_ai_analyzer/scan_results.jsonl`

If a file is already present in the results file, it is skipped automatically on the next run.

Force a re-scan of files already recorded:

```bash
python3 batch_analyze.py --start 1 --end 10 --workers 2 --force
```

The range runner prints:

- total files discovered
- selected file range
- planned files
- skipped files already present in the results file
- running files
- per-file completion lines with packet and finding counts
- running progress counters

Write JSON output too:

```bash
python3 run.py /path/to/file.pcap --no-ai --json-file findings.json
```

Run a single PCAP with the attack-focused deep dive:

```bash
python3 run.py /path/to/file.pcap --dive --json-file findings.json --report-file report.md
```

Use OpenAI reporting:

```bash
export OPENAI_API_KEY="your_key_here"
python3 run.py /path/to/file.pcap --provider openai --model gpt-4.1-mini
```

Use Gemini reporting:

```bash
export GEMINI_API_KEY="your_key_here"
python3 run.py /path/to/file.pcap --provider gemini --model gemini-2.5-flash
```

Or store the key locally once in `local_settings.py`:

```python
GEMINI_API_KEY = "your_key_here"
```

Generate the final report from the default results file:

```bash
export GEMINI_API_KEY="your_key_here"
python3 report_ai.py
```

If you use `local_settings.py`, then this is enough:

```bash
python3 report_ai.py
```

Optional local Gemini settings:

```python
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_RETRY_ATTEMPTS = 3
GEMINI_RETRY_DELAY_SECONDS = 2.0
# GEMINI_FALLBACK_MODELS = ["gemini-2.0-flash"]
```

Verify temp.sh evidence from the saved results:

```bash
python3 verify_findings.py temp-sh
```

Verify attacker-like inbound RDP from the saved results:

```bash
python3 verify_findings.py rdp
```

Require Gemini and fail if it is unavailable instead of silently using fallback:

```bash
python3 summarize_results.py scan_results.jsonl \
  --provider gemini \
  --model gemini-2.5-flash \
  --require-ai \
  --aggregate-file aggregate_summary.json \
  --report-file incident_report.md
```

## Notes

- HTTP and DCERPC parsing is heuristic and packet-based.
- The analyzer does not preserve the rest of the NetMoniAI stack.
