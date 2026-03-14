# Backend

Core forensic analysis code lives here.

## Layout

- `src/`: analyzers, detectors, report generation
- `scripts/`: CLI entrypoints
- `config/`: local configuration templates
- `tests/`: test placeholder

## Common Commands

From repository root:

```bash
python backend/scripts/run.py /path/to/capture.pcap --no-ai
python backend/scripts/batch_analyze.py --start 1 --end 10 --workers 2
python backend/scripts/summarize_results.py outputs/scan_results.jsonl --no-ai --print-json
python backend/scripts/verify_findings.py temp-sh
```

`batch_analyze.py` now writes to `outputs/scan_results.jsonl` by default.
