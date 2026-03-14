# AgenticNetSec

This repository is organized as a backend-first forensic analyzer with separated outputs.

## Structure

- `backend/src/`: core analysis modules (`analyzer`, `detectors`, `deep_dive`, `flow_analysis`, `report_ai`)
- `backend/scripts/`: CLI tools (`run.py`, `batch_analyze.py`, `summarize_results.py`, `verify_findings.py`)
- `backend/config/`: local settings template (`local_settings.example.py`)
- `backend/tests/`: test placeholder
- `frontend/`: placeholder for future UI
- `outputs/`: generated artifacts (`scan_results.jsonl`, reports, aggregates)
- `docs/`: project docs and requirement/checklist markdown files

## Install

```bash
python -m pip install -r requirements.txt
```

## Run

Single PCAP analysis:

```bash
python backend/scripts/run.py /path/to/file.pcap --no-ai
```

Batch analysis:

```bash
python backend/scripts/batch_analyze.py --start 1 --end 10 --workers 2
```

Summarize existing results:

```bash
python backend/scripts/summarize_results.py outputs/scan_results.jsonl --no-ai --print-json
```

Verify findings:

```bash
python backend/scripts/verify_findings.py temp-sh
python backend/scripts/verify_findings.py rdp
```

## Output Location

Generated outputs are stored under `outputs/`.
