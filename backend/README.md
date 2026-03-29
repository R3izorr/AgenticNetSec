# Backend

The backend is the forensic analysis engine for AgenticNetSec. It supports:

- FastAPI async analysis jobs
- local single-PCAP analysis
- batch/offline multi-PCAP analysis
- structured JSON reporting
- Markdown incident reports
- runtime and guardrail artifacts

## Layout

- `src/`
  - core analysis pipeline, detectors, deep dive, flow analysis, guardrails, reporting
- `api/`
  - FastAPI service and persisted job state
- `scripts/`
  - CLI entrypoints for local runs, batch analysis, summarization, verification, and API startup
- `config/`
  - local settings template and local overrides
- `requirements.txt`
  - Python dependencies needed to run the backend

## Main Backend Files

- `backend/src/analysis_engine.py`
  - orchestrates the full pipeline
- `backend/src/analyzer.py`
  - lightweight packet and metadata summary
- `backend/src/detectors.py`
  - rule-based forensic detectors
- `backend/src/deep_dive.py`
  - structured single-PCAP attack-flow reasoning
- `backend/src/flow_analysis.py`
  - aggregate attack-flow builder across many PCAPs
- `backend/src/guardrails.py`
  - input, consistency, confidence, and human-review gating
- `backend/src/report_ai.py`
  - AI-assisted and fallback report generation
- `backend/api/app.py`
  - FastAPI REST service
- `backend/api/job_store.py`
  - persisted job manifests and artifact readiness

## Requirements

- Python 3.11 or 3.12 recommended
- Ubuntu / WSL recommended for Scapy and packet tooling
- optional external tools for analyst verification:
  - `tshark`
  - Wireshark

## Install

From the repository root:

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
```

If you are on Ubuntu / WSL and see:

- `error: externally-managed-environment`

that means global `pip` installs are blocked by the system Python policy. Use the virtual environment workflow above instead of installing packages system-wide.

If virtual environment creation fails, install:

```bash
sudo apt install python3-venv
```

## Configuration

Create your local backend settings file:

```bash
cp backend/config/local_settings.example.py backend/config/local_settings.py
```

Then edit:

- `backend/config/local_settings.py`

The current default report provider is OpenRouter-first.

Minimum useful config:

```python
OPENROUTER_API_KEY = "paste_your_openrouter_key_here"
OPENROUTER_MODEL = "openai/gpt-5-mini"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_HTTP_REFERER = "http://localhost"
OPENROUTER_APP_NAME = "AgenticNetSec"
OPENROUTER_RETRY_ATTEMPTS = 3
OPENROUTER_RETRY_DELAY_SECONDS = 2.0

REPORT_PROVIDER = "openrouter"
REPORT_MODEL = "openai/gpt-5-mini"
```

Optional fallback providers can also be configured in the same file:

- Gemini
- OpenAI
- Groq
- Ollama

Environment variables are also supported and take precedence over `local_settings.py`.

## Run The API

From the repository root:

```bash
python backend/scripts/run_api.py --reload
```

Default API URL:

- `http://localhost:8000`

Useful endpoints:

- `http://localhost:8000/docs`
- `POST /api/v1/analysis`
- `GET /api/v1/analysis`
- `GET /api/v1/analysis/{job_id}`
- `GET /api/v1/analysis/{job_id}/report.json`
- `GET /api/v1/analysis/{job_id}/report.md`
- `GET /api/v1/analysis/{job_id}/metrics`
- `GET /api/v1/analysis/{job_id}/guardrail-audit`

Important note:

- `http://localhost:8000/` returning `404 Not Found` is expected

## Run Local Analysis

Single PCAP, deterministic:

```bash
python backend/scripts/run.py /path/to/file.pcap --no-ai
```

Single PCAP with AI enabled:

```bash
python backend/scripts/run.py /path/to/file.pcap
```

Single PCAP with deep dive:

```bash
python backend/scripts/run.py /path/to/file.pcap --dive
```

## Batch / Offline Analysis

Analyze a file range:

```bash
python backend/scripts/batch_analyze.py --start 1 --end 10 --workers 2
```

Analyze with deep dive:

```bash
python backend/scripts/batch_analyze.py --start 1 --end 30 --workers 4 --dive --force
```

Summarize batch results:

```bash
python backend/scripts/summarize_results.py outputs/scan_results.jsonl --no-ai --print-json
```

Generate aggregate AI report from batch results:

```bash
python backend/src/report_ai.py
```

## Verification / Analyst Pivots

Example verification modes:

```bash
python backend/scripts/verify_findings.py rdp --results-file outputs/scan_results.jsonl --limit 3
python backend/scripts/verify_findings.py temp-sh --results-file outputs/scan_results.jsonl --limit 3
python backend/scripts/verify_findings.py external-scan --results-file outputs/scan_results.jsonl --limit 3
python backend/scripts/verify_findings.py smb-rpc --results-file outputs/scan_results.jsonl --limit 3
python backend/scripts/verify_findings.py dcerpc --results-file outputs/scan_results.jsonl --limit 3
python backend/scripts/verify_findings.py exfil --results-file outputs/scan_results.jsonl --limit 3
python backend/scripts/verify_findings.py payload --results-file outputs/scan_results.jsonl --limit 3
```

If `tshark` is installed, these pivots can also be used to validate findings manually.

## Generated Artifacts

### API job artifacts

Written to:

- `outputs/analysis_jobs/<job_id>/`

Typical files:

- `job.json`
- `report.json`
- `report.md`
- `metrics.json`
- `guardrail_audit.json`

### Batch artifacts

Written to:

- `outputs/scan_results.jsonl`
- `outputs/aggregate_summary.json`
- `outputs/incident_report.md`

## Current Execution Model

### API mode

- FastAPI accepts upload or `pcap_path`
- job is persisted
- analysis runs in-process via `asyncio.create_task(...)`
- artifacts are written per job

### Batch mode

- `batch_analyze.py` uses multiple worker processes
- each worker analyzes a different PCAP file
- results are appended to JSONL
- summarization and flow analysis happen afterward

## Guardrails

The backend currently includes:

- input validation
- tool allowlisting
- timeouts and retries
- confidence thresholding
- contradiction and consistency checks
- human-review-required gating
- guardrail audit artifact generation

## Troubleshooting

### `ModuleNotFoundError: No module named 'uvicorn'`

Install dependencies:

```bash
pip install -r backend/requirements.txt
```

### OpenRouter key not detected

Set either:

- `OPENROUTER_API_KEY` in your environment
- or `OPENROUTER_API_KEY` in `backend/config/local_settings.py`

### `http://localhost:8000/` gives 404

Expected. Use:

- `http://localhost:8000/docs`

### AI report falls back to deterministic report

Check:

- provider key is present
- provider model is valid
- retry settings are reasonable

### `tshark` verification commands fail

Install `tshark` or run the backend without verification pivots.

## Notes

- This backend is demo-ready and local-first.
- The API currently does not implement cancel/retry endpoints or a real Celery/Redis worker path.
- If your presentation mentions those, describe them as future extensions unless you implement them.
