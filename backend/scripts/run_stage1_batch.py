from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SRC_DIR = PROJECT_ROOT / "backend" / "src"
CONFIG_DIR = PROJECT_ROOT / "backend" / "config"

for module_path in (SRC_DIR, CONFIG_DIR):
    module_path_str = str(module_path)
    if module_path_str not in sys.path:
        sys.path.insert(0, module_path_str)


PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
ANALYSIS_PROFILES = ("fast", "standard", "full")
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "outputs" / "direct_stage1_runs"
DEFAULT_INDEX_FILE = DEFAULT_OUTPUT_ROOT / "results.jsonl"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run stage-1 deterministic analysis directly in Python without the FastAPI API."
    )
    parser.add_argument(
        "pcap_dir",
        help="Directory containing PCAP files to analyze.",
    )
    parser.add_argument(
        "--analysis-profile",
        choices=ANALYSIS_PROFILES,
        default="standard",
        help="Stage-1 deterministic profile to use. Default: standard",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(2, os.cpu_count() or 1) or 1,
        help="Number of worker processes. Default: 2",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively discover PCAP files under the directory.",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="1-based start index in the discovered file list. Default: 1",
    )
    parser.add_argument(
        "--end",
        type=int,
        help="1-based end index in the discovered file list. Default: all discovered files",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional limit on how many discovered files to process.",
    )
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help=f"Directory where per-file artifacts are written. Default: {DEFAULT_OUTPUT_ROOT}",
    )
    parser.add_argument(
        "--results-file",
        default=str(DEFAULT_INDEX_FILE),
        help=f"JSONL index file where one summary record per analyzed file is appended. Default: {DEFAULT_INDEX_FILE}",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run files even if a completed direct-run artifact folder already exists for the same profile.",
    )
    return parser


def iter_pcaps(root: Path, *, recursive: bool) -> list[Path]:
    if recursive:
        candidates: Iterable[Path] = root.rglob("*")
    else:
        candidates = root.iterdir()

    return sorted(
        [
            path
            for path in candidates
            if path.is_file() and path.suffix.lower() in PCAP_EXTENSIONS
        ],
        key=lambda path: str(path.relative_to(root)),
    )


def sanitize_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-") or "pcap"


def build_artifacts_dir(output_root: Path, pcap_path: Path, analysis_profile: str) -> Path:
    stem = sanitize_name(pcap_path.stem)
    return output_root / f"{stem}__{analysis_profile}"


def load_existing_results(results_file: Path) -> dict[tuple[str, str], dict[str, Any]]:
    if not results_file.exists():
        return {}

    existing: dict[tuple[str, str], dict[str, Any]] = {}
    with results_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            path = record.get("path")
            profile = record.get("analysis_profile")
            if path and profile:
                existing[(str(path), str(profile))] = record
    return existing


def append_result(results_file: Path, result: dict[str, Any]) -> None:
    with results_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result) + "\n")


def _run_one_file(
    *,
    pcap_path_str: str,
    analysis_profile: str,
    artifacts_dir_str: str,
) -> dict[str, Any]:
    from analysis_engine import AnalysisEngine, AnalysisRequest

    pcap_path = Path(pcap_path_str).expanduser().resolve()
    artifacts_dir = Path(artifacts_dir_str).expanduser().resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    engine = AnalysisEngine()
    artifacts = engine.run(
        AnalysisRequest(
            pcap_path=str(pcap_path),
            provider="gemini",
            model=None,
            use_ai=False,
            require_ai=False,
            analysis_profile=analysis_profile,
            enable_sandbox=False,
            artifacts_dir=str(artifacts_dir),
        )
    )

    (artifacts_dir / "report.json").write_text(
        json.dumps(artifacts.report_json, indent=2) + "\n",
        encoding="utf-8",
    )
    (artifacts_dir / "report.md").write_text(
        artifacts.report_markdown + ("" if artifacts.report_markdown.endswith("\n") else "\n"),
        encoding="utf-8",
    )
    (artifacts_dir / "metrics.json").write_text(
        json.dumps(artifacts.metrics, indent=2) + "\n",
        encoding="utf-8",
    )
    (artifacts_dir / "guardrail_audit.json").write_text(
        json.dumps(artifacts.guardrail_audit, indent=2) + "\n",
        encoding="utf-8",
    )
    (artifacts_dir / "metadata.json").write_text(
        json.dumps(artifacts.metadata, indent=2) + "\n",
        encoding="utf-8",
    )
    (artifacts_dir / "analysis_record.json").write_text(
        json.dumps(artifacts.analysis_record, indent=2) + "\n",
        encoding="utf-8",
    )

    summary_record = {
        "file": pcap_path.name,
        "path": str(pcap_path),
        "artifacts_dir": str(artifacts_dir),
        "analysis_profile": artifacts.analysis_record.get("analysis_profile"),
        "attack_type": (artifacts.report_json.get("impact") or {}).get("attack_type"),
        "risk_level": (artifacts.report_json.get("impact") or {}).get("risk_level"),
        "confidence_score": (artifacts.report_json.get("findings") or {}).get("confidence_score"),
        "runtime_seconds_total": artifacts.metrics.get("runtime_seconds_total"),
        "stage1_execution": artifacts.analysis_record.get("stage1_execution") or {},
        "payload_carving_status": artifacts.analysis_record.get("payload_carving_status"),
    }
    (artifacts_dir / "result.json").write_text(
        json.dumps(summary_record, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary_record


def main() -> int:
    args = build_parser().parse_args()

    if args.start < 1:
        raise SystemExit("--start must be 1 or greater.")
    if args.end is not None and args.end < args.start:
        raise SystemExit("--end must be greater than or equal to --start.")
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1.")

    pcap_dir = Path(args.pcap_dir).expanduser().resolve()
    if not pcap_dir.exists() or not pcap_dir.is_dir():
        raise SystemExit(f"PCAP directory not found: {pcap_dir}")

    output_root = Path(args.output_root).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    results_file = Path(args.results_file).expanduser().resolve()
    results_file.parent.mkdir(parents=True, exist_ok=True)

    files = iter_pcaps(pcap_dir, recursive=args.recursive)
    total_discovered = len(files)
    if not files:
        raise SystemExit(f"No PCAP files found in {pcap_dir}")

    start_index = args.start - 1
    end_index = args.end if args.end is not None else total_discovered
    files = files[start_index:end_index]
    if args.limit is not None:
        files = files[: max(0, args.limit)]
    if not files:
        raise SystemExit("No PCAP files selected after applying range filters.")

    existing = load_existing_results(results_file)

    pending: list[Path] = []
    skipped = 0
    for path in files:
        artifacts_dir = build_artifacts_dir(output_root, path, args.analysis_profile)
        existing_key = (str(path), args.analysis_profile)
        if not args.force and (artifacts_dir / "result.json").exists() and existing_key in existing:
            skipped += 1
            continue
        pending.append(path)

    selected_end = start_index + len(files)
    print(f"Discovered {total_discovered} file(s) in {pcap_dir}")
    print(f"Selected range: {args.start} to {selected_end}")
    print(f"Selected file count: {len(files)}")
    print(f"analysis_profile: {args.analysis_profile}")
    print(f"workers: {args.workers}")
    print(f"output_root: {output_root}")
    print(f"results_file: {results_file}")
    print(f"pending: {len(pending)}")
    print(f"skipped_existing: {skipped}")

    if not pending:
        print("Nothing to do.")
        return 0

    future_map = {}
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for path in pending:
            artifacts_dir = build_artifacts_dir(output_root, path, args.analysis_profile)
            future = executor.submit(
                _run_one_file,
                pcap_path_str=str(path),
                analysis_profile=args.analysis_profile,
                artifacts_dir_str=str(artifacts_dir),
            )
            future_map[future] = path

        completed = 0
        for future in as_completed(future_map):
            path = future_map[future]
            completed += 1
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                print(f"FAIL [{completed}/{len(pending)}] {path.name} error={exc}")
                continue

            append_result(results_file, result)
            print(
                f"OK   [{completed}/{len(pending)}] {path.name} "
                f"runtime={result.get('runtime_seconds_total')} "
                f"profile={result.get('analysis_profile')} "
                f"deep_dive={((result.get('stage1_execution') or {}).get('deep_dive') or {}).get('executed')} "
                f"payload_carving={((result.get('stage1_execution') or {}).get('payload_carving') or {}).get('executed')}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
