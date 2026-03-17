from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SRC_DIR = PROJECT_ROOT / "backend" / "src"
CONFIG_DIR = PROJECT_ROOT / "backend" / "config"

for module_path in (SRC_DIR, CONFIG_DIR):
    module_path_str = str(module_path)
    if module_path_str not in sys.path:
        sys.path.insert(0, module_path_str)

from analysis_engine import AnalysisEngine, AnalysisRequest

DEFAULT_MANIFEST = PROJECT_ROOT / "docs" / "BenchmarkManifest.json"
DEFAULT_JSON_OUTPUT = PROJECT_ROOT / "outputs" / "benchmark_results.json"
DEFAULT_MD_OUTPUT = PROJECT_ROOT / "docs" / "BenchmarkReport.md"


def load_manifest(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def detected_behaviors_from_report(report_json: dict[str, Any]) -> list[str]:
    claims = {
        ref.get("claim")
        for ref in (report_json.get("evidence", {}) or {}).get("evidence_refs", [])
        if ref.get("claim")
    }
    if report_json.get("impact", {}).get("attack_type") == "scan/lateral-movement":
        claims.add("lateral_movement")
    if report_json.get("impact", {}).get("attack_type") == "exfiltration":
        claims.add("exfiltration")
    return sorted(claim for claim in claims if isinstance(claim, str))


def summarize_precision_recall(records: list[dict[str, Any]]) -> dict[str, dict[str, int | float]]:
    behaviors = sorted(
        {
            behavior
            for record in records
            for behavior in [*(record.get("expected_behaviors") or []), *(record.get("detected_behaviors") or [])]
        }
    )
    summary: dict[str, dict[str, int | float]] = {}
    for behavior in behaviors:
        tp = fp = fn = 0
        for record in records:
            expected = behavior in (record.get("expected_behaviors") or [])
            detected = behavior in (record.get("detected_behaviors") or [])
            if expected and detected:
                tp += 1
            elif detected and not expected:
                fp += 1
            elif expected and not detected:
                fn += 1
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        summary[behavior] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
        }
    return summary


def summarize_size_buckets(records: list[dict[str, Any]]) -> dict[str, dict[str, float | int]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        buckets.setdefault(str(record.get("size_bucket", "unknown")), []).append(record)

    summary: dict[str, dict[str, float | int]] = {}
    for bucket, items in buckets.items():
        runtimes = [float(item.get("runtime_seconds_total", 0.0)) for item in items if item.get("runtime_seconds_total") is not None]
        ram_values = [float(item.get("ram_mb_peak", 0.0)) for item in items if item.get("ram_mb_peak") is not None]
        summary[bucket] = {
            "case_count": len(items),
            "avg_runtime_seconds": round(sum(runtimes) / len(runtimes), 3) if runtimes else 0.0,
            "max_runtime_seconds": round(max(runtimes), 3) if runtimes else 0.0,
            "avg_ram_mb_peak": round(sum(ram_values) / len(ram_values), 3) if ram_values else 0.0,
            "max_ram_mb_peak": round(max(ram_values), 3) if ram_values else 0.0,
        }
    return summary


def run_case(engine: AnalysisEngine, entry: dict[str, Any]) -> dict[str, Any]:
    pcap_path = (PROJECT_ROOT / entry["pcap_path"]).resolve()
    start = time.perf_counter()
    if entry.get("expect_failure"):
        try:
            engine.run(AnalysisRequest(pcap_path=str(pcap_path), use_ai=False))
        except Exception as exc:  # noqa: BLE001
            return {
                "name": entry["name"],
                "pcap_path": str(pcap_path),
                "size_bucket": entry.get("size_bucket", "unknown"),
                "expected_behaviors": entry.get("expected_behaviors", []),
                "detected_behaviors": [],
                "status": "expected_failure",
                "error": str(exc),
                "runtime_seconds_total": round(time.perf_counter() - start, 3),
            }

    artifacts = engine.run(AnalysisRequest(pcap_path=str(pcap_path), use_ai=False))
    report_json = artifacts.report_json
    metrics = artifacts.metrics
    return {
        "name": entry["name"],
        "pcap_path": str(pcap_path),
        "size_bucket": entry.get("size_bucket", "unknown"),
        "expected_behaviors": entry.get("expected_behaviors", []),
        "detected_behaviors": detected_behaviors_from_report(report_json),
        "status": "completed",
        "attack_type": (report_json.get("impact") or {}).get("attack_type"),
        "mitre_techniques": (report_json.get("findings") or {}).get("mitre_techniques", []),
        "human_review_required": ((report_json.get("guardrail_verification") or {}).get("human_review_required")),
        "runtime_seconds_total": metrics.get("runtime_seconds_total"),
        "ram_mb_peak": metrics.get("ram_mb_peak"),
        "provider": metrics.get("provider"),
        "model": metrics.get("model"),
        "fallback_used": metrics.get("fallback_used"),
    }


def maybe_run_concurrency(manifest_path: Path, workers: int) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as handle:
        output_file = Path(handle.name)

    command = [
        sys.executable,
        str(PROJECT_ROOT / "backend" / "scripts" / "batch_analyze.py"),
        "--pcap-dir",
        str((PROJECT_ROOT / "outputs" / "smoke_inputs").resolve()),
        "--output-file",
        str(output_file),
        "--workers",
        str(workers),
        "--force",
    ]
    started = time.perf_counter()
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    runtime = round(time.perf_counter() - started, 3)
    return {
        "command": command,
        "returncode": completed.returncode,
        "runtime_seconds": runtime,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
        "manifest": str(manifest_path),
        "output_file": str(output_file),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Benchmark Report",
        "",
        "## Summary",
        f"- Cases run: {summary['case_count']}",
        f"- Completed: {summary['status_counts'].get('completed', 0)}",
        f"- Expected failures: {summary['status_counts'].get('expected_failure', 0)}",
        "",
        "## Precision / Recall Notes",
    ]
    for behavior, metrics in summary["precision_recall"].items():
        lines.append(
            f"- {behavior}: precision={metrics['precision']} recall={metrics['recall']} tp={metrics['tp']} fp={metrics['fp']} fn={metrics['fn']}"
        )

    lines.extend(["", "## Small / Medium / Large Runtime and Memory"])
    for bucket, metrics in summary["size_buckets"].items():
        lines.append(
            f"- {bucket}: avg_runtime={metrics['avg_runtime_seconds']}s max_runtime={metrics['max_runtime_seconds']}s avg_ram={metrics['avg_ram_mb_peak']}MB max_ram={metrics['max_ram_mb_peak']}MB"
        )

    if summary.get("concurrency"):
        lines.extend(
            [
                "",
                "## Concurrency Run",
                f"- Workers: {summary['concurrency']['workers']}",
                f"- Runtime: {summary['concurrency']['runtime_seconds']}s",
                f"- Return code: {summary['concurrency']['returncode']}",
            ]
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run benchmark cases for demo-ready AgenticNetSec evaluation.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--json-output", default=str(DEFAULT_JSON_OUTPUT))
    parser.add_argument("--markdown-output", default=str(DEFAULT_MD_OUTPUT))
    parser.add_argument("--run-concurrency", action="store_true")
    parser.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
    args = parser.parse_args()

    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest = load_manifest(manifest_path)
    engine = AnalysisEngine()

    records = [run_case(engine, entry) for entry in manifest]
    status_counts: dict[str, int] = {}
    for record in records:
        status = str(record.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1

    summary = {
        "case_count": len(records),
        "status_counts": status_counts,
        "records": records,
        "precision_recall": summarize_precision_recall(records),
        "size_buckets": summarize_size_buckets(records),
    }

    if args.run_concurrency:
        concurrency = maybe_run_concurrency(manifest_path, max(1, args.workers))
        summary["concurrency"] = {
            "workers": max(1, args.workers),
            **concurrency,
        }

    json_output = Path(args.json_output).expanduser().resolve()
    markdown_output = Path(args.markdown_output).expanduser().resolve()
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)

    json_output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    markdown_output.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Wrote benchmark JSON to {json_output}")
    print(f"Wrote benchmark markdown to {markdown_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
