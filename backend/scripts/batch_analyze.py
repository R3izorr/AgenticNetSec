from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import json
import os
from pathlib import Path
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SRC_DIR = PROJECT_ROOT / "backend" / "src"
CONFIG_DIR = PROJECT_ROOT / "backend" / "config"

for module_path in (SRC_DIR, CONFIG_DIR):
    module_path_str = str(module_path)
    if module_path_str not in sys.path:
        sys.path.insert(0, module_path_str)

DEFAULT_PCAP_DIR = Path("/mnt/c/Users/az100/1-PROJECT/network/network/pcap")
DEFAULT_RESULTS_FILE = PROJECT_ROOT / "outputs" / "scan_results.jsonl"
ANALYSIS_VERSION = "2026-03-14-payload-v3"


def iter_pcaps(root: Path) -> list[Path]:
    exts = {".pcap", ".pcapng", ".cap"}
    return sorted(
        [
            path
            for path in root.iterdir()
            if path.is_file() and path.suffix.lower() in exts
        ],
        key=lambda path: path.name,
    )


def summarize_file(pcap_path: Path, dive: bool = False) -> dict[str, Any]:
    from detectors import analyze_pcap_bundle
    from deep_dive import build_deep_dive

    bundle = analyze_pcap_bundle(str(pcap_path))
    summary = bundle["summary"]
    findings = bundle["findings"]

    external_rdp = findings.get("external_rdp", {})
    patient_zero = external_rdp.get("patient_zero_candidate")
    suspicious_rdp = [
        item for item in external_rdp.get("sessions", []) if item.get("suspicious")
    ]
    suspicious_vpn = [
        item
        for item in findings.get("vpn_like_traffic", {}).get("sessions", [])
        if item.get("total_bytes", 0) >= 50000
    ]
    suspicious_external_scanners = [
        item
        for item in findings.get("external_port_scans", {}).get("sources", [])
        if item.get("suspicious")
    ]
    suspicious_scanners = [
        item
        for item in findings.get("smb_rpc_scans", {}).get("scanners", [])
        if item.get("suspicious")
    ]
    suspicious_dcerpc = [
        item
        for item in findings.get("dcerpc_account_activity", {}).get("events", [])
        if item.get("possible_account_or_group_change")
    ]
    temp_hits = findings.get("temp_sh_traffic", {}).get("hits", [])
    uploads = findings.get("large_http_posts", {}).get("uploads", [])
    outbound_exfil = [
        item
        for item in findings.get("outbound_exfiltration_candidates", {}).get("flows", [])
        if item.get("suspicious")
    ]
    spreaders = [
        item
        for item in findings.get("rdp_payload_deployment", {}).get("spreaders", [])
        if item.get("suspicious")
    ]
    manual_drop_candidates = [
        item
        for item in findings.get("manual_payload_deployment", {}).get("candidates", [])
        if item.get("suspicious")
    ]

    result = {
        "file": pcap_path.name,
        "path": str(pcap_path),
        "size_bytes": pcap_path.stat().st_size,
        "total_packets": summary.get("total_packets"),
        "top_ips": summary.get("top_ips", [])[:5],
        "top_ports": summary.get("top_ports", [])[:5],
        "patient_zero_candidate": patient_zero,
        "suspicious_external_rdp_count": len(suspicious_rdp),
        "suspicious_external_port_scanners": suspicious_external_scanners,
        "suspicious_vpn_count": len(suspicious_vpn),
        "suspicious_smb_rpc_scanners": suspicious_scanners,
        "possible_dcerpc_account_changes": suspicious_dcerpc,
        "temp_sh_hits": temp_hits,
        "large_http_uploads": uploads,
        "possible_outbound_exfil_flows": outbound_exfil,
        "suspicious_internal_rdp_spread": spreaders,
        "manual_payload_deployment_candidates": manual_drop_candidates,
        "analysis_profile": "base+dive" if dive else "base",
        "analysis_version": ANALYSIS_VERSION,
    }
    if dive:
        deep_dive = build_deep_dive(str(pcap_path), findings)
        result["deep_dive"] = deep_dive
        result["deep_dive_focus_host"] = deep_dive.get("focus_host")
        result["deep_dive_ingress_external_ip"] = (
            (deep_dive.get("patient_zero_candidate") or {}).get("external_ip")
        )
    return result


def load_existing_results(output_file: Path) -> dict[str, dict[str, Any]]:
    if not output_file.exists():
        return {}

    existing: dict[str, dict[str, Any]] = {}
    with output_file.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"Warning: skipping invalid JSON line {line_number} in {output_file}"
                )
                continue
            path = record.get("path")
            if path:
                existing[path] = record
    return existing


def append_result(output_file: Path, result: dict[str, Any]) -> None:
    with output_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result) + "\n")
        handle.flush()


def print_result_line(
    *,
    status: str,
    selected_index: int,
    selected_total: int,
    absolute_index: int,
    absolute_total: int,
    file_name: str,
    result: dict[str, Any] | None = None,
) -> None:
    prefix = (
        f"{status:<4} "
        f"[range {selected_index}/{selected_total} | file {absolute_index}/{absolute_total}] "
        f"{file_name}"
    )
    if not result:
        print(prefix)
        return

    if result.get("error"):
        print(f"{prefix} error={result['error']}")
        return

    print(
        f"{prefix} "
        f"packets={result.get('total_packets')} "
        f"rdp={result.get('suspicious_external_rdp_count', 0)} "
        f"extscan={len(result.get('suspicious_external_port_scanners', []))} "
        f"scan={len(result.get('suspicious_smb_rpc_scanners', []))} "
        f"temp={len(result.get('temp_sh_hits', []))} "
        f"uploads={len(result.get('large_http_uploads', []))} "
        f"exfil={len(result.get('possible_outbound_exfil_flows', []))} "
        f"drop={len(result.get('manual_payload_deployment_candidates', []))} "
        f"focus={result.get('deep_dive_focus_host', '-')}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run PCAP analysis on a file-number range and append per-file results."
    )
    parser.add_argument(
        "--pcap-dir",
        default=str(DEFAULT_PCAP_DIR),
        help=f"Directory containing PCAP files. Default: {DEFAULT_PCAP_DIR}",
    )
    parser.add_argument(
        "--output-file",
        default=str(DEFAULT_RESULTS_FILE),
        help=f"JSONL file where each analyzed file result is appended. Default: {DEFAULT_RESULTS_FILE}",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(4, os.cpu_count() or 1),
        help="Number of worker processes to use",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="1-based start file number",
    )
    parser.add_argument(
        "--end",
        type=int,
        help="1-based end file number. If omitted, runs to the last file",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run files even if they already exist in the output file",
    )
    parser.add_argument(
        "--dive",
        action="store_true",
        help="Add the slower attack-focused deep dive to each per-file batch result",
    )
    args = parser.parse_args()

    if args.start <= 0:
        raise SystemExit("--start must be greater than 0")
    if args.end is not None and args.end < args.start:
        raise SystemExit("--end must be greater than or equal to --start")
    if args.workers <= 0:
        raise SystemExit("--workers must be greater than 0")

    root = Path(args.pcap_dir).expanduser().resolve()
    output_file = Path(args.output_file).expanduser().resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    pcaps = iter_pcaps(root)
    total_files = len(pcaps)
    if total_files == 0:
        print("No PCAP files found.")
        return 0

    end_index = total_files if args.end is None else min(args.end, total_files)
    if args.start > total_files:
        raise SystemExit(
            f"--start {args.start} is out of range. Total files: {total_files}"
        )

    selected = [
        (absolute_index, pcap_path)
        for absolute_index, pcap_path in enumerate(pcaps, start=1)
        if args.start <= absolute_index <= end_index
    ]
    selected_total = len(selected)

    existing = load_existing_results(output_file)
    print(f"Discovered {total_files} PCAP file(s).")
    print(f"Selected file range: {args.start} to {end_index} ({selected_total} file(s)).")
    print(f"Results file: {output_file}")
    print(f"Existing recorded results: {len(existing)}")
    print(f"Workers: {args.workers}")

    for selected_index, (absolute_index, pcap_path) in enumerate(selected, start=1):
        print_result_line(
            status="PLAN",
            selected_index=selected_index,
            selected_total=selected_total,
            absolute_index=absolute_index,
            absolute_total=total_files,
            file_name=pcap_path.name,
        )

    pending: list[tuple[int, Path]] = []
    skipped_count = 0

    for selected_index, (absolute_index, pcap_path) in enumerate(selected, start=1):
        existing_result = existing.get(str(pcap_path))
        needs_deep_dive_refresh = bool(
            args.dive and existing_result and not existing_result.get("deep_dive")
        )
        needs_exfil_refresh = bool(
            existing_result and "possible_outbound_exfil_flows" not in existing_result
        )
        needs_version_refresh = bool(
            existing_result and existing_result.get("analysis_version") != ANALYSIS_VERSION
        )
        if existing_result and not args.force and not needs_deep_dive_refresh and not needs_exfil_refresh and not needs_version_refresh:
            skipped_count += 1
            print_result_line(
                status="SKIP",
                selected_index=selected_index,
                selected_total=selected_total,
                absolute_index=absolute_index,
                absolute_total=total_files,
                file_name=pcap_path.name,
                result=existing_result,
            )
            continue
        pending.append((absolute_index, pcap_path))

    print(
        f"Starting scan: {len(pending)} file(s) to process, "
        f"{skipped_count} file(s) already present."
    )

    future_map = {}
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for absolute_index, pcap_path in pending:
            future = executor.submit(summarize_file, pcap_path, args.dive)
            future_map[future] = (absolute_index, pcap_path)
            print(f"RUN  [file {absolute_index}/{total_files}] {pcap_path.name}")

        completed = 0
        try:
            for future in as_completed(future_map):
                completed += 1
                absolute_index, pcap_path = future_map[future]
                selected_index = absolute_index - args.start + 1
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "file": pcap_path.name,
                        "path": str(pcap_path),
                        "size_bytes": pcap_path.stat().st_size,
                        "error": str(exc),
                    }
                append_result(output_file, result)
                print_result_line(
                    status="DONE",
                    selected_index=selected_index,
                    selected_total=selected_total,
                    absolute_index=absolute_index,
                    absolute_total=total_files,
                    file_name=pcap_path.name,
                    result=result,
                )
                print(
                    f"Progress: completed {completed}/{len(pending)} new file(s), "
                    f"skipped {skipped_count}."
                )
        except KeyboardInterrupt:
            print("\nInterrupted. Shutting down workers...")
            executor.shutdown(wait=False, cancel_futures=True)
            raise SystemExit(130)

    print(
        f"Finished. Newly processed: {len(pending)}. "
        f"Skipped from existing results: {skipped_count}."
    )
    print(f"Per-file results saved in {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

