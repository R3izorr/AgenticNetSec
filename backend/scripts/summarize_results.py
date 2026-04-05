from __future__ import annotations

import argparse
from collections import Counter
import json
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

from flow_analysis import build_attack_flow
from report_ai import generate_results_report


def load_results(results_file: Path) -> list[dict[str, Any]]:
    by_path: dict[str, dict[str, Any]] = {}
    records = []
    with results_file.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"Invalid JSON on line {line_number} of {results_file}: {exc}"
                )
            record_path = record.get("path")
            if record_path:
                by_path[record_path] = record
            else:
                records.append(record)
    return [*by_path.values(), *records]


def build_aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    external_rdp = [item for item in records if item.get("suspicious_external_rdp_count", 0)]
    external_scans = [item for item in records if item.get("suspicious_external_port_scanners")]
    vpn_like = [item for item in records if item.get("suspicious_vpn_count", 0)]
    smb_scan = [item for item in records if item.get("suspicious_smb_rpc_scanners")]
    dcerpc = [item for item in records if item.get("possible_dcerpc_account_changes")]
    temp_hits = [item for item in records if item.get("temp_sh_hits")]
    exfil_candidates = [item for item in records if item.get("possible_outbound_exfil_flows")]
    uploads = [item for item in records if item.get("large_http_uploads")]
    rdp_spread = [item for item in records if item.get("suspicious_internal_rdp_spread")]
    manual_payload = [item for item in records if item.get("manual_payload_deployment_candidates")]
    payload_candidates = [item for item in records if item.get("payload_carving_candidate_count", 0)]
    confirmed_payload = [item for item in records if _has_payload_recovery_status(item, "confirmed_artifact")]
    partial_payload = [item for item in records if _has_payload_recovery_status(item, "partial_evidence", "hash_only")]
    heuristic_payload_only = [
        item
        for item in payload_candidates
        if item not in confirmed_payload and item not in partial_payload
    ]
    deep_dive = [item for item in records if item.get("deep_dive")]
    focus_hosts = Counter(item.get("deep_dive_focus_host") for item in deep_dive if item.get("deep_dive_focus_host"))

    patient_zero_candidates = sorted(
        [
            {
                "file": item["file"],
                **item["patient_zero_candidate"],
            }
            for item in records
            if item.get("patient_zero_candidate")
        ],
        key=lambda item: (
            item.get("confidence_score", 0),
            item.get("total_bytes", 0),
            item.get("packet_count", 0),
        ),
        reverse=True,
    )

    return {
        "file_count": len(records),
        "files_with_external_rdp": len(external_rdp),
        "files_with_external_port_scans": len(external_scans),
        "files_with_vpn_like_ingress": len(vpn_like),
        "files_with_smb_rpc_scanning": len(smb_scan),
        "files_with_dcerpc_account_markers": len(dcerpc),
        "files_with_temp_sh_hits": len(temp_hits),
        "files_with_outbound_exfil_candidates": len(exfil_candidates),
        "files_with_large_http_uploads": len(uploads),
        "files_with_internal_rdp_spread": len(rdp_spread),
        "files_with_manual_payload_deployment": len(manual_payload),
        "files_with_payload_carving_candidates": len(payload_candidates),
        "files_with_recovered_payload_artifacts": len(confirmed_payload),
        "files_with_partial_payload_evidence": len(partial_payload),
        "files_with_heuristic_payload_only": len(heuristic_payload_only),
        "files_with_deep_dive": len(deep_dive),
        "interesting_files": {
            "external_rdp": [item["file"] for item in external_rdp[:30]],
            "external_port_scans": [item["file"] for item in external_scans[:30]],
            "vpn_like_ingress": [item["file"] for item in vpn_like[:30]],
            "smb_rpc_scanning": [item["file"] for item in smb_scan[:30]],
            "dcerpc_account_markers": [item["file"] for item in dcerpc[:30]],
            "temp_sh_hits": [item["file"] for item in temp_hits[:30]],
            "outbound_exfil_candidates": [item["file"] for item in exfil_candidates[:30]],
            "large_http_uploads": [item["file"] for item in uploads[:30]],
            "internal_rdp_spread": [item["file"] for item in rdp_spread[:30]],
            "manual_payload_deployment": [item["file"] for item in manual_payload[:30]],
            "payload_carving_candidates": [item["file"] for item in payload_candidates[:30]],
            "recovered_payload_artifacts": [item["file"] for item in confirmed_payload[:30]],
            "partial_payload_evidence": [item["file"] for item in partial_payload[:30]],
            "heuristic_payload_only": [item["file"] for item in heuristic_payload_only[:30]],
            "deep_dive": [item["file"] for item in deep_dive[:30]],
        },
        "top_patient_zero_candidates": patient_zero_candidates[:20],
        "top_deep_dive_focus_hosts": [
            {"host": host, "file_count": count} for host, count in focus_hosts.most_common(10)
        ],
        "attack_flow": build_attack_flow(records),
    }


def _has_payload_recovery_status(record: dict[str, Any], *statuses: str) -> bool:
    expected = set(statuses)
    record_status = record.get("payload_carving_status")
    if record_status in expected:
        return True
    for artifact in record.get("carved_payloads") or []:
        if artifact.get("recovery_status") in expected:
            return True
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize a scan_results JSONL file and optionally generate an AI report."
    )
    parser.add_argument("results_file", help="Path to the JSONL results file")
    parser.add_argument(
        "--provider",
        choices=["gemini", "openai", "groq", "ollama"],
        default="gemini",
        help="AI provider to use for report generation",
    )
    parser.add_argument(
        "--model",
        help="Model name for the selected AI provider. If omitted, provider defaults from local_settings.py are used.",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI and use the deterministic fallback report",
    )
    parser.add_argument(
        "--require-ai",
        action="store_true",
        help="Fail instead of silently falling back when AI report generation fails",
    )
    parser.add_argument(
        "--aggregate-file",
        help="Optional path to write the aggregate JSON summary",
    )
    parser.add_argument(
        "--report-file",
        help="Optional path to write the generated Markdown report",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the aggregate JSON summary",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    results_file = Path(args.results_file).expanduser().resolve()
    records = load_results(results_file)
    aggregate = build_aggregate(records)
    report = generate_results_report(
        aggregate,
        records,
        provider=args.provider,
        model=args.model,
        use_ai=not args.no_ai,
        require_ai=args.require_ai,
    )

    print(report)

    if args.aggregate_file:
        Path(args.aggregate_file).expanduser().write_text(
            json.dumps(aggregate, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.report_file:
        Path(args.report_file).expanduser().write_text(report + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(aggregate, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

