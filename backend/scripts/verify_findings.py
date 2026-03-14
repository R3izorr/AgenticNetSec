from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
import shlex
import subprocess
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

from summarize_results import load_results

DEFAULT_RESULTS_FILE = PROJECT_ROOT / "outputs" / "scan_results.jsonl"


def _quote(value: str) -> str:
    return shlex.quote(value)


def _run_tshark(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return f"[tshark failed] {result.stderr.strip() or result.stdout.strip()}"
    return result.stdout.strip()


def _records_with_temp_sh(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matched = []
    for record in records:
        temp_hits = record.get("temp_sh_hits") or []
        if temp_hits:
            matched.append(record)
            continue
        for flow in record.get("possible_outbound_exfil_flows") or []:
            if flow.get("temp_sh_mentions", 0):
                matched.append(record)
                break
    return matched


def _records_with_rdp(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [record for record in records if record.get("patient_zero_candidate")]


def _temp_sh_filter(record: dict[str, Any]) -> str:
    exfil_dsts = sorted(
        {
            flow.get("dst_ip")
            for flow in (record.get("possible_outbound_exfil_flows") or [])
            if flow.get("temp_sh_mentions")
        }
    )
    filter_parts = [
        'dns.qry.name contains "temp.sh"',
        'tls.handshake.extensions_server_name contains "temp.sh"',
        'http.host contains "temp.sh"',
        'frame contains "temp.sh"',
    ]
    for dst_ip in exfil_dsts[:5]:
        filter_parts.append(f"ip.addr == {dst_ip}")
    return " or ".join(filter_parts)


def _rdp_filter(record: dict[str, Any]) -> str:
    candidate = record.get("patient_zero_candidate") or {}
    external_ip = candidate.get("external_ip")
    internal_ip = candidate.get("internal_ip")
    if not external_ip or not internal_ip:
        return "tcp.port == 3389"
    return f"ip.addr == {external_ip} and ip.addr == {internal_ip} and tcp.port == 3389"


def _print_temp_sh(records: list[dict[str, Any]], *, limit: int, run_tshark: bool) -> None:
    matches = sorted(
        _records_with_temp_sh(records),
        key=lambda item: (
            len(item.get("temp_sh_hits") or []),
            max((flow.get("total_bytes", 0) for flow in (item.get("possible_outbound_exfil_flows") or [])), default=0),
        ),
        reverse=True,
    )[:limit]

    print("How to read temp.sh verification")
    print("- DNS hit means a host actually resolved temp.sh")
    print("- raw_payload hit means the byte string temp.sh appeared in the captured TCP payload")
    print("- exfil flow ties that hostname activity to a large outbound transfer")
    print()

    if not matches:
        print("No temp.sh-related records were found in the current results file.")
        return

    for record in matches:
        file_name = record.get("file", "unknown")
        pcap_path = record.get("path", "")
        temp_hits = record.get("temp_sh_hits") or []
        exfil_flows = [
            flow
            for flow in (record.get("possible_outbound_exfil_flows") or [])
            if flow.get("temp_sh_mentions")
        ]
        hit_types = Counter(hit.get("match_type", "unknown") for hit in temp_hits)
        print(f"FILE {file_name}")
        print(f"path: {pcap_path}")
        print(f"temp hits: {len(temp_hits)} by type {dict(hit_types)}")
        for hit in temp_hits[:10]:
            print(
                f"- {hit.get('match_type')} {hit.get('src_ip')} -> {hit.get('dst_ip')}:{hit.get('dst_port')} host={hit.get('host')} bytes={hit.get('observed_body_bytes')}"
            )
        for flow in exfil_flows[:5]:
            print(
                f"- exfil {flow.get('src_ip')} -> {flow.get('dst_ip')}:{flow.get('dst_port')} severity={flow.get('severity')} total_bytes={flow.get('total_bytes')} payload_bytes={flow.get('payload_bytes')}"
            )

        tshark_filter = _temp_sh_filter(record)
        tshark_cmd = (
            f"tshark -r {_quote(pcap_path)} -Y {_quote(tshark_filter)} "
            "-T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst "
            "-e tcp.srcport -e tcp.dstport -e dns.qry.name -e tls.handshake.extensions_server_name "
            "-e http.host -e http.request.method -e http.request.uri"
        )
        print("tshark command:")
        print(tshark_cmd)
        print("Wireshark display filter:")
        print(tshark_filter)
        if run_tshark and pcap_path:
            print("tshark preview:")
            preview = _run_tshark(
                [
                    "tshark",
                    "-r",
                    pcap_path,
                    "-Y",
                    tshark_filter,
                    "-T",
                    "fields",
                    "-e",
                    "frame.number",
                    "-e",
                    "frame.time_epoch",
                    "-e",
                    "ip.src",
                    "-e",
                    "ip.dst",
                    "-e",
                    "tcp.srcport",
                    "-e",
                    "tcp.dstport",
                    "-e",
                    "dns.qry.name",
                    "-e",
                    "tls.handshake.extensions_server_name",
                    "-e",
                    "http.host",
                    "-e",
                    "http.request.method",
                    "-e",
                    "http.request.uri",
                ]
            )
            print(preview[:4000])
        print()


def _rank_external_ips(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_external: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "external_ip": None,
            "files": set(),
            "targets": set(),
            "max_confidence": 0,
            "session_count": 0,
            "post_login_targets": 0,
            "handshake_complete_count": 0,
            "application_packets": 0,
        }
    )
    for record in _records_with_rdp(records):
        candidate = record.get("patient_zero_candidate") or {}
        external_ip = candidate.get("external_ip")
        internal_ip = candidate.get("internal_ip")
        if not external_ip or not internal_ip:
            continue
        bucket = by_external[external_ip]
        bucket["external_ip"] = external_ip
        bucket["files"].add(record.get("file"))
        bucket["targets"].add(internal_ip)
        bucket["max_confidence"] = max(bucket["max_confidence"], candidate.get("confidence_score", 0))
        bucket["session_count"] += 1
        bucket["post_login_targets"] += candidate.get("post_login_unique_internal_targets", 0)
        bucket["application_packets"] += candidate.get("application_packets", 0)
        bucket["handshake_complete_count"] += int(bool(candidate.get("handshake_complete")))
    ranked = []
    for bucket in by_external.values():
        ranked.append(
            {
                "external_ip": bucket["external_ip"],
                "file_count": len(bucket["files"]),
                "target_count": len(bucket["targets"]),
                "max_confidence": bucket["max_confidence"],
                "session_count": bucket["session_count"],
                "total_post_login_targets": bucket["post_login_targets"],
                "handshake_complete_count": bucket["handshake_complete_count"],
                "application_packets": bucket["application_packets"],
            }
        )
    ranked.sort(
        key=lambda item: (
            item["max_confidence"],
            item["total_post_login_targets"],
            item["file_count"],
            item["application_packets"],
        ),
        reverse=True,
    )
    return ranked


def _print_rdp(records: list[dict[str, Any]], *, limit: int, run_tshark: bool) -> None:
    print("How attacker-like inbound RDP is inferred")
    print("- external global IP -> internal private IP on tcp/3389")
    print("- handshake complete and application packets observed")
    print("- then the internal host changes behavior after login")
    print("- strongest cases also show SMB/RPC scanning or internal RDP spread from that same host")
    print()

    ranked_ips = _rank_external_ips(records)[:limit]
    print("Top external RDP sources")
    for item in ranked_ips:
        print(
            f"- {item['external_ip']} files={item['file_count']} max_confidence={item['max_confidence']} "
            f"post_login_targets={item['total_post_login_targets']} app_packets={item['application_packets']}"
        )
    print()

    top_records = sorted(
        _records_with_rdp(records),
        key=lambda item: (
            (item.get("patient_zero_candidate") or {}).get("confidence_score", 0),
            (item.get("patient_zero_candidate") or {}).get("post_login_unique_internal_targets", 0),
            (item.get("patient_zero_candidate") or {}).get("application_packets", 0),
        ),
        reverse=True,
    )[:limit]

    for record in top_records:
        candidate = record.get("patient_zero_candidate") or {}
        file_name = record.get("file", "unknown")
        pcap_path = record.get("path", "")
        print(f"FILE {file_name}")
        print(
            f"- inbound RDP {candidate.get('external_ip')} -> {candidate.get('internal_ip')} "
            f"confidence={candidate.get('confidence_score')} handshake={candidate.get('handshake_complete')} "
            f"app_packets={candidate.get('application_packets')} "
            f"post_login_targets={candidate.get('post_login_unique_internal_targets')}"
        )
        deep_dive = record.get("deep_dive") or {}
        initial_access = (deep_dive.get("initial_access") or {}).get("top_ingress_sessions") or []
        for session in initial_access[:3]:
            print(
                f"- session {session.get('external_ip')} -> {session.get('internal_ip')} packets={session.get('packet_count')} "
                f"duration={session.get('duration_seconds')} suspicious={session.get('suspicious')}"
            )
        tshark_filter = _rdp_filter(record)
        tshark_cmd = (
            f"tshark -r {_quote(pcap_path)} -Y {_quote(tshark_filter)} "
            "-T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst "
            "-e tcp.srcport -e tcp.dstport -e tcp.flags"
        )
        print("tshark command:")
        print(tshark_cmd)
        print("Wireshark display filter:")
        print(tshark_filter)
        if run_tshark and pcap_path:
            print("tshark preview:")
            preview = _run_tshark(
                [
                    "tshark",
                    "-r",
                    pcap_path,
                    "-Y",
                    tshark_filter,
                    "-T",
                    "fields",
                    "-e",
                    "frame.number",
                    "-e",
                    "frame.time_epoch",
                    "-e",
                    "ip.src",
                    "-e",
                    "ip.dst",
                    "-e",
                    "tcp.srcport",
                    "-e",
                    "tcp.dstport",
                    "-e",
                    "tcp.flags",
                ]
            )
            print(preview[:4000])
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify temp.sh and attacker-like inbound RDP findings from the current results file."
    )
    parser.add_argument(
        "mode",
        choices=["temp-sh", "rdp"],
        help="Which finding family to verify",
    )
    parser.add_argument(
        "--results-file",
        default=str(DEFAULT_RESULTS_FILE),
        help=f"JSONL results file to inspect. Default: {DEFAULT_RESULTS_FILE}",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="How many files or sources to print",
    )
    parser.add_argument(
        "--run-tshark",
        action="store_true",
        help="Run tshark previews instead of only printing the commands",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    results_file = Path(args.results_file).expanduser().resolve()
    records = load_results(results_file)

    if args.mode == "temp-sh":
        _print_temp_sh(records, limit=max(1, args.limit), run_tshark=args.run_tshark)
    else:
        _print_rdp(records, limit=max(1, args.limit), run_tshark=args.run_tshark)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

