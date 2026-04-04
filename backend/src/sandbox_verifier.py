from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

REMOTE_MANAGEMENT_FILTER = "tcp and (tcp.port == 3389 or tcp.port == 5985 or tcp.port == 5986)"
INTERNAL_SCAN_FILTER = "tcp and (tcp.dstport == 135 or tcp.dstport == 445)"
PAYLOAD_FILTER = "tcp and (tcp.dstport == 135 or tcp.dstport == 445 or tcp.dstport == 3389 or tcp.dstport == 5985 or tcp.dstport == 5986)"
EXFIL_FILTER = (
    'http.request.method in {"POST","PUT","PATCH"} or '
    'http.host contains "temp.sh" or '
    'tls.handshake.extensions_server_name contains "temp.sh" or '
    'frame contains "temp.sh"'
)
INTERNAL_IPV4_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
)
INTERNAL_IPV6_NETWORKS = (
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
    ip_network("::1/128"),
)
ALLOWED_TSHARK_FIELDS = {
    "frame.time_epoch",
    "frame.number",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.content_length",
    "tls.handshake.extensions_server_name",
}


@dataclass
class SandboxRuntimeConfig:
    enabled: bool
    mode: str
    image: str
    timeout_seconds: int
    max_rows: int
    max_pairs: int


def sandbox_verification_enabled() -> bool:
    return _load_config().enabled


def _is_internal_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip_obj = ip_address(value)
    except ValueError:
        return False
    if ip_obj.is_loopback or ip_obj.is_link_local:
        return True
    networks = INTERNAL_IPV4_NETWORKS if ip_obj.version == 4 else INTERNAL_IPV6_NETWORKS
    return any(ip_obj in network for network in networks)


def _is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip_obj = ip_address(value)
    except ValueError:
        return False
    if _is_internal_ip(value):
        return False
    return not (ip_obj.is_multicast or ip_obj.is_unspecified)


def _load_config() -> SandboxRuntimeConfig:
    enabled = os.getenv("AGENTIC_SANDBOX_VERIFY", "").strip().lower() in {"1", "true", "yes", "on"}
    mode = os.getenv("AGENTIC_SANDBOX_MODE", "auto").strip().lower() or "auto"
    image = os.getenv("AGENTIC_SANDBOX_IMAGE", "agenticnetsec-forensics-sandbox").strip() or "agenticnetsec-forensics-sandbox"
    timeout_seconds = max(15, int(os.getenv("AGENTIC_SANDBOX_TIMEOUT", "120") or "120"))
    max_rows = max(10, int(os.getenv("AGENTIC_SANDBOX_MAX_ROWS", "400") or "400"))
    max_pairs = max(3, int(os.getenv("AGENTIC_SANDBOX_MAX_PAIRS", "8") or "8"))
    return SandboxRuntimeConfig(
        enabled=enabled,
        mode=mode,
        image=image,
        timeout_seconds=timeout_seconds,
        max_rows=max_rows,
        max_pairs=max_pairs,
    )


def run_sandbox_verification(
    pcap_path: str,
    findings: dict[str, Any] | None = None,
    requested_checks: list[str] | None = None,
) -> dict[str, Any]:
    cfg = _load_config()
    resolved = Path(pcap_path).expanduser().resolve()
    result: dict[str, Any] = {
        "enabled": cfg.enabled,
        "status": "disabled" if not cfg.enabled else "unavailable",
        "mode": cfg.mode,
        "image": cfg.image,
        "pcap_path": str(resolved),
        "remote_management": {},
        "internal_scanning": {},
        "exfiltration": {},
        "notable_observations": [],
        "commands": [],
    }
    if not cfg.enabled:
        result["message"] = "Sandbox verification is disabled. Set AGENTIC_SANDBOX_VERIFY=1 to enable it."
        return result

    runner = _build_runner(cfg, resolved)
    if runner is None:
        result["message"] = "No sandbox runtime available. Install tshark locally or build the Docker sandbox image."
        return result

    requested = list(dict.fromkeys(requested_checks or ["remote_management", "internal_scanning", "exfiltration", "payload_deployment"]))
    result["requested_checks"] = requested
    try:
        remote_rows: list[dict[str, str]] = []
        scan_rows: list[dict[str, str]] = []
        exfil_rows: list[dict[str, str]] = []
        payload_rows: list[dict[str, str]] = []
        if "remote_management" in requested:
            remote_rows = _run_tshark(
                runner,
                display_filter=REMOTE_MANAGEMENT_FILTER,
                fields=("frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.flags"),
                timeout_seconds=cfg.timeout_seconds,
                max_rows=cfg.max_rows,
            )
        if "internal_scanning" in requested:
            scan_rows = _run_tshark(
                runner,
                display_filter=INTERNAL_SCAN_FILTER,
                fields=("frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport"),
                timeout_seconds=cfg.timeout_seconds,
                max_rows=cfg.max_rows,
            )
        if "exfiltration" in requested:
            exfil_rows = _run_tshark(
                runner,
                display_filter=EXFIL_FILTER,
                fields=(
                    "frame.time_epoch",
                    "ip.src",
                    "ip.dst",
                    "tcp.dstport",
                    "http.request.method",
                    "http.host",
                    "http.request.uri",
                    "http.content_length",
                    "tls.handshake.extensions_server_name",
                ),
                timeout_seconds=cfg.timeout_seconds,
                max_rows=cfg.max_rows,
            )
        if "payload_deployment" in requested:
            payload_rows = _run_tshark(
                runner,
                display_filter=PAYLOAD_FILTER,
                fields=("frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport", "tcp.flags"),
                timeout_seconds=cfg.timeout_seconds,
                max_rows=cfg.max_rows,
            )
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["message"] = str(exc)
        return result

    result["status"] = "completed"
    result["commands"] = runner["commands"]
    result["remote_management"] = _summarize_remote_management(remote_rows, cfg.max_pairs)
    result["internal_scanning"] = _summarize_internal_scanning(scan_rows, cfg.max_pairs)
    result["exfiltration"] = _summarize_exfiltration(exfil_rows, cfg.max_pairs)
    result["payload_deployment"] = _summarize_payload_deployment(payload_rows, cfg.max_pairs)
    result["notable_observations"] = _build_observations(result, findings or {})
    result["message"] = "Sandbox verification completed with compact tshark summaries."
    return result


def run_ai_tshark_queries(pcap_path: str, queries: list[dict[str, Any]]) -> dict[str, Any]:
    cfg = _load_config()
    resolved = Path(pcap_path).expanduser().resolve()
    result: dict[str, Any] = {
        "enabled": cfg.enabled,
        "status": "disabled" if not cfg.enabled else "unavailable",
        "mode": cfg.mode,
        "image": cfg.image,
        "pcap_path": str(resolved),
        "query_count": 0,
        "queries": [],
        "commands": [],
    }
    if not cfg.enabled:
        result["message"] = "Sandbox verification is disabled. Set AGENTIC_SANDBOX_VERIFY=1 to enable it."
        return result

    runner = _build_runner(cfg, resolved)
    if runner is None:
        result["message"] = "No sandbox runtime available. Install tshark locally or build the Docker sandbox image."
        return result

    safe_queries = _sanitize_ai_queries(queries)
    result["query_count"] = len(safe_queries)
    if not safe_queries:
        result["status"] = "skipped"
        result["message"] = "No safe AI-authored tshark queries were provided."
        return result

    try:
        for query in safe_queries:
            rows = _run_tshark(
                runner,
                display_filter=str(query["display_filter"]),
                fields=tuple(query["fields"]),
                timeout_seconds=cfg.timeout_seconds,
                max_rows=int(query["max_rows"]),
            )
            result["queries"].append(
                {
                    "name": query["name"],
                    "stage": query["stage"],
                    "display_filter": query["display_filter"],
                    "fields": query["fields"],
                    "row_count": len(rows),
                    "sample_rows": rows[: min(10, len(rows))],
                }
            )
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["message"] = str(exc)
        result["commands"] = runner["commands"]
        return result

    result["status"] = "completed"
    result["commands"] = runner["commands"]
    result["message"] = "AI-authored tshark queries completed."
    return result


def _build_runner(cfg: SandboxRuntimeConfig, resolved: Path) -> dict[str, Any] | None:
    if cfg.mode in {"auto", "host"} and shutil.which("tshark"):
        return {"mode": "host", "pcap_ref": str(resolved), "commands": []}

    if cfg.mode in {"auto", "docker"} and shutil.which("docker"):
        inspect = subprocess.run(
            ["docker", "image", "inspect", cfg.image],
            capture_output=True,
            text=True,
            check=False,
        )
        if inspect.returncode == 0:
            return {
                "mode": "docker",
                "pcap_ref": f"/case/{resolved.name}",
                "mount_dir": str(resolved.parent),
                "image": cfg.image,
                "commands": [],
            }
    return None


def _sanitize_ai_queries(queries: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    for index, query in enumerate(queries or [], start=1):
        if not isinstance(query, dict):
            continue
        display_filter = str(query.get("display_filter", "")).strip()
        if not display_filter:
            continue
        fields = [field for field in query.get("fields", []) if field in ALLOWED_TSHARK_FIELDS]
        if not fields:
            fields = ["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport"]
        max_rows = query.get("max_rows", 100)
        try:
            max_rows_int = max(5, min(200, int(max_rows)))
        except (TypeError, ValueError):
            max_rows_int = 100
        safe.append(
            {
                "name": str(query.get("name") or f"query_{index}"),
                "stage": str(query.get("stage") or "?"),
                "display_filter": display_filter,
                "fields": fields[:8],
                "max_rows": max_rows_int,
            }
        )
    return safe[:6]


def _run_tshark(
    runner: dict[str, Any],
    *,
    display_filter: str,
    fields: tuple[str, ...],
    timeout_seconds: int,
    max_rows: int,
) -> list[dict[str, str]]:
    base = [
        "tshark",
        "-r",
        runner["pcap_ref"],
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
        "-c",
        str(max_rows),
    ]
    for field in fields:
        base.extend(["-e", field])

    if runner["mode"] == "docker":
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{runner['mount_dir']}:/case:ro",
            runner["image"],
            *base,
        ]
    else:
        cmd = base

    runner["commands"].append(" ".join(cmd))
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark failure"
        raise RuntimeError(f"Sandbox tshark query failed: {stderr}")

    rows: list[dict[str, str]] = []
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    for line in lines:
        values = line.split("\t")
        padded = values + [""] * (len(fields) - len(values))
        rows.append({field: padded[index] for index, field in enumerate(fields)})
    return rows


def _summarize_remote_management(rows: list[dict[str, str]], limit: int) -> dict[str, Any]:
    pairs: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        src_ip = row.get("ip.src", "")
        dst_ip = row.get("ip.dst", "")
        dst_port = row.get("tcp.dstport", "")
        if not src_ip or not dst_ip or not dst_port:
            continue
        key = (src_ip, dst_ip, dst_port)
        bucket = pairs.setdefault(
            key,
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "packet_count": 0,
                "first_seen": row.get("frame.time_epoch"),
                "last_seen": row.get("frame.time_epoch"),
                "external_to_internal": _is_external_ip(src_ip) and _is_internal_ip(dst_ip),
                "internal_to_internal": _is_internal_ip(src_ip) and _is_internal_ip(dst_ip),
            },
        )
        bucket["packet_count"] += 1
        bucket["last_seen"] = row.get("frame.time_epoch")

    pair_list = sorted(
        pairs.values(),
        key=lambda item: (
            item["external_to_internal"],
            item["dst_port"] in {5985, 5986},
            item["packet_count"],
        ),
        reverse=True,
    )
    verified_winrm = [item for item in pair_list if item["dst_port"] in {5985, 5986}]
    return {
        "pair_count": len(pair_list),
        "top_pairs": pair_list[:limit],
        "verified_winrm_pairs": verified_winrm[:limit],
    }


def _summarize_internal_scanning(rows: list[dict[str, str]], limit: int) -> dict[str, Any]:
    by_source: dict[str, dict[str, Any]] = {}
    for row in rows:
        src_ip = row.get("ip.src", "")
        dst_ip = row.get("ip.dst", "")
        dst_port = row.get("tcp.dstport", "")
        if not src_ip or not dst_ip or not dst_port:
            continue
        if not (_is_internal_ip(src_ip) and _is_internal_ip(dst_ip) and src_ip != dst_ip):
            continue
        bucket = by_source.setdefault(
            src_ip,
            {
                "src_ip": src_ip,
                "targets": set(),
                "ports": Counter(),
                "packet_count": 0,
                "first_seen": row.get("frame.time_epoch"),
                "last_seen": row.get("frame.time_epoch"),
            },
        )
        bucket["targets"].add(dst_ip)
        bucket["ports"][dst_port] += 1
        bucket["packet_count"] += 1
        bucket["last_seen"] = row.get("frame.time_epoch")

    summary = []
    for bucket in by_source.values():
        summary.append(
            {
                "src_ip": bucket["src_ip"],
                "unique_targets": len(bucket["targets"]),
                "packet_count": bucket["packet_count"],
                "top_ports": [{"port": int(port), "count": count} for port, count in bucket["ports"].most_common(3)],
                "first_seen": bucket["first_seen"],
                "last_seen": bucket["last_seen"],
            }
        )
    summary.sort(key=lambda item: (item["unique_targets"], item["packet_count"]), reverse=True)
    return {"scanner_count": len(summary), "top_scanners": summary[:limit]}


def _summarize_exfiltration(rows: list[dict[str, str]], limit: int) -> dict[str, Any]:
    by_flow: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "src_ip": "",
            "dst_ip": "",
            "dst_port": 0,
            "request_count": 0,
            "http_methods": Counter(),
            "hosts": Counter(),
            "paths": Counter(),
            "content_length_sum": 0,
            "temp_sh_mentions": 0,
            "first_seen": None,
            "last_seen": None,
        }
    )

    for row in rows:
        src_ip = row.get("ip.src", "")
        dst_ip = row.get("ip.dst", "")
        dst_port = row.get("tcp.dstport", "")
        if not src_ip or not dst_ip or not dst_port or not _is_internal_ip(src_ip):
            continue
        key = (src_ip, dst_ip, dst_port)
        bucket = by_flow[key]
        bucket["src_ip"] = src_ip
        bucket["dst_ip"] = dst_ip
        bucket["dst_port"] = int(dst_port)
        bucket["request_count"] += 1
        method = row.get("http.request.method", "")
        host = row.get("http.host", "") or row.get("tls.handshake.extensions_server_name", "")
        path = row.get("http.request.uri", "")
        if method:
            bucket["http_methods"][method] += 1
        if host:
            bucket["hosts"][host] += 1
        if path:
            bucket["paths"][path] += 1
        content_length = row.get("http.content_length", "")
        if content_length.isdigit():
            bucket["content_length_sum"] += int(content_length)
        lowered = f"{host} {path}".lower()
        bucket["temp_sh_mentions"] += int("temp.sh" in lowered)
        if bucket["first_seen"] is None:
            bucket["first_seen"] = row.get("frame.time_epoch")
        bucket["last_seen"] = row.get("frame.time_epoch")

    summary = []
    for bucket in by_flow.values():
        summary.append(
            {
                "src_ip": bucket["src_ip"],
                "dst_ip": bucket["dst_ip"],
                "dst_port": bucket["dst_port"],
                "request_count": bucket["request_count"],
                "temp_sh_mentions": bucket["temp_sh_mentions"],
                "content_length_sum": bucket["content_length_sum"],
                "top_hosts": [{"host": host, "count": count} for host, count in bucket["hosts"].most_common(3)],
                "top_methods": [{"method": method, "count": count} for method, count in bucket["http_methods"].most_common(3)],
                "first_seen": bucket["first_seen"],
                "last_seen": bucket["last_seen"],
            }
        )
    summary.sort(
        key=lambda item: (item["temp_sh_mentions"], item["content_length_sum"], item["request_count"]),
        reverse=True,
    )
    temp_hits = [item for item in summary if item["temp_sh_mentions"] > 0]
    return {
        "flow_count": len(summary),
        "top_flows": summary[:limit],
        "verified_temp_sh_flows": temp_hits[:limit],
    }


def _summarize_payload_deployment(rows: list[dict[str, str]], limit: int) -> dict[str, Any]:
    by_source: dict[str, dict[str, Any]] = {}
    for row in rows:
        src_ip = row.get("ip.src", "")
        dst_ip = row.get("ip.dst", "")
        dst_port = row.get("tcp.dstport", "")
        if not src_ip or not dst_ip or not dst_port:
            continue
        if not (_is_internal_ip(src_ip) and _is_internal_ip(dst_ip) and src_ip != dst_ip):
            continue
        bucket = by_source.setdefault(
            src_ip,
            {
                "src_ip": src_ip,
                "targets": set(),
                "ports": Counter(),
                "packet_count": 0,
                "first_seen": row.get("frame.time_epoch"),
                "last_seen": row.get("frame.time_epoch"),
            },
        )
        bucket["targets"].add(dst_ip)
        bucket["ports"][dst_port] += 1
        bucket["packet_count"] += 1
        bucket["last_seen"] = row.get("frame.time_epoch")
    summary = []
    for bucket in by_source.values():
        summary.append(
            {
                "src_ip": bucket["src_ip"],
                "unique_targets": len(bucket["targets"]),
                "packet_count": bucket["packet_count"],
                "top_ports": [{"port": int(port), "count": count} for port, count in bucket["ports"].most_common(5)],
                "first_seen": bucket["first_seen"],
                "last_seen": bucket["last_seen"],
            }
        )
    summary.sort(key=lambda item: (item["unique_targets"], item["packet_count"]), reverse=True)
    return {"candidate_count": len(summary), "top_sources": summary[:limit]}


def _build_observations(result: dict[str, Any], findings: dict[str, Any]) -> list[str]:
    observations: list[str] = []

    remote = result.get("remote_management", {})
    top_pairs = remote.get("top_pairs") or []
    winrm_pairs = remote.get("verified_winrm_pairs") or []
    if top_pairs:
        top = top_pairs[0]
        observations.append(
            f"Sandbox verified remote-management traffic {top['src_ip']} -> {top['dst_ip']}:{top['dst_port']} ({top['packet_count']} packets)."
        )
    if winrm_pairs:
        top = winrm_pairs[0]
        observations.append(
            f"Sandbox confirmed WinRM traffic {top['src_ip']} -> {top['dst_ip']}:{top['dst_port']}."
        )

    scans = result.get("internal_scanning", {})
    top_scanners = scans.get("top_scanners") or []
    if top_scanners:
        top = top_scanners[0]
        observations.append(
            f"Sandbox verified internal 135/445 fan-out from {top['src_ip']} to {top['unique_targets']} targets."
        )

    exfil = result.get("exfiltration", {})
    temp_sh = exfil.get("verified_temp_sh_flows") or []
    if temp_sh:
        top = temp_sh[0]
        observations.append(
            f"Sandbox verified temp.sh-related outbound flow {top['src_ip']} -> {top['dst_ip']}:{top['dst_port']}."
        )
    payload = result.get("payload_deployment", {})
    top_payload = payload.get("top_sources") or []
    if top_payload:
        top = top_payload[0]
        observations.append(
            f"Sandbox saw internal remote-admin fan-out from {top['src_ip']} toward {top['unique_targets']} hosts on payload-relevant ports."
        )

    patient_zero = (findings.get("external_rdp") or {}).get("patient_zero_candidate") or {}
    if patient_zero and winrm_pairs:
        observations.append(
            "Sandbox observed WinRM alongside the current RDP-centric patient-zero hypothesis; review both channels before finalizing initial access."
        )

    return observations[:8]
