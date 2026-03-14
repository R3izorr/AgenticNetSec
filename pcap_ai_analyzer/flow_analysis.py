from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any


def _pick_focus_host(records: list[dict[str, Any]]) -> str | None:
    hosts = Counter()
    for record in records:
        candidate = record.get("patient_zero_candidate") or {}
        host = candidate.get("internal_ip") or record.get("deep_dive_focus_host")
        if host:
            hosts[host] += max(1, candidate.get("confidence_score", 0))
    return hosts.most_common(1)[0][0] if hosts else None


def _record_sort_key(record: dict[str, Any]) -> tuple[Any, str]:
    candidate = record.get("patient_zero_candidate") or {}
    timestamp = candidate.get("first_seen")
    if timestamp is None:
        deep_dive = record.get("deep_dive") or {}
        timestamp = (
            ((deep_dive.get("initial_access") or {}).get("first_seen"))
            or ((deep_dive.get("lateral_movement_and_discovery") or {}).get("first_scan_seen"))
            or ((deep_dive.get("exfiltration") or {}).get("first_exfil_indicator_seen"))
        )
    return (timestamp if timestamp is not None else float("inf"), record.get("file", ""))


def _sortable_timestamp(value: Any) -> float:
    if value is None:
        return float("inf")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except Exception:
            return float("inf")
    return float("inf")


def _best_external_ips(records: list[dict[str, Any]], focus_host: str | None) -> list[dict[str, Any]]:
    counter = Counter()
    for record in records:
        candidate = record.get("patient_zero_candidate") or {}
        if focus_host and candidate.get("internal_ip") != focus_host:
            continue
        external_ip = candidate.get("external_ip")
        if external_ip:
            counter[external_ip] += max(1, candidate.get("confidence_score", 0))
    return [{"external_ip": ip, "score": score} for ip, score in counter.most_common(10)]


def _is_meaningful_exfil_flow(flow: dict[str, Any]) -> bool:
    severity = flow.get("severity")
    if severity in {"medium", "high"}:
        return True
    return bool(
        flow.get("temp_sh_mentions")
        or flow.get("suspicious_archive_hits")
        or flow.get("total_bytes", 0) >= 25_000_000
        or flow.get("payload_bytes", 0) >= 5_000_000
        or flow.get("upload_like_method_count", 0) >= 1
    )


def _stage_entry(
    *,
    stage: str,
    file_name: str,
    timestamp: Any,
    detail: str,
) -> dict[str, Any]:
    return {
        "stage": stage,
        "file": file_name,
        "timestamp": timestamp,
        "detail": detail,
    }


def build_attack_flow(records: list[dict[str, Any]]) -> dict[str, Any]:
    focus_host = _pick_focus_host(records)
    primary_external_ips = _best_external_ips(records, focus_host)

    initial_access_records = []
    discovery_records = []
    admin_records = []
    exfil_records = []
    payload_records = []
    timeline = []

    for record in sorted(records, key=_record_sort_key):
        file_name = record.get("file", "unknown")
        candidate = record.get("patient_zero_candidate") or {}

        if focus_host and candidate.get("internal_ip") == focus_host:
            initial_access_records.append(record)
            timeline.append(
                _stage_entry(
                    stage="initial_access",
                    file_name=file_name,
                    timestamp=candidate.get("first_seen"),
                    detail=(
                        f"External {candidate.get('external_ip')} -> {focus_host} "
                        f"confidence={candidate.get('confidence_score')} "
                        f"post_login_targets={candidate.get('post_login_unique_internal_targets')}"
                    ),
                )
            )

        matching_scanners = [
            item
            for item in record.get("suspicious_smb_rpc_scanners", [])
            if not focus_host or item.get("src_ip") == focus_host
        ]
        for scanner in matching_scanners:
            discovery_records.append(record)
            timeline.append(
                _stage_entry(
                    stage="discovery",
                    file_name=file_name,
                    timestamp=scanner.get("first_seen"),
                    detail=(
                        f"{scanner.get('src_ip')} scanned {scanner.get('unique_targets')} "
                        f"targets over SMB/RPC"
                    ),
                )
            )

        deep_dive = record.get("deep_dive") or {}
        admin_timestamp = ((deep_dive.get("administrative_activity") or {}).get("first_marker_seen"))
        matching_admin = [
            item
            for item in record.get("possible_dcerpc_account_changes", [])
            if not focus_host or focus_host in {item.get("src_ip"), item.get("dst_ip")}
        ]
        if matching_admin:
            admin_records.append(record)
            timeline.append(
                _stage_entry(
                    stage="administrative_activity",
                    file_name=file_name,
                    timestamp=admin_timestamp,
                    detail=f"DCERPC/account markers observed around {focus_host}",
                )
            )

        matching_manual_payload = [
            item
            for item in record.get("manual_payload_deployment_candidates", [])
            if not focus_host or item.get("src_ip") == focus_host
        ]
        for candidate in matching_manual_payload:
            payload_records.append(record)
            timeline.append(
                _stage_entry(
                    stage="payload_deployment",
                    file_name=file_name,
                    timestamp=candidate.get("first_seen"),
                    detail=(
                        f"{candidate.get('src_ip')} showed manual-drop traits across "
                        f"{candidate.get('unique_targets')} targets "
                        f"(admin_share_targets={candidate.get('targets_with_admin_share_markers')}, "
                        f"remote_exec_targets={candidate.get('targets_with_remote_exec_markers')})"
                    ),
                )
            )

        matching_spread = [
            item
            for item in record.get("suspicious_internal_rdp_spread", [])
            if not focus_host or item.get("src_ip") == focus_host
        ]
        spread_records = matching_spread if not matching_manual_payload else []
        for spread in spread_records:
            payload_records.append(record)
            timeline.append(
                _stage_entry(
                    stage="payload_deployment",
                    file_name=file_name,
                    timestamp=spread.get("first_seen"),
                    detail=(
                        f"{spread.get('src_ip')} spread internal RDP to "
                        f"{spread.get('unique_targets')} targets"
                    ),
                )
            )

        matching_exfil = [
            item
            for item in record.get("possible_outbound_exfil_flows", [])
            if (not focus_host or item.get("src_ip") == focus_host) and _is_meaningful_exfil_flow(item)
        ]
        for flow in matching_exfil:
            exfil_records.append(record)
            timeline.append(
                _stage_entry(
                    stage="exfiltration",
                    file_name=file_name,
                    timestamp=flow.get("first_seen"),
                    detail=(
                        f"{flow.get('src_ip')} -> {flow.get('dst_ip')}:{flow.get('dst_port')} "
                        f"severity={flow.get('severity')} total_bytes={flow.get('total_bytes')}"
                    ),
                )
            )

    timeline.sort(key=lambda item: (_sortable_timestamp(item.get("timestamp")), item.get("file", "")))

    ordered_stages = []
    seen_stages = set()
    for entry in timeline:
        stage = entry["stage"]
        if stage not in seen_stages:
            ordered_stages.append(stage)
            seen_stages.add(stage)

    likely_path = " -> ".join(
        stage.replace("_", " ").title() for stage in ordered_stages
    ) or "No coherent attack flow was built from the current results."

    return {
        "focus_host": focus_host,
        "primary_external_ips": primary_external_ips,
        "stage_counts": {
            "initial_access": len(initial_access_records),
            "discovery": len(discovery_records),
            "administrative_activity": len(admin_records),
            "exfiltration": len(exfil_records),
            "payload_deployment": len(payload_records),
        },
        "likely_path": likely_path,
        "timeline": timeline[:100],
        "initial_access_files": [record.get("file") for record in initial_access_records[:20]],
        "discovery_files": [record.get("file") for record in discovery_records[:20]],
        "administrative_activity_files": [record.get("file") for record in admin_records[:20]],
        "exfiltration_files": [record.get("file") for record in exfil_records[:20]],
        "payload_deployment_files": [record.get("file") for record in payload_records[:20]],
    }
