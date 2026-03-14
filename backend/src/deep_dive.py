from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from detectors import _scan_detection_surfaces, collect_all_findings


def _fmt_ts(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()
    except Exception:
        return str(timestamp)


def _top_targets(events: list[dict[str, Any]], *, limit: int = 10) -> list[dict[str, Any]]:
    counts = Counter(event["dst_ip"] for event in events if event.get("dst_ip"))
    return [{"dst_ip": ip, "count": count} for ip, count in counts.most_common(limit)]


def _first_timestamp(values: list[float | None]) -> float | None:
    candidates = [value for value in values if value is not None]
    return min(candidates) if candidates else None


def _last_timestamp(values: list[float | None]) -> float | None:
    candidates = [value for value in values if value is not None]
    return max(candidates) if candidates else None


def _duration(first_seen: float | None, last_seen: float | None) -> float | None:
    if first_seen is None or last_seen is None:
        return None
    return round(max(0.0, last_seen - first_seen), 2)


def build_deep_dive(pcap_path: str, findings: dict[str, Any] | None = None) -> dict[str, Any]:
    findings = findings or collect_all_findings(pcap_path)
    scan = _scan_detection_surfaces(pcap_path)

    external_rdp = findings["external_rdp"]
    smb_rpc = findings["smb_rpc_scans"]
    dcerpc = findings["dcerpc_account_activity"]
    temp_sh = findings["temp_sh_traffic"]
    large_posts = findings["large_http_posts"]
    outbound_exfil = findings["outbound_exfiltration_candidates"]
    internal_rdp = findings["rdp_payload_deployment"]
    manual_payload = findings["manual_payload_deployment"]

    patient_zero = external_rdp.get("patient_zero_candidate") or {}
    focus_host = patient_zero.get("internal_ip")

    focus_ingress_sessions = [
        session
        for session in external_rdp.get("sessions", [])
        if not focus_host or session.get("internal_ip") == focus_host
    ][:10]

    focus_lateral_events = scan["internal_lateral_events"].get(focus_host, []) if focus_host else []
    lateral_port_counts = Counter(event["dst_port"] for event in focus_lateral_events)

    focus_scanners = [
        scanner
        for scanner in smb_rpc.get("scanners", [])
        if scanner.get("src_ip") == focus_host
    ]
    focus_rdp_spread = [
        spread
        for spread in internal_rdp.get("spreaders", [])
        if spread.get("src_ip") == focus_host
    ]
    focus_manual_payload = [
        candidate
        for candidate in manual_payload.get("candidates", [])
        if candidate.get("src_ip") == focus_host
    ]
    focus_dcerpc = [
        event
        for event in dcerpc.get("events", [])
        if focus_host and focus_host in {event.get("src_ip"), event.get("dst_ip")}
    ]
    focus_temp_sh = [
        hit for hit in temp_sh.get("hits", []) if not focus_host or hit.get("src_ip") == focus_host
    ][:10]
    focus_uploads = [
        upload
        for upload in large_posts.get("uploads", [])
        if not focus_host or upload.get("src_ip") == focus_host
    ][:10]
    focus_exfil_candidates = [
        flow
        for flow in outbound_exfil.get("flows", [])
        if not focus_host or flow.get("src_ip") == focus_host
    ][:10]

    ingress_first_seen = _first_timestamp([session.get("first_seen") for session in focus_ingress_sessions])
    ingress_last_seen = _last_timestamp([session.get("last_seen") for session in focus_ingress_sessions])
    scan_first_seen = _first_timestamp([scanner.get("first_seen") for scanner in focus_scanners])
    spread_first_seen = _first_timestamp([spread.get("first_seen") for spread in focus_rdp_spread])
    dcerpc_first_seen = _first_timestamp(
        [event.get("timestamp") for event in scan.get("dcerpc_markers", []) if not focus_host or event.get("src_ip") == focus_host]
    )
    exfil_first_seen = _first_timestamp(
        [hit.get("timestamp") for hit in focus_temp_sh]
        + [upload.get("timestamp") for upload in focus_uploads]
        + [flow.get("first_seen") for flow in focus_exfil_candidates]
    )

    analyst_filters = []
    if focus_host:
        analyst_filters.extend(
            [
                f"ip.addr == {focus_host} and tcp.port == 3389",
                f"ip.src == {focus_host} and tcp.dstport in {{135,445,3389,5985,5986}}",
                f"ip.addr == {focus_host} and tcp.port == 445",
                f"ip.addr == {focus_host} and dcerpc",
            ]
        )
    if patient_zero.get("external_ip") and focus_host:
        analyst_filters.append(
            f"ip.addr == {patient_zero['external_ip']} and ip.addr == {focus_host} and tcp.port == 3389"
        )
    analyst_filters.extend(
        [
            'http.request.method == "POST"',
            'http.host contains "temp.sh" or tls.handshake.extensions_server_name contains "temp.sh"',
        ]
    )

    notes = []
    if focus_host:
        notes.append(
            f"The challenge hypothesis fits an external-to-internal RDP compromise focused on {focus_host}."
        )
    if focus_scanners:
        notes.append(
            "The same host that received external RDP also generated broad SMB/RPC discovery, which supports rapid post-login network mapping."
        )
    if focus_rdp_spread:
        notes.append(
            "Internal RDP spread from the focus host is consistent with manual operator-driven lateral movement or payload staging."
        )
    if focus_manual_payload:
        notes.append(
            "RDP fan-out from the focus host overlaps with SMB/DCERPC admin-share or remote-exec indicators on the same targets, which is stronger evidence of manual payload drop behavior."
        )
    if not focus_temp_sh and not focus_uploads and not focus_exfil_candidates:
        notes.append(
            "This PCAP does not currently show the challenge's expected exfiltration indicators, so exfil may be elsewhere in the capture set or via another protocol."
        )
    notes.append(
        "PCAP alone cannot prove whether RDP access came from bought credentials, brute force, or a vulnerable exposed service."
    )

    return {
        "focus_host": focus_host,
        "patient_zero_candidate": patient_zero or None,
        "initial_access": {
            "top_ingress_sessions": focus_ingress_sessions,
            "first_seen": _fmt_ts(ingress_first_seen),
            "last_seen": _fmt_ts(ingress_last_seen),
            "duration_seconds": _duration(ingress_first_seen, ingress_last_seen),
            "interpretation": (
                f"External RDP into {focus_host} is the strongest initial-access hypothesis."
                if focus_host
                else "No strong patient-zero host was identified."
            ),
        },
        "lateral_movement_and_discovery": {
            "focus_host": focus_host,
            "first_scan_seen": _fmt_ts(scan_first_seen),
            "first_internal_rdp_spread_seen": _fmt_ts(spread_first_seen),
            "top_lateral_ports": [
                {"port": port, "count": count} for port, count in lateral_port_counts.most_common(10)
            ],
            "sample_lateral_targets": _top_targets(focus_lateral_events),
            "smb_rpc_scanners": focus_scanners[:10],
            "internal_rdp_spread": focus_rdp_spread[:10],
            "interpretation": (
                "The focus host shows rapid internal discovery and lateral movement patterns aligned with the challenge scenario."
                if focus_scanners or focus_rdp_spread
                else "No strong internal discovery or lateral spread pattern was isolated for the focus host in this file."
            ),
        },
        "administrative_activity": {
            "first_marker_seen": _fmt_ts(dcerpc_first_seen),
            "dcerpc_account_markers": focus_dcerpc[:10],
            "interpretation": (
                "Possible account or group administration markers were observed over SMB/DCERPC."
                if focus_dcerpc
                else "No account-creation or group-modification marker was observed in this file."
            ),
        },
        "exfiltration": {
            "first_exfil_indicator_seen": _fmt_ts(exfil_first_seen),
            "temp_sh_hits": focus_temp_sh,
            "large_http_uploads": focus_uploads,
            "outbound_exfil_candidates": focus_exfil_candidates,
            "interpretation": (
                "Outbound HTTP upload or temp.sh evidence exists and should be reviewed for archive staging and data loss."
                if focus_temp_sh or focus_uploads or focus_exfil_candidates
                else "No direct exfiltration indicator was observed in this file."
            ),
        },
        "payload_deployment": {
            "likely_operator_driven_rdp": bool(focus_rdp_spread),
            "manual_drop_candidates": focus_manual_payload[:10],
            "spread_summary": focus_rdp_spread[:10],
            "interpretation": (
                "RDP fan-out from the focus host overlapped with SMB/DCERPC admin-share or remote-exec markers on the same internal targets, which is consistent with manual payload drop activity."
                if focus_manual_payload
                else "Internal RDP fan-out from the focus host is consistent with hands-on-keyboard deployment."
                if focus_rdp_spread
                else "No strong internal RDP fan-out suggesting payload deployment was observed in this file."
            ),
        },
        "analyst_filters": analyst_filters,
        "notes": notes,
    }


def render_deep_dive_markdown(deep_dive: dict[str, Any]) -> str:
    focus_host = deep_dive.get("focus_host") or "unknown"
    patient_zero = deep_dive.get("patient_zero_candidate") or {}
    ingress_sessions = deep_dive.get("initial_access", {}).get("top_ingress_sessions", [])
    discovery = deep_dive.get("lateral_movement_and_discovery", {})
    admin_activity = deep_dive.get("administrative_activity", {})
    exfiltration = deep_dive.get("exfiltration", {})
    payload = deep_dive.get("payload_deployment", {})

    lines = [
        "## Deep Dive",
        "",
        f"Focus host: `{focus_host}`",
    ]

    if patient_zero:
        lines.append(
            f"Best ingress candidate: external `{patient_zero.get('external_ip')}` -> internal `{patient_zero.get('internal_ip')}` with confidence `{patient_zero.get('confidence_score')}`."
        )
    lines.extend(
        [
            "",
            "### Initial Access Pivot",
            deep_dive.get("initial_access", {}).get("interpretation", "No initial-access interpretation available."),
        ]
    )
    if ingress_sessions:
        for session in ingress_sessions[:5]:
            lines.append(
                f"- {session.get('external_ip')} -> {session.get('internal_ip')} packets={session.get('packet_count')} app_packets={session.get('application_packets')} post_login_targets={session.get('post_login_unique_internal_targets')} suspicious={session.get('suspicious')}"
            )

    lines.extend(
        [
            "",
            "### Lateral Movement & Discovery Pivot",
            discovery.get("interpretation", "No discovery interpretation available."),
        ]
    )
    for scanner in discovery.get("smb_rpc_scanners", [])[:3]:
        lines.append(
            f"- SMB/RPC scan source {scanner.get('src_ip')} unique_targets={scanner.get('unique_targets')} attempts={scanner.get('connection_attempts')} duration={scanner.get('duration_seconds')}"
        )
    for spread in discovery.get("internal_rdp_spread", [])[:3]:
        lines.append(
            f"- Internal RDP spread source {spread.get('src_ip')} unique_targets={spread.get('unique_targets')} sessions={spread.get('session_count')} duration={spread.get('duration_seconds')}"
        )

    lines.extend(
        [
            "",
            "### Administrative Activity Pivot",
            admin_activity.get("interpretation", "No admin-activity interpretation available."),
        ]
    )
    for event in admin_activity.get("dcerpc_account_markers", [])[:3]:
        lines.append(
            f"- DCERPC markers {event.get('src_ip')} -> {event.get('dst_ip')} markers={event.get('marker_counts')}"
        )

    lines.extend(
        [
            "",
            "### Exfiltration Pivot",
            exfiltration.get("interpretation", "No exfiltration interpretation available."),
        ]
    )
    for hit in exfiltration.get("temp_sh_hits", [])[:3]:
        lines.append(
            f"- temp.sh candidate {hit.get('src_ip')} -> {hit.get('dst_ip')} host={hit.get('host')} method={hit.get('method')}"
        )
    for flow in exfiltration.get("outbound_exfil_candidates", [])[:3]:
        lines.append(
            f"- Outbound exfil candidate {flow.get('src_ip')} -> {flow.get('dst_ip')}:{flow.get('dst_port')} total_bytes={flow.get('total_bytes')} payload_bytes={flow.get('payload_bytes')} archive_hits={flow.get('archive_hits')}"
        )
    for upload in exfiltration.get("large_http_uploads", [])[:3]:
        lines.append(
            f"- Large upload {upload.get('src_ip')} -> {upload.get('dst_ip')} bytes={upload.get('inferred_upload_bytes')} host={upload.get('host')}"
        )

    lines.extend(
        [
            "",
            "### Payload Deployment Pivot",
            payload.get("interpretation", "No payload interpretation available."),
        ]
    )
    for candidate in payload.get("manual_drop_candidates", [])[:3]:
        lines.append(
            f"- Manual-drop candidate {candidate.get('src_ip')} targets={candidate.get('unique_targets')} smb_targets={candidate.get('targets_with_smb_rpc')} admin_share_targets={candidate.get('targets_with_admin_share_markers')} remote_exec_targets={candidate.get('targets_with_remote_exec_markers')} score={candidate.get('manual_drop_score')}"
        )
    for spread in payload.get("spread_summary", [])[:3]:
        lines.append(
            f"- Internal RDP spread source {spread.get('src_ip')} unique_targets={spread.get('unique_targets')} sessions={spread.get('session_count')} duration={spread.get('duration_seconds')}"
        )
    lines.extend(
        [
            "",
            "",
            "### Recommended Filters",
        ]
    )
    for display_filter in deep_dive.get("analyst_filters", []):
        lines.append(f"- `{display_filter}`")

    lines.extend(["", "### Notes"])
    for note in deep_dive.get("notes", []):
        lines.append(f"- {note}")

    return "\n".join(lines).strip()
