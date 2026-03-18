from __future__ import annotations

from collections import Counter, defaultdict
from functools import lru_cache
from ipaddress import ip_address, ip_network
import logging
from pathlib import Path
from typing import Any

try:
    from scapy.layers import dcerpc as _scapy_dcerpc  # noqa: F401
except Exception:
    _scapy_dcerpc = None
from scapy.all import DNS, DNSQR, IP, IPv6, Raw, TCP, UDP, PcapReader

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

VPN_PORTS = {443, 500, 4500, 1194, 1701, 1723, 8443, 10443}
LATERAL_PORTS = {88, 135, 139, 389, 445, 464, 3389, 5985, 5986}
SCAN_PORTS = {135, 445}
EXTERNAL_SCAN_MIN_UNIQUE_PORTS = 20
EXTERNAL_SCAN_MIN_UNIQUE_TARGETS = 5
EXTERNAL_SCAN_MIN_ATTEMPTS = 10
EXTERNAL_SCAN_MIN_SYN_RATIO = 0.8
SEVEN_Z_MAGIC = b"\x37\x7a\xbc\xaf\x27\x1c"
ZIP_MAGIC = b"PK\x03\x04"
RAR_MAGIC = b"Rar!\x1a\x07"
GZIP_MAGIC = b"\x1f\x8b"
ARCHIVE_MAGIC_MAP = {
    "7z": SEVEN_Z_MAGIC,
    "zip": ZIP_MAGIC,
    "rar": RAR_MAGIC,
    "gzip": GZIP_MAGIC,
}
SUSPICIOUS_ARCHIVE_TYPES = {"7z", "zip", "rar"}
COMMON_TCP_UDP_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137,
    138, 139, 143, 161, 162, 389, 443, 445, 464, 514, 587, 636, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 8080, 8443,
}
COMMON_IP_PROTOCOLS = {1, 6, 17, 47, 50, 51, 58}
ASCII_MARKERS = (
    b"temp.sh",
    b"samr",
    b"lsarpc",
    b"srvsvc",
    b"svcctl",
    b"atsvc",
    b"epmapper",
    b"winreg",
    b"netlogon",
    b"admin$",
    b"ipc$",
    b"c$",
    b"psexec",
    b"paexec",
    b"remcom",
    b"schtasks",
    b"domain admins",
    b"administrators",
    b"remote desktop users",
    b"net user",
    b"net group",
    b"net localgroup",
    b"addmember",
    b"createuser",
)
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
UPLOAD_METHODS = {"POST", "PUT", "PATCH"}
ADMIN_SHARE_MARKERS = {"admin$", "c$", "ipc$"}
REMOTE_EXEC_MARKERS = {"svcctl", "atsvc", "winreg", "psexec", "paexec", "remcom", "schtasks"}
PAYLOAD_DEPLOYMENT_MARKERS = ADMIN_SHARE_MARKERS | REMOTE_EXEC_MARKERS
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


@lru_cache(maxsize=4096)
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


@lru_cache(maxsize=4096)
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


def _packet_timestamp(packet: Any) -> float | None:
    try:
        return float(packet.time)
    except Exception:
        return None


def _safe_payload(packet: Any) -> bytes:
    if Raw not in packet:
        return b""
    try:
        return bytes(packet[Raw].load)
    except Exception:
        return b""


def _extract_ips(packet: Any) -> tuple[str | None, str | None]:
    if IP in packet:
        return packet[IP].src, packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst
    return None, None


def _extract_dns_query_names(packet: Any) -> list[str]:
    if DNS not in packet or DNSQR not in packet:
        return []
    try:
        qd = packet[DNS].qd
        if qd is None:
            return []
        if isinstance(qd, list):
            raw_names = [item.qname for item in qd if getattr(item, "qname", None)]
        else:
            raw_names = [qd.qname] if getattr(qd, "qname", None) else []
        names = []
        for raw_name in raw_names:
            if isinstance(raw_name, (bytes, bytearray)):
                names.append(raw_name.decode("utf-8", errors="ignore").rstrip("."))
            else:
                names.append(str(raw_name).rstrip("."))
        return names
    except Exception:
        return []


def _extract_tcp_flags(packet: Any) -> int:
    if TCP not in packet:
        return 0
    try:
        return int(packet[TCP].flags)
    except Exception:
        return 0


def _flag_set(flags: int, mask: int) -> bool:
    return bool(flags & mask)


def _extract_http_request(payload: bytes) -> dict[str, Any] | None:
    if not payload:
        return None
    preview = payload[:16384]
    line_end = preview.find(b"\r\n")
    if line_end <= 0:
        return None
    request_line = preview[:line_end].decode("latin-1", errors="ignore")
    parts = request_line.split()
    if len(parts) < 3 or parts[0] not in HTTP_METHODS:
        return None

    header_end = preview.find(b"\r\n\r\n")
    header_blob = preview[line_end + 2 :] if header_end == -1 else preview[line_end + 2 : header_end]
    body = b"" if header_end == -1 else preview[header_end + 4 :]

    headers: dict[str, str] = {}
    for line in header_blob.split(b"\r\n"):
        if b":" not in line:
            continue
        key, raw_value = line.split(b":", 1)
        headers[key.decode("latin-1", errors="ignore").strip().lower()] = raw_value.decode("latin-1", errors="ignore").strip()

    try:
        content_length = int(headers.get("content-length", "0"))
    except ValueError:
        content_length = 0

    return {
        "method": parts[0],
        "path": parts[1],
        "host": headers.get("host", ""),
        "content_length": content_length,
        "observed_body_bytes": len(body),
        "body_contains_7z": SEVEN_Z_MAGIC in body,
        "body_mentions_temp_sh": b"temp.sh" in body.lower(),
    }


def _extract_tls_sni(payload: bytes) -> str | None:
    if len(payload) < 5 or payload[0] != 0x16:
        return None
    try:
        record_length = int.from_bytes(payload[3:5], "big")
        if len(payload) < 5 + record_length:
            return None
        handshake = payload[5 : 5 + record_length]
        if len(handshake) < 4 or handshake[0] != 0x01:
            return None
        position = 4 + 2 + 32
        session_id_length = handshake[position]
        position += 1 + session_id_length
        cipher_suites_length = int.from_bytes(handshake[position : position + 2], "big")
        position += 2 + cipher_suites_length
        compression_methods_length = handshake[position]
        position += 1 + compression_methods_length
        extensions_length = int.from_bytes(handshake[position : position + 2], "big")
        position += 2
        end = position + extensions_length

        while position + 4 <= end and position + 4 <= len(handshake):
            ext_type = int.from_bytes(handshake[position : position + 2], "big")
            ext_length = int.from_bytes(handshake[position + 2 : position + 4], "big")
            ext_value = handshake[position + 4 : position + 4 + ext_length]
            position += 4 + ext_length
            if ext_type != 0 or len(ext_value) < 5:
                continue
            list_length = int.from_bytes(ext_value[0:2], "big")
            server_name_data = ext_value[2 : 2 + list_length]
            if len(server_name_data) < 3 or server_name_data[0] != 0:
                continue
            name_length = int.from_bytes(server_name_data[1:3], "big")
            return server_name_data[3 : 3 + name_length].decode("utf-8", errors="ignore")
    except Exception:
        return None
    return None


def _duration_seconds(first_seen: float | None, last_seen: float | None) -> float | None:
    if first_seen is None or last_seen is None:
        return None
    return round(max(0.0, last_seen - first_seen), 2)


def _timestamp_in_window(
    timestamp: float | None,
    first_seen: float | None,
    last_seen: float | None,
    padding_seconds: int,
) -> bool:
    if timestamp is None:
        return False
    if first_seen is None and last_seen is None:
        return True
    start = first_seen if first_seen is not None else last_seen
    end = last_seen if last_seen is not None else first_seen
    assert start is not None and end is not None
    return (start - padding_seconds) <= timestamp <= (end + padding_seconds)


def _session_bucket() -> dict[str, Any]:
    return {
        "first_seen": None,
        "last_seen": None,
        "packet_count": 0,
        "total_bytes": 0,
        "client_bytes": 0,
        "server_bytes": 0,
        "seen_syn": False,
        "seen_synack": False,
        "seen_ack": False,
        "application_packets": 0,
    }


def _outbound_flow_bucket() -> dict[str, Any]:
    return {
        "first_seen": None,
        "last_seen": None,
        "packet_count": 0,
        "total_bytes": 0,
        "payload_bytes": 0,
        "http_methods": Counter(),
        "hosts": Counter(),
        "paths": Counter(),
        "archive_hits": Counter(),
        "temp_sh_mentions": 0,
    }


def _build_scan_candidate_summary(
    scan_attempts: dict[str, list[dict[str, Any]]],
    *,
    min_unique_ports: int = EXTERNAL_SCAN_MIN_ATTEMPTS,
    limit: int = 5,
) -> list[dict[str, Any]]:
    candidates = []
    for src_ip, events in scan_attempts.items():
        if not events:
            continue
        unique_ports = sorted({int(event["dst_port"]) for event in events if event.get("dst_port") is not None})
        if len(unique_ports) < min_unique_ports:
            continue
        target_counts = Counter(event["dst_ip"] for event in events if event.get("dst_ip"))
        syn_only_attempts = sum(1 for event in events if event.get("syn_only"))
        candidates.append(
            {
                "src_ip": src_ip,
                "unique_ports": len(unique_ports),
                "unique_targets": len(target_counts),
                "syn_only_ratio": round(syn_only_attempts / len(events), 3) if events else 0.0,
                "min_port": unique_ports[0],
                "max_port": unique_ports[-1],
                "sample_targets": [
                    {"dst_ip": dst_ip, "count": count}
                    for dst_ip, count in target_counts.most_common(3)
                ],
            }
        )
    candidates.sort(
        key=lambda item: (item["unique_ports"], item["unique_targets"], item["syn_only_ratio"]),
        reverse=True,
    )
    return candidates[:limit]


def _sample_scan_events(
    events: list[dict[str, Any]],
    *,
    limit: int = 5,
) -> list[dict[str, Any]]:
    ordered = sorted(
        [event for event in events if event.get("timestamp") is not None],
        key=lambda item: (item.get("timestamp"), item.get("dst_ip", ""), item.get("dst_port", 0)),
    )
    if not ordered:
        ordered = list(events)
    return [
        {
            "timestamp": event.get("timestamp"),
            "dst_ip": event.get("dst_ip"),
            "dst_port": event.get("dst_port"),
            "syn_only": event.get("syn_only", False),
            "basis": "external SYN probe toward an internal target",
        }
        for event in ordered[:limit]
    ]


def _update_session(session: dict[str, Any], timestamp: float | None, packet_size: int, client_to_server: bool, flags: int, has_payload: bool) -> None:
    if session["first_seen"] is None or (timestamp is not None and timestamp < session["first_seen"]):
        session["first_seen"] = timestamp
    if session["last_seen"] is None or (timestamp is not None and timestamp > session["last_seen"]):
        session["last_seen"] = timestamp
    session["packet_count"] += 1
    session["total_bytes"] += packet_size
    if client_to_server:
        session["client_bytes"] += packet_size
    else:
        session["server_bytes"] += packet_size
    if client_to_server and _flag_set(flags, 0x02) and not _flag_set(flags, 0x10):
        session["seen_syn"] = True
    if (not client_to_server) and _flag_set(flags, 0x02) and _flag_set(flags, 0x10):
        session["seen_synack"] = True
    if client_to_server and _flag_set(flags, 0x10) and not _flag_set(flags, 0x02):
        session["seen_ack"] = True
    if has_payload:
        session["application_packets"] += 1


def _update_outbound_flow(flow: dict[str, Any], timestamp: float | None, packet_size: int, payload: bytes) -> None:
    if flow["first_seen"] is None or (timestamp is not None and timestamp < flow["first_seen"]):
        flow["first_seen"] = timestamp
    if flow["last_seen"] is None or (timestamp is not None and timestamp > flow["last_seen"]):
        flow["last_seen"] = timestamp
    flow["packet_count"] += 1
    flow["total_bytes"] += packet_size
    flow["payload_bytes"] += len(payload)
    lowered = payload.lower()
    flow["temp_sh_mentions"] += int(b"temp.sh" in lowered)
    for archive_name, magic in ARCHIVE_MAGIC_MAP.items():
        if magic in payload:
            flow["archive_hits"][archive_name] += 1


@lru_cache(maxsize=4)
def _scan_detection_surfaces(pcap_path: str) -> dict[str, Any]:
    resolved = str(Path(pcap_path).expanduser().resolve())
    ip_counter = Counter()
    port_counter = Counter()
    protocol_counter = Counter()
    unusual_ports = Counter()
    unusual_protocols = Counter()
    total_packets = 0
    total_packet_bytes = 0
    external_rdp_sessions: dict[tuple[str, str], dict[str, Any]] = defaultdict(_session_bucket)
    vpn_sessions: dict[tuple[str, str, int, str], dict[str, Any]] = defaultdict(_session_bucket)
    internal_lateral_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    smb_rpc_attempts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    smb_rpc_seen_flows: dict[str, set[tuple[str, int]]] = defaultdict(set)
    dcerpc_markers: list[dict[str, Any]] = []
    http_posts: list[dict[str, Any]] = []
    temp_sh_hits: list[dict[str, Any]] = []
    internal_rdp_sessions: dict[tuple[str, str], dict[str, Any]] = defaultdict(_session_bucket)
    outbound_flows: dict[tuple[str, str, int, str], dict[str, Any]] = defaultdict(_outbound_flow_bucket)
    external_scan_attempts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    external_scan_seen_pairs: dict[str, set[tuple[str, int]]] = defaultdict(set)

    with PcapReader(resolved) as pcap:
        for packet in pcap:
            total_packets += 1
            src_ip, dst_ip = _extract_ips(packet)
            timestamp = _packet_timestamp(packet)
            packet_size = len(packet)
            total_packet_bytes += packet_size
            payload = _safe_payload(packet)

            if src_ip:
                ip_counter[src_ip] += 1
            if dst_ip:
                ip_counter[dst_ip] += 1

            if not src_ip or not dst_ip:
                continue

            if TCP in packet:
                tcp_layer = packet[TCP]
                sport = int(tcp_layer.sport)
                dport = int(tcp_layer.dport)
                flags = _extract_tcp_flags(packet)
                has_payload = bool(payload)
                protocol_counter["TCP"] += 1
                port_counter[sport] += 1
                port_counter[dport] += 1
                if dport not in COMMON_TCP_UDP_PORTS and dport > 1024:
                    unusual_ports[dport] += 1

                if _is_external_ip(src_ip) and _is_internal_ip(dst_ip) and _flag_set(flags, 0x02) and not _flag_set(flags, 0x10):
                    flow_key = (dst_ip, dport)
                    if flow_key not in external_scan_seen_pairs[src_ip]:
                        external_scan_seen_pairs[src_ip].add(flow_key)
                        external_scan_attempts[src_ip].append(
                            {
                                "timestamp": timestamp,
                                "dst_ip": dst_ip,
                                "dst_port": dport,
                                "syn_only": True,
                            }
                        )

                if _is_external_ip(src_ip) and _is_internal_ip(dst_ip) and dport == 3389:
                    _update_session(external_rdp_sessions[(src_ip, dst_ip)], timestamp, packet_size, True, flags, has_payload)
                elif _is_internal_ip(src_ip) and _is_external_ip(dst_ip) and sport == 3389:
                    _update_session(external_rdp_sessions[(dst_ip, src_ip)], timestamp, packet_size, False, flags, has_payload)

                if _is_internal_ip(src_ip) and _is_external_ip(dst_ip):
                    _update_outbound_flow(
                        outbound_flows[(src_ip, dst_ip, dport, "TCP")],
                        timestamp,
                        packet_size,
                        payload,
                    )

                if _is_internal_ip(src_ip) and _is_internal_ip(dst_ip) and src_ip != dst_ip and dport in LATERAL_PORTS and (_flag_set(flags, 0x02) or dport in {3389, 445, 135}):
                    internal_lateral_events[src_ip].append({"timestamp": timestamp, "dst_ip": dst_ip, "dst_port": dport})

                if _is_external_ip(src_ip) and _is_internal_ip(dst_ip) and dport in VPN_PORTS:
                    _update_session(vpn_sessions[(src_ip, dst_ip, dport, "TCP")], timestamp, packet_size, True, flags, has_payload)
                elif _is_internal_ip(src_ip) and _is_external_ip(dst_ip) and sport in VPN_PORTS:
                    _update_session(vpn_sessions[(dst_ip, src_ip, sport, "TCP")], timestamp, packet_size, False, flags, has_payload)

                if (
                    _is_internal_ip(src_ip)
                    and _is_internal_ip(dst_ip)
                    and src_ip != dst_ip
                    and dport in SCAN_PORTS
                ):
                    flow_key = (dst_ip, dport)
                    if flow_key not in smb_rpc_seen_flows[src_ip]:
                        smb_rpc_seen_flows[src_ip].add(flow_key)
                        smb_rpc_attempts[src_ip].append(
                            {"timestamp": timestamp, "dst_ip": dst_ip, "dst_port": dport}
                        )

                if _is_internal_ip(src_ip) and _is_internal_ip(dst_ip) and src_ip != dst_ip and dport == 3389:
                    _update_session(internal_rdp_sessions[(src_ip, dst_ip)], timestamp, packet_size, True, flags, has_payload)
                elif _is_internal_ip(src_ip) and _is_internal_ip(dst_ip) and src_ip != dst_ip and sport == 3389:
                    _update_session(internal_rdp_sessions[(dst_ip, src_ip)], timestamp, packet_size, False, flags, has_payload)

                if payload and ((sport in {135, 445}) or (dport in {135, 445})):
                    lowered = payload.lower()
                    matches = [marker.decode("ascii", errors="ignore") for marker in ASCII_MARKERS if marker in lowered]
                    if matches:
                        dcerpc_markers.append({
                            "timestamp": timestamp,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": sport,
                            "dst_port": dport,
                            "matches": sorted(set(matches)),
                        })

                if payload:
                    http = _extract_http_request(payload)
                    if http:
                        event = {
                            "timestamp": timestamp,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dport,
                            "method": http["method"],
                            "host": http["host"],
                            "path": http["path"],
                            "content_length": http["content_length"],
                            "observed_body_bytes": http["observed_body_bytes"],
                            "has_7z_magic": http["body_contains_7z"],
                            "mentions_temp_sh": "temp.sh" in http["host"].lower() or "temp.sh" in http["path"].lower() or http["body_mentions_temp_sh"],
                        }
                        if _is_internal_ip(src_ip) and _is_external_ip(dst_ip):
                            flow = outbound_flows[(src_ip, dst_ip, dport, "TCP")]
                            flow["http_methods"][event["method"]] += 1
                            if event["host"]:
                                flow["hosts"][event["host"]] += 1
                            if event["path"]:
                                flow["paths"][event["path"]] += 1
                        if event["method"] in UPLOAD_METHODS and _is_internal_ip(src_ip) and _is_external_ip(dst_ip):
                            http_posts.append(event)
                        if event["mentions_temp_sh"]:
                            event["match_type"] = "http"
                            temp_sh_hits.append(event)
                    else:
                        sni = _extract_tls_sni(payload)
                        if sni and "temp.sh" in sni.lower() and _is_internal_ip(src_ip) and _is_external_ip(dst_ip):
                            temp_sh_hits.append({
                                "timestamp": timestamp,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "dst_port": dport,
                                "method": None,
                                "host": sni,
                                "path": None,
                                "content_length": 0,
                                "observed_body_bytes": len(payload),
                                "has_7z_magic": SEVEN_Z_MAGIC in payload,
                                "mentions_temp_sh": True,
                                "match_type": "tls_sni",
                            })
                        elif b"temp.sh" in payload.lower() and _is_internal_ip(src_ip):
                            temp_sh_hits.append({
                                "timestamp": timestamp,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "dst_port": dport,
                                "method": None,
                                "host": None,
                                "path": None,
                                "content_length": 0,
                                "observed_body_bytes": len(payload),
                                "has_7z_magic": SEVEN_Z_MAGIC in payload,
                                "mentions_temp_sh": True,
                                "match_type": "raw_payload",
                            })

            elif UDP in packet:
                udp_layer = packet[UDP]
                sport = int(udp_layer.sport)
                dport = int(udp_layer.dport)
                protocol_counter["UDP"] += 1
                port_counter[sport] += 1
                port_counter[dport] += 1
                if dport not in COMMON_TCP_UDP_PORTS and dport > 1024:
                    unusual_ports[dport] += 1
                if _is_external_ip(src_ip) and _is_internal_ip(dst_ip) and dport in VPN_PORTS:
                    _update_session(vpn_sessions[(src_ip, dst_ip, dport, "UDP")], timestamp, packet_size, True, 0, bool(payload))
                elif _is_internal_ip(src_ip) and _is_external_ip(dst_ip) and sport in VPN_PORTS:
                    _update_session(vpn_sessions[(dst_ip, src_ip, sport, "UDP")], timestamp, packet_size, False, 0, bool(payload))
                for query_name in _extract_dns_query_names(packet):
                    if "temp.sh" in query_name.lower():
                        temp_sh_hits.append({
                            "timestamp": timestamp,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dport,
                            "method": "DNS",
                            "host": query_name,
                            "path": None,
                            "content_length": 0,
                            "observed_body_bytes": len(payload),
                            "has_7z_magic": False,
                            "mentions_temp_sh": True,
                            "match_type": "dns_query",
                        })
            elif IP in packet:
                proto = int(packet[IP].proto)
                protocol_counter[f"IP-{proto}"] += 1
                if proto not in COMMON_IP_PROTOCOLS:
                    unusual_protocols[proto] += 1

    return {
        "summary": {
            "total_packets": total_packets,
            "top_ips": [
                {"ip": ip, "packet_count": count}
                for ip, count in ip_counter.most_common(10)
            ],
            "top_ports": [
                {"port": port, "packet_count": count}
                for port, count in port_counter.most_common(10)
            ],
            "protocols": [
                {"protocol": proto, "packet_count": count}
                for proto, count in protocol_counter.most_common()
            ],
            "average_packet_size": round(total_packet_bytes / total_packets, 2)
            if total_packets
            else 0.0,
            "unusual_ports": [
                {"port": port, "packet_count": count}
                for port, count in unusual_ports.most_common(10)
            ],
            "unusual_protocols": [
                {"protocol_number": proto, "packet_count": count}
                for proto, count in unusual_protocols.most_common()
            ],
            "scan_candidates": _build_scan_candidate_summary(external_scan_attempts),
        },
        "external_rdp_sessions": dict(external_rdp_sessions),
        "vpn_sessions": dict(vpn_sessions),
        "external_scan_attempts": dict(external_scan_attempts),
        "internal_lateral_events": dict(internal_lateral_events),
        "smb_rpc_attempts": dict(smb_rpc_attempts),
        "dcerpc_markers": dcerpc_markers,
        "http_posts": http_posts,
        "temp_sh_hits": temp_sh_hits,
        "internal_rdp_sessions": dict(internal_rdp_sessions),
        "outbound_flows": dict(outbound_flows),
    }


def find_external_rdp(pcap_path: str) -> dict[str, Any]:
    scan = _scan_detection_surfaces(pcap_path)
    results = []
    for (external_ip, internal_ip), session in scan["external_rdp_sessions"].items():
        follow_on_events = [event for event in scan["internal_lateral_events"].get(internal_ip, []) if session["first_seen"] is None or event["timestamp"] is None or event["timestamp"] >= session["first_seen"]]
        unique_follow_on_hosts = sorted({event["dst_ip"] for event in follow_on_events})
        established = bool(session["seen_syn"] and session["seen_synack"] and session["seen_ack"])
        confidence = min(100, (25 if established else 0) + min(25, session["application_packets"] * 2) + min(30, len(unique_follow_on_hosts) * 3))
        results.append({
            "external_ip": external_ip,
            "internal_ip": internal_ip,
            "first_seen": session["first_seen"],
            "last_seen": session["last_seen"],
            "duration_seconds": _duration_seconds(session["first_seen"], session["last_seen"]),
            "packet_count": session["packet_count"],
            "total_bytes": session["total_bytes"],
            "handshake_complete": established,
            "application_packets": session["application_packets"],
            "post_login_unique_internal_targets": len(unique_follow_on_hosts),
            "suspicious": bool(established and (session["application_packets"] > 0 or len(unique_follow_on_hosts) >= 3)),
            "confidence_score": confidence,
        })
    results.sort(key=lambda item: (item["confidence_score"], item["total_bytes"]), reverse=True)
    return {
        "detector": "external_rdp",
        "evidence_count": len(results),
        "patient_zero_candidate": results[0] if results else None,
        "sessions": results,
    }


def find_external_port_scans(pcap_path: str) -> dict[str, Any]:
    scan = _scan_detection_surfaces(pcap_path)
    results = []
    for src_ip, events in scan["external_scan_attempts"].items():
        if not events:
            continue
        unique_targets = sorted({event["dst_ip"] for event in events if event.get("dst_ip")})
        unique_ports = sorted({int(event["dst_port"]) for event in events if event.get("dst_port") is not None})
        target_counts = Counter(event["dst_ip"] for event in events if event.get("dst_ip"))
        port_counts = Counter(int(event["dst_port"]) for event in events if event.get("dst_port") is not None)
        timestamps = [event["timestamp"] for event in events if event.get("timestamp") is not None]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        duration = _duration_seconds(first_seen, last_seen)
        syn_only_attempts = sum(1 for event in events if event.get("syn_only"))
        syn_only_ratio = syn_only_attempts / len(events) if events else 0.0
        suspicious = bool(
            syn_only_ratio >= EXTERNAL_SCAN_MIN_SYN_RATIO
            and (
                len(unique_ports) >= EXTERNAL_SCAN_MIN_UNIQUE_PORTS
                or (
                    len(unique_targets) >= EXTERNAL_SCAN_MIN_UNIQUE_TARGETS
                    and len(events) >= EXTERNAL_SCAN_MIN_ATTEMPTS
                )
                or (
                    len(unique_targets) == 1
                    and len(unique_ports) >= 10
                    and (unique_ports[-1] - unique_ports[0]) >= 10
                )
            )
        )
        severity = "low"
        if len(unique_ports) >= 50 or len(unique_targets) >= 10:
            severity = "high"
        elif suspicious:
            severity = "medium"
        results.append(
            {
                "src_ip": src_ip,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "duration_seconds": duration,
                "connection_attempts": len(events),
                "unique_targets": len(unique_targets),
                "unique_ports": len(unique_ports),
                "min_port": unique_ports[0] if unique_ports else None,
                "max_port": unique_ports[-1] if unique_ports else None,
                "syn_only_attempts": syn_only_attempts,
                "syn_only_ratio": round(syn_only_ratio, 3),
                "top_ports": [
                    {"port": port, "count": count}
                    for port, count in port_counts.most_common(10)
                ],
                "top_targets": [
                    {"dst_ip": dst_ip, "count": count}
                    for dst_ip, count in target_counts.most_common(5)
                ],
                "sample_events": _sample_scan_events(events),
                "basis": "External source generated repeated SYN-only probes across multiple internal ports and/or targets.",
                "suspicious": suspicious,
                "severity": severity,
            }
        )
    results.sort(
        key=lambda item: (
            item["suspicious"],
            {"high": 2, "medium": 1, "low": 0}[item["severity"]],
            item["unique_ports"],
            item["unique_targets"],
            item["connection_attempts"],
        ),
        reverse=True,
    )
    return {
        "detector": "external_port_scans",
        "evidence_count": len(results),
        "sources": results,
    }


def find_vpn_like_traffic(pcap_path: str) -> dict[str, Any]:
    scan = _scan_detection_surfaces(pcap_path)
    sessions = []
    for (external_ip, internal_ip, port, transport), session in scan["vpn_sessions"].items():
        sessions.append({
            "external_ip": external_ip,
            "internal_ip": internal_ip,
            "port": port,
            "transport": transport,
            "first_seen": session["first_seen"],
            "last_seen": session["last_seen"],
            "duration_seconds": _duration_seconds(session["first_seen"], session["last_seen"]),
            "packet_count": session["packet_count"],
            "total_bytes": session["total_bytes"],
        })
    sessions.sort(key=lambda item: item["total_bytes"], reverse=True)
    return {"detector": "vpn_like_traffic", "evidence_count": len(sessions), "sessions": sessions}


def find_smb_rpc_scans(pcap_path: str) -> dict[str, Any]:
    scan = _scan_detection_surfaces(pcap_path)
    scanners = []
    for src_ip, events in scan["smb_rpc_attempts"].items():
        unique_targets = sorted({event["dst_ip"] for event in events})
        port_counts = Counter(event["dst_port"] for event in events)
        timestamps = [event["timestamp"] for event in events if event["timestamp"] is not None]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        duration = _duration_seconds(first_seen, last_seen)
        suspicious = bool(
            len(unique_targets) >= 10
            or (
                len(unique_targets) >= 5
                and len(events) >= 8
                and duration is not None
                and duration <= 1800
            )
        )
        scanners.append({
            "src_ip": src_ip,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_seconds": duration,
            "connection_attempts": len(events),
            "unique_targets": len(unique_targets),
            "top_ports": [
                {"port": port, "count": count}
                for port, count in port_counts.most_common()
            ],
            "suspicious": suspicious,
        })
    scanners.sort(key=lambda item: (item["unique_targets"], item["connection_attempts"]), reverse=True)
    return {"detector": "smb_rpc_scans", "evidence_count": len(scanners), "scanners": scanners}


def find_dcerpc_account_activity(pcap_path: str) -> dict[str, Any]:
    scan = _scan_detection_surfaces(pcap_path)
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    interesting = {"samr", "domain admins", "administrators", "remote desktop users", "net user", "net localgroup", "addmember", "createuser"}
    for event in scan["dcerpc_markers"]:
        key = (event["src_ip"], event["dst_ip"])
        bucket = grouped.setdefault(key, {"src_ip": event["src_ip"], "dst_ip": event["dst_ip"], "matches": Counter()})
        for marker in event["matches"]:
            bucket["matches"][marker] += 1
    results = []
    for bucket in grouped.values():
        results.append({
            "src_ip": bucket["src_ip"],
            "dst_ip": bucket["dst_ip"],
            "marker_counts": dict(bucket["matches"].most_common()),
            "possible_account_or_group_change": any(marker in interesting for marker in bucket["matches"]),
        })
    results.sort(key=lambda item: (item["possible_account_or_group_change"], sum(item["marker_counts"].values())), reverse=True)
    return {"detector": "dcerpc_account_activity", "evidence_count": len(results), "events": results}


def find_temp_sh_traffic(pcap_path: str) -> dict[str, Any]:
    hits = sorted(_scan_detection_surfaces(pcap_path)["temp_sh_hits"], key=lambda item: (item.get("content_length", 0), item.get("observed_body_bytes", 0)), reverse=True)
    return {"detector": "temp_sh_traffic", "evidence_count": len(hits), "hits": hits}


def find_large_http_posts(pcap_path: str, min_upload_bytes: int = 5_000_000) -> dict[str, Any]:
    uploads = []
    grouped_sources: dict[str, dict[str, Any]] = {}
    for event in _scan_detection_surfaces(pcap_path)["http_posts"]:
        inferred_bytes = max(event["content_length"], event["observed_body_bytes"])
        if inferred_bytes < min_upload_bytes and not event["has_7z_magic"]:
            continue
        item = {**event, "inferred_upload_bytes": inferred_bytes}
        uploads.append(item)
        bucket = grouped_sources.setdefault(event["src_ip"], {"src_ip": event["src_ip"], "upload_count": 0, "total_inferred_bytes": 0, "destinations": set(), "temp_sh_related": 0, "compressed_candidates": 0})
        bucket["upload_count"] += 1
        bucket["total_inferred_bytes"] += inferred_bytes
        bucket["destinations"].add(event["dst_ip"])
        bucket["temp_sh_related"] += int(event["mentions_temp_sh"])
        bucket["compressed_candidates"] += int(event["has_7z_magic"])
    grouped = [{
        "src_ip": bucket["src_ip"],
        "upload_count": bucket["upload_count"],
        "total_inferred_bytes": bucket["total_inferred_bytes"],
        "unique_destinations": len(bucket["destinations"]),
        "temp_sh_related": bucket["temp_sh_related"],
        "compressed_candidates": bucket["compressed_candidates"],
    } for bucket in grouped_sources.values()]
    uploads.sort(key=lambda item: item["inferred_upload_bytes"], reverse=True)
    grouped.sort(key=lambda item: item["total_inferred_bytes"], reverse=True)
    return {"detector": "large_http_posts", "threshold_bytes": min_upload_bytes, "evidence_count": len(uploads), "uploads": uploads, "grouped_by_source": grouped}


def find_outbound_exfiltration_candidates(
    pcap_path: str,
    min_total_bytes: int = 25_000_000,
    min_payload_bytes: int = 5_000_000,
) -> dict[str, Any]:
    flows = []
    grouped_by_source: dict[str, dict[str, Any]] = {}
    for (src_ip, dst_ip, dst_port, transport), flow in _scan_detection_surfaces(pcap_path)["outbound_flows"].items():
        suspicious_archive_hits = {
            archive_name: count
            for archive_name, count in flow["archive_hits"].items()
            if archive_name in SUSPICIOUS_ARCHIVE_TYPES
        }
        upload_like_method_count = sum(
            flow["http_methods"].get(method, 0) for method in UPLOAD_METHODS
        )
        suspicious = bool(
            flow["temp_sh_mentions"]
            or suspicious_archive_hits
            or flow["total_bytes"] >= min_total_bytes
            or flow["payload_bytes"] >= min_payload_bytes
            or (upload_like_method_count and flow["payload_bytes"] >= 1_000_000)
        )
        if not suspicious:
            continue
        severity = "low"
        if (
            flow["temp_sh_mentions"]
            or suspicious_archive_hits
            or flow["total_bytes"] >= 100_000_000
            or flow["payload_bytes"] >= 20_000_000
        ):
            severity = "high"
        elif flow["total_bytes"] >= min_total_bytes or flow["payload_bytes"] >= min_payload_bytes:
            severity = "medium"
        item = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "transport": transport,
            "first_seen": flow["first_seen"],
            "last_seen": flow["last_seen"],
            "duration_seconds": _duration_seconds(flow["first_seen"], flow["last_seen"]),
            "packet_count": flow["packet_count"],
            "total_bytes": flow["total_bytes"],
            "payload_bytes": flow["payload_bytes"],
            "http_methods": dict(flow["http_methods"]),
            "upload_like_method_count": upload_like_method_count,
            "top_hosts": [{"host": host, "count": count} for host, count in flow["hosts"].most_common(5)],
            "top_paths": [{"path": path, "count": count} for path, count in flow["paths"].most_common(5)],
            "archive_hits": dict(flow["archive_hits"]),
            "suspicious_archive_hits": suspicious_archive_hits,
            "temp_sh_mentions": flow["temp_sh_mentions"],
            "suspicious": suspicious,
            "severity": severity,
        }
        flows.append(item)

        bucket = grouped_by_source.setdefault(
            src_ip,
            {
                "src_ip": src_ip,
                "flow_count": 0,
                "total_bytes": 0,
                "payload_bytes": 0,
                "unique_destinations": set(),
                "temp_sh_mentions": 0,
                "archive_hit_count": 0,
                "max_severity": "low",
            },
        )
        bucket["flow_count"] += 1
        bucket["total_bytes"] += flow["total_bytes"]
        bucket["payload_bytes"] += flow["payload_bytes"]
        bucket["unique_destinations"].add(dst_ip)
        bucket["temp_sh_mentions"] += flow["temp_sh_mentions"]
        bucket["archive_hit_count"] += sum(suspicious_archive_hits.values())
        if severity == "high" or (severity == "medium" and bucket["max_severity"] == "low"):
            bucket["max_severity"] = severity

    grouped = [
        {
            "src_ip": bucket["src_ip"],
            "flow_count": bucket["flow_count"],
            "total_bytes": bucket["total_bytes"],
            "payload_bytes": bucket["payload_bytes"],
            "unique_destinations": len(bucket["unique_destinations"]),
            "temp_sh_mentions": bucket["temp_sh_mentions"],
            "archive_hit_count": bucket["archive_hit_count"],
            "max_severity": bucket["max_severity"],
        }
        for bucket in grouped_by_source.values()
    ]
    flows.sort(
        key=lambda item: (
            {"high": 2, "medium": 1, "low": 0}[item["severity"]],
            item["temp_sh_mentions"],
            sum(item["suspicious_archive_hits"].values()),
            item["total_bytes"],
            item["payload_bytes"],
        ),
        reverse=True,
    )
    grouped.sort(
        key=lambda item: (
            {"high": 2, "medium": 1, "low": 0}[item["max_severity"]],
            item["temp_sh_mentions"],
            item["archive_hit_count"],
            item["total_bytes"],
            item["payload_bytes"],
        ),
        reverse=True,
    )
    return {
        "detector": "outbound_exfiltration_candidates",
        "threshold_total_bytes": min_total_bytes,
        "threshold_payload_bytes": min_payload_bytes,
        "evidence_count": len(flows),
        "flows": flows,
        "grouped_by_source": grouped,
    }


def find_rdp_payload_deployment(pcap_path: str) -> dict[str, Any]:
    grouped_sources: dict[str, dict[str, Any]] = {}
    for (src_ip, dst_ip), session in _scan_detection_surfaces(pcap_path)["internal_rdp_sessions"].items():
        bucket = grouped_sources.setdefault(src_ip, {"src_ip": src_ip, "targets": set(), "session_count": 0, "total_bytes": 0, "first_seen": None, "last_seen": None})
        bucket["targets"].add(dst_ip)
        bucket["session_count"] += 1
        bucket["total_bytes"] += session["total_bytes"]
        if bucket["first_seen"] is None or (session["first_seen"] is not None and session["first_seen"] < bucket["first_seen"]):
            bucket["first_seen"] = session["first_seen"]
        if bucket["last_seen"] is None or (session["last_seen"] is not None and session["last_seen"] > bucket["last_seen"]):
            bucket["last_seen"] = session["last_seen"]
    spreads = [{
        "src_ip": bucket["src_ip"],
        "unique_targets": len(bucket["targets"]),
        "session_count": bucket["session_count"],
        "total_bytes": bucket["total_bytes"],
        "first_seen": bucket["first_seen"],
        "last_seen": bucket["last_seen"],
        "duration_seconds": _duration_seconds(bucket["first_seen"], bucket["last_seen"]),
        "suspicious": len(bucket["targets"]) >= 3,
    } for bucket in grouped_sources.values()]
    spreads.sort(key=lambda item: (item["unique_targets"], item["total_bytes"]), reverse=True)
    return {"detector": "rdp_payload_deployment", "evidence_count": len(spreads), "spreaders": spreads}


def find_manual_payload_deployment(
    pcap_path: str,
    correlation_window_seconds: int = 3600,
) -> dict[str, Any]:
    scan = _scan_detection_surfaces(pcap_path)

    lateral_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for src_ip, events in scan["internal_lateral_events"].items():
        for event in events:
            lateral_by_pair[(src_ip, event["dst_ip"])].append(event)

    marker_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in scan["dcerpc_markers"]:
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        if not _is_internal_ip(src_ip) or not _is_internal_ip(dst_ip) or src_ip == dst_ip:
            continue
        relevant_matches = sorted(set(event.get("matches", [])) & PAYLOAD_DEPLOYMENT_MARKERS)
        if not relevant_matches:
            continue
        marker_by_pair[(src_ip, dst_ip)].append(
            {
                "timestamp": event.get("timestamp"),
                "matches": relevant_matches,
                "dst_port": event.get("dst_port"),
            }
        )

    grouped_sources: dict[str, dict[str, Any]] = {}
    for (src_ip, dst_ip), session in scan["internal_rdp_sessions"].items():
        established = bool(session["seen_syn"] and session["seen_synack"] and session["seen_ack"])
        if not established and session["application_packets"] <= 0:
            continue

        correlated_lateral = [
            event
            for event in lateral_by_pair.get((src_ip, dst_ip), [])
            if event.get("dst_port") in SCAN_PORTS
            and _timestamp_in_window(
                event.get("timestamp"),
                session.get("first_seen"),
                session.get("last_seen"),
                correlation_window_seconds,
            )
        ]
        correlated_markers = [
            event
            for event in marker_by_pair.get((src_ip, dst_ip), [])
            if _timestamp_in_window(
                event.get("timestamp"),
                session.get("first_seen"),
                session.get("last_seen"),
                correlation_window_seconds,
            )
        ]
        if not correlated_lateral and not correlated_markers:
            continue

        admin_markers = sorted(
            {
                marker
                for event in correlated_markers
                for marker in event.get("matches", [])
                if marker in ADMIN_SHARE_MARKERS
            }
        )
        remote_exec_markers = sorted(
            {
                marker
                for event in correlated_markers
                for marker in event.get("matches", [])
                if marker in REMOTE_EXEC_MARKERS
            }
        )

        bucket = grouped_sources.setdefault(
            src_ip,
            {
                "src_ip": src_ip,
                "targets": [],
                "target_set": set(),
                "targets_with_smb_rpc": set(),
                "targets_with_admin_share": set(),
                "targets_with_remote_exec": set(),
                "first_seen": None,
                "last_seen": None,
                "total_rdp_bytes": 0,
                "session_count": 0,
            },
        )
        bucket["targets"].append(
            {
                "dst_ip": dst_ip,
                "rdp_first_seen": session.get("first_seen"),
                "rdp_last_seen": session.get("last_seen"),
                "rdp_duration_seconds": _duration_seconds(session.get("first_seen"), session.get("last_seen")),
                "rdp_packet_count": session.get("packet_count"),
                "rdp_total_bytes": session.get("total_bytes"),
                "application_packets": session.get("application_packets"),
                "smb_rpc_ports": sorted({event.get("dst_port") for event in correlated_lateral if event.get("dst_port")}),
                "admin_share_markers": admin_markers,
                "remote_exec_markers": remote_exec_markers,
            }
        )
        bucket["target_set"].add(dst_ip)
        if correlated_lateral:
            bucket["targets_with_smb_rpc"].add(dst_ip)
        if admin_markers:
            bucket["targets_with_admin_share"].add(dst_ip)
        if remote_exec_markers:
            bucket["targets_with_remote_exec"].add(dst_ip)
        bucket["total_rdp_bytes"] += session.get("total_bytes", 0)
        bucket["session_count"] += 1
        first_seen = session.get("first_seen")
        last_seen = session.get("last_seen")
        if bucket["first_seen"] is None or (first_seen is not None and first_seen < bucket["first_seen"]):
            bucket["first_seen"] = first_seen
        if bucket["last_seen"] is None or (last_seen is not None and last_seen > bucket["last_seen"]):
            bucket["last_seen"] = last_seen

    candidates = []
    for bucket in grouped_sources.values():
        unique_targets = len(bucket["target_set"])
        smb_targets = len(bucket["targets_with_smb_rpc"])
        admin_targets = len(bucket["targets_with_admin_share"])
        remote_exec_targets = len(bucket["targets_with_remote_exec"])
        score = min(
            100,
            unique_targets * 4
            + smb_targets * 6
            + admin_targets * 12
            + remote_exec_targets * 18,
        )
        suspicious = bool(
            unique_targets >= 2
            and (
                remote_exec_targets >= 1
                or admin_targets >= 1
                or smb_targets >= 3
            )
        )
        candidates.append(
            {
                "src_ip": bucket["src_ip"],
                "unique_targets": unique_targets,
                "session_count": bucket["session_count"],
                "targets_with_smb_rpc": smb_targets,
                "targets_with_admin_share_markers": admin_targets,
                "targets_with_remote_exec_markers": remote_exec_targets,
                "first_seen": bucket["first_seen"],
                "last_seen": bucket["last_seen"],
                "duration_seconds": _duration_seconds(bucket["first_seen"], bucket["last_seen"]),
                "total_rdp_bytes": bucket["total_rdp_bytes"],
                "manual_drop_score": score,
                "suspicious": suspicious,
                "targets": sorted(
                    bucket["targets"],
                    key=lambda item: (
                        len(item["remote_exec_markers"]),
                        len(item["admin_share_markers"]),
                        len(item["smb_rpc_ports"]),
                        item.get("rdp_total_bytes", 0),
                    ),
                    reverse=True,
                )[:10],
            }
        )
    candidates.sort(
        key=lambda item: (
            item["suspicious"],
            item["manual_drop_score"],
            item["targets_with_remote_exec_markers"],
            item["targets_with_admin_share_markers"],
            item["unique_targets"],
        ),
        reverse=True,
    )
    return {
        "detector": "manual_payload_deployment",
        "correlation_window_seconds": correlation_window_seconds,
        "evidence_count": len(candidates),
        "candidates": candidates,
    }


def collect_all_findings(pcap_path: str) -> dict[str, Any]:
    return {
        "external_rdp": find_external_rdp(pcap_path),
        "external_port_scans": find_external_port_scans(pcap_path),
        "vpn_like_traffic": find_vpn_like_traffic(pcap_path),
        "smb_rpc_scans": find_smb_rpc_scans(pcap_path),
        "dcerpc_account_activity": find_dcerpc_account_activity(pcap_path),
        "temp_sh_traffic": find_temp_sh_traffic(pcap_path),
        "large_http_posts": find_large_http_posts(pcap_path),
        "outbound_exfiltration_candidates": find_outbound_exfiltration_candidates(pcap_path),
        "rdp_payload_deployment": find_rdp_payload_deployment(pcap_path),
        "manual_payload_deployment": find_manual_payload_deployment(pcap_path),
    }


def analyze_pcap_bundle(pcap_path: str) -> dict[str, Any]:
    scan = _scan_detection_surfaces(pcap_path)
    return {
        "summary": scan["summary"],
        "findings": {
            "external_rdp": find_external_rdp(pcap_path),
            "external_port_scans": find_external_port_scans(pcap_path),
            "vpn_like_traffic": find_vpn_like_traffic(pcap_path),
            "smb_rpc_scans": find_smb_rpc_scans(pcap_path),
            "dcerpc_account_activity": find_dcerpc_account_activity(pcap_path),
            "temp_sh_traffic": find_temp_sh_traffic(pcap_path),
            "large_http_posts": find_large_http_posts(pcap_path),
            "outbound_exfiltration_candidates": find_outbound_exfiltration_candidates(pcap_path),
            "rdp_payload_deployment": find_rdp_payload_deployment(pcap_path),
            "manual_payload_deployment": find_manual_payload_deployment(pcap_path),
        },
    }
