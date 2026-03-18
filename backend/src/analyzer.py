from __future__ import annotations

from collections import Counter
import logging
from typing import Any

try:
    from scapy.layers import dcerpc as _scapy_dcerpc  # noqa: F401
except Exception:
    _scapy_dcerpc = None
from scapy.all import IP, TCP, UDP, PcapReader

logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

COMMON_TCP_UDP_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137,
    138, 139, 143, 161, 162, 389, 443, 445, 464, 514, 587, 636, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 8080, 8443,
}
COMMON_IP_PROTOCOLS = {1, 6, 17, 47, 50, 51, 58}


def analyze_pcap_summary(pcap_path: str) -> dict:
    """Create a compact PCAP summary based on the NetMoniAI reference analyzer."""
    try:
        ip_counter = Counter()
        port_counter = Counter()
        protocol_counter = Counter()
        packet_sizes = []
        unusual_ports = Counter()
        unusual_protocols = Counter()
        tcp_scan_pairs: dict[tuple[str, str], dict[str, Any]] = {}
        total_packets = 0

        with PcapReader(pcap_path) as pcap:
            for packet in pcap:
                total_packets += 1
                packet_sizes.append(len(packet))

                if IP not in packet:
                    continue

                ip_layer = packet[IP]
                ip_counter[ip_layer.src] += 1
                ip_counter[ip_layer.dst] += 1

                if TCP in packet:
                    protocol_counter["TCP"] += 1
                    sport = int(packet[TCP].sport)
                    dport = int(packet[TCP].dport)
                    pair_key = (ip_layer.src, ip_layer.dst)
                    pair_bucket = tcp_scan_pairs.setdefault(
                        pair_key,
                        {"ports": set(), "syn_only_packets": 0, "packet_count": 0},
                    )
                    pair_bucket["ports"].add(dport)
                    pair_bucket["packet_count"] += 1
                    try:
                        flags = int(packet[TCP].flags)
                    except Exception:
                        flags = 0
                    if flags & 0x02 and not flags & 0x10:
                        pair_bucket["syn_only_packets"] += 1
                    port_counter[sport] += 1
                    port_counter[dport] += 1
                    if dport not in COMMON_TCP_UDP_PORTS and dport > 1024:
                        unusual_ports[dport] += 1
                elif UDP in packet:
                    protocol_counter["UDP"] += 1
                    sport = int(packet[UDP].sport)
                    dport = int(packet[UDP].dport)
                    port_counter[sport] += 1
                    port_counter[dport] += 1
                    if dport not in COMMON_TCP_UDP_PORTS and dport > 1024:
                        unusual_ports[dport] += 1
                else:
                    proto = int(ip_layer.proto)
                    protocol_counter[f"IP-{proto}"] += 1
                    if proto not in COMMON_IP_PROTOCOLS:
                        unusual_protocols[proto] += 1

        avg_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0.0
        scan_candidates = []
        for (src_ip, dst_ip), bucket in tcp_scan_pairs.items():
            unique_port_count = len(bucket["ports"])
            if unique_port_count < 10:
                continue
            syn_only_ratio = bucket["syn_only_packets"] / bucket["packet_count"] if bucket["packet_count"] else 0.0
            if syn_only_ratio < 0.8:
                continue
            ports = sorted(bucket["ports"])
            scan_candidates.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "unique_ports": unique_port_count,
                    "min_port": ports[0],
                    "max_port": ports[-1],
                    "syn_only_ratio": round(syn_only_ratio, 3),
                }
            )
        scan_candidates.sort(
            key=lambda item: (item["unique_ports"], item["syn_only_ratio"]),
            reverse=True,
        )
        return {
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
            "average_packet_size": round(avg_packet_size, 2),
            "unusual_ports": [
                {"port": port, "packet_count": count}
                for port, count in unusual_ports.most_common(10)
            ],
            "unusual_protocols": [
                {"protocol_number": proto, "packet_count": count}
                for proto, count in unusual_protocols.most_common()
            ],
            "scan_candidates": scan_candidates[:5],
        }
    except Exception as exc:
        logger.exception("Error analyzing PCAP summary")
        return {"error": f"Failed to analyze PCAP: {exc}"}
