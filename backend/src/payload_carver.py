from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import mimetypes
from pathlib import Path
import re
import struct
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class PayloadCarvingLimits:
    max_candidates_per_file: int = 12
    max_reconstructed_bytes_per_file: int = 64 * 1024 * 1024
    min_http_body_bytes: int = 4096


@dataclass(frozen=True)
class PayloadCarvingCandidate:
    candidate_id: str
    protocol: str
    priority: int
    basis: list[str] = field(default_factory=list)
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PayloadArtifactMetadata:
    artifact_id: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    file_magic: str | None = None
    mime_type: str | None = None
    recovered_filename: str | None = None
    pe_metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


HTTP_REQUEST_LINE_RE = re.compile(rb"(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)\s+HTTP/1\.[01]\r\n")
SMB2_HEADER_SIGNATURE = b"\xfeSMB"
SMB1_HEADER_SIGNATURE = b"\xffSMB"
SMB2_COMMAND_CREATE = 5
SMB2_COMMAND_WRITE = 9
PAYLOAD_FILENAME_RE = re.compile(
    r"([A-Za-z0-9 _.$@()-]{1,128}\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|msi|zip|7z|rar|scr|bin|dat))",
    flags=re.IGNORECASE,
)


def select_payload_carving_candidates(
    findings: dict[str, Any] | None,
    *,
    limits: PayloadCarvingLimits | None = None,
) -> list[PayloadCarvingCandidate]:
    resolved_limits = limits or PayloadCarvingLimits()
    findings = findings or {}
    candidates: list[PayloadCarvingCandidate] = []
    seen_keys: set[tuple[Any, ...]] = set()

    manual_candidates = (findings.get("manual_payload_deployment") or {}).get("candidates") or []
    for source_index, source in enumerate(manual_candidates):
        if not source.get("suspicious"):
            continue
        for target_index, target in enumerate(source.get("targets") or []):
            admin_markers = list(target.get("admin_share_markers") or [])
            remote_exec_markers = list(target.get("remote_exec_markers") or [])
            smb_rpc_ports = [int(port) for port in target.get("smb_rpc_ports") or [] if port]
            if not admin_markers and not remote_exec_markers and not smb_rpc_ports:
                continue
            dedupe_key = (
                "smb",
                source.get("src_ip"),
                target.get("dst_ip"),
                tuple(sorted(admin_markers)),
                tuple(sorted(remote_exec_markers)),
                tuple(sorted(smb_rpc_ports)),
            )
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)

            priority = 40
            priority += 30 if remote_exec_markers else 0
            priority += 20 if admin_markers else 0
            priority += min(10, len(smb_rpc_ports) * 2)
            priority += min(20, int(source.get("manual_drop_score", 0)) // 5)
            basis = ["manual_payload_deployment"]
            if admin_markers:
                basis.append("admin_share_markers")
            if remote_exec_markers:
                basis.append("remote_exec_markers")
            if smb_rpc_ports:
                basis.append("smb_rpc_ports")

            candidates.append(
                PayloadCarvingCandidate(
                    candidate_id=f"smb-{source_index}-{target_index}",
                    protocol="smb",
                    priority=priority,
                    basis=basis,
                    src_ip=source.get("src_ip"),
                    dst_ip=target.get("dst_ip"),
                    dst_port=445 if 445 in smb_rpc_ports else (smb_rpc_ports[0] if smb_rpc_ports else None),
                    metadata={
                        "manual_drop_score": source.get("manual_drop_score"),
                        "admin_share_markers": admin_markers,
                        "remote_exec_markers": remote_exec_markers,
                        "smb_rpc_ports": smb_rpc_ports,
                        "rdp_total_bytes": target.get("rdp_total_bytes"),
                        "sample_events": list(target.get("sample_events") or [])[:5],
                    },
                )
            )

    http_uploads = (findings.get("large_http_posts") or {}).get("uploads") or []
    for upload_index, upload in enumerate(http_uploads):
        inferred_bytes = int(upload.get("inferred_upload_bytes", 0) or 0)
        has_7z_magic = bool(upload.get("has_7z_magic"))
        mentions_temp_sh = bool(upload.get("mentions_temp_sh"))
        if inferred_bytes < resolved_limits.min_http_body_bytes and not has_7z_magic and not mentions_temp_sh:
            continue
        dedupe_key = (
            "http",
            upload.get("src_ip"),
            upload.get("dst_ip"),
            upload.get("host"),
            upload.get("path"),
            upload.get("method"),
        )
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)

        priority = 35
        priority += min(35, inferred_bytes // (1024 * 1024))
        priority += 20 if has_7z_magic else 0
        priority += 15 if mentions_temp_sh else 0

        basis = ["large_http_posts"]
        if has_7z_magic:
            basis.append("archive_magic")
        if mentions_temp_sh:
            basis.append("temp_sh_reference")

        candidates.append(
            PayloadCarvingCandidate(
                candidate_id=f"http-upload-{upload_index}",
                protocol="http",
                priority=priority,
                basis=basis,
                src_ip=upload.get("src_ip"),
                dst_ip=upload.get("dst_ip"),
                dst_port=int(upload.get("dst_port")) if upload.get("dst_port") else None,
                metadata={
                    "method": upload.get("method"),
                    "host": upload.get("host"),
                    "path": upload.get("path"),
                    "content_length": upload.get("content_length"),
                    "observed_body_bytes": upload.get("observed_body_bytes"),
                    "inferred_upload_bytes": inferred_bytes,
                    "has_7z_magic": has_7z_magic,
                    "mentions_temp_sh": mentions_temp_sh,
                },
            )
        )

    temp_sh_hits = (findings.get("temp_sh_traffic") or {}).get("hits") or []
    for hit_index, hit in enumerate(temp_sh_hits):
        indicator_type = str(hit.get("indicator_type") or "")
        if indicator_type not in {"http_body", "http_host", "http_uri"}:
            continue
        dedupe_key = (
            "http-hit",
            hit.get("src_ip"),
            hit.get("dst_ip"),
            hit.get("value"),
            indicator_type,
        )
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        candidates.append(
            PayloadCarvingCandidate(
                candidate_id=f"http-hit-{hit_index}",
                protocol="http",
                priority=30,
                basis=["temp_sh_traffic"],
                src_ip=hit.get("src_ip"),
                dst_ip=hit.get("dst_ip"),
                dst_port=int(hit.get("dst_port")) if hit.get("dst_port") else None,
                metadata={
                    "indicator_type": indicator_type,
                    "value": hit.get("value"),
                    "content_length": hit.get("content_length"),
                    "observed_body_bytes": hit.get("observed_body_bytes"),
                },
            )
        )

    candidates.sort(key=lambda item: (item.priority, item.protocol, item.candidate_id), reverse=True)
    return candidates[: resolved_limits.max_candidates_per_file]


def describe_payload_bytes(
    payload_bytes: bytes,
    *,
    artifact_id: str,
    recovered_filename: str | None = None,
) -> PayloadArtifactMetadata:
    md5_hash = hashlib.md5(payload_bytes).hexdigest()
    sha1_hash = hashlib.sha1(payload_bytes).hexdigest()
    sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
    file_magic = detect_file_magic(payload_bytes)
    mime_type = detect_mime_type(payload_bytes, recovered_filename=recovered_filename, file_magic=file_magic)
    pe_metadata = parse_pe_metadata(payload_bytes)
    return PayloadArtifactMetadata(
        artifact_id=artifact_id,
        size_bytes=len(payload_bytes),
        md5=md5_hash,
        sha1=sha1_hash,
        sha256=sha256_hash,
        file_magic=file_magic,
        mime_type=mime_type,
        recovered_filename=recovered_filename,
        pe_metadata=pe_metadata,
    )


def detect_file_magic(payload_bytes: bytes) -> str | None:
    if payload_bytes.startswith(b"MZ"):
        return "pe"
    if payload_bytes.startswith(b"\x7fELF"):
        return "elf"
    if payload_bytes.startswith(b"PK\x03\x04"):
        return "zip"
    if payload_bytes.startswith(b"\x1f\x8b"):
        return "gzip"
    if payload_bytes.startswith(b"\x37\x7a\xbc\xaf\x27\x1c"):
        return "7z"
    if payload_bytes.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if payload_bytes.startswith(b"%PDF-"):
        return "pdf"
    if payload_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if payload_bytes.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if payload_bytes.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if payload_bytes.startswith(b"#!/"):
        return "script"
    if payload_bytes[:32].lstrip().startswith((b"<html", b"<!doctype html")):
        return "html"
    return None


def detect_mime_type(
    payload_bytes: bytes,
    *,
    recovered_filename: str | None = None,
    file_magic: str | None = None,
) -> str | None:
    magic_to_mime = {
        "pe": "application/vnd.microsoft.portable-executable",
        "elf": "application/x-elf",
        "zip": "application/zip",
        "gzip": "application/gzip",
        "7z": "application/x-7z-compressed",
        "rar": "application/vnd.rar",
        "pdf": "application/pdf",
        "png": "image/png",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "script": "text/x-shellscript",
        "html": "text/html",
    }
    if file_magic and file_magic in magic_to_mime:
        return magic_to_mime[file_magic]
    if recovered_filename:
        guessed, _ = mimetypes.guess_type(recovered_filename)
        if guessed:
            return guessed
    if payload_bytes.startswith(b"{") or payload_bytes.startswith(b"["):
        return "application/json"
    if payload_bytes[:128].strip() and all(32 <= byte <= 126 or byte in {9, 10, 13} for byte in payload_bytes[:128]):
        return "text/plain"
    return None


def parse_pe_metadata(payload_bytes: bytes) -> dict[str, Any] | None:
    if len(payload_bytes) < 0x40 or not payload_bytes.startswith(b"MZ"):
        return None
    pe_offset = struct.unpack_from("<I", payload_bytes, 0x3C)[0]
    if pe_offset <= 0 or pe_offset + 0x18 >= len(payload_bytes):
        return None
    if payload_bytes[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None

    try:
        machine, number_of_sections, timestamp = struct.unpack_from("<HHI", payload_bytes, pe_offset + 4)
        size_of_optional_header = struct.unpack_from("<H", payload_bytes, pe_offset + 20)[0]
        optional_offset = pe_offset + 24
        if optional_offset + size_of_optional_header > len(payload_bytes):
            return None
        magic = struct.unpack_from("<H", payload_bytes, optional_offset)[0]
        subsystem_offset = optional_offset + (68 if magic == 0x10B else 88 if magic == 0x20B else -1)
        subsystem = None
        if subsystem_offset > optional_offset and subsystem_offset + 2 <= len(payload_bytes):
            subsystem = struct.unpack_from("<H", payload_bytes, subsystem_offset)[0]
        return {
            "machine": hex(machine),
            "number_of_sections": number_of_sections,
            "timestamp": timestamp,
            "pe_format": "pe32+" if magic == 0x20B else "pe32" if magic == 0x10B else hex(magic),
            "subsystem": subsystem,
        }
    except (struct.error, ValueError):
        return None


def build_payload_iocs(artifacts: list[PayloadArtifactMetadata]) -> list[str]:
    iocs: list[str] = []
    for artifact in artifacts:
        if artifact.recovered_filename:
            iocs.append(f"filename:{artifact.recovered_filename}")
        if artifact.sha256:
            iocs.append(f"sha256:{artifact.sha256}")
        if artifact.sha1:
            iocs.append(f"sha1:{artifact.sha1}")
        if artifact.md5:
            iocs.append(f"md5:{artifact.md5}")
        if artifact.file_magic:
            iocs.append(f"file_magic:{artifact.file_magic}")
        if artifact.mime_type:
            iocs.append(f"mime_type:{artifact.mime_type}")
    return iocs


def _find_payload_magic_offset(payload_bytes: bytes) -> int | None:
    signatures = [
        b"MZ",
        b"\x7fELF",
        b"PK\x03\x04",
        b"\x1f\x8b",
        b"\x37\x7a\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"%PDF-",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"#!/",
    ]
    offsets = [payload_bytes.find(signature) for signature in signatures]
    found = [offset for offset in offsets if offset >= 0]
    return min(found) if found else None


def _extract_filename_hints(payload_bytes: bytes) -> list[str]:
    hints: list[str] = []

    ascii_view = payload_bytes.decode("latin-1", errors="ignore").replace("\x00", "")
    hints.extend(_sanitize_filename(Path(match.replace("\\", "/")).name) for match in PAYLOAD_FILENAME_RE.findall(ascii_view))

    for raw in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", payload_bytes):
        try:
            decoded = raw.decode("utf-16le", errors="ignore")
        except Exception:
            continue
        hints.extend(_sanitize_filename(Path(match.replace("\\", "/")).name) for match in PAYLOAD_FILENAME_RE.findall(decoded))

    return list(dict.fromkeys(hints))


def _iter_smb_messages(payload: bytes) -> list[bytes]:
    messages: list[bytes] = []
    position = 0
    while position < len(payload):
        if position + 8 <= len(payload) and payload[position] == 0x00 and payload[position + 4 : position + 8] in {
            SMB2_HEADER_SIGNATURE,
            SMB1_HEADER_SIGNATURE,
        }:
            message_length = int.from_bytes(payload[position + 1 : position + 4], "big")
            end = min(len(payload), position + 4 + message_length)
            if end > position + 4:
                messages.append(payload[position + 4 : end])
            position = end
            continue
        if payload[position : position + 4] in {SMB2_HEADER_SIGNATURE, SMB1_HEADER_SIGNATURE}:
            messages.append(payload[position:])
            break
        next_positions = [
            candidate
            for candidate in (
                payload.find(SMB2_HEADER_SIGNATURE, position + 1),
                payload.find(SMB1_HEADER_SIGNATURE, position + 1),
                payload.find(b"\x00" + SMB2_HEADER_SIGNATURE, position + 1),
                payload.find(b"\x00" + SMB1_HEADER_SIGNATURE, position + 1),
            )
            if candidate >= 0
        ]
        if not next_positions:
            break
        position = min(next_positions)
    return messages


def _read_smb2_command(message: bytes) -> int | None:
    if len(message) < 64 or not message.startswith(SMB2_HEADER_SIGNATURE):
        return None
    return int.from_bytes(message[12:14], "little")


def _extract_smb2_create_name(message: bytes) -> str | None:
    command = _read_smb2_command(message)
    if command != SMB2_COMMAND_CREATE or len(message) < 120:
        return None
    name_offset = int.from_bytes(message[108:110], "little")
    name_length = int.from_bytes(message[110:112], "little")
    if name_offset <= 0 or name_length <= 0 or name_offset + name_length > len(message):
        return None
    raw_name = message[name_offset : name_offset + name_length]
    try:
        decoded = raw_name.decode("utf-16le", errors="ignore")
    except Exception:
        return None
    basename = Path(decoded.replace("\\", "/")).name
    return _sanitize_filename(basename) if basename else None


def _extract_smb2_write_chunk(message: bytes) -> dict[str, Any] | None:
    command = _read_smb2_command(message)
    if command != SMB2_COMMAND_WRITE or len(message) < 112:
        return None
    data_offset = int.from_bytes(message[66:68], "little")
    data_length = int.from_bytes(message[68:72], "little")
    if data_offset <= 0 or data_length <= 0 or data_offset + data_length > len(message):
        return None
    return {
        "file_id": message[80:96].hex(),
        "data": message[data_offset : data_offset + data_length],
    }


def _event_matches_smb_candidate(event: dict[str, Any], candidate: PayloadCarvingCandidate) -> bool:
    if event.get("src_ip") != candidate.src_ip or event.get("dst_ip") != candidate.dst_ip:
        return False
    candidate_ports = {int(port) for port in candidate.metadata.get("smb_rpc_ports") or [] if port}
    if candidate.dst_port:
        candidate_ports.add(int(candidate.dst_port))
    if not candidate_ports:
        candidate_ports = {445}
    return int(event.get("dst_port", 0) or 0) in candidate_ports


def _recover_smb_filename(
    candidate: PayloadCarvingCandidate,
    filename_hints: list[str],
    metadata: PayloadArtifactMetadata,
) -> str:
    if filename_hints:
        return _sanitize_filename(filename_hints[-1])
    return _sanitize_filename(f"{candidate.candidate_id}{_default_extension(metadata.file_magic, metadata.mime_type)}")


def _recover_smb_payloads(
    pcap_path: str,
    candidates: list[PayloadCarvingCandidate],
    *,
    artifacts_dir: str | Path | None,
    limits: PayloadCarvingLimits,
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]], int, list[str]]:
    smb_candidates = [candidate for candidate in candidates if candidate.protocol == "smb"]
    if not smb_candidates:
        return [], [], [], 0, []

    try:
        events = _iter_tcp_payloads(pcap_path)
    except Exception as exc:  # pragma: no cover - exercised via caller contract
        return [], [], [{"reason": "pcap_read_error", "error": str(exc)}], 0, [f"SMB carving could not read the PCAP: {exc}"]

    notes: list[str] = []
    carved_payloads: list[dict[str, Any]] = []
    payload_iocs: list[str] = []
    skipped_candidates: list[dict[str, Any]] = []
    recovered_bytes = 0
    total_scanned = 0

    for candidate in smb_candidates:
        filename_hints: list[str] = []
        write_chunks: list[bytes] = []
        file_ids: list[str] = []

        for event in events:
            if not _event_matches_smb_candidate(event, candidate):
                continue
            payload = bytes(event.get("payload") or b"")
            if not payload:
                continue

            remaining = limits.max_reconstructed_bytes_per_file - total_scanned
            if remaining <= 0:
                skipped_candidates.append(
                    {
                        "candidate_id": candidate.candidate_id,
                        "protocol": "smb",
                        "reason": "reconstruction_byte_cap_reached",
                    }
                )
                break
            if len(payload) > remaining:
                payload = payload[:remaining]
                skipped_candidates.append(
                    {
                        "candidate_id": candidate.candidate_id,
                        "protocol": "smb",
                        "reason": "stream_truncated_by_byte_cap",
                    }
                )
            total_scanned += len(payload)

            filename_hints.extend(_extract_filename_hints(payload))
            for message in _iter_smb_messages(payload):
                create_name = _extract_smb2_create_name(message)
                if create_name:
                    filename_hints.append(create_name)
                write_chunk = _extract_smb2_write_chunk(message)
                if not write_chunk:
                    continue
                write_chunks.append(bytes(write_chunk["data"]))
                file_ids.append(str(write_chunk["file_id"]))

        if not write_chunks:
            skipped_candidates.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "protocol": "smb",
                    "reason": "no_smb_write_payloads",
                    "src_ip": candidate.src_ip,
                    "dst_ip": candidate.dst_ip,
                    "dst_port": candidate.dst_port,
                    "admin_share_markers": list(candidate.metadata.get("admin_share_markers") or []),
                    "remote_exec_markers": list(candidate.metadata.get("remote_exec_markers") or []),
                }
            )
            continue

        candidate_bytes = b"".join(write_chunks)
        magic_offset = _find_payload_magic_offset(candidate_bytes)
        recovered_payload = candidate_bytes[magic_offset:] if magic_offset is not None else candidate_bytes
        if not recovered_payload:
            skipped_candidates.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "protocol": "smb",
                    "reason": "empty_smb_payload_after_parsing",
                }
            )
            continue

        artifact_id = f"{candidate.candidate_id}-write"
        metadata = describe_payload_bytes(recovered_payload, artifact_id=artifact_id)
        recovered_filename = _recover_smb_filename(candidate, filename_hints, metadata)
        metadata = describe_payload_bytes(
            recovered_payload,
            artifact_id=artifact_id,
            recovered_filename=recovered_filename,
        )
        saved_path = None
        if artifacts_dir:
            saved_path = _build_saved_payload_path(
                artifacts_dir,
                candidate_id=candidate.candidate_id,
                recovered_filename=recovered_filename,
            )
            saved_path.write_bytes(recovered_payload)

        recovery_status = "confirmed_artifact" if magic_offset is not None else "partial_evidence"
        artifact_record = {
            "artifact_id": metadata.artifact_id,
            "candidate_id": candidate.candidate_id,
            "protocol": "smb",
            "src_ip": candidate.src_ip,
            "dst_ip": candidate.dst_ip,
            "dst_port": candidate.dst_port,
            "candidate_basis": list(candidate.basis),
            "recovery_status": recovery_status,
            "saved_path": str(saved_path) if saved_path else None,
            "recovered_filename": metadata.recovered_filename,
            "size_bytes": metadata.size_bytes,
            "md5": metadata.md5,
            "sha1": metadata.sha1,
            "sha256": metadata.sha256,
            "file_magic": metadata.file_magic,
            "mime_type": metadata.mime_type,
            "pe_metadata": metadata.pe_metadata,
            "smb_write_chunk_count": len(write_chunks),
            "smb_file_ids": list(dict.fromkeys(file_ids)),
            "magic_offset": magic_offset,
        }
        carved_payloads.append(artifact_record)
        recovered_bytes += len(recovered_payload)
        payload_iocs.extend(build_payload_iocs([metadata]))

    if carved_payloads:
        notes.append(f"SMB carving recovered {len(carved_payloads)} payload artifact(s) from SMB2 write traffic.")
    elif total_scanned > 0:
        notes.append("SMB carving inspected suspicious SMB candidate flows but did not recover an artifact.")
    return carved_payloads, sorted(set(payload_iocs)), skipped_candidates, recovered_bytes, notes


def _summarize_smb_candidates(
    candidates: list[PayloadCarvingCandidate],
) -> list[str]:
    smb_candidates = [candidate for candidate in candidates if candidate.protocol == "smb"]
    if not smb_candidates:
        return []

    payload_iocs: list[str] = []
    for candidate in smb_candidates:
        if candidate.src_ip:
            payload_iocs.append(f"smb_source:{candidate.src_ip}")
        if candidate.dst_ip:
            payload_iocs.append(f"smb_target:{candidate.dst_ip}")
        if candidate.dst_port:
            payload_iocs.append(f"smb_port:{candidate.dst_port}")
        for marker in candidate.metadata.get("admin_share_markers") or []:
            payload_iocs.append(f"admin_share_marker:{marker}")
        for marker in candidate.metadata.get("remote_exec_markers") or []:
            payload_iocs.append(f"remote_exec_marker:{marker}")
        for port in candidate.metadata.get("smb_rpc_ports") or []:
            payload_iocs.append(f"smb_rpc_port:{port}")
    return sorted(set(payload_iocs))


def _iter_tcp_payloads(pcap_path: str) -> list[dict[str, Any]]:
    from scapy.all import IP, IPv6, Raw, TCP, PcapReader

    events: list[dict[str, Any]] = []
    with PcapReader(pcap_path) as reader:
        for packet in reader:
            if TCP not in packet or Raw not in packet:
                continue
            payload = bytes(packet[Raw].load)
            if not payload:
                continue
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            else:
                continue
            events.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": int(packet[TCP].sport),
                    "dst_port": int(packet[TCP].dport),
                    "payload": payload,
                    "timestamp": float(getattr(packet, "time", 0.0) or 0.0),
                }
            )
    return events


def _parse_http_headers(header_blob: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in header_blob.split(b"\r\n"):
        if b":" not in line:
            continue
        key, raw_value = line.split(b":", 1)
        headers[key.decode("latin-1", errors="ignore").strip().lower()] = raw_value.decode("latin-1", errors="ignore").strip()
    return headers


def _parse_chunked_body(stream: bytes, body_start: int) -> tuple[bytes, int, bool]:
    position = body_start
    chunks: list[bytes] = []
    while position < len(stream):
        line_end = stream.find(b"\r\n", position)
        if line_end == -1:
            return b"".join(chunks), len(stream) - body_start, False
        size_blob = stream[position:line_end].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_blob.decode("ascii", errors="ignore"), 16)
        except ValueError:
            return b"".join(chunks), len(stream) - body_start, False
        position = line_end + 2
        if chunk_size == 0:
            trailer_end = stream.find(b"\r\n\r\n", position)
            if trailer_end == -1:
                if position + 2 <= len(stream) and stream[position : position + 2] == b"\r\n":
                    return b"".join(chunks), position + 2 - body_start, True
                return b"".join(chunks), len(stream) - body_start, False
            return b"".join(chunks), trailer_end + 4 - body_start, True
        if position + chunk_size + 2 > len(stream):
            chunks.append(stream[position : len(stream)])
            return b"".join(chunks), len(stream) - body_start, False
        chunks.append(stream[position : position + chunk_size])
        position += chunk_size
        if stream[position : position + 2] != b"\r\n":
            return b"".join(chunks), len(stream) - body_start, False
        position += 2
    return b"".join(chunks), len(stream) - body_start, False


def _parse_http_requests(stream: bytes) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    position = 0
    while position < len(stream):
        match = HTTP_REQUEST_LINE_RE.search(stream, position)
        if not match:
            break
        start = match.start()
        line_end = stream.find(b"\r\n", start)
        header_end = stream.find(b"\r\n\r\n", line_end + 2)
        if line_end == -1 or header_end == -1:
            break
        request_line = stream[start:line_end].decode("latin-1", errors="ignore")
        parts = request_line.split()
        if len(parts) < 3:
            position = start + 1
            continue

        headers = _parse_http_headers(stream[line_end + 2 : header_end])
        body_start = header_end + 4
        content_length_raw = headers.get("content-length", "0")
        try:
            content_length = int(content_length_raw)
        except ValueError:
            content_length = 0

        body = b""
        body_complete = False
        next_position = body_start
        if content_length > 0:
            available = min(max(len(stream) - body_start, 0), content_length)
            body = stream[body_start : body_start + available]
            body_complete = available >= content_length
            next_position = body_start + available
            if body_complete:
                next_position = body_start + content_length
        elif headers.get("transfer-encoding", "").lower() == "chunked":
            body, consumed_bytes, body_complete = _parse_chunked_body(stream, body_start)
            next_position = body_start + consumed_bytes

        requests.append(
            {
                "method": parts[0],
                "path": parts[1],
                "host": headers.get("host", ""),
                "headers": headers,
                "content_length": content_length,
                "body": body,
                "body_complete": body_complete,
            }
        )
        position = max(next_position, start + 1)
    return requests


def _candidate_matches_http_request(candidate: PayloadCarvingCandidate, request: dict[str, Any]) -> bool:
    metadata = candidate.metadata or {}
    expected_method = metadata.get("method")
    expected_host = metadata.get("host")
    expected_path = metadata.get("path")
    if expected_method and request.get("method") != expected_method:
        return False
    if expected_host and request.get("host") != expected_host:
        return False
    if expected_path and request.get("path") != expected_path:
        return False

    indicator_type = metadata.get("indicator_type")
    indicator_value = str(metadata.get("value") or "").lower()
    if indicator_value:
        host = str(request.get("host") or "").lower()
        path = str(request.get("path") or "").lower()
        body = bytes(request.get("body") or b"").lower()
        if indicator_type == "http_host":
            return indicator_value in host
        if indicator_type == "http_uri":
            return indicator_value in path
        if indicator_type == "http_body":
            return indicator_value.encode("latin-1", errors="ignore") in body
    return True


def _sanitize_filename(name: str) -> str:
    collapsed = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return collapsed.strip("._") or "payload.bin"


def _filename_from_content_disposition(header_value: str | None) -> str | None:
    if not header_value:
        return None
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', header_value, flags=re.IGNORECASE)
    if not match:
        return None
    return _sanitize_filename(match.group(1))


def _default_extension(file_magic: str | None, mime_type: str | None) -> str:
    by_magic = {
        "pe": ".exe",
        "elf": ".elf",
        "zip": ".zip",
        "gzip": ".gz",
        "7z": ".7z",
        "rar": ".rar",
        "pdf": ".pdf",
        "png": ".png",
        "jpeg": ".jpg",
        "gif": ".gif",
        "script": ".sh",
        "html": ".html",
    }
    if file_magic in by_magic:
        return by_magic[file_magic]
    if mime_type == "application/json":
        return ".json"
    if mime_type and mime_type.startswith("text/"):
        return ".txt"
    return ".bin"


def _recover_http_filename(
    candidate: PayloadCarvingCandidate,
    request: dict[str, Any],
    metadata: PayloadArtifactMetadata,
) -> str:
    headers = request.get("headers") or {}
    from_header = _filename_from_content_disposition(headers.get("content-disposition"))
    if from_header:
        return from_header

    parsed_path = urlparse(str(request.get("path") or "")).path
    basename = Path(parsed_path).name
    if basename and basename not in {".", ".."}:
        return _sanitize_filename(basename)

    return _sanitize_filename(f"{candidate.candidate_id}{_default_extension(metadata.file_magic, metadata.mime_type)}")


def _build_saved_payload_path(
    artifacts_dir: str | Path,
    *,
    candidate_id: str,
    recovered_filename: str,
) -> Path:
    carved_dir = Path(artifacts_dir).expanduser().resolve() / "carved-artifacts"
    carved_dir.mkdir(parents=True, exist_ok=True)
    return carved_dir / _sanitize_filename(f"{candidate_id}_{recovered_filename}")


def _normalize_saved_payloads(
    payloads: list[dict[str, Any]],
    *,
    artifacts_root: Path,
) -> list[dict[str, Any]]:
    normalized_payloads: list[dict[str, Any]] = []
    for payload in payloads:
        payload_copy = dict(payload)
        saved_path = payload_copy.get("saved_path")
        if saved_path:
            try:
                payload_copy["saved_path"] = str(Path(saved_path).resolve().relative_to(artifacts_root))
            except ValueError:
                payload_copy["saved_path"] = Path(saved_path).name
        normalized_payloads.append(payload_copy)
    return normalized_payloads


def _load_http_candidate_streams(
    pcap_path: str,
    candidates: list[PayloadCarvingCandidate],
    *,
    limits: PayloadCarvingLimits,
) -> tuple[dict[tuple[str, str, int | None], bytes], int, list[dict[str, Any]]]:
    flow_keys = {
        (candidate.src_ip, candidate.dst_ip, candidate.dst_port)
        for candidate in candidates
        if candidate.protocol == "http" and candidate.src_ip and candidate.dst_ip
    }
    if not flow_keys:
        return {}, 0, []

    streams = {key: bytearray() for key in flow_keys}
    skipped_candidates: list[dict[str, Any]] = []
    total_bytes = 0
    for event in _iter_tcp_payloads(pcap_path):
        flow_key = (event["src_ip"], event["dst_ip"], event["dst_port"])
        if flow_key not in streams:
            continue
        remaining = limits.max_reconstructed_bytes_per_file - total_bytes
        if remaining <= 0:
            skipped_candidates.append(
                {
                    "reason": "reconstruction_byte_cap_reached",
                    "candidate_id": None,
                }
            )
            break
        payload = bytes(event["payload"])
        if len(payload) > remaining:
            streams[flow_key].extend(payload[:remaining])
            total_bytes += remaining
            skipped_candidates.append(
                {
                    "reason": "stream_truncated_by_byte_cap",
                    "candidate_id": None,
                    "src_ip": event["src_ip"],
                    "dst_ip": event["dst_ip"],
                    "dst_port": event["dst_port"],
                }
            )
            break
        streams[flow_key].extend(payload)
        total_bytes += len(payload)
    return {key: bytes(value) for key, value in streams.items()}, total_bytes, skipped_candidates


def _recover_http_payloads(
    pcap_path: str,
    candidates: list[PayloadCarvingCandidate],
    *,
    artifacts_dir: str | Path | None,
    limits: PayloadCarvingLimits,
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]], int, list[str]]:
    http_candidates = [candidate for candidate in candidates if candidate.protocol == "http"]
    if not http_candidates:
        return [], [], [], 0, []

    notes: list[str] = []
    try:
        streams, bytes_scanned, skipped_candidates = _load_http_candidate_streams(
            pcap_path,
            http_candidates,
            limits=limits,
        )
    except Exception as exc:  # pragma: no cover - exercised via caller contract
        return [], [], [{"reason": "pcap_read_error", "error": str(exc)}], 0, [f"HTTP carving could not read the PCAP: {exc}"]

    parsed_requests_by_flow: dict[tuple[str, str, int | None], list[dict[str, Any]]] = {
        flow_key: _parse_http_requests(stream)
        for flow_key, stream in streams.items()
        if stream
    }
    used_request_ids: set[tuple[tuple[str, str, int | None], int]] = set()
    carved_payloads: list[dict[str, Any]] = []
    payload_iocs: list[str] = []
    recovered_bytes = 0

    for candidate in http_candidates:
        flow_key = (candidate.src_ip, candidate.dst_ip, candidate.dst_port)
        requests = parsed_requests_by_flow.get(flow_key) or []
        if not requests:
            skipped_candidates.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "protocol": candidate.protocol,
                    "reason": "no_http_requests_reconstructed",
                }
            )
            continue

        matched_index = None
        matched_request = None
        for request_index, request in enumerate(requests):
            request_key = (flow_key, request_index)
            if request_key in used_request_ids:
                continue
            if _candidate_matches_http_request(candidate, request):
                matched_index = request_index
                matched_request = request
                break

        if matched_index is None or matched_request is None:
            skipped_candidates.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "protocol": candidate.protocol,
                    "reason": "no_matching_http_candidate",
                }
            )
            continue

        used_request_ids.add((flow_key, matched_index))
        body = bytes(matched_request.get("body") or b"")
        if not body:
            skipped_candidates.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "protocol": candidate.protocol,
                    "reason": "http_body_empty",
                }
            )
            continue

        is_low_signal = (
            len(body) < limits.min_http_body_bytes
            and not candidate.metadata.get("has_7z_magic")
            and not candidate.metadata.get("mentions_temp_sh")
            and "temp_sh_traffic" not in candidate.basis
        )
        if is_low_signal and not matched_request.get("body_complete"):
            skipped_candidates.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "protocol": candidate.protocol,
                    "reason": "tiny_low_signal_fragment",
                    "size_bytes": len(body),
                }
            )
            continue

        artifact_id = f"{candidate.candidate_id}-body"
        metadata = describe_payload_bytes(body, artifact_id=artifact_id)
        recovered_filename = _recover_http_filename(candidate, matched_request, metadata)
        metadata = describe_payload_bytes(
            body,
            artifact_id=artifact_id,
            recovered_filename=recovered_filename,
        )
        saved_path = None
        if artifacts_dir:
            saved_path = _build_saved_payload_path(
                artifacts_dir,
                candidate_id=candidate.candidate_id,
                recovered_filename=recovered_filename,
            )
            saved_path.write_bytes(body)

        recovery_status = "confirmed_artifact" if matched_request.get("body_complete") else "partial_evidence"
        artifact_record = {
            "artifact_id": metadata.artifact_id,
            "candidate_id": candidate.candidate_id,
            "protocol": "http",
            "src_ip": candidate.src_ip,
            "dst_ip": candidate.dst_ip,
            "dst_port": candidate.dst_port,
            "candidate_basis": list(candidate.basis),
            "recovery_status": recovery_status,
            "saved_path": str(saved_path) if saved_path else None,
            "recovered_filename": metadata.recovered_filename,
            "size_bytes": metadata.size_bytes,
            "md5": metadata.md5,
            "sha1": metadata.sha1,
            "sha256": metadata.sha256,
            "file_magic": metadata.file_magic,
            "mime_type": metadata.mime_type,
            "pe_metadata": metadata.pe_metadata,
            "http_method": matched_request.get("method"),
            "http_host": matched_request.get("host"),
            "http_path": matched_request.get("path"),
            "body_complete": bool(matched_request.get("body_complete")),
            "content_length": int(matched_request.get("content_length", 0) or 0),
        }
        carved_payloads.append(artifact_record)
        recovered_bytes += len(body)
        payload_iocs.extend(build_payload_iocs([metadata]))
        if matched_request.get("host"):
            payload_iocs.append(f"http_host:{matched_request['host']}")
        if matched_request.get("path"):
            payload_iocs.append(f"http_path:{matched_request['path']}")

    if carved_payloads:
        notes.append(f"HTTP carving recovered {len(carved_payloads)} payload artifact(s).")
    elif bytes_scanned > 0:
        notes.append("HTTP carving inspected suspicious candidate flows but did not recover an artifact.")
    return carved_payloads, sorted(set(payload_iocs)), skipped_candidates, recovered_bytes, notes


def run_payload_carving(
    pcap_path: str,
    findings: dict[str, Any] | None,
    *,
    artifacts_dir: str | Path | None = None,
    limits: PayloadCarvingLimits | None = None,
) -> dict[str, Any]:
    resolved_limits = limits or PayloadCarvingLimits()
    candidates = select_payload_carving_candidates(findings, limits=resolved_limits)
    carved_payloads: list[dict[str, Any]] = []
    payload_iocs: list[str] = []
    skipped_candidates: list[dict[str, Any]] = []
    bytes_reconstructed = 0
    notes: list[str] = []
    smb_iocs = _summarize_smb_candidates(candidates)
    payload_iocs.extend(smb_iocs)

    if candidates:
        (
            smb_payloads,
            smb_payload_iocs,
            smb_skipped_candidates,
            smb_recovered_bytes,
            smb_notes,
        ) = _recover_smb_payloads(
            pcap_path,
            candidates,
            artifacts_dir=artifacts_dir,
            limits=resolved_limits,
        )
        carved_payloads.extend(smb_payloads)
        payload_iocs.extend(smb_payload_iocs)
        skipped_candidates.extend(smb_skipped_candidates)
        bytes_reconstructed += smb_recovered_bytes
        notes.extend(smb_notes)

        (
            http_payloads,
            http_payload_iocs,
            http_skipped_candidates,
            http_recovered_bytes,
            recovery_notes,
        ) = _recover_http_payloads(
            pcap_path,
            candidates,
            artifacts_dir=artifacts_dir,
            limits=resolved_limits,
        )
        carved_payloads.extend(http_payloads)
        payload_iocs.extend(http_payload_iocs)
        skipped_candidates.extend(http_skipped_candidates)
        bytes_reconstructed += http_recovered_bytes
        notes.extend(recovery_notes)

    confirmed_count = sum(1 for artifact in carved_payloads if artifact.get("recovery_status") == "confirmed_artifact")
    partial_count = sum(
        1 for artifact in carved_payloads if artifact.get("recovery_status") in {"partial_evidence", "hash_only"}
    )
    if confirmed_count:
        status = "confirmed_artifact"
        confidence = 0.95
    elif partial_count:
        status = "partial_evidence"
        confidence = 0.7
    elif candidates:
        status = "heuristic_only"
        confidence = 0.35
    else:
        status = "no_candidates"
        confidence = 0.0

    if not notes:
        if status == "heuristic_only":
            notes.append("Suspicious payload-deployment candidates were identified, but no artifact was recovered.")
        elif status == "no_candidates":
            notes.append("No suspicious payload-deployment candidates met the carving gate.")

    result = {
        "status": status,
        "pcap_path": str(Path(pcap_path).resolve()),
        "artifacts_dir": str(Path(artifacts_dir).resolve()) if artifacts_dir else None,
        "limits": asdict(resolved_limits),
        "candidate_count": len(candidates),
        "selected_candidates": [candidate.to_dict() for candidate in candidates],
        "carved_payloads": carved_payloads,
        "payload_iocs": sorted(set(payload_iocs)),
        "payload_deployment_confidence": confidence,
        "bytes_reconstructed": bytes_reconstructed,
        "manifest_path": None,
        "skipped_candidates": skipped_candidates,
        "notes": notes,
    }
    if artifacts_dir:
        manifest_path = persist_payload_carving_artifacts(result, artifacts_dir=artifacts_dir)
        result["manifest_path"] = manifest_path
    return result


def persist_payload_carving_artifacts(
    result: dict[str, Any],
    *,
    artifacts_dir: str | Path,
) -> str:
    artifacts_root = Path(artifacts_dir).expanduser().resolve()
    carved_dir = artifacts_root / "carved-artifacts"
    carved_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = artifacts_root / "carved_manifest.json"

    normalized_payloads = _normalize_saved_payloads(
        list(result.get("carved_payloads") or []),
        artifacts_root=artifacts_root,
    )
    result["carved_payloads"] = normalized_payloads

    manifest = {
        "status": result.get("status"),
        "pcap_path": result.get("pcap_path"),
        "carved_artifacts_dir": str(carved_dir.relative_to(artifacts_root)),
        "limits": result.get("limits") or {},
        "candidate_count": int(result.get("candidate_count", 0) or 0),
        "selected_candidates": list(result.get("selected_candidates") or []),
        "carved_payload_count": len(normalized_payloads),
        "carved_payloads": normalized_payloads,
        "payload_iocs": list(result.get("payload_iocs") or []),
        "payload_deployment_confidence": float(result.get("payload_deployment_confidence", 0.0) or 0.0),
        "bytes_reconstructed": int(result.get("bytes_reconstructed", 0) or 0),
        "skipped_candidates": list(result.get("skipped_candidates") or []),
        "notes": list(result.get("notes") or []),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return str(manifest_path.relative_to(artifacts_root))


__all__ = [
    "PayloadArtifactMetadata",
    "PayloadCarvingCandidate",
    "PayloadCarvingLimits",
    "build_payload_iocs",
    "describe_payload_bytes",
    "detect_file_magic",
    "detect_mime_type",
    "parse_pe_metadata",
    "persist_payload_carving_artifacts",
    "run_payload_carving",
    "select_payload_carving_candidates",
]
