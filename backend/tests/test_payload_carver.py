from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from payload_carver import (  # noqa: E402
    PayloadCarvingLimits,
    describe_payload_bytes,
    persist_payload_carving_artifacts,
    run_payload_carving,
    select_payload_carving_candidates,
)


def _wrap_netbios(message: bytes) -> bytes:
    return b"\x00" + len(message).to_bytes(3, "big") + message


def _build_smb2_header(command: int) -> bytearray:
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = int(command).to_bytes(2, "little")
    return header


def _build_smb2_create_request(path: str) -> bytes:
    header = _build_smb2_header(5)
    path_bytes = path.encode("utf-16le")
    body = bytearray(56)
    body[0:2] = (57).to_bytes(2, "little")
    body[44:46] = (120).to_bytes(2, "little")
    body[46:48] = len(path_bytes).to_bytes(2, "little")
    return _wrap_netbios(bytes(header + body + path_bytes))


def _build_smb2_write_request(data: bytes, *, file_id: bytes | None = None) -> bytes:
    header = _build_smb2_header(9)
    body = bytearray(48)
    body[0:2] = (49).to_bytes(2, "little")
    body[2:4] = (112).to_bytes(2, "little")
    body[4:8] = len(data).to_bytes(4, "little")
    body[16:32] = file_id or (b"\x01" * 16)
    return _wrap_netbios(bytes(header + body + data))


class PayloadCarverTests(unittest.TestCase):
    def test_select_candidates_from_smb_and_http_signals(self) -> None:
        findings = {
            "manual_payload_deployment": {
                "candidates": [
                    {
                        "suspicious": True,
                        "src_ip": "10.0.0.5",
                        "manual_drop_score": 72,
                        "targets": [
                            {
                                "dst_ip": "10.0.0.10",
                                "admin_share_markers": ["admin$"],
                                "remote_exec_markers": ["psexec"],
                                "smb_rpc_ports": [445],
                                "rdp_total_bytes": 4096,
                                "sample_events": [{"timestamp": 1.0}],
                            }
                        ],
                    }
                ]
            },
            "large_http_posts": {
                "uploads": [
                    {
                        "src_ip": "10.0.0.5",
                        "dst_ip": "1.2.3.4",
                        "dst_port": 80,
                        "host": "evil.example",
                        "path": "/upload",
                        "method": "POST",
                        "content_length": 9000,
                        "observed_body_bytes": 8192,
                        "inferred_upload_bytes": 9000,
                        "has_7z_magic": True,
                        "mentions_temp_sh": False,
                    }
                ]
            },
            "temp_sh_traffic": {
                "hits": [
                    {
                        "src_ip": "10.0.0.5",
                        "dst_ip": "1.2.3.4",
                        "dst_port": 80,
                        "indicator_type": "http_body",
                        "value": "temp.sh",
                    }
                ]
            },
        }

        candidates = select_payload_carving_candidates(findings)

        self.assertEqual(len(candidates), 3)
        self.assertEqual([candidate.protocol for candidate in candidates], ["smb", "http", "http"])
        self.assertEqual(candidates[0].src_ip, "10.0.0.5")
        self.assertEqual(candidates[0].dst_ip, "10.0.0.10")
        self.assertIn("manual_payload_deployment", candidates[0].basis)

    def test_select_candidates_respects_max_candidates(self) -> None:
        findings = {
            "large_http_posts": {
                "uploads": [
                    {
                        "src_ip": "10.0.0.5",
                        "dst_ip": f"1.2.3.{index}",
                        "dst_port": 80,
                        "host": "evil.example",
                        "path": f"/upload/{index}",
                        "method": "POST",
                        "content_length": 9000 + index,
                        "observed_body_bytes": 8192,
                        "inferred_upload_bytes": 9000 + index,
                        "has_7z_magic": False,
                        "mentions_temp_sh": False,
                    }
                    for index in range(10)
                ]
            }
        }

        candidates = select_payload_carving_candidates(
            findings,
            limits=PayloadCarvingLimits(max_candidates_per_file=4),
        )

        self.assertEqual(len(candidates), 4)

    def test_describe_payload_bytes_reports_hashes_and_magic(self) -> None:
        metadata = describe_payload_bytes(
            b"MZ" + (b"\x00" * 126),
            artifact_id="artifact-1",
            recovered_filename="sample.exe",
        )

        self.assertEqual(metadata.file_magic, "pe")
        self.assertEqual(metadata.mime_type, "application/vnd.microsoft.portable-executable")
        self.assertEqual(len(metadata.md5), 32)
        self.assertEqual(len(metadata.sha1), 40)
        self.assertEqual(len(metadata.sha256), 64)

    def test_run_payload_carving_returns_stable_contract(self) -> None:
        findings = {
            "temp_sh_traffic": {
                "hits": [
                    {
                        "src_ip": "10.0.0.5",
                        "dst_ip": "1.2.3.4",
                        "dst_port": 80,
                        "indicator_type": "http_body",
                        "value": "temp.sh",
                    }
                ]
            }
        }

        result = run_payload_carving("backend/src/payload_carver.py", findings)

        self.assertEqual(result["status"], "heuristic_only")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["carved_payloads"], [])
        self.assertEqual(result["payload_iocs"], [])
        self.assertEqual(result["payload_deployment_confidence"], 0.35)
        self.assertTrue(result["notes"])

    def test_run_payload_carving_keeps_smb_candidates_as_heuristic_evidence(self) -> None:
        findings = {
            "manual_payload_deployment": {
                "candidates": [
                    {
                        "suspicious": True,
                        "src_ip": "10.0.0.5",
                        "manual_drop_score": 72,
                        "targets": [
                            {
                                "dst_ip": "10.0.0.10",
                                "admin_share_markers": ["admin$", "c$"],
                                "remote_exec_markers": ["psexec"],
                                "smb_rpc_ports": [445, 135],
                                "rdp_total_bytes": 4096,
                                "sample_events": [{"timestamp": 1.0}],
                            }
                        ],
                    }
                ]
            }
        }

        with patch("payload_carver._iter_tcp_payloads", return_value=[]):
            result = run_payload_carving("sample.pcap", findings)

        self.assertEqual(result["status"], "heuristic_only")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["carved_payloads"], [])
        self.assertIn("smb_source:10.0.0.5", result["payload_iocs"])
        self.assertIn("smb_target:10.0.0.10", result["payload_iocs"])
        self.assertIn("admin_share_marker:admin$", result["payload_iocs"])
        self.assertIn("remote_exec_marker:psexec", result["payload_iocs"])
        self.assertEqual(result["payload_deployment_confidence"], 0.35)
        self.assertEqual(len(result["skipped_candidates"]), 1)
        self.assertEqual(result["skipped_candidates"][0]["reason"], "no_smb_write_payloads")
        self.assertTrue(any("no artifact was recovered" in note.lower() for note in result["notes"]))

    def test_run_payload_carving_recovers_confirmed_smb_artifact(self) -> None:
        findings = {
            "manual_payload_deployment": {
                "candidates": [
                    {
                        "suspicious": True,
                        "src_ip": "10.0.0.5",
                        "manual_drop_score": 72,
                        "targets": [
                            {
                                "dst_ip": "10.0.0.10",
                                "admin_share_markers": ["admin$"],
                                "remote_exec_markers": ["psexec"],
                                "smb_rpc_ports": [445, 135],
                                "rdp_total_bytes": 4096,
                                "sample_events": [{"timestamp": 1.0}],
                            }
                        ],
                    }
                ]
            }
        }
        file_id = b"\x01" * 16
        events = [
            {
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "src_port": 50000,
                "dst_port": 445,
                "payload": _build_smb2_create_request(r"\\10.0.0.10\ADMIN$\Temp\dropper.exe"),
                "timestamp": 1.0,
            },
            {
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "src_port": 50000,
                "dst_port": 445,
                "payload": _build_smb2_write_request(b"MZpay", file_id=file_id),
                "timestamp": 1.1,
            },
            {
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "src_port": 50000,
                "dst_port": 445,
                "payload": _build_smb2_write_request(b"loadbytes", file_id=file_id),
                "timestamp": 1.2,
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "payload_carver._iter_tcp_payloads",
            return_value=events,
        ):
            result = run_payload_carving("sample.pcap", findings, artifacts_dir=temp_dir)

            self.assertEqual(result["status"], "confirmed_artifact")
            self.assertEqual(result["candidate_count"], 1)
            self.assertEqual(len(result["carved_payloads"]), 1)
            artifact = result["carved_payloads"][0]
            self.assertEqual(artifact["protocol"], "smb")
            self.assertEqual(artifact["recovery_status"], "confirmed_artifact")
            self.assertEqual(artifact["recovered_filename"], "dropper.exe")
            self.assertEqual(artifact["file_magic"], "pe")
            self.assertEqual(artifact["smb_write_chunk_count"], 2)
            self.assertEqual(len(artifact["smb_file_ids"]), 1)
            self.assertEqual(result["bytes_reconstructed"], len(b"MZpayloadbytes"))
            self.assertTrue(any(ioc.startswith("sha256:") for ioc in result["payload_iocs"]))
            self.assertTrue(any("SMB carving recovered" in note for note in result["notes"]))

            saved_path = Path(temp_dir) / artifact["saved_path"]
            self.assertTrue(saved_path.exists())
            self.assertEqual(saved_path.read_bytes(), b"MZpayloadbytes")

    def test_run_payload_carving_recovers_confirmed_http_artifact(self) -> None:
        findings = {
            "large_http_posts": {
                "uploads": [
                    {
                        "src_ip": "10.0.0.5",
                        "dst_ip": "1.2.3.4",
                        "dst_port": 80,
                        "host": "evil.example",
                        "path": "/dropper.exe",
                        "method": "POST",
                        "content_length": 14,
                        "observed_body_bytes": 14,
                        "inferred_upload_bytes": 14,
                        "has_7z_magic": False,
                        "mentions_temp_sh": False,
                    }
                ]
            }
        }
        http_payload = (
            b"POST /dropper.exe HTTP/1.1\r\n"
            b"Host: evil.example\r\n"
            b"Content-Length: 14\r\n"
            b"\r\n"
            b"MZpayloadbytes"
        )

        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "payload_carver._iter_tcp_payloads",
            return_value=[
                {
                    "src_ip": "10.0.0.5",
                    "dst_ip": "1.2.3.4",
                    "src_port": 41000,
                    "dst_port": 80,
                    "payload": http_payload,
                    "timestamp": 1.0,
                }
            ],
        ):
            result = run_payload_carving(
                "sample.pcap",
                findings,
                artifacts_dir=temp_dir,
                limits=PayloadCarvingLimits(min_http_body_bytes=8),
            )

            self.assertEqual(result["status"], "confirmed_artifact")
            self.assertEqual(result["candidate_count"], 1)
            self.assertEqual(len(result["carved_payloads"]), 1)
            artifact = result["carved_payloads"][0]
            self.assertEqual(artifact["recovery_status"], "confirmed_artifact")
            self.assertEqual(artifact["file_magic"], "pe")
            self.assertEqual(artifact["mime_type"], "application/vnd.microsoft.portable-executable")
            self.assertEqual(artifact["recovered_filename"], "dropper.exe")
            self.assertTrue(artifact["saved_path"].endswith(".exe"))
            self.assertTrue(any(ioc.startswith("sha256:") for ioc in result["payload_iocs"]))
            self.assertEqual(result["payload_deployment_confidence"], 0.95)
            self.assertEqual(result["bytes_reconstructed"], len(b"MZpayloadbytes"))

            saved_path = Path(temp_dir) / artifact["saved_path"]
            self.assertTrue(saved_path.exists())
            self.assertEqual(saved_path.read_bytes(), b"MZpayloadbytes")

    def test_run_payload_carving_recovers_partial_http_artifact(self) -> None:
        findings = {
            "temp_sh_traffic": {
                "hits": [
                    {
                        "src_ip": "10.0.0.5",
                        "dst_ip": "1.2.3.4",
                        "dst_port": 80,
                        "indicator_type": "http_body",
                        "value": "temp.sh",
                    }
                ]
            }
        }
        http_payload = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: temp.sh\r\n"
            b"Content-Length: 32\r\n"
            b"\r\n"
            b"temp.sh-partial"
        )

        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "payload_carver._iter_tcp_payloads",
            return_value=[
                {
                    "src_ip": "10.0.0.5",
                    "dst_ip": "1.2.3.4",
                    "src_port": 41000,
                    "dst_port": 80,
                    "payload": http_payload,
                    "timestamp": 1.0,
                }
            ],
        ):
            result = run_payload_carving("sample.pcap", findings, artifacts_dir=temp_dir)

            self.assertEqual(result["status"], "partial_evidence")
            self.assertEqual(len(result["carved_payloads"]), 1)
            artifact = result["carved_payloads"][0]
            self.assertEqual(artifact["recovery_status"], "partial_evidence")
            self.assertFalse(artifact["body_complete"])
            self.assertEqual(result["payload_deployment_confidence"], 0.7)
            self.assertEqual(result["bytes_reconstructed"], len(b"temp.sh-partial"))
            self.assertTrue((Path(temp_dir) / artifact["saved_path"]).exists())

    def test_run_payload_carving_persists_manifest_and_directory(self) -> None:
        findings = {
            "temp_sh_traffic": {
                "hits": [
                    {
                        "src_ip": "10.0.0.5",
                        "dst_ip": "1.2.3.4",
                        "dst_port": 80,
                        "indicator_type": "http_body",
                        "value": "temp.sh",
                    }
                ]
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_payload_carving(
                "backend/src/payload_carver.py",
                findings,
                artifacts_dir=temp_dir,
            )

            manifest_path = Path(temp_dir) / "carved_manifest.json"
            carved_dir = Path(temp_dir) / "carved-artifacts"

            self.assertTrue(manifest_path.exists())
            self.assertTrue(carved_dir.is_dir())
            self.assertEqual(result["manifest_path"], "carved_manifest.json")

            manifest = manifest_path.read_text(encoding="utf-8")
            self.assertIn("\"carved_artifacts_dir\": \"carved-artifacts\"", manifest)
            self.assertIn("\"candidate_count\": 1", manifest)

    def test_persist_payload_carving_artifacts_normalizes_saved_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts_root = Path(temp_dir)
            saved_payload = artifacts_root / "carved-artifacts" / "sample.bin"
            saved_payload.parent.mkdir(parents=True, exist_ok=True)
            saved_payload.write_bytes(b"abc")

            manifest_relative = persist_payload_carving_artifacts(
                {
                    "status": "partial_evidence",
                    "pcap_path": "/tmp/sample.pcap",
                    "limits": {},
                    "candidate_count": 1,
                    "selected_candidates": [{"candidate_id": "http-0"}],
                    "carved_payloads": [
                        {
                            "artifact_id": "artifact-1",
                            "saved_path": str(saved_payload),
                        }
                    ],
                    "payload_iocs": ["sha256:abc123"],
                    "payload_deployment_confidence": 0.6,
                    "bytes_reconstructed": 3,
                    "notes": [],
                },
                artifacts_dir=artifacts_root,
            )

            self.assertEqual(manifest_relative, "carved_manifest.json")
            manifest = (artifacts_root / manifest_relative).read_text(encoding="utf-8")
            self.assertIn("carved-artifacts/sample.bin", manifest)


if __name__ == "__main__":
    unittest.main()
