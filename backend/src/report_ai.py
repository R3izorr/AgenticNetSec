from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import os
import sys
import time
from pathlib import Path
from textwrap import dedent
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "backend" / "config"

config_path = str(CONFIG_DIR)
if config_path not in sys.path:
    sys.path.insert(0, config_path)

from flow_analysis import build_attack_flow

DEFAULT_RESULTS_FILE = PROJECT_ROOT / "outputs" / "scan_results.jsonl"
DEFAULT_AGGREGATE_FILE = PROJECT_ROOT / "outputs" / "aggregate_summary.json"
DEFAULT_REPORT_FILE = PROJECT_ROOT / "outputs" / "incident_report.md"

try:
    import local_settings as _local_settings
except ModuleNotFoundError:
    _local_settings = None
except Exception as exc:
    print(f"Failed to import local_settings.py: {exc}", file=sys.stderr)
    _local_settings = None


SYSTEM_PROMPT = dedent(
    """
    You are a senior network forensic analyst producing an incident report from structured PCAP findings.
    Stay grounded in the provided evidence.
    If evidence is heuristic or incomplete, say so explicitly.
    Use the following report sections:
    1. Initial Access
    2. Lateral Movement & Discovery
    3. Exfiltration
    4. Payload Deployment
    5. Confidence / Gaps
    """
).strip()


@dataclass
class ReportGenerationResult:
    text: str
    provider: str
    model: str
    llm_tokens_in: int = 0
    llm_tokens_out: int = 0
    fallback_used: bool = False
    api_attempted: bool = False
    failure_reason: str | None = None


REPORT_SECTIONS = [
    ("Initial Access", "initial_access"),
    ("Lateral Movement & Discovery", "lateral_movement_discovery"),
    ("Exfiltration", "exfiltration"),
    ("Payload Deployment", "payload_deployment"),
    ("Confidence / Gaps", "confidence_gaps"),
]


def _take(items: list[Any] | None, limit: int) -> list[Any]:
    return list(items or [])[:limit]


def _compact_patient_zero(candidate: dict[str, Any] | None) -> dict[str, Any] | None:
    if not candidate:
        return None
    return {
        "internal_ip": candidate.get("internal_ip"),
        "external_ip": candidate.get("external_ip"),
        "confidence_score": candidate.get("confidence_score"),
        "rdp_packets": candidate.get("rdp_packets"),
        "handshake_complete": candidate.get("handshake_complete"),
        "post_login_unique_internal_targets": candidate.get("post_login_unique_internal_targets"),
        "post_login_follow_on_seconds": candidate.get("post_login_follow_on_seconds"),
        "sample_events": _take(candidate.get("sample_events"), 3),
    }


def _compact_flow_hypothesis(flow: dict[str, Any] | None) -> dict[str, Any] | None:
    if not flow:
        return None
    stages = []
    for stage in _take(flow.get("stages"), 8):
        stages.append(
            {
                "stage": stage.get("stage"),
                "supported": stage.get("supported"),
                "weakly_supported": stage.get("weakly_supported"),
                "confidence": stage.get("confidence"),
                "first_seen": stage.get("first_seen"),
                "evidence_summary": _take(stage.get("evidence_summary"), 3),
            }
        )
    return {
        "focus_host": flow.get("focus_host"),
        "strongest_external_ip": flow.get("strongest_external_ip"),
        "likely_path": flow.get("likely_path"),
        "summary": flow.get("summary"),
        "stages": stages,
    }


def _field_guide() -> str:
    return dedent(
        """
        Field guide:
        - patient_zero_candidate: strongest external-to-internal remote access hypothesis.
        - suspicious_external_port_scanners: external reconnaissance evidence, not confirmed access.
        - suspicious_smb_rpc_scanners: noisy internal SMB/RPC discovery.
        - possible_dcerpc_account_changes: admin/account/group activity indicators, still heuristic.
        - possible_outbound_exfil_flows: suspicious outbound bulk transfer candidates.
        - manual_payload_deployment_candidates: correlated internal RDP + SMB/DCERPC/admin-share deployment evidence.
        - carved_payloads: recovered payload artifacts. Empty means no artifact has been recovered yet.
        - payload_carving_status: overall carving outcome such as heuristic_only, partial_evidence, hash_only, or confirmed_artifact.
        - payload_iocs: hashes, filenames, or file-type indicators derived from carving.
        - payload_deployment_confidence: normalized confidence for Requirement D evidence.
        - ai_tshark_review: targeted sandbox tshark follow-up generated after the initial AI campaign summary to confirm or expand weak sections.
        - suspected_attack_flow: stage-by-stage hypothesis map. Treat weakly_supported stages as hints, not proof.
        """
    ).strip()


def _payload_artifacts_by_status(payload_carving: dict[str, Any] | None, *statuses: str) -> list[dict[str, Any]]:
    expected = set(statuses)
    payload_carving = payload_carving or {}
    return [
        item
        for item in (payload_carving.get("carved_payloads") or [])
        if item.get("recovery_status") in expected
    ]


def _format_payload_artifact_summary(artifacts: list[dict[str, Any]], limit: int = 3) -> str:
    summaries: list[str] = []
    for artifact in artifacts[:limit]:
        label = artifact.get("recovered_filename") or artifact.get("artifact_id") or "recovered artifact"
        parts = [str(label)]
        if artifact.get("file_magic"):
            parts.append(f"type={artifact['file_magic']}")
        if artifact.get("sha256"):
            parts.append(f"sha256={str(artifact['sha256'])[:12]}")
        summaries.append(" ".join(parts))
    return ", ".join(summaries)


def _format_single_payload_deployment_section(findings: dict[str, Any]) -> str:
    payload_carving = findings.get("payload_carving") or {}
    manual_drop = [item for item in findings.get("manual_payload_deployment", {}).get("candidates", []) if item.get("suspicious")][:3]
    spreaders = [item for item in findings.get("rdp_payload_deployment", {}).get("spreaders", []) if item.get("suspicious")][:3]
    status = payload_carving.get("status")
    confidence = payload_carving.get("payload_deployment_confidence")
    confirmed_artifacts = _payload_artifacts_by_status(payload_carving, "confirmed_artifact")
    partial_artifacts = _payload_artifacts_by_status(payload_carving, "partial_evidence", "hash_only")
    payload_iocs = list(payload_carving.get("payload_iocs") or [])

    if confirmed_artifacts:
        artifact_summary = _format_payload_artifact_summary(confirmed_artifacts)
        return (
            "Recovered payload artifacts confirm transferred payload evidence. "
            + artifact_summary
            + (f". Confidence={confidence:.2f}." if isinstance(confidence, (int, float)) else ".")
        )

    if partial_artifacts or status in {"partial_evidence", "hash_only"}:
        artifact_summary = _format_payload_artifact_summary(partial_artifacts)
        text = "Partial or hash-only payload evidence was recovered, but full artifact reconstruction remains incomplete."
        if artifact_summary:
            text += " Recovered material: " + artifact_summary + "."
        if payload_iocs:
            text += " Payload IOCs: " + ", ".join(payload_iocs[:4]) + "."
        if isinstance(confidence, (int, float)):
            text += f" Confidence={confidence:.2f}."
        return text

    if manual_drop:
        return (
            "Heuristic deployment evidence is present through correlated RDP plus SMB/DCERPC admin-share activity from "
            + ", ".join(
                f"{item['src_ip']} to {item['unique_targets']} hosts "
                f"(admin_share_targets={item['targets_with_admin_share_markers']}, remote_exec_targets={item['targets_with_remote_exec_markers']})"
                for item in manual_drop
            )
            + (f". Confidence={confidence:.2f}." if isinstance(confidence, (int, float)) else ".")
        )

    if spreaders:
        return (
            "Heuristic deployment evidence is limited to internal RDP spread from "
            + ", ".join(f"{item['src_ip']} to {item['unique_targets']} hosts" for item in spreaders)
            + "."
        )

    return "The current packet evidence does not strongly prove RDP-based internal deployment or transferred payload recovery."


def _format_batch_payload_deployment_section(aggregate: dict[str, Any], records: list[dict[str, Any]]) -> str:
    confirmed = [item for item in records if item.get("payload_carving_status") == "confirmed_artifact"][:5]
    partial = [item for item in records if item.get("payload_carving_status") in {"partial_evidence", "hash_only"}][:5]
    heuristic_only = [
        item
        for item in records
        if item.get("payload_carving_candidate_count")
        and item.get("payload_carving_status") not in {"confirmed_artifact", "partial_evidence", "hash_only"}
    ][:5]
    manual_payload = [item for item in records if item.get("manual_payload_deployment_candidates")][:5]
    spreaders = [item for item in records if item.get("suspicious_internal_rdp_spread")][:5]

    parts: list[str] = []
    if confirmed:
        parts.append(
            "Confirmed recovered payload artifacts appear in "
            + ", ".join(item["file"] for item in confirmed)
            + f" ({aggregate.get('files_with_recovered_payload_artifacts', len(confirmed))} file(s))."
        )
    if partial:
        parts.append(
            "Partial or hash-only payload evidence appears in "
            + ", ".join(item["file"] for item in partial)
            + f" ({aggregate.get('files_with_partial_payload_evidence', len(partial))} file(s))."
        )
    if heuristic_only:
        parts.append(
            "Heuristic-only payload deployment evidence appears in "
            + ", ".join(item["file"] for item in heuristic_only)
            + f" ({aggregate.get('files_with_heuristic_payload_only', len(heuristic_only))} file(s))."
        )
    if not parts and manual_payload:
        parts.append("Manual RDP/SMB deployment candidates appear in " + ", ".join(item["file"] for item in manual_payload) + ".")
    if not parts and spreaders:
        parts.append("Internal RDP spread appears in " + ", ".join(item["file"] for item in spreaders) + ".")
    if not parts:
        parts.append("No strong internal payload deployment evidence is currently present in the results file.")
    return " ".join(parts)


def _compact_single_context(summary: dict[str, Any], findings: dict[str, Any]) -> dict[str, Any]:
    flow = findings.get("suspected_attack_flow") or ((findings.get("deep_dive") or {}).get("suspected_attack_flow"))
    external_rdp = findings.get("external_rdp", {})
    external_scans = findings.get("external_port_scans", {})
    smb_rpc = findings.get("smb_rpc_scans", {})
    dcerpc = findings.get("dcerpc_account_activity", {})
    temp_sh = findings.get("temp_sh_traffic", {})
    large_http = findings.get("large_http_posts", {})
    exfil = findings.get("outbound_exfiltration_candidates", {})
    rdp_spread = findings.get("rdp_payload_deployment", {})
    manual_drop = findings.get("manual_payload_deployment", {})
    payload_carving = findings.get("payload_carving", {})
    zero_day = findings.get("zero_day_heuristics", {})
    sandbox = findings.get("sandbox_verification", {})

    return {
        "pcap_summary": {
            "total_packets": summary.get("total_packets"),
            "top_ips": _take(summary.get("top_ips"), 5),
            "top_ports": _take(summary.get("top_ports"), 8),
            "protocols": summary.get("protocols"),
            "average_packet_size": summary.get("average_packet_size"),
            "unusual_ports": _take(summary.get("unusual_ports"), 8),
            "unusual_protocols": _take(summary.get("unusual_protocols"), 8),
            "scan_candidates": _take(summary.get("scan_candidates"), 5),
        },
        "high_signal_findings": {
            "patient_zero_candidate": _compact_patient_zero(external_rdp.get("patient_zero_candidate")),
            "external_reconnaissance": [
                {
                    "src_ip": item.get("src_ip"),
                    "unique_targets": item.get("unique_targets"),
                    "unique_ports": item.get("unique_ports"),
                    "syn_only_ratio": item.get("syn_only_ratio"),
                    "sample_events": _take(item.get("sample_events"), 3),
                }
                for item in _take([src for src in external_scans.get("sources", []) if src.get("suspicious")], 3)
            ],
            "smb_rpc_scanners": [
                {
                    "src_ip": item.get("src_ip"),
                    "unique_targets": item.get("unique_targets"),
                    "attempt_count": item.get("attempt_count"),
                    "duration_seconds": item.get("duration_seconds"),
                    "sample_events": _take(item.get("sample_events"), 3),
                }
                for item in _take([src for src in smb_rpc.get("scanners", []) if src.get("suspicious")], 3)
            ],
            "dcerpc_account_changes": [
                {
                    "src_ip": item.get("src_ip"),
                    "dst_ip": item.get("dst_ip"),
                    "marker": item.get("marker"),
                    "sample_events": _take(item.get("sample_events"), 2),
                }
                for item in _take(dcerpc.get("changes"), 4)
            ],
            "temp_sh_hits": [
                {
                    "src_ip": item.get("src_ip"),
                    "dst_ip": item.get("dst_ip"),
                    "indicator_type": item.get("indicator_type"),
                    "value": item.get("value"),
                }
                for item in _take(temp_sh.get("hits"), 4)
            ],
            "large_http_uploads": [
                {
                    "src_ip": item.get("src_ip"),
                    "dst_ip": item.get("dst_ip"),
                    "host": item.get("host"),
                    "inferred_upload_bytes": item.get("inferred_upload_bytes"),
                }
                for item in _take(large_http.get("uploads"), 4)
            ],
            "outbound_exfil_flows": [
                {
                    "src_ip": item.get("src_ip"),
                    "dst_ip": item.get("dst_ip"),
                    "dst_port": item.get("dst_port"),
                    "total_bytes": item.get("total_bytes"),
                    "severity": item.get("severity"),
                    "archive_hits": item.get("archive_hits"),
                    "temp_sh_mentions": item.get("temp_sh_mentions"),
                    "sample_events": _take(item.get("sample_events"), 2),
                }
                for item in _take(exfil.get("flows"), 4)
            ],
            "internal_rdp_spread": [
                {
                    "src_ip": item.get("src_ip"),
                    "unique_targets": item.get("unique_targets"),
                    "attempt_count": item.get("attempt_count"),
                    "sample_events": _take(item.get("sample_events"), 3),
                }
                for item in _take([src for src in rdp_spread.get("spreaders", []) if src.get("suspicious")], 3)
            ],
            "manual_payload_deployment_candidates": [
                {
                    "src_ip": item.get("src_ip"),
                    "unique_targets": item.get("unique_targets"),
                    "targets_with_smb_rpc": item.get("targets_with_smb_rpc"),
                    "targets_with_admin_share_markers": item.get("targets_with_admin_share_markers"),
                    "targets_with_remote_exec_markers": item.get("targets_with_remote_exec_markers"),
                    "manual_drop_score": item.get("manual_drop_score"),
                    "sample_events": _take(item.get("sample_events"), 3),
                }
                for item in _take([src for src in manual_drop.get("candidates", []) if src.get("suspicious")], 3)
            ],
            "carved_payloads": [
                {
                    "artifact_id": item.get("artifact_id"),
                    "protocol": item.get("protocol"),
                    "recovery_status": item.get("recovery_status"),
                    "recovered_filename": item.get("recovered_filename"),
                    "saved_path": item.get("saved_path"),
                    "sha256": item.get("sha256"),
                    "file_magic": item.get("file_magic"),
                    "mime_type": item.get("mime_type"),
                }
                for item in _take(payload_carving.get("carved_payloads"), 4)
            ],
            "payload_carving_status": payload_carving.get("status"),
            "payload_iocs": _take(payload_carving.get("payload_iocs"), 8),
            "payload_deployment_confidence": payload_carving.get("payload_deployment_confidence"),
            "payload_carving_candidate_count": payload_carving.get("candidate_count"),
        },
        "zero_day_heuristics": zero_day,
        "sandbox_verification": {
            "status": sandbox.get("status"),
            "mode": sandbox.get("mode"),
            "notable_observations": _take(sandbox.get("notable_observations"), 5),
            "verified_winrm_pairs": _take((sandbox.get("remote_management") or {}).get("verified_winrm_pairs"), 3),
            "verified_temp_sh_flows": _take((sandbox.get("exfiltration") or {}).get("verified_temp_sh_flows"), 3),
        },
        "suspected_attack_flow": _compact_flow_hypothesis(flow),
    }


def _compact_record_for_batch(item: dict[str, Any]) -> dict[str, Any]:
    ai_tshark_review = item.get("ai_tshark_review") or {}
    return {
        "file": item.get("file"),
        "packet_count": item.get("packet_count"),
        "patient_zero_candidate": _compact_patient_zero(item.get("patient_zero_candidate")),
        "external_port_scans": [
            {
                "src_ip": source.get("src_ip"),
                "unique_targets": source.get("unique_targets"),
                "unique_ports": source.get("unique_ports"),
                "syn_only_ratio": source.get("syn_only_ratio"),
            }
            for source in _take(item.get("suspicious_external_port_scanners"), 2)
        ],
        "smb_rpc_scanners": [
            {
                "src_ip": scanner.get("src_ip"),
                "unique_targets": scanner.get("unique_targets"),
                "attempts": scanner.get("attempt_count"),
                "duration_seconds": scanner.get("duration_seconds"),
            }
            for scanner in _take(item.get("suspicious_smb_rpc_scanners"), 2)
        ],
        "dcerpc_account_markers": [
            {
                "src_ip": change.get("src_ip"),
                "dst_ip": change.get("dst_ip"),
                "marker": change.get("marker"),
            }
            for change in _take(item.get("possible_dcerpc_account_changes"), 3)
        ],
        "temp_sh_hits": [
            {
                "indicator_type": hit.get("indicator_type"),
                "src_ip": hit.get("src_ip"),
                "dst_ip": hit.get("dst_ip"),
                "value": hit.get("value"),
            }
            for hit in _take(item.get("temp_sh_hits"), 3)
        ],
        "outbound_exfil_flows": [
            {
                "src_ip": flow.get("src_ip"),
                "dst_ip": flow.get("dst_ip"),
                "dst_port": flow.get("dst_port"),
                "total_bytes": flow.get("total_bytes"),
                "severity": flow.get("severity"),
                "archive_hits": flow.get("archive_hits"),
                "temp_sh_mentions": flow.get("temp_sh_mentions"),
            }
            for flow in _take(item.get("possible_outbound_exfil_flows"), 2)
        ],
        "large_http_uploads": [
            {
                "src_ip": upload.get("src_ip"),
                "dst_ip": upload.get("dst_ip"),
                "host": upload.get("host"),
                "inferred_upload_bytes": upload.get("inferred_upload_bytes"),
            }
            for upload in _take(item.get("large_http_uploads"), 2)
        ],
        "internal_rdp_spread": [
            {
                "src_ip": spreader.get("src_ip"),
                "unique_targets": spreader.get("unique_targets"),
                "attempt_count": spreader.get("attempt_count"),
            }
            for spreader in _take(item.get("suspicious_internal_rdp_spread"), 2)
        ],
        "manual_payload_deployment_candidates": [
            {
                "src_ip": candidate.get("src_ip"),
                "unique_targets": candidate.get("unique_targets"),
                "targets_with_smb_rpc": candidate.get("targets_with_smb_rpc"),
                "targets_with_admin_share_markers": candidate.get("targets_with_admin_share_markers"),
                "targets_with_remote_exec_markers": candidate.get("targets_with_remote_exec_markers"),
                "manual_drop_score": candidate.get("manual_drop_score"),
            }
            for candidate in _take(item.get("manual_payload_deployment_candidates"), 2)
        ],
        "carved_payloads": [
            {
                "artifact_id": payload.get("artifact_id"),
                "protocol": payload.get("protocol"),
                "recovery_status": payload.get("recovery_status"),
                "recovered_filename": payload.get("recovered_filename"),
                "sha256": payload.get("sha256"),
                "file_magic": payload.get("file_magic"),
            }
            for payload in _take(item.get("carved_payloads"), 2)
        ],
        "payload_carving_status": item.get("payload_carving_status"),
        "payload_iocs": _take(item.get("payload_iocs"), 6),
        "payload_deployment_confidence": item.get("payload_deployment_confidence"),
        "payload_carving_candidate_count": item.get("payload_carving_candidate_count"),
        "ai_tshark_review": {
            "status": ai_tshark_review.get("status"),
            "query_count": ai_tshark_review.get("query_count"),
            "queries": [
                {
                    "name": query.get("name"),
                    "stage": query.get("stage"),
                    "row_count": query.get("row_count"),
                    "sample_rows": _take(query.get("sample_rows"), 3),
                }
                for query in _take(ai_tshark_review.get("queries"), 3)
            ],
        },
        "deep_dive_focus_host": item.get("deep_dive_focus_host"),
        "deep_dive_ingress_external_ip": item.get("deep_dive_ingress_external_ip"),
        "suspected_attack_flow": _compact_flow_hypothesis((item.get("deep_dive") or {}).get("suspected_attack_flow")),
    }


def _compact_batch_context(aggregate: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    ai_tshark_records = [item for item in records if (item.get("ai_tshark_review") or {}).get("query_count")]
    top_records = sorted(
        records,
        key=lambda item: (
            (item.get("patient_zero_candidate") or {}).get("confidence_score", 0),
            len(item.get("suspicious_external_port_scanners", [])),
            item.get("suspicious_external_rdp_count", 0),
            len(item.get("temp_sh_hits", [])),
            len(item.get("possible_outbound_exfil_flows", [])),
            len(item.get("large_http_uploads", [])),
        ),
        reverse=True,
    )[:10]

    return {
        "aggregate_summary": {
            "file_count": aggregate.get("file_count"),
            "files_with_external_rdp": aggregate.get("files_with_external_rdp"),
            "files_with_external_port_scans": aggregate.get("files_with_external_port_scans"),
            "files_with_vpn_like_ingress": aggregate.get("files_with_vpn_like_ingress"),
            "files_with_smb_rpc_scanning": aggregate.get("files_with_smb_rpc_scanning"),
            "files_with_dcerpc_account_markers": aggregate.get("files_with_dcerpc_account_markers"),
            "files_with_temp_sh_hits": aggregate.get("files_with_temp_sh_hits"),
            "files_with_outbound_exfil_candidates": aggregate.get("files_with_outbound_exfil_candidates"),
            "files_with_large_http_uploads": aggregate.get("files_with_large_http_uploads"),
            "files_with_internal_rdp_spread": aggregate.get("files_with_internal_rdp_spread"),
            "files_with_manual_payload_deployment": aggregate.get("files_with_manual_payload_deployment"),
            "files_with_payload_carving_candidates": aggregate.get("files_with_payload_carving_candidates"),
            "files_with_recovered_payload_artifacts": aggregate.get("files_with_recovered_payload_artifacts"),
            "files_with_partial_payload_evidence": aggregate.get("files_with_partial_payload_evidence"),
            "files_with_heuristic_payload_only": aggregate.get("files_with_heuristic_payload_only"),
            "files_with_ai_tshark_follow_up": len(ai_tshark_records),
            "top_patient_zero_candidates": _take(aggregate.get("top_patient_zero_candidates"), 5),
            "top_deep_dive_focus_hosts": _take(aggregate.get("top_deep_dive_focus_hosts"), 5),
            "attack_flow": aggregate.get("attack_flow"),
            "interesting_files": {
                key: _take(value, 8)
                for key, value in (aggregate.get("interesting_files") or {}).items()
            },
        },
        "representative_records": {
            "top_overall": [_compact_record_for_batch(item) for item in top_records[:4]],
            "external_reconnaissance": [
                _compact_record_for_batch(item)
                for item in _take([item for item in records if item.get("suspicious_external_port_scanners")], 3)
            ],
            "discovery": [
                _compact_record_for_batch(item)
                for item in _take([item for item in records if item.get("suspicious_smb_rpc_scanners")], 4)
            ],
            "administrative_activity": [
                _compact_record_for_batch(item)
                for item in _take([item for item in records if item.get("possible_dcerpc_account_changes")], 4)
            ],
            "exfiltration": [
                _compact_record_for_batch(item)
                for item in _take([item for item in records if item.get("possible_outbound_exfil_flows") or item.get("temp_sh_hits")], 4)
            ],
            "payload_deployment": [
                _compact_record_for_batch(item)
                for item in _take([item for item in records if item.get("manual_payload_deployment_candidates")], 4)
            ],
        },
    }


def build_prompt(summary: dict[str, Any], findings: dict[str, Any]) -> str:
    context = _compact_single_context(summary, findings)
    return dedent(
        f"""
        Apex Global Logistics incident evidence is below.

        {_field_guide()}

        Compact Evidence Context:
        {json.dumps(context, indent=2)}
        """
    ).strip()


def build_results_prompt(
    aggregate: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    compact: bool = False,
) -> str:
    prompt_context = _compact_batch_context(aggregate, records)
    return dedent(
        f"""
        Apex Global Logistics incident evidence from a multi-file PCAP scan is below.

        {_field_guide()}

        Compact Evidence Context:
        {json.dumps(prompt_context, indent=2)}

        Write a structured incident report with these sections:
        1. Initial Access
        2. Lateral Movement & Discovery
        3. Exfiltration
        4. Payload Deployment
        5. Confidence / Gaps

        Requirements:
        - Name the strongest patient-zero candidate and cite the file(s) that support it.
        - Distinguish direct evidence from heuristic inference.
        - Explain the likely attack flow in order when the evidence supports it.
        - Treat external reconnaissance separately from confirmed initial access.
        - Call out if external reconnaissance, temp.sh, outbound exfil candidates, large uploads, SMB/RPC scanning, DCERPC account markers, manual payload-deployment candidates, or internal RDP spread are absent.
        - Be concise and operational.
        """
    ).strip()


def _fallback_report(summary: dict[str, Any], findings: dict[str, Any]) -> str:
    suspected_flow = findings.get("suspected_attack_flow") or ((findings.get("deep_dive") or {}).get("suspected_attack_flow")) or {}
    patient_zero = findings.get("external_rdp", {}).get("patient_zero_candidate")
    external_scans = [item for item in findings.get("external_port_scans", {}).get("sources", []) if item.get("suspicious")][:3]
    temp_hits = findings.get("temp_sh_traffic", {}).get("hits", [])[:5]
    uploads = findings.get("large_http_posts", {}).get("uploads", [])[:5]
    exfil_candidates = findings.get("outbound_exfiltration_candidates", {}).get("flows", [])[:5]
    scanners = [item for item in findings.get("smb_rpc_scans", {}).get("scanners", []) if item.get("suspicious")][:3]

    initial_access = (
        f"Most likely patient zero is {patient_zero['internal_ip']} after ingress from {patient_zero['external_ip']} over RDP."
        if patient_zero
        else "No strong external RDP patient-zero candidate was identified."
    )
    lateral = (
        "Rapid SMB/RPC scanning was observed from " + ", ".join(f"{item['src_ip']} ({item['unique_targets']} targets)" for item in scanners)
        if scanners else "No high-confidence SMB/RPC scanning pattern crossed the current thresholds."
    )
    if external_scans:
        lateral = "External reconnaissance was also observed from " + ", ".join(
            f"{item['src_ip']} ({item['unique_ports']} ports / {item['unique_targets']} targets)"
            for item in external_scans
        ) + ". " + lateral
    exfiltration = (
        "Evidence supports outbound exfiltration to temp.sh from " + ", ".join(f"{hit['src_ip']} -> {hit['dst_ip']}" for hit in temp_hits)
        if temp_hits else "No direct temp.sh indicator was found."
    )
    if exfil_candidates:
        exfiltration += " Additional outbound transfer spikes were observed from " + ", ".join(
            f"{item['src_ip']} -> {item['dst_ip']}:{item['dst_port']} ({item['total_bytes']} bytes)"
            for item in exfil_candidates
        ) + "."
    if uploads:
        exfiltration += " Large outbound HTTP POST uploads were also observed from " + ", ".join(f"{item['src_ip']} ({item['inferred_upload_bytes']} bytes)" for item in uploads) + "."
    payload = _format_single_payload_deployment_section(findings)
    flow_summary = suspected_flow.get("summary")

    return dedent(
        f"""
        # Incident Report

        ## Initial Access
        {initial_access}

        ## Lateral Movement & Discovery
        {lateral}

        ## Exfiltration
        {exfiltration}

        ## Payload Deployment
        {payload}

        ## Confidence / Gaps
        Total packets analyzed: {summary.get("total_packets", "unknown")}. Findings are heuristic and packet-based.
        {flow_summary or "No explicit single-file attack-flow hypothesis was provided."}
        """
    ).strip()


def _fallback_results_report(aggregate: dict[str, Any], records: list[dict[str, Any]]) -> str:
    attack_flow = (aggregate.get("attack_flow") or {}).get("likely_path")
    ai_tshark_follow_up = sum(
        1 for item in records if (item.get("ai_tshark_review") or {}).get("query_count")
    )
    patient_zero_candidates = sorted(
        [
            {
                "file": item["file"],
                **item["patient_zero_candidate"],
            }
            for item in records
            if item.get("patient_zero_candidate")
        ],
        key=lambda item: item.get("confidence_score", 0),
        reverse=True,
    )
    scanners = [
        item for item in records if item.get("suspicious_external_port_scanners")
    ][:5]
    smb_scanners = [
        item
        for item in records
        if item.get("suspicious_smb_rpc_scanners")
    ][:5]
    dcerpc_hits = [item for item in records if item.get("possible_dcerpc_account_changes")][:5]
    temp_hits = [item for item in records if item.get("temp_sh_hits")][:5]
    exfil_candidates = [item for item in records if item.get("possible_outbound_exfil_flows")][:5]
    uploads = [item for item in records if item.get("large_http_uploads")][:5]

    initial_access = (
        "Strongest patient-zero candidate is "
        f"{patient_zero_candidates[0]['internal_ip']} from external "
        f"{patient_zero_candidates[0]['external_ip']} in file "
        f"{patient_zero_candidates[0]['file']}."
        if patient_zero_candidates
        else "No patient-zero candidate was found in the current results file."
    )
    lateral = (
        "Possible external reconnaissance appears in "
        + ", ".join(item["file"] for item in scanners)
        + "."
        if scanners
        else "No external reconnaissance evidence is currently present in the results file."
    )
    if smb_scanners:
        lateral += " Possible SMB/RPC scanning appears in " + ", ".join(
            item["file"] for item in smb_scanners
        ) + "."
    else:
        lateral += " No SMB/RPC scanning evidence is currently present in the results file."
    if dcerpc_hits:
        lateral += " DCERPC or account/group markers appear in " + ", ".join(
            item["file"] for item in dcerpc_hits
        ) + "."
    exfiltration = (
        "temp.sh indicators appear in "
        + ", ".join(item["file"] for item in temp_hits)
        if temp_hits
        else "No temp.sh indicator is currently present in the results file."
    )
    if exfil_candidates:
        exfiltration += " Outbound transfer spike candidates appear in " + ", ".join(
            item["file"] for item in exfil_candidates
        ) + "."
    if uploads:
        exfiltration += " Large HTTP uploads appear in " + ", ".join(
            item["file"] for item in uploads
        ) + "."
    payload = _format_batch_payload_deployment_section(aggregate, records)

    return dedent(
        f"""
        # Incident Report

        Attack Flow:
        {attack_flow or "No coherent attack flow was built from the current results."}

        ## Initial Access
        {initial_access}

        ## Lateral Movement & Discovery
        {lateral}

        ## Exfiltration
        {exfiltration}

        ## Payload Deployment
        {payload}

        ## Confidence / Gaps
        Files analyzed in results file: {aggregate.get("file_count", 0)}. Targeted AI-authored tshark follow-up ran on {ai_tshark_follow_up} file(s). This report is based on aggregated per-file scan results and remains heuristic.
        """
    ).strip()


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _read_value(source: Any, *keys: str) -> Any:
    current = source
    for key in keys:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(key)
        else:
            current = getattr(current, key, None)
    return current


def _extract_usage_tokens(payload: Any) -> tuple[int, int]:
    prompt_tokens = (
        _read_value(payload, "usage", "input_tokens")
        or _read_value(payload, "usage", "prompt_tokens")
        or _read_value(payload, "usage_metadata", "prompt_token_count")
        or _read_value(payload, "usage_metadata", "input_tokens")
        or _read_value(payload, "prompt_eval_count")
        or _read_value(payload, "prompt_tokens")
    )
    completion_tokens = (
        _read_value(payload, "usage", "output_tokens")
        or _read_value(payload, "usage", "completion_tokens")
        or _read_value(payload, "usage_metadata", "candidates_token_count")
        or _read_value(payload, "usage_metadata", "output_tokens")
        or _read_value(payload, "eval_count")
        or _read_value(payload, "completion_tokens")
    )
    return _safe_int(prompt_tokens), _safe_int(completion_tokens)


def _result_from_text(
    *,
    text: str,
    provider: str,
    model: str,
    usage_payload: Any | None = None,
    fallback_used: bool = False,
    api_attempted: bool | None = None,
    failure_reason: str | None = None,
) -> ReportGenerationResult:
    llm_tokens_in, llm_tokens_out = _extract_usage_tokens(usage_payload)
    resolved_api_attempted = bool(api_attempted) if api_attempted is not None else usage_payload is not None
    return ReportGenerationResult(
        text=text.strip(),
        provider=provider,
        model=model,
        llm_tokens_in=llm_tokens_in,
        llm_tokens_out=llm_tokens_out,
        fallback_used=fallback_used,
        api_attempted=resolved_api_attempted,
        failure_reason=failure_reason,
    )


def _failure_result(
    *,
    provider: str,
    model: str,
    api_attempted: bool,
    failure_reason: str,
) -> ReportGenerationResult:
    return ReportGenerationResult(
        text="",
        provider=provider,
        model=model,
        fallback_used=True,
        api_attempted=api_attempted,
        failure_reason=failure_reason,
    )


def _extract_text_from_response_payload(response: Any) -> str:
    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    choices = getattr(response, "choices", None)
    if choices:
        for choice in choices:
            message = getattr(choice, "message", None)
            if not message:
                continue
            content = getattr(message, "content", None)
            if isinstance(content, str) and content.strip():
                return content.strip()
            if isinstance(content, list):
                text_parts = []
                for part in content:
                    if isinstance(part, dict):
                        text = part.get("text")
                        if text:
                            text_parts.append(str(text))
                    else:
                        text = getattr(part, "text", None)
                        if text:
                            text_parts.append(str(text))
                if text_parts:
                    return "\n".join(part.strip() for part in text_parts if part and str(part).strip()).strip()

    output = getattr(response, "output", None)
    if isinstance(output, list):
        text_parts = []
        for item in output:
            content = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
            if not content:
                continue
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        text = part.get("text")
                        if text:
                            text_parts.append(str(text))
                    else:
                        text = getattr(part, "text", None)
                        if text:
                            text_parts.append(str(text))
            elif isinstance(content, str) and content.strip():
                text_parts.append(content)
        if text_parts:
            return "\n".join(part.strip() for part in text_parts if part and str(part).strip()).strip()

    return ""


def _generate_with_openai(prompt: str, model: str | None) -> ReportGenerationResult | None:
    api_key = _get_secret("OPENAI_API_KEY")
    selected_model = str(model or _get_setting("OPENAI_MODEL", "gpt-5-mini"))
    if not api_key:
        print(
            "OpenAI unavailable: OPENAI_API_KEY is not set in the environment or local_settings.py. Using fallback report.",
            file=sys.stderr,
        )
        return _failure_result(
            provider="openai",
            model=selected_model,
            api_attempted=False,
            failure_reason="missing_api_key",
        )
    max_output_tokens = max(200, _get_setting_int("OPENAI_MAX_OUTPUT_TOKENS", _get_setting_int("REPORT_MAX_OUTPUT_TOKENS", 1200)))
    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        retry_attempts = max(1, _get_setting_int("OPENAI_RETRY_ATTEMPTS", 3))
        retry_delay = max(0.5, _get_setting_float("OPENAI_RETRY_DELAY_SECONDS", 2.0))
        for attempt in range(1, retry_attempts + 1):
            try:
                response = client.responses.create(
                    model=selected_model,
                    max_output_tokens=max_output_tokens,
                    input=prompt,
                )
                text = _extract_text_from_response_payload(response)
                if text:
                    print(f"OpenAI request succeeded using model {selected_model}.", file=sys.stderr)
                    return _result_from_text(
                        text=text,
                        provider="openai",
                        model=selected_model,
                        usage_payload=response,
                        api_attempted=True,
                    )
                print(
                    f"OpenAI model {selected_model} returned no text on attempt {attempt}/{retry_attempts}.",
                    file=sys.stderr,
                )
                return _failure_result(
                    provider="openai",
                    model=selected_model,
                    api_attempted=True,
                    failure_reason="empty_response",
                )
            except Exception as exc:
                is_last_attempt = attempt >= retry_attempts
                if _is_transient_api_error(exc) and not is_last_attempt:
                    sleep_seconds = retry_delay * attempt
                    print(
                        f"OpenAI transient failure on {selected_model} attempt {attempt}/{retry_attempts}: {exc}. Retrying in {sleep_seconds:.1f}s.",
                        file=sys.stderr,
                    )
                    time.sleep(sleep_seconds)
                    continue
                print(
                    f"OpenAI request failed on model {selected_model} attempt {attempt}/{retry_attempts}: {exc}.",
                    file=sys.stderr,
                )
                return _failure_result(
                    provider="openai",
                    model=selected_model,
                    api_attempted=True,
                    failure_reason="request_failed",
                )
    except Exception as exc:
        print(f"OpenAI client setup failed: {exc}. Using fallback report.", file=sys.stderr)
        return _failure_result(
            provider="openai",
            model=selected_model,
            api_attempted=False,
            failure_reason="client_setup_failed",
        )
    return _failure_result(
        provider="openai",
        model=selected_model,
        api_attempted=False,
        failure_reason="no_api_call",
    )


def _generate_with_openrouter(prompt: str, model: str | None) -> ReportGenerationResult | None:
    api_keys = _get_secret_candidates("OPENROUTER_API_KEY")
    selected_model = str(model or _get_setting("OPENROUTER_MODEL", "openai/gpt-5-mini"))
    if not api_keys:
        print(
            "OpenRouter unavailable: OPENROUTER_API_KEY/OPENROUTER_API_KEYS is not set in the environment or local_settings.py. Trying next report option.",
            file=sys.stderr,
        )
        return _failure_result(
            provider="openrouter",
            model=selected_model,
            api_attempted=False,
            failure_reason="missing_api_key",
        )
    base_url = str(_get_setting("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")).rstrip("/")
    max_output_tokens = max(200, _get_setting_int("OPENROUTER_MAX_OUTPUT_TOKENS", _get_setting_int("REPORT_MAX_OUTPUT_TOKENS", 900)))
    try:
        from openai import OpenAI

        retry_attempts = max(1, _get_setting_int("OPENROUTER_RETRY_ATTEMPTS", 3))
        retry_delay = max(0.5, _get_setting_float("OPENROUTER_RETRY_DELAY_SECONDS", 2.0))
        last_failure_reason = "no_api_call"
        for key_index, api_key in enumerate(api_keys, start=1):
            client = OpenAI(
                api_key=api_key,
                base_url=base_url,
            )
            for attempt in range(1, retry_attempts + 1):
                try:
                    response = client.chat.completions.create(
                        model=selected_model,
                        max_tokens=max_output_tokens,
                        temperature=0,
                        messages=[
                            {"role": "user", "content": prompt},
                        ],
                        extra_headers={
                            "HTTP-Referer": str(_get_setting("OPENROUTER_HTTP_REFERER", "http://localhost")),
                            "X-Title": str(_get_setting("OPENROUTER_APP_NAME", "AgenticNetSec")),
                        },
                    )
                    text = _extract_text_from_response_payload(response)
                    if text:
                        print(f"OpenRouter request succeeded using model {selected_model}.", file=sys.stderr)
                        return _result_from_text(
                            text=text,
                            provider="openrouter",
                            model=selected_model,
                            usage_payload=response,
                            api_attempted=True,
                        )
                    last_failure_reason = "empty_response"
                    print(
                        f"OpenRouter model {selected_model} returned no text using key {key_index}/{len(api_keys)} attempt {attempt}/{retry_attempts}.",
                        file=sys.stderr,
                    )
                except Exception as exc:
                    last_failure_reason = "request_failed"
                    print(
                        f"OpenRouter request failed on model {selected_model} using key {key_index}/{len(api_keys)} attempt {attempt}/{retry_attempts}: {exc}.",
                        file=sys.stderr,
                    )
                    if _is_transient_api_error(exc) and attempt < retry_attempts:
                        sleep_seconds = retry_delay * attempt
                        print(
                            f"OpenRouter transient failure on {selected_model} using key {key_index}/{len(api_keys)} attempt {attempt}/{retry_attempts}. Retrying in {sleep_seconds:.1f}s.",
                            file=sys.stderr,
                        )
                        time.sleep(sleep_seconds)
            if key_index < len(api_keys):
                print(
                    f"OpenRouter key {key_index}/{len(api_keys)} failed after {retry_attempts} attempt(s). Trying next key.",
                    file=sys.stderr,
                )
        print(
            f"OpenRouter unavailable after {len(api_keys)} key(s) and {retry_attempts} attempt(s) per key. Trying next report option.",
            file=sys.stderr,
        )
        return _failure_result(
            provider="openrouter",
            model=selected_model,
            api_attempted=True,
            failure_reason="all_api_keys_failed" if len(api_keys) > 1 else last_failure_reason,
        )
    except Exception as exc:
        print(f"OpenRouter client setup failed: {exc}. Trying next report option.", file=sys.stderr)
        return _failure_result(
            provider="openrouter",
            model=selected_model,
            api_attempted=False,
            failure_reason="client_setup_failed",
        )
    return _failure_result(
        provider="openrouter",
        model=selected_model,
        api_attempted=False,
        failure_reason="no_api_call",
    )


def _generate_with_groq(prompt: str, model: str | None) -> ReportGenerationResult | None:
    api_key = _get_secret("GROQ_API_KEY")
    selected_model = str(model or _get_setting("GROQ_MODEL", "openai/gpt-oss-20b"))
    if not api_key:
        print(
            "Groq unavailable: GROQ_API_KEY is not set in the environment or local_settings.py. Using fallback report.",
            file=sys.stderr,
        )
        return _failure_result(
            provider="groq",
            model=selected_model,
            api_attempted=False,
            failure_reason="missing_api_key",
        )
    max_output_tokens = max(200, _get_setting_int("GROQ_MAX_OUTPUT_TOKENS", _get_setting_int("REPORT_MAX_OUTPUT_TOKENS", 1200)))
    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=api_key,
            base_url=str(_get_setting("GROQ_BASE_URL", "https://api.groq.com/openai/v1")),
        )
        retry_attempts = max(1, _get_setting_int("GROQ_RETRY_ATTEMPTS", 3))
        retry_delay = max(0.5, _get_setting_float("GROQ_RETRY_DELAY_SECONDS", 2.0))
        for attempt in range(1, retry_attempts + 1):
            try:
                response = client.responses.create(
                    model=selected_model,
                    max_output_tokens=max_output_tokens,
                    input=prompt,
                )
                text = _extract_text_from_response_payload(response)
                if text:
                    print(f"Groq request succeeded using model {selected_model}.", file=sys.stderr)
                    return _result_from_text(
                        text=text,
                        provider="groq",
                        model=selected_model,
                        usage_payload=response,
                        api_attempted=True,
                    )
                print(
                    f"Groq model {selected_model} returned no text on attempt {attempt}/{retry_attempts}.",
                    file=sys.stderr,
                )
                return _failure_result(
                    provider="groq",
                    model=selected_model,
                    api_attempted=True,
                    failure_reason="empty_response",
                )
            except Exception as exc:
                is_last_attempt = attempt >= retry_attempts
                if _is_transient_api_error(exc) and not is_last_attempt:
                    sleep_seconds = retry_delay * attempt
                    print(
                        f"Groq transient failure on {selected_model} attempt {attempt}/{retry_attempts}: {exc}. Retrying in {sleep_seconds:.1f}s.",
                        file=sys.stderr,
                    )
                    time.sleep(sleep_seconds)
                    continue
                print(
                    f"Groq request failed on model {selected_model} attempt {attempt}/{retry_attempts}: {exc}.",
                    file=sys.stderr,
                )
                return _failure_result(
                    provider="groq",
                    model=selected_model,
                    api_attempted=True,
                    failure_reason="request_failed",
                )
    except Exception as exc:
        print(f"Groq client setup failed: {exc}. Using fallback report.", file=sys.stderr)
        return _failure_result(
            provider="groq",
            model=selected_model,
            api_attempted=False,
            failure_reason="client_setup_failed",
        )
    return _failure_result(
        provider="groq",
        model=selected_model,
        api_attempted=False,
        failure_reason="no_api_call",
    )


def _get_secret(name: str) -> str | None:
    value = os.getenv(name)
    if value:
        return value
    if _local_settings is not None:
        return getattr(_local_settings, name, None)
    return None


def _coerce_secret_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        return [item.strip() for item in stripped.replace("\n", ",").split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _get_secret_candidates(name: str) -> list[str]:
    plural_name = f"{name}S"
    sources: list[Any]
    if os.getenv(plural_name) or os.getenv(name):
        sources = [os.getenv(plural_name), os.getenv(name)]
    elif _local_settings is not None:
        sources = [getattr(_local_settings, plural_name, None), getattr(_local_settings, name, None)]
    else:
        sources = []

    candidates: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for candidate in _coerce_secret_list(source):
            if candidate not in seen:
                candidates.append(candidate)
                seen.add(candidate)
    return candidates


def _get_secret_source(name: str) -> str | None:
    if os.getenv(name):
        return name
    if _local_settings is not None and getattr(_local_settings, name, None):
        return f"local_settings.py:{name}"
    return None


def _get_setting(name: str, default: Any = None) -> Any:
    if os.getenv(name):
        return os.getenv(name)
    if _local_settings is not None and hasattr(_local_settings, name):
        return getattr(_local_settings, name)
    return default


def _get_setting_int(name: str, default: int) -> int:
    value = _get_setting(name, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _get_setting_float(name: str, default: float) -> float:
    value = _get_setting(name, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _get_gemini_model_candidates(primary_model: str | None) -> list[str]:
    preferred = _get_setting("GEMINI_MODEL", primary_model or "gemini-2.5-flash") or primary_model or "gemini-2.5-flash"
    fallback_models = _get_setting("GEMINI_FALLBACK_MODELS", [])
    if isinstance(fallback_models, str):
        fallback_models = [item.strip() for item in fallback_models.split(",") if item.strip()]
    elif not isinstance(fallback_models, (list, tuple)):
        fallback_models = []

    ordered_models: list[str] = []
    for candidate in [preferred, *fallback_models]:
        if candidate and candidate not in ordered_models:
            ordered_models.append(str(candidate))
    return ordered_models or [primary_model or "gemini-2.5-flash"]


def _is_transient_gemini_error(exc: Exception) -> bool:
    message = str(exc).upper()
    transient_markers = [
        "503",
        "UNAVAILABLE",
        "RESOURCE_EXHAUSTED",
        "429",
        "DEADLINE_EXCEEDED",
        "TIMEOUT",
        "TIMED OUT",
    ]
    return any(marker in message for marker in transient_markers)


def _is_transient_api_error(exc: Exception) -> bool:
    message = str(exc).upper()
    transient_markers = [
        "429",
        "500",
        "502",
        "503",
        "504",
        "TIMEOUT",
        "TIMED OUT",
        "RATE LIMIT",
        "CONNECTION RESET",
        "TEMPORAR",
        "UNAVAILABLE",
    ]
    return any(marker in message for marker in transient_markers)


def _get_gemini_api_key() -> str | None:
    candidates = _get_gemini_api_key_candidates()
    return candidates[0] if candidates else None


def _get_gemini_api_key_candidates() -> list[str]:
    env_sources = [
        os.getenv("GEMINI_API_KEYS"),
        os.getenv("GEMINI_API_KEY"),
        os.getenv("GOOGLE_API_KEYS"),
        os.getenv("GOOGLE_API_KEY"),
    ]
    if any(env_sources):
        sources = env_sources
    elif _local_settings is not None:
        sources = [
            getattr(_local_settings, "GEMINI_API_KEYS", None),
            getattr(_local_settings, "GEMINI_API_KEY", None),
            getattr(_local_settings, "GOOGLE_API_KEYS", None),
            getattr(_local_settings, "GOOGLE_API_KEY", None),
        ]
    else:
        sources = []

    candidates: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for candidate in _coerce_secret_list(source):
            if candidate not in seen:
                candidates.append(candidate)
                seen.add(candidate)
    return candidates


def _get_gemini_api_key_source() -> str | None:
    if os.getenv("GEMINI_API_KEYS"):
        return "GEMINI_API_KEYS"
    if os.getenv("GEMINI_API_KEY"):
        return "GEMINI_API_KEY"
    if os.getenv("GOOGLE_API_KEYS"):
        return "GOOGLE_API_KEYS"
    if os.getenv("GOOGLE_API_KEY"):
        return "GOOGLE_API_KEY"
    if _local_settings is not None and getattr(_local_settings, "GEMINI_API_KEYS", None):
        return "local_settings.py:GEMINI_API_KEYS"
    if _local_settings is not None and getattr(_local_settings, "GEMINI_API_KEY", None):
        return "local_settings.py:GEMINI_API_KEY"
    if _local_settings is not None and getattr(_local_settings, "GOOGLE_API_KEYS", None):
        return "local_settings.py:GOOGLE_API_KEYS"
    if _local_settings is not None and getattr(_local_settings, "GOOGLE_API_KEY", None):
        return "local_settings.py:GOOGLE_API_KEY"
    return None


def _generate_with_gemini(prompt: str, model: str | None) -> ReportGenerationResult | None:
    api_keys = _get_gemini_api_key_candidates()
    key_source = _get_gemini_api_key_source()
    requested_model = str(model or _get_setting("GEMINI_MODEL", "gemini-2.5-flash"))
    if not api_keys:
        print(
            "Gemini unavailable: neither GEMINI_API_KEY/GEMINI_API_KEYS nor GOOGLE_API_KEY/GOOGLE_API_KEYS is set in the environment or local_settings.py. Using fallback report.",
            file=sys.stderr,
        )
        return _failure_result(
            provider="gemini",
            model=requested_model,
            api_attempted=False,
            failure_reason="missing_api_key",
        )
    try:
        from google import genai

        retry_attempts = max(1, _get_setting_int("GEMINI_RETRY_ATTEMPTS", 3))
        retry_delay = max(0.5, _get_setting_float("GEMINI_RETRY_DELAY_SECONDS", 2.0))
        model_candidates = _get_gemini_model_candidates(model)
        api_attempted = False
        last_failure_reason = "no_api_call"

        for key_index, api_key in enumerate(api_keys, start=1):
            try:
                client = genai.Client(api_key=api_key)
            except Exception as exc:
                last_failure_reason = "client_setup_failed"
                print(
                    f"Gemini client setup failed for key {key_index}/{len(api_keys)}: {exc}.",
                    file=sys.stderr,
                )
                continue

            for model_index, candidate_model in enumerate(model_candidates, start=1):
                print(
                    f"Trying Gemini model {candidate_model} ({model_index}/{len(model_candidates)}) using key {key_index}/{len(api_keys)}",
                    file=sys.stderr,
                )
                for attempt in range(1, retry_attempts + 1):
                    try:
                        api_attempted = True
                        response = client.models.generate_content(
                            model=candidate_model,
                            contents=f"{SYSTEM_PROMPT}\n\n{prompt}",
                        )
                        text = getattr(response, "text", None)
                        if text:
                            if key_source:
                                print(
                                    f"Gemini request succeeded using {key_source} key {key_index}/{len(api_keys)} and model {candidate_model}.",
                                    file=sys.stderr,
                                )
                            return _result_from_text(
                                text=text,
                                provider="gemini",
                                model=candidate_model,
                                usage_payload=response,
                                api_attempted=True,
                            )
                        last_failure_reason = "empty_response"
                        print(
                            f"Gemini model {candidate_model} returned no text using key {key_index}/{len(api_keys)} attempt {attempt}/{retry_attempts}.",
                            file=sys.stderr,
                        )
                    except Exception as exc:
                        last_failure_reason = "request_failed"
                        is_last_attempt = attempt >= retry_attempts
                        if _is_transient_gemini_error(exc) and not is_last_attempt:
                            sleep_seconds = retry_delay * attempt
                            print(
                                f"Gemini transient failure on {candidate_model} using key {key_index}/{len(api_keys)} attempt {attempt}/{retry_attempts}: {exc}. Retrying in {sleep_seconds:.1f}s.",
                                file=sys.stderr,
                            )
                            time.sleep(sleep_seconds)
                            continue
                        print(
                            f"Gemini request failed on model {candidate_model} using key {key_index}/{len(api_keys)} attempt {attempt}/{retry_attempts}: {exc}.",
                            file=sys.stderr,
                        )
                        break
            if key_index < len(api_keys):
                print(
                    f"Gemini key {key_index}/{len(api_keys)} failed after configured model/retry attempts. Trying next key.",
                    file=sys.stderr,
                )
        print("Gemini unavailable after retries and model fallbacks. Using fallback report.", file=sys.stderr)
        return _failure_result(
            provider="gemini",
            model=model_candidates[0] if model_candidates else requested_model,
            api_attempted=api_attempted,
            failure_reason="all_api_keys_failed" if len(api_keys) > 1 else last_failure_reason,
        )
    except Exception as exc:
        print(f"Gemini client setup failed: {exc}. Using fallback report.", file=sys.stderr)
        return _failure_result(
            provider="gemini",
            model=requested_model,
            api_attempted=False,
            failure_reason="client_setup_failed",
        )


def _get_ollama_model_candidates(primary_model: str | None) -> list[str]:
    preferred = _get_setting("OLLAMA_MODEL", primary_model or "qwen2.5:7b-instruct") or primary_model or "qwen2.5:7b-instruct"
    fallback_models = _get_setting("OLLAMA_FALLBACK_MODELS", [])
    if isinstance(fallback_models, str):
        fallback_models = [item.strip() for item in fallback_models.split(",") if item.strip()]
    elif not isinstance(fallback_models, (list, tuple)):
        fallback_models = []

    ordered_models: list[str] = []
    for candidate in [preferred, *fallback_models]:
        if candidate and candidate not in ordered_models:
            ordered_models.append(str(candidate))
    return ordered_models or [primary_model or "qwen2.5:7b-instruct"]


def _get_ollama_base_url() -> str:
    return str(_get_setting("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")


def _generate_with_ollama(prompt: str, model: str | None) -> ReportGenerationResult | None:
    base_url = _get_ollama_base_url()
    model_candidates = _get_ollama_model_candidates(model)
    timeout_seconds = max(30.0, _get_setting_float("OLLAMA_TIMEOUT_SECONDS", 300.0))
    api_attempted = False

    for model_index, candidate_model in enumerate(model_candidates, start=1):
        print(
            f"Trying Ollama model {candidate_model} ({model_index}/{len(model_candidates)})",
            file=sys.stderr,
        )
        request_body = json.dumps(
            {
                "model": candidate_model,
                "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
                "stream": False,
                "options": {
                    "temperature": 0.2,
                },
            }
        ).encode("utf-8")
        request = urllib_request.Request(
            f"{base_url}/api/generate",
            data=request_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            api_attempted = True
            with urllib_request.urlopen(request, timeout=timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
            text = payload.get("response")
            if text:
                print(
                    f"Ollama request succeeded using model {candidate_model} at {base_url}.",
                    file=sys.stderr,
                )
                return _result_from_text(
                    text=text,
                    provider="ollama",
                    model=candidate_model,
                    usage_payload=payload,
                    api_attempted=True,
                )
            print(
                f"Ollama model {candidate_model} returned no text. Trying next option if available.",
                file=sys.stderr,
            )
        except urllib_error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            print(
                f"Ollama request failed on model {candidate_model}: HTTP {exc.code} {body}.",
                file=sys.stderr,
            )
        except urllib_error.URLError as exc:
            print(
                f"Ollama unavailable at {base_url}: {exc}. Install/start Ollama or adjust OLLAMA_BASE_URL. Using fallback report.",
                file=sys.stderr,
            )
            return _failure_result(
                provider="ollama",
                model=candidate_model,
                api_attempted=api_attempted,
                failure_reason="unavailable",
            )
        except Exception as exc:
            print(
                f"Ollama request failed on model {candidate_model}: {exc}.",
                file=sys.stderr,
            )
    print("Ollama unavailable after trying configured model candidates. Using fallback report.", file=sys.stderr)
    return _failure_result(
        provider="ollama",
        model=model_candidates[0] if model_candidates else str(model or "qwen2.5:7b-instruct"),
        api_attempted=api_attempted,
        failure_reason="empty_response_or_request_failed",
    )


def _resolve_provider_chain(provider: str) -> list[str]:
    normalized = (provider or "auto").strip().lower()
    if normalized == "auto":
        return ["openrouter", "gemini", "openai", "groq", "ollama"]
    if normalized == "openrouter":
        return ["openrouter", "gemini", "openai", "groq", "ollama"]
    if normalized == "gemini":
        return ["gemini", "openrouter", "openai", "groq", "ollama"]
    if normalized == "openai":
        return ["openai", "openrouter", "gemini", "groq", "ollama"]
    if normalized == "groq":
        return ["groq", "openrouter", "gemini", "openai", "ollama"]
    if normalized == "ollama":
        return ["ollama", "openrouter", "gemini", "openai", "groq"]
    return [normalized]


def _model_for_provider(provider: str, model: str | None, preferred_provider: str | None = None) -> str | None:
    if model and (preferred_provider is None or provider == preferred_provider):
        return model
    if provider == "openrouter":
        return str(_get_setting("OPENROUTER_MODEL", "openai/gpt-5-mini"))
    if provider == "gemini":
        return str(_get_setting("GEMINI_MODEL", "gemini-2.5-flash"))
    if provider == "openai":
        return str(_get_setting("OPENAI_MODEL", "gpt-5-mini"))
    if provider == "groq":
        return str(_get_setting("GROQ_MODEL", "openai/gpt-oss-20b"))
    if provider == "ollama":
        return str(_get_setting("OLLAMA_MODEL", "qwen2.5:7b-instruct"))
    return model


def _generate_with_provider(
    prompt: str,
    provider: str,
    model: str | None,
    *,
    preferred_provider: str | None = None,
) -> ReportGenerationResult | None:
    if provider == "openrouter":
        return _generate_with_openrouter(prompt, _model_for_provider(provider, model, preferred_provider))
    if provider == "gemini":
        return _generate_with_gemini(prompt, _model_for_provider(provider, model, preferred_provider))
    if provider == "groq":
        return _generate_with_groq(prompt, _model_for_provider(provider, model, preferred_provider))
    if provider == "ollama":
        return _generate_with_ollama(prompt, _model_for_provider(provider, model, preferred_provider))
    if provider == "openai":
        return _generate_with_openai(prompt, _model_for_provider(provider, model, preferred_provider))
    return None


def _normalize_requested_provider(provider: str | None) -> str:
    normalized = (provider or "openrouter").strip().lower()
    return normalized or "openrouter"


def _resolve_requested_model(provider: str | None, model: str | None) -> str:
    normalized_provider = _normalize_requested_provider(provider)
    resolved_model = _model_for_provider(
        normalized_provider,
        model,
        normalized_provider,
    )
    if resolved_model:
        return str(resolved_model)
    configured_report_model = _get_setting("REPORT_MODEL", "fallback")
    return str(configured_report_model or "fallback")


def _generate_best_result(
    prompt: str,
    *,
    provider: str,
    model: str | None,
    require_ai: bool,
    allow_provider_fallback: bool = True,
) -> ReportGenerationResult | None:
    provider_chain = _resolve_provider_chain(provider) if allow_provider_fallback else [(provider or "auto").strip().lower()]
    preferred_provider = provider_chain[0] if provider_chain else provider
    failure_results: list[ReportGenerationResult] = []
    for candidate_provider in provider_chain:
        result = _generate_with_provider(
            prompt,
            candidate_provider,
            model,
            preferred_provider=preferred_provider,
        )
        if result and result.text:
            return result
        if result:
            failure_results.append(result)
    if require_ai:
        raise RuntimeError(f"{provider} report generation failed")
    requested_provider = _normalize_requested_provider(provider)
    requested_model = _resolve_requested_model(requested_provider, model)
    api_attempted = any(result.api_attempted for result in failure_results)
    failure_reason = next(
        (result.failure_reason for result in failure_results if result.failure_reason),
        "no_api_call",
    )
    return _failure_result(
        provider=requested_provider,
        model=requested_model,
        api_attempted=api_attempted,
        failure_reason=failure_reason,
    )


def _combine_results(
    *,
    text: str,
    results: list[ReportGenerationResult],
    fallback_used: bool = False,
    fallback_provider: str = "fallback",
    fallback_model: str = "fallback",
) -> ReportGenerationResult:
    if not results:
        return _result_from_text(
            text=text,
            provider=fallback_provider,
            model=fallback_model,
            fallback_used=fallback_used,
        )
    providers = {result.provider for result in results}
    models = {result.model for result in results}
    return ReportGenerationResult(
        text=text.strip(),
        provider=results[0].provider if len(providers) == 1 else "mixed",
        model=results[0].model if len(models) == 1 else "mixed",
        llm_tokens_in=sum(result.llm_tokens_in for result in results),
        llm_tokens_out=sum(result.llm_tokens_out for result in results),
        fallback_used=fallback_used or any(result.fallback_used for result in results),
        api_attempted=any(result.api_attempted for result in results),
        failure_reason=next((result.failure_reason for result in results if result.failure_reason), None),
    )


def generate_text_result(
    *,
    prompt: str,
    system_prompt: str,
    provider: str = "openrouter",
    model: str | None = None,
    require_ai: bool = False,
    allow_provider_fallback: bool = True,
) -> ReportGenerationResult | None:
    full_prompt = f"{system_prompt}\n\n{prompt}".strip()
    return _generate_best_result(
        full_prompt,
        provider=provider,
        model=model,
        require_ai=require_ai,
        allow_provider_fallback=allow_provider_fallback,
    )


def _build_section_prompt(
    *,
    section_title: str,
    context: dict[str, Any],
    case_scope: str,
) -> str:
    return dedent(
        f"""
        {SYSTEM_PROMPT}

        Write only the body for the report section titled "{section_title}" for a {case_scope}.
        Do not include the heading itself.
        Keep it concise and operational.
        Distinguish direct evidence from heuristic inference.
        If evidence is weak or absent, say so clearly.

        {_field_guide()}

        Compact Evidence Context:
        {json.dumps(context, indent=2)}
        """
    ).strip()


def _section_context(context: dict[str, Any], section_key: str, case_scope: str) -> dict[str, Any]:
    if case_scope == "single-PCAP incident":
        signals = context.get("high_signal_findings", {})
        base = {
            "pcap_summary": {
                "total_packets": (context.get("pcap_summary") or {}).get("total_packets"),
                "scan_candidates": (context.get("pcap_summary") or {}).get("scan_candidates"),
            },
            "suspected_attack_flow": context.get("suspected_attack_flow"),
        }
        if section_key == "initial_access":
            base["relevant_findings"] = {
                "patient_zero_candidate": signals.get("patient_zero_candidate"),
                "external_reconnaissance": signals.get("external_reconnaissance"),
            }
        elif section_key == "lateral_movement_discovery":
            base["relevant_findings"] = {
                "external_reconnaissance": signals.get("external_reconnaissance"),
                "smb_rpc_scanners": signals.get("smb_rpc_scanners"),
                "dcerpc_account_changes": signals.get("dcerpc_account_changes"),
                "internal_rdp_spread": signals.get("internal_rdp_spread"),
            }
        elif section_key == "exfiltration":
            base["relevant_findings"] = {
                "temp_sh_hits": signals.get("temp_sh_hits"),
                "large_http_uploads": signals.get("large_http_uploads"),
                "outbound_exfil_flows": signals.get("outbound_exfil_flows"),
            }
        elif section_key == "payload_deployment":
            base["relevant_findings"] = {
                "internal_rdp_spread": signals.get("internal_rdp_spread"),
                "manual_payload_deployment_candidates": signals.get("manual_payload_deployment_candidates"),
                "dcerpc_account_changes": signals.get("dcerpc_account_changes"),
                "carved_payloads": signals.get("carved_payloads"),
                "payload_carving_status": signals.get("payload_carving_status"),
                "payload_iocs": signals.get("payload_iocs"),
                "payload_deployment_confidence": signals.get("payload_deployment_confidence"),
            }
        else:
            base["relevant_findings"] = {
                "patient_zero_candidate": signals.get("patient_zero_candidate"),
                "smb_rpc_scanners": signals.get("smb_rpc_scanners"),
                "outbound_exfil_flows": signals.get("outbound_exfil_flows"),
                "manual_payload_deployment_candidates": signals.get("manual_payload_deployment_candidates"),
                "zero_day_heuristics": context.get("zero_day_heuristics"),
            }
        return base

    aggregate_summary = context.get("aggregate_summary", {})
    representative_records = context.get("representative_records", {})
    base = {
        "aggregate_summary": {
            "file_count": aggregate_summary.get("file_count"),
            "attack_flow": aggregate_summary.get("attack_flow"),
        }
    }
    if section_key == "initial_access":
        base["aggregate_signals"] = {
            "files_with_external_rdp": aggregate_summary.get("files_with_external_rdp"),
            "files_with_vpn_like_ingress": aggregate_summary.get("files_with_vpn_like_ingress"),
            "top_patient_zero_candidates": aggregate_summary.get("top_patient_zero_candidates"),
        }
        base["representative_records"] = representative_records.get("top_overall")
    elif section_key == "lateral_movement_discovery":
        base["aggregate_signals"] = {
            "files_with_external_port_scans": aggregate_summary.get("files_with_external_port_scans"),
            "files_with_smb_rpc_scanning": aggregate_summary.get("files_with_smb_rpc_scanning"),
            "files_with_dcerpc_account_markers": aggregate_summary.get("files_with_dcerpc_account_markers"),
        }
        base["representative_records"] = {
            "external_reconnaissance": representative_records.get("external_reconnaissance"),
            "discovery": representative_records.get("discovery"),
            "administrative_activity": representative_records.get("administrative_activity"),
        }
    elif section_key == "exfiltration":
        base["aggregate_signals"] = {
            "files_with_temp_sh_hits": aggregate_summary.get("files_with_temp_sh_hits"),
            "files_with_outbound_exfil_candidates": aggregate_summary.get("files_with_outbound_exfil_candidates"),
            "files_with_large_http_uploads": aggregate_summary.get("files_with_large_http_uploads"),
        }
        base["representative_records"] = representative_records.get("exfiltration")
    elif section_key == "payload_deployment":
        base["aggregate_signals"] = {
            "files_with_internal_rdp_spread": aggregate_summary.get("files_with_internal_rdp_spread"),
            "files_with_manual_payload_deployment": aggregate_summary.get("files_with_manual_payload_deployment"),
            "files_with_payload_carving_candidates": aggregate_summary.get("files_with_payload_carving_candidates"),
            "files_with_recovered_payload_artifacts": aggregate_summary.get("files_with_recovered_payload_artifacts"),
            "files_with_partial_payload_evidence": aggregate_summary.get("files_with_partial_payload_evidence"),
            "files_with_heuristic_payload_only": aggregate_summary.get("files_with_heuristic_payload_only"),
        }
        base["representative_records"] = representative_records.get("payload_deployment")
    else:
        base["aggregate_signals"] = {
            "top_deep_dive_focus_hosts": aggregate_summary.get("top_deep_dive_focus_hosts"),
            "interesting_files": aggregate_summary.get("interesting_files"),
        }
        base["representative_records"] = representative_records.get("top_overall")
    return base


def _compose_report(section_bodies: dict[str, str], *, attack_flow: str | None = None) -> str:
    lines = ["# Incident Report", ""]
    if attack_flow:
        lines.extend(["Attack Flow:", attack_flow, ""])
    for title, key in REPORT_SECTIONS:
        lines.extend([f"## {title}", section_bodies.get(key, "No material evidence was summarized for this section."), ""])
    return "\n".join(lines).strip()


def _generate_sectioned_report(
    *,
    context: dict[str, Any],
    provider: str,
    model: str | None,
    use_ai: bool,
    require_ai: bool,
    case_scope: str,
    attack_flow: str | None = None,
    fallback_text: str,
) -> ReportGenerationResult:
    requested_provider = _normalize_requested_provider(provider)
    requested_model = _resolve_requested_model(requested_provider, model)
    if not use_ai:
        return _result_from_text(
            text=fallback_text,
            provider=requested_provider,
            model=requested_model,
            fallback_used=True,
        )

    section_results: list[ReportGenerationResult] = []
    section_bodies: dict[str, str] = {}
    for section_title, section_key in REPORT_SECTIONS:
        scoped_context = _section_context(context, section_key, case_scope)
        prompt = _build_section_prompt(
            section_title=section_title,
            context=scoped_context,
            case_scope=case_scope,
        )
        result = _generate_best_result(
            prompt,
            provider=requested_provider,
            model=model,
            require_ai=require_ai,
            allow_provider_fallback=False,
        )
        if not result or not result.text:
            return _result_from_text(
                text=fallback_text,
                provider=requested_provider,
                model=requested_model,
                fallback_used=True,
                api_attempted=result.api_attempted if result else False,
                failure_reason=result.failure_reason if result else "no_api_call",
            )
        section_results.append(result)
        section_bodies[section_key] = result.text.strip()

    return _combine_results(
        text=_compose_report(section_bodies, attack_flow=attack_flow),
        results=section_results,
    )


def generate_report_result(
    summary: dict[str, Any],
    findings: dict[str, Any],
    *,
    provider: str = "openrouter",
    model: str | None = None,
    use_ai: bool = True,
    require_ai: bool = False,
) -> ReportGenerationResult:
    compact_context = _compact_single_context(summary, findings)
    flow = compact_context.get("suspected_attack_flow") or {}
    return _generate_sectioned_report(
        context=compact_context,
        provider=provider,
        model=model,
        use_ai=use_ai,
        require_ai=require_ai,
        case_scope="single-PCAP incident",
        attack_flow=flow.get("likely_path"),
        fallback_text=_fallback_report(summary, findings),
    )


def generate_report(
    summary: dict[str, Any],
    findings: dict[str, Any],
    *,
    provider: str = "openrouter",
    model: str | None = None,
    use_ai: bool = True,
    require_ai: bool = False,
) -> str:
    return generate_report_result(
        summary,
        findings,
        provider=provider,
        model=model,
        use_ai=use_ai,
        require_ai=require_ai,
    ).text


def generate_results_report(
    aggregate: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    provider: str = "openrouter",
    model: str | None = None,
    use_ai: bool = True,
    require_ai: bool = False,
) -> str:
    return generate_results_report_result(
        aggregate,
        records,
        provider=provider,
        model=model,
        use_ai=use_ai,
        require_ai=require_ai,
    ).text


def generate_results_report_result(
    aggregate: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    provider: str = "openrouter",
    model: str | None = None,
    use_ai: bool = True,
    require_ai: bool = False,
) -> ReportGenerationResult:
    compact_context = _compact_batch_context(aggregate, records)
    return _generate_sectioned_report(
        context=compact_context,
        provider=provider,
        model=model,
        use_ai=use_ai,
        require_ai=require_ai,
        case_scope="multi-file PCAP campaign",
        attack_flow=(aggregate.get("attack_flow") or {}).get("likely_path"),
        fallback_text=_fallback_results_report(aggregate, records),
    )


def _load_results(results_file: Path) -> list[dict[str, Any]]:
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


def _build_aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
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
    confirmed_payload = [item for item in records if item.get("payload_carving_status") == "confirmed_artifact"]
    partial_payload = [item for item in records if item.get("payload_carving_status") in {"partial_evidence", "hash_only"}]
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


def main() -> int:
    results_file = DEFAULT_RESULTS_FILE
    aggregate_file = DEFAULT_AGGREGATE_FILE
    report_file = DEFAULT_REPORT_FILE
    provider = str(_get_setting("REPORT_PROVIDER", "openrouter"))
    model = _get_setting("REPORT_MODEL", None)
    if not model:
        if provider == "openrouter":
            model = _get_setting("OPENROUTER_MODEL", "openai/gpt-5-mini")
        elif provider == "ollama":
            model = _get_setting("OLLAMA_MODEL", "qwen2.5:7b-instruct")
        elif provider == "groq":
            model = _get_setting("GROQ_MODEL", "openai/gpt-oss-20b")
        elif provider == "openai":
            model = _get_setting("OPENAI_MODEL", "gpt-5-mini")
        else:
            model = _get_setting("GEMINI_MODEL", "gemini-2.5-flash")

    print(f"Reading results from {results_file}")
    print(f"Report provider: {provider} | model: {model}")
    if provider == "openrouter":
        key_source = _get_secret_source("OPENROUTER_API_KEY")
        if key_source:
            print(f"OpenRouter key detected from {key_source}")
        else:
            print("OpenRouter key not detected in OPENROUTER_API_KEY")
    elif provider == "gemini":
        key_source = _get_gemini_api_key_source()
        if key_source:
            print(f"Gemini key detected from {key_source}")
        else:
            print("Gemini key not detected in GEMINI_API_KEY or GOOGLE_API_KEY")
    elif provider == "openai":
        key_source = _get_secret_source("OPENAI_API_KEY")
        if key_source:
            print(f"OpenAI key detected from {key_source}")
        else:
            print("OpenAI key not detected in OPENAI_API_KEY")
    elif provider == "groq":
        key_source = _get_secret_source("GROQ_API_KEY")
        if key_source:
            print(f"Groq key detected from {key_source}")
        else:
            print("Groq key not detected in GROQ_API_KEY")
    elif provider == "ollama":
        print(f"Ollama base URL: {_get_ollama_base_url()}")
    records = _load_results(results_file)
    aggregate = _build_aggregate(records)
    report = generate_results_report(
        aggregate,
        records,
        provider=provider,
        model=str(model) if model is not None else None,
        use_ai=True,
        require_ai=False,
    )

    aggregate_file.write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")
    report_file.write_text(report + "\n", encoding="utf-8")
    print(f"Wrote aggregate summary to {aggregate_file}")
    print(f"Wrote report to {report_file}")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

