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


def build_prompt(summary: dict[str, Any], findings: dict[str, Any]) -> str:
    flow = findings.get("suspected_attack_flow") or ((findings.get("deep_dive") or {}).get("suspected_attack_flow"))
    return dedent(
        f"""
        Apex Global Logistics incident evidence is below.

        PCAP Summary:
        {json.dumps(summary, indent=2)}

        Structured Findings:
        {json.dumps(findings, indent=2)}

        Structured Flow Hypothesis:
        {json.dumps(flow, indent=2) if flow else "None provided"}

        If a structured flow hypothesis is provided, use it as an evidence-backed hypothesis map.
        Do not treat unsupported stages as proven.
        """
    ).strip()


def build_results_prompt(
    aggregate: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    compact: bool = False,
) -> str:
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
    )[:12]

    def compact_patient_zero(candidate: dict[str, Any] | None) -> dict[str, Any] | None:
        if not candidate:
            return None
        return {
            "internal_ip": candidate.get("internal_ip"),
            "external_ip": candidate.get("external_ip"),
            "confidence_score": candidate.get("confidence_score"),
            "rdp_packets": candidate.get("rdp_packets"),
            "established": candidate.get("handshake_complete"),
            "post_login_unique_internal_targets": candidate.get("post_login_unique_internal_targets"),
        }

    def compact_record(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "file": item.get("file"),
            "packet_count": item.get("packet_count"),
            "patient_zero_candidate": compact_patient_zero(item.get("patient_zero_candidate")),
            "suspicious_external_rdp_count": item.get("suspicious_external_rdp_count", 0),
            "external_port_scans": [
                {
                    "src_ip": source.get("src_ip"),
                    "unique_targets": source.get("unique_targets"),
                    "unique_ports": source.get("unique_ports"),
                    "syn_only_ratio": source.get("syn_only_ratio"),
                }
                for source in item.get("suspicious_external_port_scanners", [])[:2]
            ],
            "suspicious_vpn_count": item.get("suspicious_vpn_count", 0),
            "smb_rpc_scanners": [
                {
                    "src_ip": scanner.get("src_ip"),
                    "unique_targets": scanner.get("unique_targets"),
                    "attempts": scanner.get("attempt_count"),
                    "duration_seconds": scanner.get("duration_seconds"),
                }
                for scanner in item.get("suspicious_smb_rpc_scanners", [])[:2]
            ],
            "dcerpc_account_markers": [
                {
                    "src_ip": change.get("src_ip"),
                    "dst_ip": change.get("dst_ip"),
                    "marker": change.get("marker"),
                }
                for change in item.get("possible_dcerpc_account_changes", [])[:3]
            ],
            "temp_sh_hits": [
                {
                    "indicator_type": hit.get("indicator_type"),
                    "src_ip": hit.get("src_ip"),
                    "dst_ip": hit.get("dst_ip"),
                    "value": hit.get("value"),
                }
                for hit in item.get("temp_sh_hits", [])[:3]
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
                for flow in item.get("possible_outbound_exfil_flows", [])[:2]
            ],
            "large_http_uploads": [
                {
                    "src_ip": upload.get("src_ip"),
                    "dst_ip": upload.get("dst_ip"),
                    "host": upload.get("host"),
                    "inferred_upload_bytes": upload.get("inferred_upload_bytes"),
                }
                for upload in item.get("large_http_uploads", [])[:2]
            ],
            "internal_rdp_spread": [
                {
                    "src_ip": spreader.get("src_ip"),
                    "unique_targets": spreader.get("unique_targets"),
                    "attempt_count": spreader.get("attempt_count"),
                }
                for spreader in item.get("suspicious_internal_rdp_spread", [])[:2]
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
                for candidate in item.get("manual_payload_deployment_candidates", [])[:2]
            ],
            "deep_dive_focus_host": item.get("deep_dive_focus_host"),
            "deep_dive_ingress_external_ip": item.get("deep_dive_ingress_external_ip"),
        }

    category_examples = {
        "patient_zero_candidates": [compact_record(item) for item in top_records[: (3 if compact else 6)]],
        "external_port_scan_records": [compact_record(item) for item in records if item.get("suspicious_external_port_scanners")][: (3 if compact else 5)],
        "smb_rpc_scan_records": [compact_record(item) for item in records if item.get("suspicious_smb_rpc_scanners")][: (3 if compact else 6)],
        "dcerpc_account_records": [compact_record(item) for item in records if item.get("possible_dcerpc_account_changes")][: (3 if compact else 5)],
        "temp_sh_records": [compact_record(item) for item in records if item.get("temp_sh_hits")][: (3 if compact else 5)],
        "outbound_exfil_records": [compact_record(item) for item in records if item.get("possible_outbound_exfil_flows")][: (3 if compact else 5)],
        "large_upload_records": [compact_record(item) for item in records if item.get("large_http_uploads")][: (2 if compact else 4)],
        "internal_rdp_spread_records": [compact_record(item) for item in records if item.get("suspicious_internal_rdp_spread")][: (3 if compact else 5)],
        "manual_payload_deployment_records": [compact_record(item) for item in records if item.get("manual_payload_deployment_candidates")][: (3 if compact else 5)],
        "deep_dive_records": [compact_record(item) for item in records if item.get("deep_dive")][: (2 if compact else 4)],
    }
    prompt_aggregate = aggregate
    if compact:
        prompt_aggregate = {
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
            "top_patient_zero_candidates": aggregate.get("top_patient_zero_candidates", [])[:3],
            "attack_flow": aggregate.get("attack_flow"),
            "interesting_files": {
                key: value[:5]
                for key, value in (aggregate.get("interesting_files") or {}).items()
            },
        }
    return dedent(
        f"""
        Apex Global Logistics incident evidence from a multi-file PCAP scan is below.

        Aggregate Summary:
        {json.dumps(prompt_aggregate, indent=2)}

        Representative Records By Category:
        {json.dumps(category_examples, indent=2)}

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
    spreaders = [item for item in findings.get("rdp_payload_deployment", {}).get("spreaders", []) if item.get("suspicious")][:3]
    manual_drop = [item for item in findings.get("manual_payload_deployment", {}).get("candidates", []) if item.get("suspicious")][:3]

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
    payload = (
        "Correlated RDP plus SMB/DCERPC admin-share activity suggests manual deployment from "
        + ", ".join(
            f"{item['src_ip']} to {item['unique_targets']} hosts "
            f"(admin_share_targets={item['targets_with_admin_share_markers']}, remote_exec_targets={item['targets_with_remote_exec_markers']})"
            for item in manual_drop
        )
        if manual_drop
        else "Internal RDP spread suggests possible manual deployment from "
        + ", ".join(f"{item['src_ip']} to {item['unique_targets']} hosts" for item in spreaders)
        if spreaders
        else "The current packet evidence does not strongly prove RDP-based internal deployment."
    )
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
    spreaders = [item for item in records if item.get("suspicious_internal_rdp_spread")][:5]
    manual_payload = [item for item in records if item.get("manual_payload_deployment_candidates")][:5]

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
    payload = (
        "Manual RDP/SMB deployment candidates appear in "
        + ", ".join(item["file"] for item in manual_payload)
        if manual_payload
        else "Internal RDP spread appears in "
        + ", ".join(item["file"] for item in spreaders)
        if spreaders
        else "No strong internal RDP spread evidence is currently present in the results file."
    )

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
        Files analyzed in results file: {aggregate.get("file_count", 0)}. This report is based on aggregated per-file scan results and remains heuristic.
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
) -> ReportGenerationResult:
    llm_tokens_in, llm_tokens_out = _extract_usage_tokens(usage_payload)
    return ReportGenerationResult(
        text=text.strip(),
        provider=provider,
        model=model,
        llm_tokens_in=llm_tokens_in,
        llm_tokens_out=llm_tokens_out,
        fallback_used=fallback_used,
    )


def _generate_with_openai(prompt: str, model: str | None) -> ReportGenerationResult | None:
    api_key = _get_secret("OPENAI_API_KEY")
    if not api_key:
        print(
            "OpenAI unavailable: OPENAI_API_KEY is not set in the environment or local_settings.py. Using fallback report.",
            file=sys.stderr,
        )
        return None
    selected_model = str(_get_setting("OPENAI_MODEL", model or "gpt-5-mini"))
    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        retry_attempts = max(1, _get_setting_int("OPENAI_RETRY_ATTEMPTS", 3))
        retry_delay = max(0.5, _get_setting_float("OPENAI_RETRY_DELAY_SECONDS", 2.0))
        for attempt in range(1, retry_attempts + 1):
            try:
                response = client.responses.create(
                    model=selected_model,
                    input=[
                        {"role": "system", "content": [{"type": "text", "text": SYSTEM_PROMPT}]},
                        {"role": "user", "content": [{"type": "text", "text": prompt}]},
                    ],
                )
                if response.output_text:
                    print(f"OpenAI request succeeded using model {selected_model}.", file=sys.stderr)
                    return _result_from_text(
                        text=response.output_text,
                        provider="openai",
                        model=selected_model,
                        usage_payload=response,
                    )
                print(
                    f"OpenAI model {selected_model} returned no text on attempt {attempt}/{retry_attempts}.",
                    file=sys.stderr,
                )
                break
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
                break
    except Exception as exc:
        print(f"OpenAI client setup failed: {exc}. Using fallback report.", file=sys.stderr)
        return None
    return None


def _generate_with_openrouter(prompt: str, model: str | None) -> ReportGenerationResult | None:
    api_key = _get_secret("OPENROUTER_API_KEY")
    if not api_key:
        print(
            "OpenRouter unavailable: OPENROUTER_API_KEY is not set in the environment or local_settings.py. Trying next report option.",
            file=sys.stderr,
        )
        return None
    selected_model = str(_get_setting("OPENROUTER_MODEL", model or "openai/gpt-5-mini"))
    base_url = str(_get_setting("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")).rstrip("/")
    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        retry_attempts = max(1, _get_setting_int("OPENROUTER_RETRY_ATTEMPTS", 3))
        retry_delay = max(0.5, _get_setting_float("OPENROUTER_RETRY_DELAY_SECONDS", 2.0))
        for attempt in range(1, retry_attempts + 1):
            try:
                response = client.responses.create(
                    model=selected_model,
                    input=f"{SYSTEM_PROMPT}\n\n{prompt}",
                    extra_headers={
                        "HTTP-Referer": str(_get_setting("OPENROUTER_HTTP_REFERER", "http://localhost")),
                        "X-Title": str(_get_setting("OPENROUTER_APP_NAME", "AgenticNetSec")),
                    },
                )
                if response.output_text:
                    print(f"OpenRouter request succeeded using model {selected_model}.", file=sys.stderr)
                    return _result_from_text(
                        text=response.output_text,
                        provider="openrouter",
                        model=selected_model,
                        usage_payload=response,
                    )
                print(
                    f"OpenRouter model {selected_model} returned no text on attempt {attempt}/{retry_attempts}.",
                    file=sys.stderr,
                )
                break
            except Exception as exc:
                is_last_attempt = attempt >= retry_attempts
                if _is_transient_api_error(exc) and not is_last_attempt:
                    sleep_seconds = retry_delay * attempt
                    print(
                        f"OpenRouter transient failure on {selected_model} attempt {attempt}/{retry_attempts}: {exc}. Retrying in {sleep_seconds:.1f}s.",
                        file=sys.stderr,
                    )
                    time.sleep(sleep_seconds)
                    continue
                print(
                    f"OpenRouter request failed on model {selected_model} attempt {attempt}/{retry_attempts}: {exc}. Trying next report option.",
                    file=sys.stderr,
                )
                break
    except Exception as exc:
        print(f"OpenRouter client setup failed: {exc}. Trying next report option.", file=sys.stderr)
        return None
    return None


def _generate_with_groq(prompt: str, model: str | None) -> ReportGenerationResult | None:
    api_key = _get_secret("GROQ_API_KEY")
    if not api_key:
        print(
            "Groq unavailable: GROQ_API_KEY is not set in the environment or local_settings.py. Using fallback report.",
            file=sys.stderr,
        )
        return None
    selected_model = str(_get_setting("GROQ_MODEL", model or "openai/gpt-oss-20b"))
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
                    input=f"{SYSTEM_PROMPT}\n\n{prompt}",
                )
                if response.output_text:
                    print(f"Groq request succeeded using model {selected_model}.", file=sys.stderr)
                    return _result_from_text(
                        text=response.output_text,
                        provider="groq",
                        model=selected_model,
                        usage_payload=response,
                    )
                print(
                    f"Groq model {selected_model} returned no text on attempt {attempt}/{retry_attempts}.",
                    file=sys.stderr,
                )
                break
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
                break
    except Exception as exc:
        print(f"Groq client setup failed: {exc}. Using fallback report.", file=sys.stderr)
        return None
    return None


def _get_secret(name: str) -> str | None:
    value = os.getenv(name)
    if value:
        return value
    if _local_settings is not None:
        return getattr(_local_settings, name, None)
    return None


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
    return _get_secret("GEMINI_API_KEY") or _get_secret("GOOGLE_API_KEY")


def _get_gemini_api_key_source() -> str | None:
    source = _get_secret_source("GEMINI_API_KEY")
    if source:
        return source
    source = _get_secret_source("GOOGLE_API_KEY")
    if source:
        return source
    return None


def _generate_with_gemini(prompt: str, model: str | None) -> ReportGenerationResult | None:
    api_key = _get_gemini_api_key()
    key_source = _get_gemini_api_key_source()
    if not api_key:
        print(
            "Gemini unavailable: neither GEMINI_API_KEY nor GOOGLE_API_KEY is set in the environment or local_settings.py. Using fallback report.",
            file=sys.stderr,
        )
        return None
    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        retry_attempts = max(1, _get_setting_int("GEMINI_RETRY_ATTEMPTS", 3))
        retry_delay = max(0.5, _get_setting_float("GEMINI_RETRY_DELAY_SECONDS", 2.0))
        model_candidates = _get_gemini_model_candidates(model)

        for model_index, candidate_model in enumerate(model_candidates, start=1):
            print(
                f"Trying Gemini model {candidate_model} ({model_index}/{len(model_candidates)})",
                file=sys.stderr,
            )
            for attempt in range(1, retry_attempts + 1):
                try:
                    response = client.models.generate_content(
                        model=candidate_model,
                        contents=f"{SYSTEM_PROMPT}\n\n{prompt}",
                    )
                    text = getattr(response, "text", None)
                    if text:
                        if key_source:
                            print(
                                f"Gemini request succeeded using {key_source} and model {candidate_model}.",
                                file=sys.stderr,
                            )
                        return _result_from_text(
                            text=text,
                            provider="gemini",
                            model=candidate_model,
                            usage_payload=response,
                        )
                    print(
                        f"Gemini model {candidate_model} returned no text. Trying next option if available.",
                        file=sys.stderr,
                    )
                    break
                except Exception as exc:
                    is_last_attempt = attempt >= retry_attempts
                    if _is_transient_gemini_error(exc) and not is_last_attempt:
                        sleep_seconds = retry_delay * attempt
                        print(
                            f"Gemini transient failure on {candidate_model} attempt {attempt}/{retry_attempts}: {exc}. Retrying in {sleep_seconds:.1f}s.",
                            file=sys.stderr,
                        )
                        time.sleep(sleep_seconds)
                        continue
                    print(
                        f"Gemini request failed on model {candidate_model} attempt {attempt}/{retry_attempts}: {exc}.",
                        file=sys.stderr,
                    )
                    break
        print("Gemini unavailable after retries and model fallbacks. Using fallback report.", file=sys.stderr)
    except Exception as exc:
        print(f"Gemini client setup failed: {exc}. Using fallback report.", file=sys.stderr)
        return None
    return None


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
            return None
        except Exception as exc:
            print(
                f"Ollama request failed on model {candidate_model}: {exc}.",
                file=sys.stderr,
            )
    print("Ollama unavailable after trying configured model candidates. Using fallback report.", file=sys.stderr)
    return None


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


def generate_report_result(
    summary: dict[str, Any],
    findings: dict[str, Any],
    *,
    provider: str = "openrouter",
    model: str | None = None,
    use_ai: bool = True,
    require_ai: bool = False,
) -> ReportGenerationResult:
    prompt = build_prompt(summary, findings)
    if use_ai:
        preferred_provider = _resolve_provider_chain(provider)[0]
        for candidate_provider in _resolve_provider_chain(provider):
            result = _generate_with_provider(
                prompt,
                candidate_provider,
                model,
                preferred_provider=preferred_provider,
            )
            if result:
                return result
        if require_ai:
            raise RuntimeError(f"{provider} report generation failed")
    return _result_from_text(
        text=_fallback_report(summary, findings),
        provider=provider,
        model=str(model or _get_setting("REPORT_MODEL", "fallback")),
        fallback_used=True,
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
    provider_chain = _resolve_provider_chain(provider)
    effective_provider = provider_chain[0] if provider_chain else provider
    prompt = build_results_prompt(aggregate, records, compact=(effective_provider in {"groq", "ollama"}))
    if use_ai:
        preferred_provider = provider_chain[0] if provider_chain else provider
        for candidate_provider in provider_chain:
            result = _generate_with_provider(
                prompt,
                candidate_provider,
                model,
                preferred_provider=preferred_provider,
            )
            if result:
                return result.text
        if require_ai:
            raise RuntimeError(f"{provider} report generation failed")
    return _fallback_results_report(aggregate, records)


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

