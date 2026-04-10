from __future__ import annotations

import json
from textwrap import dedent
from typing import Any

from report_ai import generate_results_report_result, generate_text_result

SECTION_FILE_KEYS = {
    "A": ["external_rdp"],
    "B": ["external_port_scans", "smb_rpc_scanning", "dcerpc_account_markers"],
    "C": ["temp_sh_hits", "outbound_exfil_candidates", "large_http_uploads"],
    "D": ["internal_rdp_spread", "manual_payload_deployment"],
}

SECTION_TITLES = {
    "A": "Initial Access",
    "B": "Lateral Movement & Discovery",
    "C": "Exfiltration",
    "D": "Payload Deployment",
}


def build_case_summary(
    aggregate: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    provider: str = "gemini",
    model: str | None = None,
    require_ai: bool = False,
    summary_text: str | None = None,
) -> dict[str, Any]:
    if summary_text:
        return {
            "provider": "file",
            "model": None,
            "report_text": summary_text,
            "fallback_used": False,
            "llm_tokens_in": 0,
            "llm_tokens_out": 0,
            "ai_callable": False,
            "api_attempted": False,
            "status": "file_provided",
        }
    result = generate_results_report_result(
        aggregate,
        records,
        provider=provider,
        model=model,
        use_ai=True,
        require_ai=require_ai,
    )
    return {
        "provider": result.provider,
        "model": result.model,
        "report_text": result.text,
        "fallback_used": result.fallback_used,
        "llm_tokens_in": result.llm_tokens_in,
        "llm_tokens_out": result.llm_tokens_out,
        "ai_callable": not result.fallback_used,
        "api_attempted": result.api_attempted,
        "failure_reason": result.failure_reason,
        "status": "ai_generated" if not result.fallback_used else "fallback_report",
    }


def build_ai_tshark_plan(
    *,
    record: dict[str, Any],
    aggregate: dict[str, Any],
    report_text: str,
    focus_sections: list[str] | None = None,
    provider: str = "openrouter",
    model: str | None = None,
    require_ai: bool = False,
) -> dict[str, Any]:
    prompt = _build_prompt(record, aggregate, report_text, focus_sections=focus_sections)
    result = generate_text_result(
        prompt=prompt,
        system_prompt=_planner_system_prompt(),
        provider=provider,
        model=model,
        require_ai=require_ai,
        allow_provider_fallback=False,
    )
    heuristic = _heuristic_record_plan(record, aggregate, focus_sections=focus_sections)
    if not result or not result.text:
        return {
            **heuristic,
            "planner_source": "heuristic_after_ai_failure" if result and result.api_attempted else "heuristic_no_api_call",
            "planner_provider": result.provider if result else provider,
            "planner_model": result.model if result else model,
            "ai_api_attempted": bool(result.api_attempted) if result else False,
            "failure_reason": result.failure_reason if result else "no_api_call",
        }

    parsed = _parse_plan(result.text)
    if not parsed:
        return {
            **heuristic,
            "planner_source": "heuristic_after_ai_parse_failure",
            "planner_provider": result.provider,
            "planner_model": result.model,
            "ai_api_attempted": bool(result.api_attempted),
            "failure_reason": result.failure_reason,
            "raw_text": result.text,
        }

    parsed["planner_source"] = "ai"
    parsed["planner_provider"] = result.provider
    parsed["planner_model"] = result.model
    return parsed


def build_campaign_weak_sections(
    *,
    aggregate: dict[str, Any],
    report_text: str,
    provider: str = "openrouter",
    model: str | None = None,
    require_ai: bool = False,
) -> dict[str, Any]:
    prompt = _build_campaign_prompt(aggregate, report_text)
    result = generate_text_result(
        prompt=prompt,
        system_prompt=_campaign_system_prompt(),
        provider=provider,
        model=model,
        require_ai=require_ai,
        allow_provider_fallback=False,
    )
    heuristic = _heuristic_campaign_plan(aggregate, report_text)
    if not result or not result.text:
        return {
            **heuristic,
            "planner_source": "heuristic_after_ai_failure" if result and result.api_attempted else "heuristic_no_api_call",
            "planner_provider": result.provider if result else provider,
            "planner_model": result.model if result else model,
            "ai_api_attempted": bool(result.api_attempted) if result else False,
            "failure_reason": result.failure_reason if result else "no_api_call",
        }

    parsed = _parse_campaign_plan(result.text)
    if not parsed:
        return {
            **heuristic,
            "planner_source": "heuristic_after_ai_parse_failure",
            "planner_provider": result.provider,
            "planner_model": result.model,
            "ai_api_attempted": bool(result.api_attempted),
            "failure_reason": result.failure_reason,
            "raw_text": result.text,
        }

    parsed["planner_source"] = "ai"
    parsed["planner_provider"] = result.provider
    parsed["planner_model"] = result.model
    return parsed


def select_records_for_sections(
    *,
    records: list[dict[str, Any]],
    aggregate: dict[str, Any],
    weak_sections: list[str],
    limit: int | None = None,
) -> list[dict[str, Any]]:
    if not weak_sections:
        return []

    candidate_files: list[str] = []
    interesting_files = aggregate.get("interesting_files") or {}
    for section in weak_sections:
        for key in SECTION_FILE_KEYS.get(section, []):
            candidate_files.extend(interesting_files.get(key) or [])
        if section == "A":
            candidate_files.extend(
                item.get("file")
                for item in (aggregate.get("top_patient_zero_candidates") or [])[:20]
                if item.get("file")
            )

    seen = set()
    ordered_files = []
    for file_name in candidate_files:
        if file_name and file_name not in seen:
            seen.add(file_name)
            ordered_files.append(file_name)

    by_file = {record.get("file"): record for record in records if record.get("file")}
    selected = [by_file[file_name] for file_name in ordered_files if file_name in by_file]
    if selected:
        return selected[:limit] if limit else selected

    scored_records: list[tuple[int, dict[str, Any]]] = []
    for record in records:
        score = 0
        if "A" in weak_sections:
            score += 3 if record.get("patient_zero_candidate") else 0
            score += int(record.get("suspicious_external_rdp_count") or 0)
        if "B" in weak_sections:
            score += 3 if record.get("suspicious_smb_rpc_scanners") else 0
            score += 2 if record.get("possible_dcerpc_account_changes") else 0
            score += 1 if record.get("suspicious_internal_rdp_spread") else 0
        if "C" in weak_sections:
            score += 3 if record.get("temp_sh_hits") else 0
            score += 2 if record.get("possible_outbound_exfil_flows") else 0
            score += 1 if record.get("large_http_uploads") else 0
        if "D" in weak_sections:
            score += 3 if record.get("manual_payload_deployment_candidates") else 0
            score += 2 if record.get("suspicious_internal_rdp_spread") else 0
        if score <= 0 and record.get("patient_zero_candidate"):
            score = 1
        if score > 0:
            scored_records.append((score, record))

    scored_records.sort(key=lambda item: (-item[0], str(item[1].get("file") or "")))
    fallback_selected = [record for _, record in scored_records]
    if not fallback_selected:
        fallback_selected = list(records)
    return fallback_selected[:limit] if limit else fallback_selected[: min(4, len(fallback_selected))]


def _planner_system_prompt() -> str:
    return dedent(
        """
        You are a senior DFIR tshark planning assistant.
        Another model already wrote the high-level incident summary.
        Your job is to identify weak sections in ABCD and produce tshark plans to investigate them.
        You are planning for a constrained sandbox executor, similar to a tool-card workflow.

        A = Initial Access
        B = Lateral Movement & Discovery
        C = Exfiltration
        D = Payload Deployment

        Available tool:
        - tshark over one PCAP at a time
        - You may only provide a Wireshark display filter plus a compact list of fields

        Allowed fields:
        - frame.time_epoch
        - ip.src
        - ip.dst
        - tcp.srcport
        - tcp.dstport
        - tcp.flags
        - http.request.method
        - http.host
        - http.request.uri
        - tls.handshake.extensions_server_name
        - smb.cmd
        - dcerpc.cn_call_id

        Display-filter rules:
        - Use simple, valid Wireshark display syntax only.
        - Prefer ==, !=, &&, ||, parentheses, and repeated comparisons.
        - Do not use regex operators like ~.
        - Do not use set syntax like in { ... }.
        - Do not invent unsupported field names.
        - For multiple IPs or ports, expand them with explicit || comparisons.
        - Keep filters narrow and anchored to hosts already present in the record.

        Investigation intent by stage:
        - A Initial Access:
          Prefer remote-management ingress around a suspected patient-zero host.
          Good anchors: tcp.dstport == 3389, tcp.dstport == 5985, tcp.dstport == 5986.
          Focus on external-to-internal flows, repeated source churn, or bursty access.
          Do not waste queries on broad internal traffic.
        - B Lateral Movement & Discovery:
          Prefer internal SMB/RPC/DCERPC movement between likely compromised hosts and the domain controller.
          Good anchors: tcp.dstport == 445, tcp.dstport == 135, dcerpc.cn_call_id.
          Focus on fan-out, repeated host-to-host attempts, or DC-related RPC.
        - C Exfiltration:
          Prefer outbound HTTP/TLS evidence.
          Good anchors: http.request.method, http.host, http.request.uri, tls.handshake.extensions_server_name.
          Focus on temp.sh, outbound uploads, or suspicious external destinations already present in the record.
          Do not use RDP-only filters for exfiltration.
        - D Payload Deployment:
          Prefer internal deployment behavior from a compromised internal host to other internal hosts.
          Good anchors: tcp.dstport == 445, tcp.dstport == 135, tcp.dstport == 3389, smb.cmd.
          Focus on internal-to-internal propagation or admin-share style activity.
          Do not use external-to-internal RDP as a D query unless the record explicitly says deployment was external.

        Anti-patterns:
        - Do not label a query as exfiltration if the filter is only RDP.
        - Do not label a query as payload deployment if it only shows generic external scanning.
        - Do not query the same host/port pattern repeatedly with cosmetic differences.
        - If the record already strongly supports a section, prefer another unresolved section instead.
        - When in doubt, produce fewer, sharper queries.

        Output strict JSON only:
        {
          "weak_sections": ["A","C"],
          "queries": [
            {
              "name": "initial_access_winrm_focus",
              "stage": "A",
              "display_filter": "tcp.port == 5985 && ip.addr == 10.0.0.5",
              "fields": ["frame.time_epoch","ip.src","ip.dst","tcp.srcport","tcp.dstport","tcp.flags"],
              "max_rows": 80,
              "reason": "Check whether WinRM is present around the suspected patient zero."
            }
          ]
        }

        Rules:
        - Use at most 4 queries.
        - Keep fields compact.
        - Prefer display filters that narrow to the most relevant host(s) from the record.
        - Investigate only weak or ambiguous sections.
        - If a section is already strong, omit it.
        - Query names must describe evidence, not conclusions.
        - Each query reason must mention the exact host or signal it is trying to validate.
        - Do not explain outside JSON.
        """
    ).strip()


def _heuristic_campaign_plan(aggregate: dict[str, Any], report_text: str) -> dict[str, Any]:
    weak_sections: list[str] = []
    reasons: dict[str, str] = {}

    report_lower = report_text.lower()
    if _section_looks_weak(report_text, "Initial Access") and not (aggregate.get("files_with_external_rdp") or aggregate.get("files_with_vpn_like_ingress")):
        weak_sections.append("A")
        reasons["A"] = "Initial access remains weak and lacks direct remote-management confirmation."
    if _section_looks_weak(report_text, "Lateral Movement & Discovery") or (
        not aggregate.get("files_with_smb_rpc_scanning") and not aggregate.get("files_with_dcerpc_account_markers")
    ):
        weak_sections.append("B")
        reasons["B"] = "Discovery and lateral movement are still thin or mostly inferred."
    if _section_looks_weak(report_text, "Exfiltration") or (
        not aggregate.get("files_with_temp_sh_hits")
        and not aggregate.get("files_with_outbound_exfil_candidates")
        and not aggregate.get("files_with_large_http_uploads")
    ):
        weak_sections.append("C")
        reasons["C"] = "Exfiltration remains under-evidenced and needs targeted outbound verification."
    if _section_looks_weak(report_text, "Payload Deployment") or (
        not aggregate.get("files_with_manual_payload_deployment")
        and not aggregate.get("files_with_internal_rdp_spread")
        and not aggregate.get("files_with_recovered_payload_artifacts")
    ):
        weak_sections.append("D")
        reasons["D"] = "Payload deployment is still mostly inferred or lacks recovered artifacts."

    if not weak_sections and "weak" in report_lower:
        weak_sections = ["B", "C", "D"]
        reasons = {
            "B": "Discovery remains weak in the report narrative.",
            "C": "Exfiltration remains weak in the report narrative.",
            "D": "Payload deployment remains weak in the report narrative.",
        }

    return {
        "weak_sections": weak_sections[:3],
        "section_reasons": {key: reasons[key] for key in weak_sections[:3]},
    }


def _heuristic_record_plan(
    record: dict[str, Any],
    aggregate: dict[str, Any],
    *,
    focus_sections: list[str] | None = None,
) -> dict[str, Any]:
    requested_sections = [item for item in (focus_sections or []) if item in {"A", "B", "C", "D"}]
    if not requested_sections:
        if not record.get("possible_outbound_exfil_flows") and not record.get("temp_sh_hits") and not record.get("large_http_uploads"):
            requested_sections.append("C")
        if not record.get("manual_payload_deployment_candidates") and not record.get("suspicious_internal_rdp_spread"):
            requested_sections.append("D")
        if not record.get("suspicious_smb_rpc_scanners") and not record.get("possible_dcerpc_account_changes"):
            requested_sections.append("B")
    if not requested_sections:
        requested_sections = ["B"]

    candidate_hosts = _candidate_hosts(record, aggregate)
    queries: list[dict[str, Any]] = []
    for section in requested_sections:
        query = _heuristic_query_for_section(section, record, candidate_hosts)
        if query:
            queries.append(query)
        if len(queries) >= 4:
            break

    return {
        "weak_sections": requested_sections[:4],
        "queries": queries,
    }


def _campaign_system_prompt() -> str:
    return dedent(
        """
        You are a DFIR campaign-review assistant.
        Read the incident report and aggregate signals.
        Decide which ABCD sections remain weak or ambiguous at the campaign level.

        Decision rules:
        - Mark a section weak only if the report still sounds inferred, caveated, or under-evidenced.
        - Do not keep choosing the same section just because it has many hits; choose it only if the evidence is still weak.
        - Prefer A if initial compromise is not directly evidenced.
        - Prefer C if exfiltration destination, protocol, or upload evidence is still thin.
        - Prefer B or D only when host-to-host movement or deployment is still mostly inferred.
        - Return only the sections that genuinely need follow-up, not all possibly relevant sections.

        Output strict JSON only:
        {
          "weak_sections": ["B", "D"],
          "section_reasons": {
            "B": "Discovery and lateral movement remain suggestive but under-validated.",
            "D": "Payload deployment is still mostly inferred."
          }
        }
        """
    ).strip()


def _build_campaign_prompt(aggregate: dict[str, Any], report_text: str) -> str:
    compact_aggregate = {
        "file_count": aggregate.get("file_count"),
        "attack_flow": (aggregate.get("attack_flow") or {}).get("likely_path"),
        "files_with_external_rdp": aggregate.get("files_with_external_rdp"),
        "files_with_smb_rpc_scanning": aggregate.get("files_with_smb_rpc_scanning"),
        "files_with_dcerpc_account_markers": aggregate.get("files_with_dcerpc_account_markers"),
        "files_with_temp_sh_hits": aggregate.get("files_with_temp_sh_hits"),
        "files_with_outbound_exfil_candidates": aggregate.get("files_with_outbound_exfil_candidates"),
        "files_with_manual_payload_deployment": aggregate.get("files_with_manual_payload_deployment"),
        "files_with_internal_rdp_spread": aggregate.get("files_with_internal_rdp_spread"),
        "top_patient_zero_candidates": (aggregate.get("top_patient_zero_candidates") or [])[:5],
    }
    return dedent(
        f"""
        Incident report:
        {report_text}

        Aggregate signals:
        {json.dumps(compact_aggregate, indent=2)}

        Which ABCD sections still look weak or ambiguous enough to justify targeted tshark follow-up?
        """
    ).strip()


def _build_prompt(
    record: dict[str, Any],
    aggregate: dict[str, Any],
    report_text: str,
    *,
    focus_sections: list[str] | None = None,
) -> str:
    candidate_hosts = [
        host
        for host in [
            record.get("deep_dive_focus_host"),
            (record.get("patient_zero_candidate") or {}).get("internal_ip"),
        ]
        if host
    ]
    candidate_hosts.extend(
        item.get("internal_ip")
        for item in (aggregate.get("top_patient_zero_candidates") or [])[:5]
        if item.get("internal_ip")
    )
    deduped_hosts: list[str] = []
    seen_hosts = set()
    for host in candidate_hosts:
        if host not in seen_hosts:
            seen_hosts.add(host)
            deduped_hosts.append(host)

    compact_record = {
        "file": record.get("file"),
        "path": record.get("path"),
        "patient_zero_candidate": record.get("patient_zero_candidate"),
        "suspicious_external_rdp_count": record.get("suspicious_external_rdp_count"),
        "suspicious_smb_rpc_scanners": record.get("suspicious_smb_rpc_scanners"),
        "possible_dcerpc_account_changes": record.get("possible_dcerpc_account_changes"),
        "temp_sh_hits": record.get("temp_sh_hits"),
        "possible_outbound_exfil_flows": record.get("possible_outbound_exfil_flows"),
        "large_http_uploads": record.get("large_http_uploads"),
        "suspicious_internal_rdp_spread": record.get("suspicious_internal_rdp_spread"),
        "manual_payload_deployment_candidates": record.get("manual_payload_deployment_candidates"),
        "deep_dive_focus_host": record.get("deep_dive_focus_host"),
        "sandbox_verification": record.get("sandbox_verification"),
        "candidate_hosts_for_filtering": deduped_hosts[:6],
    }
    compact_aggregate = {
        "file_count": aggregate.get("file_count"),
        "attack_flow": (aggregate.get("attack_flow") or {}).get("likely_path"),
        "top_patient_zero_candidates": (aggregate.get("top_patient_zero_candidates") or [])[:5],
    }
    focus = [item for item in (focus_sections or []) if item in {"A", "B", "C", "D"}]
    report_excerpt = _relevant_report_excerpt(report_text, focus)
    return dedent(
        f"""
        Relevant incident-report excerpt:
        {report_excerpt}

        Aggregate context:
        {json.dumps(compact_aggregate, indent=2)}

        Per-PCAP record to inspect:
        {json.dumps(compact_record, indent=2)}

        Campaign-level weak sections to focus on:
        {json.dumps(focus, indent=2)}

        Author compact tshark query plans only for the relevant weak sections for this file.
        Prefer the candidate hosts already listed in the record.
        Avoid generic queries that are not tightly tied to this PCAP's evidence.
        """
    ).strip()


def _relevant_report_excerpt(report_text: str, focus_sections: list[str]) -> str:
    normalized = [item for item in focus_sections if item in SECTION_TITLES]
    if not report_text.strip():
        return ""
    if not normalized:
        return report_text[:2400]

    lines = report_text.splitlines()
    selected_blocks: list[str] = []
    current_heading = ""
    current_lines: list[str] = []

    def flush() -> None:
        if not current_heading:
            return
        for section, title in SECTION_TITLES.items():
            if section in normalized and current_heading.lower() == f"## {title}".lower():
                block = "\n".join([current_heading, *current_lines]).strip()
                if block:
                    selected_blocks.append(block)
                return

    for line in lines:
        if line.startswith("## "):
            flush()
            current_heading = line.strip()
            current_lines = []
            continue
        if current_heading:
            current_lines.append(line)
    flush()

    excerpt = "\n\n".join(selected_blocks).strip()
    if not excerpt:
        excerpt = report_text[:2400]
    return excerpt[:4000]


def _section_looks_weak(report_text: str, title: str) -> bool:
    block = _section_block(report_text, title)
    if not block:
        return False
    lowered = block.lower()
    weakness_markers = (
        "no direct evidence",
        "weakly supported",
        "heuristic",
        "inferred",
        "unconfirmed",
        "gap",
        "limited",
        "thin",
        "absence of",
        "no payload artifacts",
    )
    return any(marker in lowered for marker in weakness_markers)


def _section_block(report_text: str, title: str) -> str:
    wanted_heading = f"## {title}".lower()
    current_heading = ""
    current_lines: list[str] = []
    selected = ""

    def flush() -> None:
        nonlocal selected
        if current_heading == wanted_heading:
            selected = "\n".join(current_lines).strip()

    for raw_line in report_text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            flush()
            current_heading = line.lower()
            current_lines = []
            continue
        if current_heading:
            current_lines.append(raw_line)
    flush()
    return selected


def _candidate_hosts(record: dict[str, Any], aggregate: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    for host in [
        record.get("deep_dive_focus_host"),
        (record.get("patient_zero_candidate") or {}).get("internal_ip"),
    ]:
        if host and host not in hosts:
            hosts.append(host)
    for item in (aggregate.get("top_patient_zero_candidates") or [])[:5]:
        host = item.get("internal_ip")
        if host and host not in hosts:
            hosts.append(host)
    return hosts[:6]


def _ip_filter(hosts: list[str]) -> str:
    comparisons = [f"ip.addr == {host}" for host in hosts if host]
    if not comparisons:
        return ""
    return "(" + " || ".join(comparisons) + ")"


def _heuristic_query_for_section(section: str, record: dict[str, Any], hosts: list[str]) -> dict[str, Any] | None:
    host_filter = _ip_filter(hosts)
    if section == "A":
        display_filter = "tcp.dstport == 3389"
        if host_filter:
            display_filter += f" && {host_filter}"
        return {
            "name": "initial_access_rdp_focus",
            "stage": "A",
            "display_filter": display_filter,
            "fields": ["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.flags"],
            "max_rows": 80,
            "reason": f"Confirm external RDP ingress around suspected patient-zero hosts {', '.join(hosts) or 'already flagged systems'}.",
        }
    if section == "B":
        display_filter = "(tcp.dstport == 445 || tcp.dstport == 135)"
        if host_filter:
            display_filter += f" && {host_filter}"
        return {
            "name": "lateral_movement_smb_rpc_focus",
            "stage": "B",
            "display_filter": display_filter,
            "fields": ["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport", "dcerpc.cn_call_id"],
            "max_rows": 120,
            "reason": f"Check SMB/RPC discovery or admin activity involving hosts {', '.join(hosts) or 'already flagged systems'}.",
        }
    if section == "C":
        exfil_candidates = record.get("possible_outbound_exfil_flows") or []
        display_filter = (
            'http.request.method == "POST" || http.request.method == "PUT" || '
            'http.host contains "temp.sh" || tls.handshake.extensions_server_name contains "temp.sh"'
        )
        if exfil_candidates:
            candidate_ips = []
            for item in exfil_candidates[:3]:
                for key in ("external_ip", "dst_ip", "ip"):
                    value = item.get(key)
                    if value and value not in candidate_ips:
                        candidate_ips.append(value)
            if candidate_ips:
                display_filter += " && (" + " || ".join(f"ip.addr == {value}" for value in candidate_ips) + ")"
        elif host_filter:
            display_filter += f" && {host_filter}"
        return {
            "name": "exfiltration_http_temp_sh_focus",
            "stage": "C",
            "display_filter": display_filter,
            "fields": [
                "frame.time_epoch",
                "ip.src",
                "ip.dst",
                "tcp.dstport",
                "http.request.method",
                "http.host",
                "http.request.uri",
                "tls.handshake.extensions_server_name",
            ],
            "max_rows": 100,
            "reason": "Validate outbound upload behavior and temp.sh-style destinations around the candidate exfil flow.",
        }
    if section == "D":
        display_filter = "(tcp.dstport == 3389 || tcp.dstport == 445 || tcp.dstport == 135)"
        if host_filter:
            display_filter += f" && {host_filter}"
        return {
            "name": "payload_deployment_internal_spread_focus",
            "stage": "D",
            "display_filter": display_filter,
            "fields": ["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport", "tcp.flags", "smb.cmd"],
            "max_rows": 120,
            "reason": f"Check whether suspected compromised hosts {', '.join(hosts) or 'already flagged systems'} spread internally over RDP/SMB/RPC.",
        }
    return None


def _parse_plan(text: str) -> dict[str, Any] | None:
    text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    weak_sections = [item for item in data.get("weak_sections", []) if item in {"A", "B", "C", "D"}]
    queries = data.get("queries", [])
    if not isinstance(queries, list):
        queries = []
    return {
        "weak_sections": weak_sections,
        "queries": queries,
    }


def _parse_campaign_plan(text: str) -> dict[str, Any] | None:
    text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    weak_sections = [item for item in data.get("weak_sections", []) if item in {"A", "B", "C", "D"}]
    section_reasons = data.get("section_reasons", {})
    if not isinstance(section_reasons, dict):
        section_reasons = {}
    return {
        "weak_sections": weak_sections,
        "section_reasons": section_reasons,
    }
