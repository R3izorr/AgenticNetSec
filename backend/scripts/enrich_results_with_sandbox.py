from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SRC_DIR = PROJECT_ROOT / "backend" / "src"
CONFIG_DIR = PROJECT_ROOT / "backend" / "config"

for module_path in (SRC_DIR, CONFIG_DIR):
    module_path_str = str(module_path)
    if module_path_str not in sys.path:
        sys.path.insert(0, module_path_str)

from sandbox_verifier import run_sandbox_verification, sandbox_verification_enabled
from sandbox_verifier import run_ai_tshark_queries
from payload_carver import run_payload_carving
from summarize_results import build_aggregate, load_results
from verification_planner import build_verification_plan
from report_ai import generate_results_report_result
from ai_tshark_planner import (
    build_ai_tshark_plan,
    build_campaign_weak_sections,
    build_case_summary,
    select_records_for_sections,
)


def load_jsonl(results_file: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with results_file.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"Invalid JSON on line {line_number} of {results_file}: {exc}"
                )
    return records


def write_jsonl(output_file: Path, records: list[dict[str, Any]]) -> None:
    with output_file.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def enrich_record(record: dict[str, Any]) -> dict[str, Any]:
    return enrich_record_with_plan(record, {"requested_checks": ["remote_management", "internal_scanning", "exfiltration", "payload_deployment"]})


def enrich_record_with_plan(record: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    pcap_path = record.get("path")
    if not pcap_path:
        record["sandbox_verification"] = {
            "enabled": True,
            "status": "skipped",
            "message": "Record has no path field.",
        }
        record["ai_verification_plan"] = plan
        return record

    requested_checks = plan.get("requested_checks") or ["remote_management", "internal_scanning", "exfiltration", "payload_deployment"]
    sandbox = run_sandbox_verification(pcap_path, requested_checks=requested_checks)
    record["sandbox_verification"] = sandbox
    record["ai_verification_plan"] = plan
    record["sandbox_verified_winrm_pairs"] = len(
        (sandbox.get("remote_management") or {}).get("verified_winrm_pairs", [])
    )
    record["sandbox_verified_temp_sh_flows"] = len(
        (sandbox.get("exfiltration") or {}).get("verified_temp_sh_flows", [])
    )
    return record


def _payload_carving_findings_from_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "manual_payload_deployment": {
            "candidates": list(record.get("manual_payload_deployment_candidates") or []),
        },
        "rdp_payload_deployment": {
            "spreaders": list(record.get("suspicious_internal_rdp_spread") or []),
        },
        "large_http_posts": {
            "uploads": list(record.get("large_http_uploads") or []),
        },
        "temp_sh_traffic": {
            "hits": list(record.get("temp_sh_hits") or []),
        },
    }


def _should_run_stage2_payload_carving(
    record: dict[str, Any],
    *,
    plan: dict[str, Any] | None = None,
    ai_plan: dict[str, Any] | None = None,
) -> bool:
    if record.get("manual_payload_deployment_candidates"):
        return True
    if record.get("suspicious_internal_rdp_spread"):
        return True
    if record.get("large_http_uploads"):
        return True
    if record.get("temp_sh_hits"):
        return True

    sandbox = record.get("sandbox_verification") or {}
    if ((sandbox.get("payload_deployment") or {}).get("candidate_count", 0) or 0) > 0:
        return True
    if (sandbox.get("exfiltration") or {}).get("verified_temp_sh_flows"):
        return True

    requested_checks = list((plan or {}).get("requested_checks") or [])
    if "payload_deployment" in requested_checks:
        weak_sections = list((ai_plan or {}).get("weak_sections") or [])
        return "D" in weak_sections

    return False


def _record_payload_artifacts_dir(
    artifacts_root: str | Path | None,
    record: dict[str, Any],
    index: int,
) -> str | None:
    if not artifacts_root:
        return None
    root = Path(artifacts_root).expanduser().resolve() / "sandbox-payload-carving"
    label = str(record.get("file") or Path(str(record.get("path") or f"record-{index}")).name or f"record-{index}")
    safe_label = re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("._") or f"record-{index}"
    return str(root / f"{index:03d}-{safe_label}")


def _resolve_payload_manifest_path(
    payload_carving: dict[str, Any],
    *,
    artifacts_dir: str | Path | None = None,
) -> str | None:
    manifest_path = payload_carving.get("manifest_path")
    if not manifest_path:
        return None
    resolved_manifest_path = Path(str(manifest_path))
    if resolved_manifest_path.is_absolute() or not artifacts_dir:
        return str(resolved_manifest_path)
    return str(Path(artifacts_dir).expanduser().resolve() / resolved_manifest_path)


def _merge_payload_carving_record(
    record: dict[str, Any],
    payload_carving: dict[str, Any],
    *,
    artifacts_dir: str | Path | None = None,
) -> dict[str, Any]:
    merged_payload_carving = dict(payload_carving)
    resolved_manifest_path = _resolve_payload_manifest_path(
        merged_payload_carving,
        artifacts_dir=artifacts_dir,
    )
    merged_payload_carving["manifest_path"] = resolved_manifest_path
    record["payload_carving"] = merged_payload_carving
    record["carved_payloads"] = list(merged_payload_carving.get("carved_payloads") or [])
    record["payload_iocs"] = list(merged_payload_carving.get("payload_iocs") or [])
    record["payload_deployment_confidence"] = float(merged_payload_carving.get("payload_deployment_confidence", 0.0) or 0.0)
    record["payload_carving_candidate_count"] = int(merged_payload_carving.get("candidate_count", 0) or 0)
    record["payload_carving_status"] = merged_payload_carving.get("status")
    record["payload_carving_manifest_path"] = resolved_manifest_path
    record["payload_carving_selected_candidates"] = list(merged_payload_carving.get("selected_candidates") or [])
    record["payload_carving_stage"] = "stage2_sandbox_enrichment"
    return record


def run_campaign_summary_route(
    records: list[dict[str, Any]],
    aggregate: dict[str, Any],
    *,
    report_provider: str = "gemini",
    report_model: str | None = None,
    planner_provider: str = "openrouter",
    planner_model: str | None = None,
    require_ai: bool = False,
    progress_callback: Callable[[str, float], None] | None = None,
    artifacts_dir: str | Path | None = None,
) -> dict[str, Any]:
    copied_records = [dict(record) for record in records]
    all_checks_plan = {
        "requested_checks": ["remote_management", "internal_scanning", "exfiltration", "payload_deployment"]
    }

    case_summary = build_case_summary(
        aggregate,
        copied_records,
        provider=report_provider,
        model=report_model,
        require_ai=require_ai,
    )
    if progress_callback:
        progress_callback("initial_summary", 0.35)

    campaign_plan = build_campaign_weak_sections(
        aggregate=aggregate,
        report_text=case_summary.get("report_text", ""),
        provider=planner_provider,
        model=planner_model,
        require_ai=require_ai,
    )
    weak_sections = campaign_plan.get("weak_sections") or []
    selected_follow_up_records = select_records_for_sections(
        records=copied_records,
        aggregate=aggregate,
        weak_sections=weak_sections,
    )
    selected_follow_up_paths = {
        record.get("path")
        for record in selected_follow_up_records
        if record.get("path")
    }
    if progress_callback:
        progress_callback("campaign_plan", 0.45)

    enriched_records: list[dict[str, Any]] = []
    for index, record in enumerate(copied_records, start=1):
        enriched_record = enrich_record_with_plan(dict(record), dict(all_checks_plan))

        ai_plan = None
        ai_review = None
        if enriched_record.get("path") in selected_follow_up_paths:
            ai_plan = build_ai_tshark_plan(
                record=enriched_record,
                aggregate=aggregate,
                report_text=case_summary.get("report_text", ""),
                focus_sections=weak_sections,
                provider=planner_provider,
                model=planner_model,
                require_ai=require_ai,
            )
            ai_review = run_ai_tshark_queries(enriched_record["path"], ai_plan.get("queries", []))
            enriched_record["ai_verification_plan"] = ai_plan
            enriched_record["ai_tshark_review"] = ai_review
            enriched_record["ai_tshark_query_count"] = len((ai_review.get("queries") or []))
        else:
            enriched_record["ai_tshark_query_count"] = 0

        if _should_run_stage2_payload_carving(
            enriched_record,
            plan=all_checks_plan,
            ai_plan=ai_plan,
        ):
            payload_artifacts_dir = _record_payload_artifacts_dir(artifacts_dir, enriched_record, index)
            payload_carving = run_payload_carving(
                enriched_record["path"],
                _payload_carving_findings_from_record(enriched_record),
                artifacts_dir=payload_artifacts_dir,
            )
            enriched_record = _merge_payload_carving_record(
                enriched_record,
                payload_carving,
                artifacts_dir=payload_artifacts_dir,
            )

        enriched_records.append(enriched_record)
        if progress_callback:
            progress_callback(
                "record_enrichment",
                0.45 + (0.35 * index / max(1, len(copied_records))),
            )

    final_aggregate = build_aggregate(enriched_records)
    if progress_callback:
        progress_callback("final_aggregate", 0.85)

    final_report = generate_results_report_result(
        final_aggregate,
        enriched_records,
        provider=report_provider,
        model=report_model,
        use_ai=True,
        require_ai=require_ai,
    )
    if progress_callback:
        progress_callback("final_report", 0.95)

    return {
        "initial_summary": case_summary,
        "campaign_plan": campaign_plan,
        "selected_follow_up_records": [
            {
                "file": record.get("file"),
                "path": record.get("path"),
            }
            for record in selected_follow_up_records
        ],
        "enriched_records": enriched_records,
        "aggregate": final_aggregate,
        "final_report": {
            "provider": final_report.provider,
            "model": final_report.model,
            "fallback_used": final_report.fallback_used,
            "llm_tokens_in": final_report.llm_tokens_in,
            "llm_tokens_out": final_report.llm_tokens_out,
            "ai_callable": not final_report.fallback_used,
            "status": "ai_generated" if not final_report.fallback_used else "fallback_report",
            "report_text": final_report.text,
        },
        "final_report_markdown": final_report.text,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read an existing scan_results JSONL file, use each record's PCAP path, and append sandbox verification results."
    )
    parser.add_argument("results_file", help="Path to the existing scan_results JSONL file")
    parser.add_argument(
        "--output-file",
        help="Optional path for the enriched JSONL output. Defaults to in-place update unless --dry-run is used.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Only enrich the first N records from the input file",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run sandbox verification even when the record already has sandbox_verification",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be enriched without writing output",
    )
    parser.add_argument(
        "--use-ai",
        action="store_true",
        help="Use the configured LLM provider to decide which ABCD sections are weak and which tshark checks to run.",
    )
    parser.add_argument(
        "--provider",
        default="auto",
        choices=["auto", "openrouter", "gemini", "openai", "groq", "ollama"],
        help="LLM provider for AI-guided verification planning.",
    )
    parser.add_argument(
        "--model",
        help="Optional model override for AI-guided verification planning.",
    )
    parser.add_argument(
        "--require-ai",
        action="store_true",
        help="Fail instead of falling back to heuristic planning when AI planning is unavailable.",
    )
    parser.add_argument(
        "--ai-tshark",
        action="store_true",
        help="Use Gemini for the case summary and a second AI planner to generate custom tshark queries for weak ABCD sections.",
    )
    parser.add_argument(
        "--summary-provider",
        default="gemini",
        choices=["auto", "openrouter", "gemini", "openai", "groq", "ollama"],
        help="Provider for the high-level case summary used before AI tshark planning.",
    )
    parser.add_argument(
        "--summary-model",
        help="Optional model override for the summary stage.",
    )
    parser.add_argument(
        "--summary-file",
        help="Optional existing Markdown report to reuse instead of generating a new summary with Gemini.",
    )
    parser.add_argument(
        "--planner-provider",
        default="openrouter",
        choices=["auto", "openrouter", "gemini", "openai", "groq", "ollama"],
        help="Provider for the tshark planning stage.",
    )
    parser.add_argument(
        "--planner-model",
        help="Optional model override for the planner stage.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not sandbox_verification_enabled():
        raise SystemExit(
            "Sandbox verification is not enabled. Set AGENTIC_SANDBOX_VERIFY=1 before running this script."
        )

    results_file = Path(args.results_file).expanduser().resolve()
    output_file = (
        Path(args.output_file).expanduser().resolve()
        if args.output_file
        else results_file
    )
    records = load_jsonl(results_file)
    aggregate_records = load_results(results_file)
    aggregate = build_aggregate(aggregate_records)

    selected = records[: max(0, args.limit)] if args.limit else records
    print(f"Loaded {len(records)} record(s) from {results_file}")
    print(f"Initially selected {len(selected)} record(s) for sandbox enrichment")

    case_summary = None
    campaign_plan = None
    if args.ai_tshark:
        summary_text = None
        if args.summary_file:
            summary_text = Path(args.summary_file).expanduser().resolve().read_text(encoding="utf-8")
        case_summary = build_case_summary(
            aggregate,
            aggregate_records,
            provider=args.summary_provider,
            model=args.summary_model,
            require_ai=args.require_ai,
            summary_text=summary_text,
        )
        print(
            f"SUMMARY provider={case_summary.get('provider')} model={case_summary.get('model') or '-'} "
            f"chars={len(case_summary.get('report_text', ''))}"
        )
        campaign_plan = build_campaign_weak_sections(
            aggregate=aggregate,
            report_text=case_summary.get("report_text", ""),
            provider=args.planner_provider,
            model=args.planner_model,
            require_ai=args.require_ai,
        )
        weak_sections = campaign_plan.get("weak_sections") or []
        section_selected = select_records_for_sections(
            records=records,
            aggregate=aggregate,
            weak_sections=weak_sections,
            limit=args.limit,
        )
        selected = section_selected
        print(
            f"CAMPAIGN weak={','.join(weak_sections) or '-'} "
            f"source={campaign_plan.get('planner_source', '-')}"
        )
        print(f"Related-file selection produced {len(selected)} record(s)")

    selected_paths = {record.get("path") for record in selected if record.get("path")}

    updated = 0
    for index, record in enumerate(records, start=1):
        if record.get("path") not in selected_paths:
            continue
        if record.get("sandbox_verification") and not args.force:
            print(f"SKIP [{index}/{len(records)}] {record.get('file', '-')}: sandbox_verification already present")
            continue
        file_name = record.get("file", f"record-{index}")
        pcap_path = record.get("path", "-")
        if args.ai_tshark and case_summary:
            plan = build_ai_tshark_plan(
                record=record,
                aggregate=aggregate,
                report_text=case_summary.get("report_text", ""),
                focus_sections=(campaign_plan or {}).get("weak_sections"),
                provider=args.planner_provider,
                model=args.planner_model,
                require_ai=args.require_ai,
            )
        else:
            plan = build_verification_plan(
                record,
                use_ai=args.use_ai,
                provider=args.provider,
                model=args.model,
                require_ai=args.require_ai,
            )
        print(f"RUN  [{index}/{len(records)}] {file_name} path={pcap_path}")
        print(
            f"PLAN [{index}/{len(records)}] weak={','.join(plan.get('weak_sections', [])) or '-'} "
            f"checks={','.join(plan.get('requested_checks', [])) or str(len(plan.get('queries', [])))} "
            f"source={plan.get('planner_source', 'heuristic')}"
        )
        if args.dry_run:
            continue
        if args.ai_tshark:
            record["ai_verification_plan"] = plan
            ai_review = run_ai_tshark_queries(pcap_path, plan.get("queries", []))
            record["ai_tshark_review"] = ai_review
            record["sandbox_verification"] = ai_review
            record["sandbox_verified_winrm_pairs"] = 0
            record["sandbox_verified_temp_sh_flows"] = 0
        else:
            enrich_record_with_plan(record, plan)
        updated += 1
        print(
            f"DONE [{index}/{len(records)}] {file_name} "
            f"winrm={record.get('sandbox_verified_winrm_pairs', 0)} "
            f"temp={record.get('sandbox_verified_temp_sh_flows', 0)} "
            f"ai_queries={len(((record.get('ai_tshark_review') or {}).get('queries') or []))}"
        )

    if args.dry_run:
        print("Dry run complete. No files written.")
        return 0

    write_jsonl(output_file, records)
    print(f"Wrote {len(records)} record(s) to {output_file}")
    print(f"Updated {updated} record(s) with sandbox verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
