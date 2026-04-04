from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SRC_DIR = PROJECT_ROOT / "backend" / "src"
CONFIG_DIR = PROJECT_ROOT / "backend" / "config"

for module_path in (SRC_DIR, CONFIG_DIR):
    module_path_str = str(module_path)
    if module_path_str not in sys.path:
        sys.path.insert(0, module_path_str)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze a PCAP and generate structured forensic findings.")
    parser.add_argument("pcap", help="Path to the PCAP file to analyze")
    parser.add_argument("--provider", choices=["gemini", "openai", "groq", "ollama"], default="gemini", help="AI provider to use for reporting")
    parser.add_argument("--model", help="Model to use when AI reporting is enabled. If omitted, provider defaults from local_settings.py are used.")
    parser.add_argument("--dive", action="store_true", help="Run the slower attack-focused deep dive aligned to the challenge scenario")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI reporting and use the local deterministic report")
    parser.add_argument("--require-ai", action="store_true", help="Fail instead of silently falling back when AI report generation fails")
    parser.add_argument("--json-file", help="Optional path to write the summary/findings/report bundle as JSON")
    parser.add_argument("--report-file", help="Optional path to write the generated Markdown report")
    parser.add_argument("--print-json", action="store_true", help="Print the structured JSON bundle after the report")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        from analyzer import analyze_pcap_summary
        from detectors import collect_all_findings
        from deep_dive import build_deep_dive, render_deep_dive_markdown
        from report_ai import generate_report
        from sandbox_verifier import run_sandbox_verification, sandbox_verification_enabled
    except ModuleNotFoundError as exc:
        parser.error(f"Missing dependency: {exc.name}. Install requirements with `python3 -m pip install -r requirements.txt`.")

    pcap_path = str(Path(args.pcap).expanduser().resolve())
    summary = analyze_pcap_summary(pcap_path)
    findings = collect_all_findings(pcap_path)
    deep_dive = build_deep_dive(pcap_path, findings) if args.dive else None
    sandbox = run_sandbox_verification(pcap_path, findings) if sandbox_verification_enabled() else None
    report_findings = (
        {
            **findings,
            "deep_dive": deep_dive,
            "suspected_attack_flow": (deep_dive or {}).get("suspected_attack_flow"),
            "sandbox_verification": sandbox,
        }
        if (deep_dive or sandbox)
        else findings
    )
    report = generate_report(
        summary,
        report_findings,
        provider=args.provider,
        model=args.model,
        use_ai=not args.no_ai,
        require_ai=args.require_ai,
    )
    if deep_dive:
        report = f"{report}\n\n{render_deep_dive_markdown(deep_dive)}"
    bundle = {"pcap_path": pcap_path, "summary": summary, "findings": findings, "report": report}
    if deep_dive:
        bundle["deep_dive"] = deep_dive
    if sandbox:
        bundle["sandbox_verification"] = sandbox

    print(report)

    if args.report_file:
        Path(args.report_file).expanduser().write_text(report + "\n", encoding="utf-8")
    if args.json_file:
        Path(args.json_file).expanduser().write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(bundle, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
