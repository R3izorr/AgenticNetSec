from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Iterable
from urllib import error as urllib_error
from urllib import request as urllib_request


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
ANALYSIS_PROFILES = ("fast", "standard", "full")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Submit one directory of PCAP files to the AgenticNetSec batch API."
    )
    parser.add_argument(
        "pcap_dir",
        help="Directory containing the PCAP files to submit.",
    )
    parser.add_argument(
        "--api-base-url",
        default="http://127.0.0.1:8000",
        help="Base URL of the FastAPI service. Default: http://127.0.0.1:8000",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="worker_count value sent to the batch API. Default: 4",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively discover PCAP files under the directory.",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="1-based start index in the discovered file list. Default: 1",
    )
    parser.add_argument(
        "--end",
        type=int,
        help="1-based end index in the discovered file list. Default: all discovered files",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional limit on how many discovered files to submit.",
    )
    parser.add_argument(
        "--analysis-profile",
        choices=ANALYSIS_PROFILES,
        default="standard",
        help="Stage-1 deterministic profile to use. Default: standard",
    )
    return parser


def iter_pcaps(root: Path, *, recursive: bool) -> list[Path]:
    if recursive:
        candidates: Iterable[Path] = root.rglob("*")
    else:
        candidates = root.iterdir()

    return sorted(
        [
            path
            for path in candidates
            if path.is_file() and path.suffix.lower() in PCAP_EXTENSIONS
        ],
        key=lambda path: str(path.relative_to(root)),
    )


def submit_batch(
    *,
    api_base_url: str,
    worker_count: int,
    files: list[Path],
    analysis_profile: str,
) -> dict[str, Any]:
    payload = json.dumps(
        {
            "worker_count": worker_count,
            "analysis_profile": analysis_profile,
            "pcap_paths": [str(path) for path in files],
        }
    ).encode("utf-8")
    request = urllib_request.Request(
        url=f"{api_base_url.rstrip('/')}/api/v1/analysis/batch",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib_request.urlopen(request, timeout=300) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    args = build_parser().parse_args()

    pcap_dir = Path(args.pcap_dir).expanduser().resolve()
    if not pcap_dir.exists() or not pcap_dir.is_dir():
        raise SystemExit(f"PCAP directory not found: {pcap_dir}")

    files = iter_pcaps(pcap_dir, recursive=args.recursive)
    total_discovered = len(files)

    if args.start < 1:
        raise SystemExit("--start must be 1 or greater.")
    if args.end is not None and args.end < args.start:
        raise SystemExit("--end must be greater than or equal to --start.")

    start_index = args.start - 1
    end_index = args.end if args.end is not None else total_discovered
    files = files[start_index:end_index]

    if args.limit is not None:
        files = files[: max(0, args.limit)]

    if not files:
        raise SystemExit(f"No PCAP files found in {pcap_dir}")

    selected_end = start_index + len(files)
    print(f"Discovered {total_discovered} file(s) in {pcap_dir}")
    print(f"Selected range: {args.start} to {selected_end}")
    print(f"Submitting {len(files)} file(s) from {pcap_dir}")
    print(f"API base URL: {args.api_base_url}")
    print(f"worker_count: {args.workers}")
    print(f"analysis_profile: {args.analysis_profile}")

    try:
        payload = submit_batch(
            api_base_url=args.api_base_url,
            worker_count=args.workers,
            files=files,
            analysis_profile=args.analysis_profile,
        )
    except urllib_error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Batch submit failed: HTTP {exc.code}\n{body}") from exc
    except urllib_error.URLError as exc:
        raise SystemExit(f"Batch submit failed: {exc}") from exc

    skipped_files = payload.get("skipped_files") or []
    accepted_file_count = payload.get("accepted_file_count", len(files))
    if skipped_files:
        print(f"Skipped existing files: {len(skipped_files)}")
        for item in skipped_files[:10]:
            print(
                "SKIP "
                f"{item.get('filename') or item.get('path')} "
                f"reason={item.get('reason')} "
                f"existing_job={item.get('existing_analysis_job_id')} "
                f"status={item.get('existing_status')}"
            )
        if len(skipped_files) > 10:
            print(f"... and {len(skipped_files) - 10} more skipped file(s)")

    total_job_id = payload.get("total_job_id")
    if not total_job_id:
        print("No new files were submitted. All selected files were already in the system.")
        return 0

    print("Batch submit accepted.")
    print(f"accepted_file_count: {accepted_file_count}")
    print(f"total_job_id: {total_job_id}")
    print(f"status_url: {args.api_base_url.rstrip('/')}/api/v1/total-jobs/{total_job_id}")
    print(f"ui_url: http://localhost:3000/total-jobs/{total_job_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
