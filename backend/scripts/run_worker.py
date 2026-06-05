from __future__ import annotations

import argparse
from pathlib import Path
import sys

from redis import Redis
from rq import Worker

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.api.worker_queue import queue_name, redis_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the AgenticNetSec Redis worker.")
    parser.add_argument("--redis-url", default=redis_url(), help="Redis URL for the worker queue")
    parser.add_argument("--queue", default=queue_name(), help="RQ queue name to consume")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    connection = Redis.from_url(args.redis_url)
    worker = Worker([args.queue], connection=connection)
    worker.work()
