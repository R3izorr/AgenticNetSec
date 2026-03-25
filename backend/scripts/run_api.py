from __future__ import annotations

import argparse
from pathlib import Path
import sys

import uvicorn

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the AgenticNetSec FastAPI service.")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind the API server to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind the API server to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for local development")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    uvicorn.run(
        "backend.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
