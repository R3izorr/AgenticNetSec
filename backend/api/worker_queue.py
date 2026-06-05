from __future__ import annotations

import os
from typing import Any


DEFAULT_REDIS_URL = "redis://localhost:6379/0"
DEFAULT_QUEUE_NAME = "agenticnetsec"


class QueueUnavailable(RuntimeError):
    pass


def redis_url() -> str:
    return os.getenv("REDIS_URL", DEFAULT_REDIS_URL)


def queue_name() -> str:
    return os.getenv("AGENTIC_WORKER_QUEUE", DEFAULT_QUEUE_NAME)


def enqueue_worker_call(func_path: str, *args: Any, **kwargs: Any) -> str:
    try:
        from redis import Redis
        from rq import Queue
    except ImportError as exc:
        raise QueueUnavailable("Redis queue dependencies are not installed. Run pip install -r requirements.txt.") from exc

    try:
        redis_conn = Redis.from_url(redis_url())
        redis_conn.ping()
        queue = Queue(queue_name(), connection=redis_conn)
        job = queue.enqueue(func_path, *args, **kwargs)
        return str(job.id)
    except Exception as exc:  # noqa: BLE001
        raise QueueUnavailable(f"Worker queue is unavailable: {exc}") from exc
