from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class ToolPolicy:
    timeout_seconds: float = 60.0
    retries: int = 2


class ToolExecutor:
    def __init__(self, allowed_tools: set[str]):
        self.allowed_tools = allowed_tools

    def execute(
        self,
        tool_name: str,
        func: Callable[..., Any],
        *args: Any,
        policy: ToolPolicy | None = None,
        fallback: Callable[..., Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        if tool_name not in self.allowed_tools:
            raise PermissionError(f"Tool '{tool_name}' is not in allowlist")

        policy = policy or ToolPolicy()
        attempts = max(1, policy.retries + 1)

        last_error: Exception | None = None
        for _ in range(attempts):
            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(func, *args, **kwargs)
                    return future.result(timeout=policy.timeout_seconds)
            except FutureTimeout as exc:
                last_error = TimeoutError(f"Tool '{tool_name}' timed out")
            except Exception as exc:  # noqa: BLE001
                last_error = exc

        if fallback is not None:
            return fallback(*args, **kwargs)

        raise RuntimeError(f"Tool '{tool_name}' failed after retries: {last_error}")
