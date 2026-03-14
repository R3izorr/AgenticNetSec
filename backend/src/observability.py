from __future__ import annotations

import time
from contextlib import contextmanager

try:
    import psutil
except Exception:  # noqa: BLE001
    psutil = None


class MetricsTracker:
    def __init__(self) -> None:
        self._phase_starts: dict[str, float] = {}
        self.phase_timings: dict[str, float] = {}
        self.started_at = time.perf_counter()
        self.cpu_percent_peak: float | None = None
        self.ram_mb_peak: float | None = None

    @contextmanager
    def phase(self, name: str):
        self._phase_starts[name] = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - self._phase_starts[name]
            self.phase_timings[name] = self.phase_timings.get(name, 0.0) + duration
            self._capture_resource_snapshot()

    def _capture_resource_snapshot(self) -> None:
        if psutil is None:
            return
        process = psutil.Process()
        cpu = psutil.cpu_percent(interval=None)
        ram_mb = process.memory_info().rss / (1024 * 1024)

        if self.cpu_percent_peak is None or cpu > self.cpu_percent_peak:
            self.cpu_percent_peak = cpu
        if self.ram_mb_peak is None or ram_mb > self.ram_mb_peak:
            self.ram_mb_peak = ram_mb

    def total_runtime_seconds(self) -> float:
        return time.perf_counter() - self.started_at


def estimate_cost(
    llm_tokens_in: int,
    llm_tokens_out: int,
    price_in_per_million: float = 0.50,
    price_out_per_million: float = 1.50,
    compute_cost: float = 0.0,
    storage_cost: float = 0.0,
) -> tuple[float, float, float, float]:
    llm_cost = (llm_tokens_in / 1_000_000) * price_in_per_million + (llm_tokens_out / 1_000_000) * price_out_per_million
    total = compute_cost + llm_cost + storage_cost
    return compute_cost, llm_cost, storage_cost, total
