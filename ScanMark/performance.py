"""Small, dependency-free runtime controls for ScanMark's hot paths.

The module intentionally avoids a metrics network client.  Workers keep a
bounded diagnostic window which can be scraped through the application's
Prometheus endpoint, while the bounded executor prevents a lecture burst from
turning notification work into an unbounded in-process queue.
"""

from __future__ import annotations

import math
import threading
import time
from collections import Counter, defaultdict, deque
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable
from sqlalchemy.pool import QueuePool


class RuntimeMetrics:
    """Thread-safe counters, gauges, and bounded latency samples."""

    def __init__(self, sample_limit: int = 4096):
        self._lock = threading.Lock()
        self._counters: Counter[str] = Counter()
        self._gauges: dict[str, float] = {}
        self._samples = defaultdict(lambda: deque(maxlen=sample_limit))

    def increment(self, name: str, amount: float = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def observe_ms(self, name: str, value_ms: float) -> None:
        with self._lock:
            self._samples[name].append(max(0.0, float(value_ms)))

    def snapshot(self) -> dict:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            samples = {name: list(values) for name, values in self._samples.items()}
        histograms = {}
        for name, values in samples.items():
            ordered = sorted(values)
            histograms[name] = {
                "count": len(ordered),
                "p50": _percentile(ordered, 0.50),
                "p95": _percentile(ordered, 0.95),
                "p99": _percentile(ordered, 0.99),
                "max": ordered[-1] if ordered else 0,
            }
        return {"counters": counters, "gauges": gauges, "histograms": histograms}

    def prometheus(self) -> str:
        snapshot = self.snapshot()
        lines = []
        for name, value in sorted(snapshot["counters"].items()):
            lines.append(f"scanmark_{_metric_name(name)}_total {value}")
        for name, value in sorted(snapshot["gauges"].items()):
            lines.append(f"scanmark_{_metric_name(name)} {value}")
        for name, stats in sorted(snapshot["histograms"].items()):
            safe_name = _metric_name(name)
            lines.append(f"scanmark_{safe_name}_count {stats['count']}")
            for percentile in ("p50", "p95", "p99", "max"):
                lines.append(
                    f'scanmark_{safe_name}_ms{{stat="{percentile}"}} '
                    f"{stats[percentile]:.3f}"
                )
        return "\n".join(lines) + "\n"


def _metric_name(name: str) -> str:
    return "".join(character if character.isalnum() else "_" for character in name).strip("_")


def _percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0
    return values[min(len(values) - 1, max(0, math.ceil(len(values) * ratio) - 1))]


class BoundedExecutor:
    """Thread pool with an explicit, observable pending-work ceiling.

    ``submit`` is deliberately non-blocking.  A full queue returns ``None`` so
    callers can record/drop optional work without adding latency to a scan.
    """

    def __init__(self, *, name: str, max_workers: int, max_queue: int, metrics: RuntimeMetrics):
        self.name = name
        self.max_workers = max_workers
        self.max_queue = max_queue
        self._metrics = metrics
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=name)
        self._capacity = threading.BoundedSemaphore(max_workers + max_queue)
        self._lock = threading.Lock()
        self._queued_at: deque[float] = deque()
        self._active = 0

    def submit(self, function: Callable, *args, **kwargs) -> Future | None:
        if not self._capacity.acquire(blocking=False):
            self._metrics.increment(f"{self.name}.rejected")
            self._publish_gauges()
            return None

        queued_at = time.perf_counter()
        with self._lock:
            self._queued_at.append(queued_at)
        self._metrics.increment(f"{self.name}.submitted")
        self._publish_gauges()

        def run():
            with self._lock:
                started_at = self._queued_at.popleft() if self._queued_at else queued_at
                self._active += 1
            self._metrics.observe_ms(f"{self.name}.queue_delay", (time.perf_counter() - started_at) * 1000)
            self._publish_gauges()
            try:
                return function(*args, **kwargs)
            finally:
                with self._lock:
                    self._active -= 1
                self._capacity.release()
                self._metrics.increment(f"{self.name}.completed")
                self._publish_gauges()

        try:
            return self._executor.submit(run)
        except RuntimeError:
            with self._lock:
                try:
                    self._queued_at.remove(queued_at)
                except ValueError:
                    pass
            self._capacity.release()
            self._metrics.increment(f"{self.name}.rejected")
            self._publish_gauges()
            return None

    def _publish_gauges(self) -> None:
        with self._lock:
            queue_depth = len(self._queued_at)
            active = self._active
            oldest_ms = (
                (time.perf_counter() - self._queued_at[0]) * 1000
                if self._queued_at else 0
            )
        self._metrics.gauge(f"{self.name}.queue_depth", queue_depth)
        self._metrics.gauge(f"{self.name}.active", active)
        self._metrics.gauge(f"{self.name}.oldest_job_ms", oldest_ms)

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=not wait)


runtime_metrics = RuntimeMetrics()


class InstrumentedQueuePool(QueuePool):
    """QueuePool that records time spent waiting for an available connection."""

    def _do_get(self):
        started = time.perf_counter()
        try:
            return super()._do_get()
        finally:
            runtime_metrics.observe_ms(
                'db.pool.wait', (time.perf_counter() - started) * 1000
            )
