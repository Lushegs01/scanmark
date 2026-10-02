"""Small, dependency-free runtime controls for ScanMark's hot paths.

The module intentionally avoids a metrics network client.  Workers keep a
bounded diagnostic window which can be scraped through the application's
Prometheus endpoint, while the bounded executor prevents a lecture burst from
turning notification work into an unbounded in-process queue.
"""

from __future__ import annotations

import math
import os
import threading
import time
import weakref
from bisect import bisect_right
from collections import Counter, defaultdict, deque
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable
from sqlalchemy.pool import QueuePool


#: Latency buckets, in milliseconds, shared by every timing metric.
#
# Chosen around the numbers this application actually has to defend: the scan
# SLO (50 / 150 / 300 ms), a Redis or Postgres round trip (well under 5 ms),
# and the far tail where a request has stopped being useful to a student.
LATENCY_BUCKETS_MS = (
    1, 2.5, 5, 10, 25, 50, 100, 150, 250, 500, 1000, 2500, 5000, 10000,
)


class RuntimeMetrics:
    """
    Thread-safe counters, gauges, bounded latency samples AND cumulative
    histogram buckets.

    The buckets are not decoration, and they are not a duplicate of the
    percentiles beside them. They exist because THE PERCENTILES CANNOT BE
    ADDED UP.

    This process is one of `workers` in one of N instances, and each one keeps
    its own reservoir. A Prometheus scrape reaches exactly one of them, so
    `p95` here has always meant "the 95th percentile of the requests that
    happened to land on this worker" — measured, one scrape saw 48 of the 200
    scans a run had just performed. There is no arithmetic that turns a set of
    per-worker p95s into the p95 of the service; averaging them is simply
    wrong, and taking the max is a different statistic that answers a
    different question.

    Bucket COUNTS do add up. Summing `..._bucket{le="150"}` across every
    worker and every instance gives the true number of requests under 150 ms
    for the whole deployment, and `histogram_quantile()` computes a real
    service-wide p95 from it. That is what makes a single dashboard possible
    at all once there is more than one process — which, for this application,
    is always.

    The per-worker percentiles are kept as well: they are the cheapest way to
    see one worker misbehaving, which an aggregate deliberately hides.
    """

    def __init__(self, sample_limit: int = 4096):
        self._lock = threading.Lock()
        self._counters: Counter[str] = Counter()
        self._gauges: dict[str, float] = {}
        self._samples = defaultdict(lambda: deque(maxlen=sample_limit))
        # name -> [count per bucket..., +Inf], plus a running sum for averages
        self._buckets: dict[str, list[int]] = {}
        self._sums: dict[str, float] = {}

    def increment(self, name: str, amount: float = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def observe_ms(self, name: str, value_ms: float) -> None:
        value = max(0.0, float(value_ms))
        # bisect, not a scan: this runs on the hot path, several times per
        # request, and O(log n) over a fixed 14-element ladder is free.
        index = bisect_right(LATENCY_BUCKETS_MS, value)
        with self._lock:
            self._samples[name].append(value)
            counts = self._buckets.get(name)
            if counts is None:
                counts = self._buckets[name] = [0] * (len(LATENCY_BUCKETS_MS) + 1)
            counts[index] += 1
            self._sums[name] = self._sums.get(name, 0.0) + value

    def snapshot(self) -> dict:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            samples = {name: list(values) for name, values in self._samples.items()}
            buckets = {name: list(values) for name, values in self._buckets.items()}
            sums = dict(self._sums)
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
        return {"counters": counters, "gauges": gauges, "histograms": histograms,
                "buckets": buckets, "sums": sums}

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
            # Kept per worker, and labelled as such: an aggregate cannot show
            # you that ONE worker is the slow one.
            for percentile in ("p50", "p95", "p99", "max"):
                lines.append(
                    f'scanmark_{safe_name}_ms{{stat="{percentile}"}} '
                    f"{stats[percentile]:.3f}"
                )
        # The mergeable half. Cumulative ("le" = less-than-or-equal) counts,
        # which is the shape histogram_quantile() expects and the only shape
        # that survives being summed across workers and instances.
        for name, counts in sorted(snapshot["buckets"].items()):
            safe_name = _metric_name(name)
            running = 0
            for edge, count in zip(LATENCY_BUCKETS_MS, counts):
                running += count
                lines.append(
                    f'scanmark_{safe_name}_ms_bucket{{le="{edge}"}} {running}')
            running += counts[-1]
            lines.append(f'scanmark_{safe_name}_ms_bucket{{le="+Inf"}} {running}')
            lines.append(f'scanmark_{safe_name}_ms_sum '
                         f'{snapshot["sums"].get(name, 0.0):.3f}')
            lines.append(f'scanmark_{safe_name}_ms_hcount {running}')
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
        self._start()

        # Threads do not survive fork, and under gunicorn's `preload_app` the
        # master imports the app — which already runs a job on the email pool
        # (the Brevo sender check) — and then forks the workers. Each worker
        # inherited a pool that believed an idle thread was waiting, so its
        # first job sat in the queue until a second one arrived and started a
        # thread. Signup sends two emails, which hid it; a password reset sends
        # one, so the first reset after every boot silently went nowhere. A
        # forked child gets a pool of its own instead.
        if hasattr(os, 'register_at_fork'):
            reference = weakref.ref(self)

            def _restart_in_child():
                executor = reference()
                if executor is not None:
                    executor._start()

            os.register_at_fork(after_in_child=_restart_in_child)

    def _start(self) -> None:
        """Fresh threads, locks and accounting. Nothing queued carries over."""
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers,
                                            thread_name_prefix=self.name)
        self._capacity = threading.BoundedSemaphore(self.max_workers + self.max_queue)
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
