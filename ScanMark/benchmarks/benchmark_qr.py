"""Measure the real ScanMark QR verifier at 10k or 100k iterations."""

import argparse
import os
import pathlib
import statistics
import sys
import time

os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
os.environ.setdefault('SECRET_KEY', 'benchmark-only-secret')
os.environ.setdefault('SCANMARK_DISABLE_SCHEDULER', '1')
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import generate_signed_qr, verify_signed_qr  # noqa: E402


def percentile(ordered, ratio):
    return ordered[min(len(ordered) - 1, int(len(ordered) * ratio))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--iterations', type=int, choices=(10_000, 100_000), default=10_000)
    arguments = parser.parse_args()
    token = generate_signed_qr(1)
    samples = []
    started = time.perf_counter()
    for _ in range(arguments.iterations):
        call_started = time.perf_counter_ns()
        verify_signed_qr(token)
        samples.append((time.perf_counter_ns() - call_started) / 1_000_000)
    elapsed = time.perf_counter() - started
    samples.sort()
    print({
        'iterations': arguments.iterations,
        'elapsed_s': round(elapsed, 3),
        'verifications_per_s': round(arguments.iterations / elapsed),
        'mean_ms': round(statistics.fmean(samples), 5),
        'p50_ms': round(percentile(samples, .50), 5),
        'p95_ms': round(percentile(samples, .95), 5),
        'p99_ms': round(percentile(samples, .99), 5),
    })


if __name__ == '__main__':
    main()
