#!/usr/bin/env python3
"""
Accept or reject a Locust run against the scan SLO.

A capacity run is not evidence until something checks it, and reading a CSV by
eye is how "mostly fine" gets recorded as a pass. This exits non-zero on any
breach so it can gate a release.

    python loadtest/check_slo.py loadtest/results/class-2000

The prefix is what you passed to ``--csv``; Locust writes
``<prefix>_stats.csv`` and ``<prefix>_failures.csv`` next to it.

What it refuses, and why each one matters:

  unexpected 4xx        a legitimate scan the server turned away
  any 5xx               a fault, as opposed to deliberate shedding
  token expiry          the amplifying failure: expired scans make phones
                        retry, which is the burst again but larger
  admission shedding    above a tolerance; shedding a whole class is not
                        "the class was marked"
  SLO breach            p50 <100ms, p95 <300ms, p99 <750ms on the scan
"""

import argparse
import csv
import os
import sys


# The staging gate. Overridable for a deliberately different target, but the
# defaults are the numbers the deployment guide commits to.
DEFAULT_P50_MS = float(os.environ.get('SLO_P50_MS', 100))
DEFAULT_P95_MS = float(os.environ.get('SLO_P95_MS', 300))
DEFAULT_P99_MS = float(os.environ.get('SLO_P99_MS', 750))

# Deliberate shedding is a valid response to a burst, but a run that sheds a
# large share has not shown the class can be marked. Default 0: prove it at
# the arrival rate you claim, then raise this knowingly if you have decided
# shedding is acceptable at some rate.
DEFAULT_MAX_SHED_RATIO = float(os.environ.get('SLO_MAX_SHED_RATIO', 0))

SCAN_ROW = '/mark_attendance [scan]'


def _read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline='', encoding='utf-8') as handle:
        return list(csv.DictReader(handle))


def _number(row, *names, default=0.0):
    """Locust has renamed these columns between versions; accept either."""
    for name in names:
        value = row.get(name)
        if value not in (None, '', 'N/A'):
            try:
                return float(value)
            except ValueError:
                continue
    return default


def check(prefix, p50_ms, p95_ms, p99_ms, max_shed_ratio):
    stats = _read_csv(f'{prefix}_stats.csv')
    failures = _read_csv(f'{prefix}_failures.csv')
    if not stats:
        return [f'no stats CSV at {prefix}_stats.csv — did the run start?'], {}

    problems = []
    scan_rows = [r for r in stats
                 if r.get('Name') == SCAN_ROW or SCAN_ROW in (r.get('Name') or '')]
    aggregated = [r for r in stats if (r.get('Name') or '').lower() == 'aggregated']
    row = scan_rows[0] if scan_rows else (aggregated[0] if aggregated else stats[0])

    requests = _number(row, 'Request Count', '# requests')
    failed = _number(row, 'Failure Count', '# failures')
    p50 = _number(row, '50%', 'Median Response Time', default=float('inf'))
    p95 = _number(row, '95%', default=float('inf'))
    p99 = _number(row, '99%', default=float('inf'))

    summary = {
        'requests': requests,
        'failures': failed,
        'p50_ms': p50,
        'p95_ms': p95,
        'p99_ms': p99,
    }

    if not requests:
        problems.append('the scan endpoint recorded no requests at all')

    # --- Failure taxonomy -------------------------------------------------
    # Locust's failure CSV carries the message each task reported, which is
    # why the locustfile reports outcomes by name rather than "HTTP 4xx".
    expired = shed = saturated = 0
    other = []
    for failure in failures:
        message = (failure.get('Error') or failure.get('Message') or '').lower()
        occurrences = int(_number(failure, 'Occurrences', 'Occurrence', default=0))
        if 'expired' in message:
            expired += occurrences
        elif 'admission_throttled' in message:
            shed += occurrences
        elif 'database_saturated' in message:
            saturated += occurrences
        elif occurrences:
            other.append((failure.get('Error') or failure.get('Message'), occurrences))

    summary.update({'expired': expired, 'shed': shed, 'saturated': saturated})

    if expired:
        problems.append(
            f'{expired} scan(s) bounced as token-expired. This is the amplifying '
            'failure: the phones retry, which is the burst again but larger.')
    if saturated:
        problems.append(
            f'{saturated} scan(s) hit database saturation (503). The pool ran '
            'out of connections — retune the gunicorn matrix before raising load.')
    if other:
        detail = '; '.join(f'{count}x {msg}' for msg, count in other[:5])
        problems.append(f'unexpected failures: {detail}')

    if requests and max_shed_ratio is not None:
        shed_ratio = shed / requests
        summary['shed_ratio'] = shed_ratio
        if shed_ratio > max_shed_ratio:
            problems.append(
                f'{shed} of {int(requests)} scans were shed by admission control '
                f'({shed_ratio:.1%} > {max_shed_ratio:.1%}). Shedding is a valid '
                'response to a burst, but a run that sheds this much has not '
                'shown the class can be marked.')

    # --- Latency ----------------------------------------------------------
    for label, actual, budget in (('p50', p50, p50_ms),
                                  ('p95', p95, p95_ms),
                                  ('p99', p99, p99_ms)):
        if actual > budget:
            problems.append(f'{label} {actual:.0f} ms exceeds the {budget:.0f} ms SLO')

    return problems, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('prefix', help='the --csv prefix the run was written with')
    parser.add_argument('--p50-ms', type=float, default=DEFAULT_P50_MS)
    parser.add_argument('--p95-ms', type=float, default=DEFAULT_P95_MS)
    parser.add_argument('--p99-ms', type=float, default=DEFAULT_P99_MS)
    parser.add_argument('--max-shed-ratio', type=float, default=DEFAULT_MAX_SHED_RATIO,
                        help='fraction of scans admission control may shed (default 0)')
    args = parser.parse_args()

    problems, summary = check(args.prefix, args.p50_ms, args.p95_ms,
                              args.p99_ms, args.max_shed_ratio)

    if summary:
        print(f"scans={int(summary.get('requests', 0))} "
              f"failures={int(summary.get('failures', 0))} "
              f"p50={summary.get('p50_ms', 0):.0f}ms "
              f"p95={summary.get('p95_ms', 0):.0f}ms "
              f"p99={summary.get('p99_ms', 0):.0f}ms "
              f"expired={summary.get('expired', 0)} "
              f"shed={summary.get('shed', 0)} "
              f"saturated={summary.get('saturated', 0)}")

    if problems:
        print(f'\nREJECTED ({len(problems)} problem(s)):')
        for problem in problems:
            print(f'  - {problem}')
        return 1

    print('\nACCEPTED: within the scan SLO with no unexpected failures.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
