"""
What the server side spent during a burst: CPU, memory, database connections
and Redis command cost. Run beside scan_burst.py on the SAME host as the
server (it reads /proc), and stop it with SIGINT/SIGTERM when the burst ends.

    python loadtest/resource_sampler.py --out /tmp/res.json \\
        --database-url "$DATABASE_URL" --redis-url "$REDIS_URL" &
    python loadtest/scan_burst.py ...
    kill -INT %1

It is a separate process on purpose: the burst harness is a gevent loop, and
a blocking poll of Postgres from inside it would perturb the very latencies
it is measuring.

Reports, for the sampling window:
  cpu_seconds / mean and peak cores busy, per process group (gunicorn,
      postgres, redis-server), from /proc/<pid>/stat utime+stime
  peak RSS per group, from /proc/<pid>/status
  database connections: peak total and peak ACTIVE for the target database,
      from pg_stat_activity (a cross-worker view the app's per-worker metrics
      cannot give)
  Redis: per-command calls and microseconds-per-call over the window, from
      INFO commandstats — Redis's own cost, excluding the network
"""

import argparse
import json
import os
import signal
import time

GROUPS = ('gunicorn', 'postgres', 'redis-server')
CLOCK_TICKS = os.sysconf('SC_CLK_TCK')


def _processes():
    found = {}
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            with open(f'/proc/{entry}/comm') as handle:
                name = handle.read().strip()
            if name not in GROUPS:
                continue
            with open(f'/proc/{entry}/stat') as handle:
                fields = handle.read().rsplit(')', 1)[1].split()
            cpu = (int(fields[11]) + int(fields[12])) / CLOCK_TICKS
            rss_kb = 0
            with open(f'/proc/{entry}/status') as handle:
                for line in handle:
                    if line.startswith('VmRSS:'):
                        rss_kb = int(line.split()[1])
                        break
            found[int(entry)] = (name, cpu, rss_kb)
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
            continue
    return found


def _commandstats(client):
    stats = {}
    for name, values in client.info('commandstats').items():
        stats[name.replace('cmdstat_', '')] = (values['calls'], values['usec'])
    return stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    parser.add_argument('--interval', type=float, default=0.25)
    parser.add_argument('--database-url', default=os.environ.get('DATABASE_URL', ''))
    parser.add_argument('--redis-url', default=os.environ.get('REDIS_URL', ''))
    parser.add_argument('--max-seconds', type=float, default=600)
    args = parser.parse_args()

    stop = {'now': False}
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.update(now=True))

    pg = None
    if args.database_url:
        import psycopg2
        pg = psycopg2.connect(args.database_url.replace('postgresql+psycopg2://', 'postgresql://'))
        pg.autocommit = True
    rds = None
    if args.redis_url:
        import redis
        rds = redis.Redis.from_url(args.redis_url)
        redis_before = _commandstats(rds)

    first = _processes()
    previous = dict(first)
    started = time.monotonic()
    busy_peak = {group: 0.0 for group in GROUPS}
    rss_peak = {group: 0 for group in GROUPS}
    cpu_total = {group: 0.0 for group in GROUPS}
    db_peak_total = db_peak_active = 0
    samples = 0
    last = started
    while not stop['now'] and time.monotonic() - started < args.max_seconds:
        time.sleep(args.interval)
        now = time.monotonic()
        current = _processes()
        elapsed = max(1e-6, now - last)
        last = now
        busy = {group: 0.0 for group in GROUPS}
        rss = {group: 0 for group in GROUPS}
        for pid, (name, cpu, rss_kb) in current.items():
            before = previous.get(pid)
            delta = cpu - before[1] if before and before[0] == name else 0.0
            busy[name] += delta / elapsed
            cpu_total[name] += delta
            rss[name] += rss_kb
        for group in GROUPS:
            busy_peak[group] = max(busy_peak[group], busy[group])
            rss_peak[group] = max(rss_peak[group], rss[group])
        previous = current
        if pg is not None:
            with pg.cursor() as cursor:
                cursor.execute("SELECT count(*), count(*) FILTER (WHERE state = 'active') "
                               "FROM pg_stat_activity WHERE datname = current_database() "
                               "AND pid <> pg_backend_pid()")
                total, active = cursor.fetchone()
            db_peak_total = max(db_peak_total, total)
            db_peak_active = max(db_peak_active, active)
        samples += 1

    window = time.monotonic() - started
    report = {
        'window_s': round(window, 2),
        'samples': samples,
        'cpu_seconds': {group: round(value, 2) for group, value in cpu_total.items()},
        'mean_cores_busy': {group: round(value / max(window, 1e-6), 2)
                            for group, value in cpu_total.items()},
        'peak_cores_busy': {group: round(value, 2) for group, value in busy_peak.items()},
        'peak_rss_mb': {group: round(value / 1024, 1) for group, value in rss_peak.items()},
        'db_connections': {'peak_total': db_peak_total, 'peak_active': db_peak_active},
    }
    if rds is not None:
        after = _commandstats(rds)
        commands = {}
        for name, (calls, usec) in after.items():
            calls_before, usec_before = redis_before.get(name, (0, 0))
            if calls > calls_before:
                commands[name] = {'calls': calls - calls_before,
                                  'usec_per_call': round((usec - usec_before)
                                                         / (calls - calls_before), 2)}
        report['redis_commands'] = dict(sorted(commands.items(),
                                               key=lambda item: -item[1]['calls']))
    with open(args.out, 'w', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)


if __name__ == '__main__':
    main()
