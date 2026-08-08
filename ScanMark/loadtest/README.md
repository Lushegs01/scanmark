# ScanMark staging load test

These scenarios require seeded staging students, active session ids, and the
staging `SECRET_KEY`. They intentionally create attendance and must not run
against production.

Set `TARGET_SECRET_KEY`, `TARGET_SESSION_IDS`, `STUDENT_PASSWORD`, then use:

```powershell
# Baseline grid: repeat for 200/600/1000/2000 users and 10/25/50/100/200 rates.
locust -f loadtest/locustfile.py --host https://staging.example --headless --users 600 --spawn-rate 25 --run-time 2m --csv loadtest/results/baseline-600-r25

# Exact 600-student class, admitted within 30 seconds.
locust -f loadtest/locustfile.py --host https://staging.example --headless --users 600 --spawn-rate 25 --run-time 45s --csv loadtest/results/class-600-30s

# 2,000-student single class.
locust -f loadtest/locustfile.py --host https://staging.example --headless --users 2000 --spawn-rate 100 --run-time 3m --csv loadtest/results/class-2000

# One authenticated student firing 20 concurrent duplicate scans.
$env:SCENARIO='double_scan'; $env:DOUBLE_SCAN_CONCURRENCY='20'
locust -f loadtest/locustfile.py --host https://staging.example --headless --users 1 --spawn-rate 1 --run-time 20s --csv loadtest/results/double-scan-20

# Five 600-student classes at once (3,000 students total).
$env:SCENARIO='scan'; $env:TARGET_SESSION_IDS='101,102,103,104,105'
locust -f loadtest/locustfile.py --host https://staging.example --headless --users 3000 --spawn-rate 100 --run-time 4m --csv loadtest/results/5x600

# Ten 300-student classes at once.
$env:TARGET_SESSION_IDS='201,202,203,204,205,206,207,208,209,210'
locust -f loadtest/locustfile.py --host https://staging.example --headless --users 3000 --spawn-rate 100 --run-time 4m --csv loadtest/results/10x300

# Login stampede is measured separately from already-authenticated scans.
$env:SCENARIO='login'
locust -f loadtest/locustfile.py --host https://staging.example --headless --users 600 --spawn-rate 25 --run-time 45s --csv loadtest/results/login-600
```

For each CSV capture p50/p95/p99/max, throughput, failures, 429/5xx counts,
CPU, memory, Postgres CPU/locks/connections, Redis latency, executor queue age,
and projector visibility delay. The scan SLO is p50 <100 ms, p95 <300 ms,
p99 <750 ms under the accepted staging capacity; do not claim it from a local
SQLite run.
