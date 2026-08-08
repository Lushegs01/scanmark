# Gunicorn capacity matrix

Benchmark these configurations against the same staging release and database.
Run the 600-, 2,000-, 5x600-, and 10x300-student scenarios for each row; do
not select a winner from worker/thread count alone.

| Case | `WEB_CONCURRENCY` | `GUNICORN_THREADS` | Request slots | Maximum app DB connections with pool 5+5 |
|---|---:|---:|---:|---:|
| A | 2 | 8 | 16 | 20 |
| B | 4 | 8 | 32 | 40 |
| C | 4 | 12 | 48 | 40 |
| D | 6 | 8 | 48 | 60 |

For every case record mark-attendance p50/p95/p99/max, scans/s, 429/5xx,
QR-expired rate, CPU, RSS, Postgres active/waiting connections, pool checkout
count, query p95, Redis p95, and background queue depth/oldest age. Reject a
case if it breaches the database connection budget even if HTTP latency is
lower.

PgBouncer remains a conditional deployment change: add transaction pooling
when the measured direct-connection budget is exhausted or more application
instances make the computed maximum exceed the Postgres plan. Keep direct
connections while the measured pool is healthy; adding another queue without
evidence makes diagnosis harder.
