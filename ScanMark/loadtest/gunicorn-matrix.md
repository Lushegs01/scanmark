# Gunicorn capacity matrix

Benchmark these configurations against the same release and database. Run the
600-, 1,000- and 2,000-student bursts for each row; do not select a winner
from worker/thread count alone.

```bash
WEB_CONCURRENCY=8 GUNICORN_THREADS=2 gunicorn --config gunicorn.conf.py app:app
python loadtest/scan_burst.py --host https://staging.example \
    --students 2000 --session-id 1 --secret "$TARGET_SECRET_KEY" \
    --database-url "$DATABASE_URL" --label 8x2
```

## The result that decided the shipped defaults

600 simultaneous scans, one 4-CPU container running the application,
Postgres, Redis **and** the load generator. Everything on: CSRF, rate
limiting, server-side sessions, the geofence, `captured_at`.

| `WEB_CONCURRENCY` | `GUNICORN_THREADS` | Slots | Pool | scans/sec | server p50 | server p95 | client p95 |
|---:|---:|---:|---|---:|---:|---:|---:|
| 2 | 8 | 16 | 5+5 | 160.5 | 24.3 ms | 42.4 ms | 3184 ms |
| 4 | 8 | 32 | 5+5 | 200.9 | 31.0 ms | 64.6 ms | 2387 ms |
| 4 | 16 | 64 | 8+8 | 219.3 | 49.4 ms | 119.0 ms | 2263 ms |
| 8 | 4 | 32 | 3+3 | 237.9 | 29.8 ms | 66.9 ms | 1941 ms |
| 4 | 4 | 16 | 5+5 | 255.7 | 15.4 ms | 27.9 ms | 1732 ms |
| **8** | **2** | **16** | **3+2** | **318.5** | **14.5 ms** | **29.4 ms** | **1455 ms** |

Two things to take from it, neither of them obvious:

**Threads are not capacity here.** 4×16 has the most request slots of any row
and is nearly the worst. A scan is dominated by Python and SQLAlchemy work,
not by waiting on the network — on this codebase a Postgres round trip is
~0.13 ms and a Redis one ~0.07 ms, against ~9 ms of CPU per request. Threads
cannot run Python in parallel, so past the CPU count each one adds contention
and queueing rather than throughput. It shows up unmistakably in the
per-stage timings: under 32 threads, `qr_verify` — an HMAC over a short
string, with no I/O at all — measured 7.3 ms at p95. That is not work; that
is waiting for the GIL.

**More slots can mean worse latency at the same throughput.** Slots past the
point the CPU can serve only move the queue from the kernel's accept backlog
into the application, where each waiting request also holds a database
connection and a thread stack.

The shape that generalises: **about two processes per core, two threads
each.** The threads exist to overlap the one genuinely blocking thing a scan
does — waiting on Postgres — not to add parallelism Python cannot deliver.

## Re-measure on your own instance

The ranking should hold; the absolute numbers will not. For every case
record: scans/sec, server-stage p50/p95/p99, client p50/p95, 429/5xx counts,
QR-expired rate, CPU, RSS, `scanmark_db_pool_wait_ms`, Postgres
active/waiting connections, `scanmark_redis_*`, and
`scanmark_campos_outbox_pending`. `loadtest/scan_burst.py` prints most of it
and `/internal/metrics` has the rest.

Reject a case if it breaches the database connection budget even when its
HTTP latency is lower. The budget is:

```
instances x WEB_CONCURRENCY x (DB_POOL_SIZE + DB_MAX_OVERFLOW)
```

PgBouncer remains a conditional deployment change: add transaction pooling
when the measured direct-connection budget is exhausted, or when more
application instances make the computed maximum exceed the Postgres plan.
Keep direct connections while the measured pool is healthy; adding another
queue without evidence makes diagnosis harder.
