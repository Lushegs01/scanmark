# ScanMark performance report — concurrency round

Date: 2026-08-31

## How to read the numbers in this document

Everything below was measured on **one 4-CPU container** running the
application, PostgreSQL 16, Redis 7 **and** the load generator, all competing
for the same four cores. That makes it a pessimistic environment, and it makes
two numbers mean different things:

* **server stages** — what the application itself spent on a request, summed
  from the `Server-Timing` header it returns. This is the number that
  code changes move.
* **client-observed** — what the load generator saw, which includes queueing
  in front of the application. This is the number that *capacity* moves; with
  2,000 requests arriving simultaneously at an instance with 16 request
  slots, most of it is Little's Law, not the application.

Every run had CSRF, rate limiting, server-side sessions, the geofence,
`captured_at` and `user_marker` all enabled. No run turned a control off to
make a number look better.

**These are not capacity guarantees for your deployment.** They are evidence
for the changes, and a shape to re-measure with the checked-in tools.

---

## 1. Performance bottleneck report

Ranked. Every one was measured before it was changed; two hypotheses that
measurement *disproved* are recorded at the end, because not changing things
is half the work.

### P0 — A Redis outage returned HTTP 500 to every request in the application

* **File / function:** `app.py`, Flask-Session's `open_session` (installed by `Session(app)`)
* **Bottleneck:** Flask-Session reads the session inside Flask's `ctx.push()`,
  which runs *before* the request context exists — so an exception there
  escapes as a bare WSGI 500 that no `@app.errorhandler` can catch or shape.
  Redis was therefore a hard dependency of every route, not a cache.
* **Evidence:** stopped Redis mid-lecture with 20 authenticated students;
  **19 of 19 scans returned HTTP 500** and none were recorded. Traceback in
  `redis/connection.py` → `flask_session/redis/redis.py:64` → `flask/ctx.py:386`.
* **Change:** a session interface that serves signed-cookie sessions while
  Redis is unreachable, behind a short circuit breaker; plus fallbacks on
  every other Redis read (classroom pin → the saved `Classroom` row, QR token
  → mint a fresh one, rate limiter → `swallow_errors=True`), and one
  automatic page reload in the scanner to pick up the new CSRF token.
* **Result:** **29 of 29 scans recorded** during a full Redis outage, 0
  duplicates, 1.08 s for all 29 — the breaker also removes the 2 s connect
  timeout that would otherwise be added to *every* request.
* **Risk:** while Redis is down the session lives in a signed (not encrypted)
  cookie, exposing a user their own id and security stamp. Revocation is
  unaffected: `load_user` still checks the stamp against the database on
  every request. Students see one automatic reload.

### P0 — Password verification, and what it does to everything else

* **File / function:** `app.py::login`, `werkzeug.security.check_password_hash`
* **Bottleneck:** scrypt (N=32768, r=8) costs **~104 ms of CPU and ~32 MB of
  RAM per verification**, and it is memory-*hard* by design, so throughput
  stops improving at about four concurrent hashes while latency and memory
  keep growing linearly. Unbounded, a pre-lecture sign-in rush takes every
  request slot in the process and ~1 GB of transient RSS.
* **Evidence:** `benchmarks/benchmark_password_hash.py` — 1→9.9/s, 2→19.6/s,
  4→36.7/s, 8→36.4/s (215 ms each), 16→37.2/s (429 ms), 32→37.4/s (854 ms,
  1 GB). And an interference run: 600 scans with 40 concurrent logins
  running throughout.
* **Change:** an instance-wide semaphore sized to the measured knee, shared
  across workers; logins past it wait briefly then are shed with 503 +
  `Retry-After`. Separately, identity-provider accounts no longer hash a
  32-byte random placeholder they will never verify — that was ~104 ms of
  memory-hard work protecting a secret nobody can guess, landing on the SSO
  login path.
* **Result (scans under a login stampede):** 164.1 → **193.6 scans/sec**
  (+18%), server p50 20.2 → **13.9 ms** (−31%), p95 34.2 → **25.3 ms** (−26%).
* **Risk:** logins are deliberately the ones that pay — competing-login p95
  rose 2759 → 3506 ms and fewer completed. That is the intended trade: a scan
  has a QR deadline, a login does not. No configuration makes 2,000 logins
  fast; it is ~70 s of memory-bound work, and the answer to that is capacity
  and the 30-day remember-me cookie, not tuning.

### P1 — CampOS delivery could be lost, and had no retry, backoff or dead letter

* **File / function:** `app.py::mark_attendance` → `campos_executor.submit(...)`
* **Bottleneck:** delivery existed only in an in-process thread pool. It was
  lost three ways — a full queue (logged, dropped), a raised error (logged,
  dropped), or a deploy/crash while queued (not even logged) — and nothing
  anywhere recorded that a scan still owed CampOS a record. "Is every scan in
  CampOS?" was not a question the system could answer.
* **Evidence:** source; `report_attendance_to_campos` caught
  `CamposIntegrationError` and returned. Phase 8 of the brief requires a
  durable queue, idempotency, backoff, jitter and dead-lettering; none existed.
* **Change:** a transactional outbox on the attendance row itself
  (`campos_state`, `campos_attempts`, `campos_next_attempt_at`), written by
  the same INSERT — no extra statement, nothing added to the request. A
  sweeper claims overdue rows with `FOR UPDATE SKIP LOCKED` (safe across
  instances), retries with capped exponential backoff and full jitter, and
  dead-letters after `CAMPOS_MAX_ATTEMPTS`. One sweeper per deployment, via a
  Redis lease, degrading to all-sweep if Redis is down.
* **Result:** with CampOS unreachable, 2,000 simultaneous scans all succeeded
  and all 2,000 were queued; when CampOS returned, the sweeper delivered
  **exactly 2,000 distinct `externalId`s in 30 seconds**, 0 duplicates.
* **Risk:** a partial index on the pending rows, maintained by every INSERT.
  It stays empty in a healthy deployment, so the cost is negligible.

### P1 — A CampOS outage cost a third of scan capacity

* **File / function:** `app.py::report_attendance_to_campos`
* **Bottleneck:** with CampOS down, every scan handed a pool thread a request
  that would spend ~10 s failing (connect timeout × 3 bounded retries), and
  each failure then wrote the row's retry schedule back to Postgres — during
  the burst.
* **Evidence:** 2,000 scans with CampOS unreachable: **177.7 scans/sec** vs
  256.8 with CampOS unconfigured; server p50 27.5 ms vs 16.3 ms.
* **Change:** a breaker in front of the immediate attempt (after 3
  consecutive failures it stands down for 60 s and leaves everything to the
  sweeper), and the immediate attempt no longer retries inline — retries
  belong to the outbox, which runs off the burst.
* **Result:** **304.1 scans/sec** with CampOS completely down (+71%), server
  p50 15.7 ms — statistically indistinguishable from CampOS being absent.
* **Risk:** a transient CampOS blip is no longer retried within the request;
  it waits for the next sweep (≤30 s). That is the correct place for it.

### P1 — Behind a load balancer, every per-IP rate limit was one global bucket

* **File / function:** `app.py`, `get_remote_address` / `user_based_rate_limit_key`
* **Bottleneck:** no `ProxyFix`. `request.remote_addr` is the router, so
  `/signup` (5/hour), `/forgot_password` (10/hour), `/resend_verification`
  and the anonymous default all shared **one bucket for the entire
  internet**. A capacity bug (legitimate users refused by a counter somebody
  else filled) and a security bug (a brute-forcer's per-IP cap is shared with,
  and therefore hidden among, the people it is meant to distinguish them
  from). Scaling out makes it worse: every instance sees the same address.
* **Evidence:** source — and the audit log at `record_audit` parsed
  `X-Forwarded-For` by hand, proving the header was known about in one place
  and missed in the other.
* **Change:** `ProxyFix` with a configurable `TRUSTED_PROXY_COUNT` (1 in
  production, 0 elsewhere), `x_for`/`x_proto` only — the host stays governed
  by `PUBLIC_ORIGIN`/`TRUSTED_HOSTS`. The audit log now uses the normalised
  address, which also closes a spoofing hole: it took the *leftmost*
  `X-Forwarded-For` entry, the one part of that header a client writes itself.
* **Risk:** a wrong hop count is exploitable in either direction. Documented,
  defaulted to the common case (one platform router), and 0 disables it.

### P1 — `postgresql+psycopg2://` silently skipped the entire pool configuration

* **File / function:** `app.py`, the `SQLALCHEMY_ENGINE_OPTIONS` block
* **Bottleneck:** the test was `_db_uri.startswith('postgresql://')`.
  `postgresql+psycopg2://` and `postgresql+psycopg://` are ordinary,
  documented forms — psycopg 3 *requires* the explicit driver. Such a
  deployment was refused at boot as "not a PostgreSQL URL"; and if an
  operator set `ALLOW_SQLITE_IN_PRODUCTION` to get past that, the engine
  options block was skipped too, so the pool ran on SQLAlchemy's defaults
  with **no `InstrumentedQueuePool`, no `pool_size`, no `pool_timeout`, no
  `pool_pre_ping`** — the pool-wait metric that exists to tell saturation from
  slowness silently measured nothing, and the 503-on-saturation path could no
  longer be reached at the configured boundary.
* **Evidence:** hit directly while setting up the rehearsal; the boot refused
  a correct URL.
* **Change:** parse the scheme properly. Parametrised regression test.

### P1 — `gunicorn keepalive = 2 s` (the default)

* **File:** `gunicorn.conf.py`
* **Bottleneck:** two distinct failures. A phone loads the scan page and waits
  for the lecturer to project the code — always longer than two seconds — so
  the socket is closed and **every scan pays a fresh TCP (and, at the router,
  TLS) handshake**: 2–3 extra round trips, 200–600 ms on a Nigerian mobile
  network. And because it is *below* every platform router's idle timeout
  (~60 s), the router will eventually write a request into a socket gunicorn
  has already closed and hand the client a 502 for a request the application
  never saw.
* **Evidence:** 165 of 300 scans posted after a ~20 s wait returned
  `RemoteDisconnected` instead of a response.
* **Change:** `keepalive = 75`, above the router's idle timeout so the app
  hangs up last. Documented as a rule, not a number.

### P1 — Per-worker metrics made `/internal/metrics` a 1/N sample

* **File / function:** `performance.py::RuntimeMetrics`
* **Bottleneck:** each worker keeps its own reservoir, and a scrape reaches
  one of them. Percentiles cannot be summed, averaged or maxed into a service
  figure, so with 8 workers × N instances there was no way to compute the
  deployment's real p95 — which Phase 16 asks for.
* **Evidence:** a scrape after a 200-scan run reported
  `scanmark_scan_response_count 48`.
* **Change:** cumulative histogram **buckets** (`_bucket{le="…"}`, `_sum`)
  alongside the existing per-worker percentiles. Bucket counts *do* sum, so
  `histogram_quantile()` gives a true service-wide quantile; the per-worker
  percentiles stay because an aggregate deliberately hides one bad worker.

### P2 — Five SQL statements and four Redis round trips per successful scan

* **File / function:** `app.py::mark_attendance`
* **Bottleneck:** (1) the enrolment check was its own statement; (2) reading
  `current_user.matric_no` for the CampOS hand-off *after* the commit
  triggered a second full `SELECT "user".*`, because SQLAlchemy expires every
  instance on commit; (3) Flask defaults `SESSION_REFRESH_EACH_REQUEST` to
  true, so every authenticated request wrote its session back to Redis purely
  to push out an expiry.
* **Evidence:** instrumented one request end to end — 5 statements, 4 Redis
  commands, listed individually.
* **Change:** fold the enrolment into the existing session/course/room join
  as an outer join (which keeps 404 and 403 distinguishable); read the two
  User columns before the commit; turn off the session rewrite.
* **Result:** **3 SQL statements, 3 Redis round trips.** A regression test
  holds the SQL count at three.

### P2 — The scanner ignored `Retry-After`

* **File:** `static/scanner.js`, `app.py::ratelimit_handler`
* **Bottleneck:** the scanner had bounded exponential backoff with jitter
  (good) but used its own 1.5 s → 15 s ladder regardless of what the server
  said. Admission control sheds with `Retry-After: 1` (it is smoothing a
  microburst, not queueing attendance) and pool exhaustion with 2 s. Guessing
  longer wastes the QR window; guessing shorter is the burst again. The
  limiter's own 429 also carried neither `Retry-After` nor the
  machine-readable `outcome` every other refusal carries.
* **Change:** the scanner honours `Retry-After` where present — clamped to
  30 s and jittered, because every phone in the room was shed by the same
  response — and falls back to its own ladder otherwise. The 429 handler now
  sends `Retry-After` and `outcome: "rate_limited"`.

### P2 — The scanner asked 2,000 students to reload by hand

* **File:** `static/scanner.js`
* **Bottleneck:** a non-JSON 4xx (the CSRF guard rejecting a page whose token
  no longer matches the session) showed "Reload this page, then scan again".
  Correct, and useless in a lecture theatre.
* **Change:** reload automatically, once, guarded by a `sessionStorage`
  marker so a persistent fault shows the message instead of looping. This is
  what makes the Redis-outage path recover without anyone noticing.

### P3 — Test isolation, found by the new tests

`test_performance.py` passed only because `test_app.py` ran first and its
fixture assigned `scanmark.GEOFENCE_REQUIRED = False` on the module without
restoring it; the same for `limiter.enabled`. Run alone, the file failed with
422s and an unrelated 429. Both are now set explicitly in its own fixture.

### Two hypotheses the measurements disproved

* **The global metrics lock.** A scan takes ~25 acquisitions of one
  `RuntimeMetrics` lock, and the `enqueue` stage was reporting 13.9 ms at p50
  for what is a non-blocking queue put — an obvious suspect. Benchmarked at
  32 threads: **29 µs per submit**, not 13.9 ms. Not the cause; left alone.
* **"The stages are slow."** `qr_verify` — an HMAC over a short string, no
  I/O — measured 7.3 ms at p95 under 32 threads. Nothing in that stage can
  take 7 ms. It was GIL contention, and the fix was the worker/thread shape,
  not the code. This is the finding that produced the configuration change
  below, and it would have been invisible without per-stage timings.


---

## 2. Architecture report

### Current architecture (before this round)

One Flask application behind gunicorn (`gthread`, 4 workers × 8 threads),
PostgreSQL for the record, Redis for sessions, rate limits, the classroom
pin, the QR token and its rendered PNG, and in-process thread pools for
email and CampOS delivery.

The shape was already sound: attendance commits on its own, tokens are
signed, duplicates are prevented by a unique index rather than by application
logic. What it lacked was any answer to a *dependency* failing, and its
process shape assumed the work was I/O-bound when it is CPU-bound.

### Proposed architecture (what this round implements)

```
                        Phone / low-end Android
                                  |
                     HTTP/2, keep-alive > router idle
                                  v
                    ┌─────────────────────────────┐
                    │  Load balancer (TLS ends)   │   X-Forwarded-For / -Proto
                    │  Cloudflare or platform     │   -> TRUSTED_PROXY_COUNT
                    └──────────────┬──────────────┘
              ┌──────────────┬─────┴────────┬──────────────┐
              v              v              v              v
         App instance   App instance   App instance    (autoscale)
         8 workers x 2 threads, keepalive 75s, stateless
              │              │              │
              │  sessions, rate limits, admission buckets, pins, QR cache
              └──────────────┴──────┬───────┴──────────────┘
                                    v
                        ┌───────────────────────┐
                        │   Redis (accelerator) │  every read has a fallback;
                        │   failure => degraded │  outage != outage of ScanMark
                        └───────────────────────┘
              ┌──────────────┬──────────────┬──────────────┐
              v              v              v              v
                        ┌───────────────────────┐
                        │  PgBouncer (2+ inst.) │  transaction pooling
                        └───────────┬───────────┘
                                    v
                        ┌───────────────────────┐
                        │      PostgreSQL       │  the record, AND the queue
                        │  attendance.campos_*  │  (transactional outbox)
                        └───────────┬───────────┘
                                    │  FOR UPDATE SKIP LOCKED
                                    v
                        ┌───────────────────────┐
                        │   Outbox sweeper      │  one per deployment
                        │   (in every worker,   │  (Redis lease elects it)
                        │    elected by lease)  │
                        └───────────┬───────────┘
                                    v
                                 CampOS
```

**Scaling model.** Instances are interchangeable and disposable. Nothing that
must survive a request lives in process memory: sessions, rate-limit
counters, admission buckets, classroom pins and the QR token are in Redis;
the CampOS work queue is in Postgres. Local memory is used only as an
optimisation (the session-store breaker, the CampOS breaker, the per-worker
metric reservoir) and never as the authority for anything. Verified by
sending eight consecutive `SIGHUP` rolling reloads through a 2,000-scan
burst: all 2,000 scans recorded, 0 duplicates.

**Database topology.** One primary. No replica is justified by anything
measured here — `db_query` p50 is 0.46 ms and pool wait p99 is 0.07 ms at
2,000 concurrent scans, so reads are not the constraint. Add PgBouncer in
transaction mode when instance count × `workers × (pool + overflow)`
approaches the plan's `max_connections`; with the shipped defaults that is
40 per instance, so a three-instance deployment (120) already exceeds several
managed plans.

**Redis topology.** Single instance is acceptable *because* a failure is now
degraded rather than fatal. Managed Redis with automatic failover is still
worth the money — the degraded mode costs every phone one page reload — but
it is no longer load-bearing for availability.

**Background workers.** Deliberately **not** Celery, RQ, Dramatiq or ARQ. The
durability requirement is satisfied by the outbox, which needs no extra
broker, no extra process type, no extra deployment unit and no extra failure
mode — and which makes the queue queryable with SQL, so "which attendance
has not reached CampOS?" is a `WHERE campos_state='pending'`. A separate
broker would be the right answer if the work were heterogeneous, high-volume
or long-running; it is one small idempotent HTTP POST per scan. Adding a
broker for that is the "avoid adding infrastructure because it is popular"
case the brief warns about. If the volume or variety changes, the outbox is
also the natural feed for one.

**Load balancer strategy.** Least-connections or round-robin both work; there
is no session affinity to preserve, which is the point. TLS terminates at the
router. The router's idle timeout must be *below* `GUNICORN_KEEPALIVE`.

---

## 3. Performance changes

| # | File | Change |
|---|---|---|
| 1 | `app.py` | `ResilientSessionInterface`: signed-cookie sessions while Redis is unreachable, behind a circuit breaker. Redis is no longer able to 500 the application. |
| 2 | `app.py` | `get_class_location` / `set_class_location` fall back to the saved `Classroom` row on `RedisError`. |
| 3 | `app.py` | `generate_signed_qr` and the QR PNG endpoint survive a Redis outage instead of taking the projector down. |
| 4 | `app.py` | Rate limiter `swallow_errors=True` — a counter store outage must not be a second way to lose attendance. |
| 5 | `app.py` | Password hashing admission control: instance-wide semaphore, bounded wait, 503 + `Retry-After`, metrics. |
| 6 | `app.py` | `UNUSABLE_PASSWORD` sentinel for identity-provider accounts; no scrypt over an unguessable placeholder on the SSO path. |
| 7 | `app.py`, `models.py` | CampOS transactional outbox: three columns on `attendance`, a partial index, written by the existing INSERT. |
| 8 | `app.py` | Outbox sweeper with `SKIP LOCKED` claiming, capped exponential backoff with full jitter, dead-lettering, Redis-lease election, queue-depth/oldest-age metrics. |
| 9 | `app.py` | CampOS circuit breaker; the immediate attempt no longer retries inline. |
| 10 | `app.py` | `ProxyFix` with configurable `TRUSTED_PROXY_COUNT`; audit log uses the normalised client address. |
| 11 | `app.py` | `_is_postgres_uri` — every documented PostgreSQL URL spelling gets the pool configuration. |
| 12 | `app.py` | Pool sized from the thread count; `pool_timeout` 30 s → 10 s. |
| 13 | `app.py` | Enrolment folded into the session/course/room join (outer join, 404 and 403 still distinct). |
| 14 | `app.py` | Read `matric_no`/`email` before the commit — removes a full post-commit `SELECT "user".*` per successful scan. |
| 15 | `app.py` | `SESSION_REFRESH_EACH_REQUEST=false`; explicit session lifetime. |
| 16 | `app.py` | 429 responses carry `Retry-After` and `outcome`. |
| 17 | `performance.py` | Cumulative histogram buckets (`_bucket{le}`, `_sum`) that sum across workers and instances. |
| 18 | `gunicorn.conf.py` | 8×2 from the measured matrix; `keepalive=75`; `post_fork` restarts the sweeper in each worker (threads do not survive fork under `preload_app`). |
| 19 | `static/scanner.js` | Honour `Retry-After`; one automatic reload on a session/CSRF mismatch. |
| 20 | `loadtest/scan_burst.py` | **New.** Pre-authenticated simultaneous burst, so scan latency stops being measured as `login + scan`. Login-stampede interference, projector polling, `Retry-After`-aware login retry, and a database correctness check. |
| 21 | `loadtest/locustfile.py` | Send `Referer` — without it the harness cannot authenticate against *any* HTTPS deployment, because Flask-WTF's `WTF_CSRF_SSL_STRICT` refuses an HTTPS POST that has none. |
| 22 | `benchmarks/benchmark_password_hash.py` | **New.** Finds this machine's hashing knee so `PASSWORD_HASH_CONCURRENCY` is measured rather than guessed. |
| 23 | `test_performance.py` | 29 new tests: hot-path SQL budget, enrolment 403/404, no post-commit user read, outbox (intent-in-insert, full-queue deferral, backoff, dead-letter, idempotency key, drain), password gate and shed semantics, unusable-password sentinel, PostgreSQL URL spellings, ProxyFix hop counting, mergeable buckets, `Retry-After` contract, four Redis-outage paths. |

---

## 4. Benchmark results

600 simultaneous pre-authenticated scans, same box, all controls on.
"Before" is the shipped `4×8` configuration and the previous code.

| Metric | Before | After | |
|---|---:|---:|---|
| Scan p50 (server) | 39.0 ms | **13.4 ms** | −66% |
| Scan p95 (server) | 62.0 ms | **29.2 ms** | −53% |
| Scan p99 (server) | 73.9 ms | **38.1 ms** | −48% |
| Scan p50 (client) | 1303 ms | **933 ms** | −28% |
| Scan p95 (client) | 2637 ms | **1405 ms** | −47% |
| Requests/sec | 185.4 | **315.9** | +70% |
| SQL statements/scan | 5 | **3** | −40% |
| Redis round trips/scan | 4 | **3** | −25% |
| DB pool wait p99 | 76.8 ms | **0.07 ms** | −99.9% |
| DB query p50 | 4.19 ms | **0.46 ms** | −89% |
| Redis GET p50 | 3.25 ms | **1.15 ms** | −65% |
| Projector payload (no change) | 98 B | 97 B | — |
| Projector payload (max batch) | 21,846 B | 21,702 B | — |
| Duplicate attendance | 0 | **0** | — |
| Lost attendance | 0 | **0** | — |

At 2,000 simultaneous scans: 226.1 → **332.0 scans/sec**, server p50
49.9 → **15.0 ms**, p95 86.6 → **29.9 ms**, p99 116.5 → **38.1 ms**,
client p95 7128 → **4579 ms**.

The pool-wait and query-latency improvements are mostly the worker/thread
change: 32 threads on 4 cores were contending for 40 database connections and
one GIL each; 16 threads across 8 processes contend for neither.

---

## 5. Load-test results

Every run: 2,000 seeded students, real Postgres, real Redis, CSRF, rate
limiting, geofence and `captured_at` all on, cold TCP connections (the
connection a phone opens after waiting for the projector).

| Test | Scenario | scans/s | srv p50 | srv p95 | srv p99 | cli p50 | cli p95 | rows | dupes | lost |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A | 200 students | 310.2 | 16.4 | 31.1 | 40.4 | 334 | 482 | 200 | 0 | 0 |
| B | 600 students | 315.9 | 13.4 | 29.2 | 38.1 | 933 | 1405 | 600 | 0 | 0 |
| C | 1,000 students | 342.2 | 14.6 | 29.5 | 36.1 | 1452 | 2216 | 1000 | 0 | 0 |
| D | 2,000 students | 332.0 | 15.0 | 29.9 | 38.1 | 3013 | 4579 | 2000 | 0 | 0 |
| E | 5 classes × 400 | 312.3 | 15.8 | 30.1 | 35.8 | 3047 | 4661 | 2000 | 0 | 0 |
| F | 10 classes × 200 | 341.4 | 15.5 | 28.6 | 35.5 | 2942 | 4460 | 2000 | 0 | 0 |
| G | 2,000 sign-ins | 28.5 logins/s — CPU-bound, see P0 above | | | | | | | | |
| H | 2,000 + 3 projector screens polling every 1 s | 316.4 | 15.5 | 32.4 | 43.0 | 3277 | 4829 | 2000 | 0 | 0 |
| I | 2,000 + CampOS totally unreachable | 304.1 | 15.7 | 38.9 | 64.6 | 3461 | 5204 | 2000 | 0 | 0 |
| J | Redis killed mid-lecture | see below | | | | | | 29/29 | 0 | 0 |
| L/M | 2,000 + 8 rolling `SIGHUP` reloads mid-burst | 284.2 | 15.1 | 37.2 | 58.8 | 3723 | 5057 | 2000 | 0 | 0 |
| N | 30 students × 20 simultaneous identical scans | 600 requests | | | | | | 30 | **0** | 0 |
| O | Retry storm | every shed response carries `Retry-After`; the scanner honours it, jittered, bounded to 3 attempts | | | | | | | | |

Notes on the ones that do not fit a row:

* **J (Redis chaos).** Before: 19 of 19 scans HTTP 500, nothing recorded.
  After: all 29 recorded. The first attempt returns 400 (the CSRF token was
  minted against the Redis session); the scanner reloads itself once and the
  scan succeeds. 29 scans took 1.08 s in total — the breaker means no request
  pays the Redis connect timeout. On recovery, normal service resumes.
* **I (CampOS chaos), the recovery half.** All 2,000 rows sat `pending`.
  Pointing CampOS back at a live endpoint, the sweeper drained them in
  **30 seconds** and the receiving end counted **exactly 2,000 distinct
  `externalId`s** — every scan delivered, each exactly once.
* **N (duplicate race).** 20 simultaneous requests per student with one
  token: exactly one `success` each, the rest `duplicate` or rate-limited.
  30 rows for 30 students.
* **K (database saturation)** is covered by unit test rather than by load: a
  `PoolTimeoutError` returns 503 with `Retry-After` and `outcome:
  "database_saturated"`, never a 500. Reproducing genuine saturation on this
  box would have required crippling Postgres rather than loading ScanMark.

**The one number that is not good enough, and why.** Client-observed p95 at
2,000 users is 4.6 s against a 150 ms target. That is not the application —
server-side p95 is 29.9 ms, comfortably inside it. It is 2,000 requests
arriving at once at an instance with 16 request slots: ~6 seconds to drain,
which is arithmetic, not a defect, and it is well inside the 45 s
`QR_CODE_WINDOW`, so no scan expires and nothing retries. **The p95 target is
an instance-count decision, not a code one**: three instances put it near
1.5 s, and the application is now safe to run three of.

---

## 6. Remaining bottlenecks

Honest list of what is still constrained, and by what:

1. **Login throughput, ~30/sec per instance — infrastructure, unfixable in
   code.** scrypt is memory-hard on purpose. The only levers are more
   instances, the 30-day remember-me cookie (so the real rush is a fraction
   of the roster), and the concurrency bound that stops it stealing scan
   capacity. Reducing the work factor would trade password security for
   throughput and is not on the table.
2. **Client-observed scan latency under a true 2,000-at-once burst —
   capacity.** Per instance: ~330 scans/sec, ~6 s to drain 2,000. Scale out.
3. **`load_user` runs a full `SELECT "user".*` on every authenticated
   request** — one of the three remaining statements. It could be a narrow
   column list, or cached against the security stamp for a few seconds. Not
   done: it is ~0.4 ms, the cache would delay revocation, and Phase 20 says
   not to optimise speculatively. It is the obvious next candidate if
   profiling ever says so.
4. **Redis is still one instance.** Failure is degraded, not fatal, but the
   degraded mode costs every phone a reload. Managed Redis with failover is
   the fix, and it is an infrastructure choice.
5. **Three Redis round trips per scan** (session read, limiter, classroom
   pin). The pin read and the admission script could be pipelined into one.
   Not done: locally Redis is 0.07 ms so there is nothing to see, and the
   change costs clarity on the hot path for perhaps 1 ms on a managed Redis.
   Listed so the option is on the record with its reasoning, per Phase 6.
6. **Scanner and camera performance on real devices is still unmeasured.**
   No Android hardware was available. `client_metrics` (camera-ready,
   decode, GPS wait, capture-to-request) are collected and exposed; the
   numbers have to come from a real classroom.
7. **PgBouncer is not deployed**, deliberately. Pool wait p99 is 0.07 ms at
   2,000 concurrent scans, so nothing measured justifies it yet. The trigger
   is documented arithmetic, not a feeling.

---

## 7. Deployment configuration

Derived from the matrix in `loadtest/gunicorn-matrix.md` and the hashing
benchmark. **Re-derive on your instance size**; both tools are checked in.

For a 4-CPU / 4 GB instance:

| Setting | Value | Derived from |
|---|---|---|
| `WEB_CONCURRENCY` | 8 (`2 × CPUs`, cap 12) | matrix: 8×2 beat 4×8 by 59% on throughput and halved p95 |
| `GUNICORN_THREADS` | 2 | matrix: 4×16 had the most slots and nearly the worst latency |
| `GUNICORN_KEEPALIVE` | 75 s | must exceed the router idle timeout (~60 s) |
| `GUNICORN_TIMEOUT` | 60 s | above the router timeout so gunicorn is not first to abandon |
| `DB_POOL_SIZE` | 3 (`threads + 1`) | a worker cannot use more than `threads` at once |
| `DB_MAX_OVERFLOW` | 2 (`threads`) | burst allowance that is returned |
| `DB_POOL_TIMEOUT` | 10 s | a scan waiting 30 s has an expired token anyway |
| **Postgres connections** | **40/instance** | `8 × (3 + 2)`; keep `instances × 40` under the plan cap |
| `REDIS_MAX_CONNECTIONS` | 24 (`workers × threads + 8`) | request slots plus background headroom |
| `PASSWORD_HASH_CONCURRENCY` | 4 | measured knee: 4→36.7/s, 8→36.4/s at double the latency |
| `PASSWORD_HASH_MAX_WAIT_SECONDS` | 2 | absorbs a clump without holding slots to the gunicorn timeout |
| `CAMPOS_WORKERS` | 4 | immediate delivery is now single-attempt and breaker-guarded |
| `CAMPOS_QUEUE_SIZE` | 2000 | a full queue is a deferral, not a loss |
| `CAMPOS_SWEEP_INTERVAL_SECONDS` | 30 | drains 2,000 rows in ~30 s at batch 250 |
| `CAMPOS_MAX_ATTEMPTS` | 8 | ~4 hours of capped backoff before dead-lettering |
| `SCAN_ADMISSION_RATE` | **set it from your own run** | ships at 0 (off); a default here would be a guess with a measured number's authority |
| `TRUSTED_PROXY_COUNT` | 1 (2 behind Cloudflare + platform) | count the hops that rewrite `X-Forwarded-For` |

**Autoscaling.** Scale on **request queue depth or p95 latency, not CPU.**
CPU is a poor signal here: a login stampede pins the CPU while scans are
fine, and a scan burst queues at the request slot before CPU saturates. If
only CPU is available, target **60%** — above that, the 16 request slots are
already queueing. Memory target **70%**, and size for
`PASSWORD_HASH_CONCURRENCY × 32 MB` of transient scrypt working set on top of
the baseline. Scale **out** for scans (throughput is per-instance) and scale
**ahead of the timetable**, not reactively: a 2,000-scan burst is over in six
seconds, which is faster than any autoscaler reacts.

---

## 8. Production checklist

**Before the first deploy of this change**

- [ ] `TRUSTED_PROXY_COUNT` matches your actual topology. Confirm by checking
      that `/internal/metrics` and the audit log show *client* addresses, not
      the router's. Getting this wrong in either direction is a security bug.
- [ ] `GUNICORN_KEEPALIVE` (75 s) is **above** your router's idle timeout.
- [ ] `instances × WEB_CONCURRENCY × (DB_POOL_SIZE + DB_MAX_OVERFLOW)` is
      under the Postgres plan's `max_connections`, with headroom for
      migrations and psql.
- [ ] `python benchmarks/benchmark_password_hash.py` on the real instance
      size; set `PASSWORD_HASH_CONCURRENCY` to the knee it reports.
- [ ] `loadtest/gunicorn-matrix.md` re-run on the real instance size; adopt
      its winner rather than the defaults here.
- [ ] The schema migration adds three columns and a partial index to
      `attendance`. On a large table, create the index `CONCURRENTLY` by hand
      first — the boot-time `CREATE INDEX IF NOT EXISTS` will then no-op.
- [ ] Existing attendance rows are backfilled `campos_state='skipped'`, so
      the first sweep does **not** replay history at CampOS. Confirm:
      `SELECT campos_state, count(*) FROM attendance GROUP BY 1`.

**Alerts worth having (all from `/internal/metrics`)**

- [ ] `scanmark_campos_outbox_pending` growing, or
      `scanmark_campos_outbox_oldest_seconds` above one lecture — delivery is
      not draining.
- [ ] `scanmark_campos_outbox_failed` above zero — dead letters need a human.
- [ ] `scanmark_session_store_up == 0` — Redis is down and the deployment is
      running on cookie sessions.
- [ ] `scanmark_password_shed_total` rising — a login stampede is being shed;
      scale out before the next lecture slot.
- [ ] `scanmark_db_pool_exhausted_total` above zero — 503s are being served;
      this is the PgBouncer trigger.
- [ ] `scanmark_scan_budget_exceeded_*` — says *which* stage is over budget,
      so "scans got slow" becomes a component name.
- [ ] Service-wide p95 from the buckets, not the per-worker percentiles:
      `histogram_quantile(0.95, sum(rate(scanmark_scan_response_ms_bucket[5m])) by (le))`.

**Rehearsal, on staging, before the first real lecture**

- [ ] `loadtest/scan_burst.py` at 200 / 600 / 1,000 / 2,000. Accept only on
      **rows == admitted, duplicates == 0** — latency is secondary to that.
- [ ] `--login-noise 40` at 600, to see what a sign-in rush does to scans.
- [ ] `--projector-watchers 3` at 2,000.
- [ ] Kill Redis mid-run. Expect degraded, not down.
- [ ] Point CampOS at a black hole, run 2,000 scans, confirm all succeed and
      all queue; restore CampOS and confirm the outbox drains to zero.
- [ ] `SIGHUP` during a burst. Expect zero loss.
- [ ] Set `SCAN_ADMISSION_RATE` from the throughput the run actually
      sustained — not from this document.

**On the day**

- [ ] Scale out *before* the timetable, not on CPU. A burst is over in six
      seconds; no autoscaler is that fast.
- [ ] Watch outbox depth and `session_store_up`. Everything else is
      diagnostics.

---

# Appendix: the previous round (2026-08-08)

Date: 2026-08-08

## Evidence boundaries

The repository has no staging URL, seeded staging identities, production
Postgres/Redis credentials, deployment telemetry, or physical Android devices.
Accordingly, this change does **not** claim 600- or 2,000-user concurrent
capacity and does not invent camera/GPS/CPU numbers. The checked-in Locust
matrix is the required staging gate. Measurements below are from the bundled
Python runtime on this workstation, in-memory SQLite, cookie sessions, and
sequential requests unless a row explicitly says otherwise.

Initial evidence: the original focused suite reached 58 passing tests but did
not terminate within 90 seconds. Importing the original application on this
Windows console failed with `UnicodeEncodeError` before an application route
could be benchmarked. After the changes, the complete suite terminates normally
with 72 passing tests in 3.18 seconds.


## Capacity hardening and harness rebuild (this change)

### What the previous capacity evidence was worth

The Locust harness sent `lat: null, lon: null` and omitted `accuracy_m`,
`location_age_ms` and `captured_at`. With the geofence on, those scans are
refused at the location check — before the database insert, the CampOS
enqueue and most of the work a real scan does. Any throughput number it
produced described the rejection path. It has been rebuilt to send the exact
body a phone sends, and the scenarios now run with CSRF, rate limiting,
Redis, Postgres, sessions and the geofence all enabled.

### Local harness validation (NOT a capacity claim)

Run on one 4-core container with Postgres 16, Redis 7, gunicorn 4x8 and the
load generator all competing for the same cores. That makes the
client-observed latency a measurement of the box, not of ScanMark; it is
recorded here only to show what the harness now exercises.

Scenario: 2,000 seeded students, one open session, one QR token, spawn rate
500/sec, geofence required, `captured_at` required, CSRF on, rate limiting on.

| Measure | Result |
|---|---|
| Scans issued | 2,000 |
| Locust failures | 0 |
| Attendance rows written | 2,000 |
| Distinct students | 2,000 |
| Duplicate (student, session) pairs | 0 |
| Roster entries with no attendance | 0 |
| Distinct device ids | 2,000 |
| Token-expiry rejections | 0 |
| 5xx | 0 |
| Server-side `scan_response` p50 / p95 / p99 | 31 / 60 / 76 ms |
| Client-observed p50 / p95 | 3,600 / 6,700 ms |

The gap between 31 ms server-side and 3.6 s client-observed is queueing in
front of the application on a saturated 4-core box shared with the load
generator. That the two can be told apart at all is the point of the
per-stage instrumentation: on staging the same comparison distinguishes "the
app is slow" from "gunicorn is queueing".

**The staging matrix remains the only capacity authority.** No number above
should be quoted as user capacity.

One observation worth carrying into staging: on this contended box the stage
most often over budget was `enqueue` (the hand-off to the bounded CampOS
executor) at ~8 ms p50 against a 5 ms budget, not `db_insert` at ~10 ms
against 20 ms. On four shared cores that is as likely to be scheduling
contention as real work, which is exactly why the budgets are documented as
requiring calibration from staging rather than accepted from this run.

### Two defects the local run exposed

Both were invisible without actually running it:

1. **The harness under-counted its own load.** With `--processes 3`, each
   Locust process imported the file fresh and restarted its user counter, so
   three processes signed in as the same students. The duplicates came back
   409, which the scenario counts as success — correctly, from a student's
   point of view — so the run reported 2,000 scans against **667 rows**.
   Processes now take disjoint interleaved slices of the roster.

2. **The suite could not run against real Redis.** Pinned classrooms, cached
   headcounts and admission buckets persisted between tests, and because ids
   repeat, a classroom pinned for "session 1" in one test was still pinned in
   the next — so tests expecting no geofence silently got one. 12 tests
   failed the first time the suite met a real Redis. Redis is now flushed
   between tests exactly as the in-memory fallback is cleared, and the whole
   suite passes both with and without it.

### Admission control, measured against real Redis

`SCAN_ADMISSION_RATE=50`, `SCAN_ADMISSION_BURST=60`:

| Input | Admitted | Expected |
|---|---:|---|
| 500 calls, instantaneous | 62 | 60 burst + ~0.05s refill ~= 63 |
| 500 calls after 1s idle | 53 | ~50, one second of refill |
| 10 calls on a different session | 10 | unaffected — buckets are per session |
| Any call with Redis unreachable | admitted | fails open by design |

The local load generator tops out around 80 scans/sec, well under any
sensible bucket, so shedding could not be provoked end-to-end on this
hardware — it is verified directly against Redis and by unit tests instead.
Set the rate from the staging matrix; it ships at 0 (off).

### Redis is no longer on the write path

A successful scan performed a Redis `DELETE` to invalidate the lecturer's
cached headcount: 2,000 round trips inside 2,000 requests, to save at most
`ATTENDEE_SUMMARY_TTL` (2s) on a number that is visibly moving anyway. Removed.
The TTL alone bounds staleness, and the feed now falls back to Postgres when
Redis is unhealthy rather than failing.


## 1. Attendance correctness and hot database path (P0/P2)

FILE(S): `app.py`, `models.py`, `test_performance.py`

CURRENT BEHAVIOR: The source used the 100 m configured geofence in its message
but enforced a hard-coded 50 m threshold. It loaded session and course
separately, materialized the student's enrollment relationship, selected for a
duplicate, and only then attempted an insert.

MEASURED BOTTLENECK: The old source contains two point lookups, a relationship
membership load, and a duplicate query before the write. A valid before-latency
sample is unavailable because the original app did not import in the local
runtime. This limitation is preserved rather than replaced with an estimate.

ROOT CAUSE: Two sources of truth for geofence distance and application-level
check-then-insert logic.

CHANGE: `GEOFENCE_RADIUS_M` is authoritative. Session/course are fetched by one
join, enrollment by an indexed existence query, and attendance by dialect-native
`INSERT ... ON CONFLICT DO NOTHING ... RETURNING`. Postgres and SQLite use the
same conflict contract. The unique student/session index remains the final
guard. `(session_id,id)` and instructor course-side indexes support cursor and
authorization queries.

WHY IT IS FASTER: The successful path avoids ORM relationship materialization
and removes the duplicate SELECT. The transaction contains only the insert and
commit.

SECURITY/CORRECTNESS IMPACT: 78 m and 99 m are accepted at a 100 m radius; 101 m
is rejected. Invalid/stale coordinates and cross-user offline queue records are
rejected. Exactly one attendance row can win a duplicate race.

BEFORE: Hard-coded `dist > 50`; application duplicate SELECT; no executable
route baseline on this workstation.

AFTER: Route regression budget is at most 5 SQL statements including user load.
The local 600-student sequential guard completed 600/600 successful requests at
130.4 requests/s: p50 6.388 ms, p95 10.492 ms, p99 14.001 ms, max 16.334 ms.
This is a microbenchmark, not concurrent capacity.

TEST: `pytest -q -p no:cacheprovider`; `python -B
benchmarks/benchmark_scan_endpoint.py --students 600 --max-p99-ms 50`.

## 2. QR verification and phone scanner (P1)

FILE(S): `app.py`, `templates/scan.html`, `static/scanner.js`,
`static/vendor/jsQR.min.js`, `templates/student_dashboard.html`,
`benchmarks/benchmark_qr.py`

CURRENT BEHAVIOR: The rendered scanner requested 1920x1080 video, decoded the
entire frame with jsQR every 100 ms, started a new 2-second focus interval on
each open, waited an artificial 500 ms after detection, and only then requested
a zero-cache GPS fix. A second scanner implementation and remote dependency
also lived in the student dashboard.

MEASURED BOTTLENECK: This is source-level evidence. Low-end Android decode time,
thermal load, camera startup, and GPS distributions were not measurable without
the required devices.

ROOT CAUSE: Oversized analysis frames, fixed polling, serial QR/GPS work, leaked
timers, and duplicate scanner implementations.

CHANGE: One scanner now requests 1280x720, decodes a centered square bounded at
960 px with periodic full-frame fallback, prefers native `BarcodeDetector`, and
uses pinned self-hosted jsQR 1.4.0 as fallback (SHA-256
`32214c74ee92d37de6d88276987690d996ce757668e82ca1709dba5e0be9fcce`).
Cadence adapts to decode cost. GPS prewarms while the camera opens, accepts a
recent 10-second fix, sends age/accuracy/client timing, and removes the 500 ms
wait. Tracks, animation frames, intervals, and retries are cleaned up.

WHY IT IS FASTER: Analysis touches substantially fewer pixels, avoids overlapping
decode calls, uses a native detector where available, and overlaps location
acquisition with scanning.

SECURITY/CORRECTNESS IMPACT: HMAC-SHA256 and `compare_digest` remain local;
display cache is 12 seconds and server acceptance remains 45 seconds. Future,
oversized, malformed, tampered, and expired tokens are rejected. CSRF remains on
the JSON request.

BEFORE: Full 1920x1080 jsQR every 100 ms plus a fixed 500 ms post-detect delay.
No trustworthy device timing baseline is available.

AFTER: 10,000 verifier iterations: p50 0.0070 ms, p95 0.0146 ms, p99 0.0349 ms,
112,109 verifications/s. 100,000 iterations: p50 0.0070 ms, p95 0.0183 ms,
p99 0.0363 ms, 103,498/s. Camera/CPU/GPS after-values remain a device staging
gate.

TEST: QR round-trip/tamper/expiry/future regression; rendered scanner assertions;
`node --check static/scanner.js`; `python -B benchmarks/benchmark_qr.py
--iterations 100000`.

## 3. Incremental lecturer feed (P2)

FILE(S): `app.py`, `templates/generate_qr.html`, `models.py`,
`benchmarks/benchmark_attendee_feed.py`

CURRENT BEHAVIOR: Every 3 seconds the endpoint serialized every attendee and the
browser cleared/rebuilt the entire list. QR PNG was requested every 5 seconds
despite a 12-second token cache.

MEASURED BOTTLENECK: Replaying the old response shape over identical fixtures
measured 51,667 bytes per poll at 600 attendees and 172,068 bytes at 2,000,
before transport compression. The old browser also performed 600/2,000 row
rebuilds per poll.

ROOT CAUSE: No cursor and whole-list DOM replacement.

CHANGE: `/api/session/<id>/attendees?after=<attendance_id>&limit=250` returns
`present`, `enrolled`, `new_attendees`, `last_id`, and `has_more`. Rows use the
`(session_id,id)` cursor index. Counts have a two-second shared cache invalidated
after commit. The projector polls once per second while visible, drains bounded
batches, and prepends only new nodes using `textContent`.

WHY IT IS FASTER: Steady-state traffic and DOM work are proportional to new
scans, not class size.

SECURITY/CORRECTNESS IMPACT: Existing course authorization remains. DOM content
is no longer constructed with attendee HTML, reducing injection risk.

BEFORE: 51,667/172,068 bytes and a complete 600/2,000-row rebuild every poll.

AFTER: At 600, largest batch 21,846 bytes, one-time initial transfer 52,381
bytes in 3 batches, then 98-byte empty polls. At 2,000, largest batch 22,099
bytes, one-time initial transfer 175,675 bytes in 8 batches, then 100-byte empty
polls. Local SQLite maximum batch times were 10.928 ms and 18.583 ms; empty
polls were 2.446 ms and 2.412 ms. Real projector visibility p95 remains a
staging/browser measurement.

TEST: Cursor/payload/query-budget regression; `python -B
benchmarks/benchmark_attendee_feed.py --attendees 600` and `--attendees 2000`.

## 4. Background stability and CampOS isolation (P3)

FILE(S): `performance.py`, `app.py`, `notifications.py`,
`campos_integration.py`

CURRENT BEHAVIOR: Two standard `ThreadPoolExecutor` instances had unbounded
queues. Notification preference could be queried repeatedly in one workflow.
CampOS retries used deterministic delays.

MEASURED BOTTLENECK: Queue depth and oldest age were unobservable, so a valid
before queue measurement is unavailable. The unbounded queue type and repeated
preference queries are direct source evidence.

ROOT CAUSE: No admission bound or queue telemetry; nested notification helpers
did not share their already-loaded preference.

CHANGE: Separate bounded pools serve post-scan work, CampOS delivery, and
outbound providers. Default pending capacity is 2,000 per path; submit is
non-blocking and rejection is counted/logged. Metrics expose depth, active
workers, oldest job age, queue delay, submitted/completed/rejected. Preference
is passed through the early-warning pipeline. CampOS keeps bounded retries with
production jitter. Attendance commits before any external submission.

WHY IT IS FASTER: Web threads never wait for providers and optional work cannot
consume unbounded memory.

SECURITY/CORRECTNESS IMPACT: Provider/CampOS failures cannot roll back attendance.
No durable broker was added without evidence. A full/restarting in-process queue
can lose optional delivery and is surfaced as a rejection metric; if staging
shows that condition, deploy a durable worker queue as the next change.

BEFORE: Unbounded pending work; no queue age/depth; deterministic retries.

AFTER: Bound/rejection behavior has an automated test. Live queue depth and
CampOS delivery delay require the 2,000-user staging run.

TEST: `test_bounded_executor_rejects_excess_work`; existing CampOS retry tests.

## 5. Database/session/startup observability (P0/P3)

FILE(S): `app.py`, `performance.py`, `gunicorn.conf.py`, `models.py`

CURRENT BEHAVIOR: Missing imports made SQLite application startup unreachable
after the console error. Daily-session lookup wrapped the timestamp column in
`DATE()` and could race across workers. `/healthz` still entered Flask, where a
server-side session may be opened.

MEASURED BOTTLENECK: Original application import failed locally. The health
route's zero-work claim was not enforced before the Flask session interface.

ROOT CAUSE: Import/startup gaps, non-sargable daily lookup, application-only
session creation check, and route-level rather than WSGI-level health response.

CHANGE: Imports/startup are fixed; console output is encoding-safe. Daily lookup
uses a timestamp range, a per-process lock, and a Postgres advisory transaction
lock. `/healthz` returns 204 in outer WSGI middleware before Flask. Postgres uses
an instrumented queue pool. Metrics include DB query latency/count, checked-out
connections, pool wait, Redis operation latency/count, scan stage/response
timings, client timings, feed timing, 500s, and background queues. Scheduler can
be disabled for tests and shuts down cleanly.

WHY IT IS FASTER: Indexes can serve the day range; health probes consume no
session/DB/Redis work; pool wait and query latency identify the actual constraint
before worker/pool changes.

SECURITY/CORRECTNESS IMPACT: One production daily session is created across
preloaded Gunicorn workers. Metrics contain aggregate timing/counts and no user
identity. Production metrics require a bearer token and are otherwise hidden.

BEFORE: Local import failure; health route inside Flask; daily check could race.

AFTER: Import smoke succeeds with 41 routes; health is 204 with zero SQL; 20
repeated daily creation attempts return one id. Live pool/Redis distributions
require staging.

TEST: Import/health smoke command; health zero-query and daily-session tests.

## 6. Whole-application bounded work (P4)

FILE(S): `app.py`, `templates/view_attendance.html`,
`templates/hod_dashboard.html`, `templates/dean_dashboard.html`,
`templates/base.html`, `static/service-worker.js`

CURRENT BEHAVIOR: Attendance history loaded an unbounded semester, HOD/Dean/DAP
routes loaded full object collections, CSV used repeated string concatenation,
Chart.js loaded on every page, and offline cursor sync awaited network activity
inside an IndexedDB cursor transaction.

MEASURED BOTTLENECK: These were unbounded source paths. No production history
cardinality or page p95 was supplied.

ROOT CAUSE: Missing pagination, materialization for counts, quadratic CSV string
growth, global asset placement, and transaction lifetime misuse.

CHANGE: Attendance sessions paginate 10/page and HOD courses 50/page; Dean/DAP
use counts without unused collections. CSV writes to a 1 MiB spooled stream and
then yields 64 KiB chunks. Chart.js is limited to analytics pages. Offline scans
use a user+QR dedupe key, queued (not success) status, current-user guard, fresh
CSRF, sequential retry, and deletion only after definitive JSON responses.

WHY IT IS FASTER: Page work is bounded, large CSVs spill instead of growing a
quadratic in-memory string, and common pages avoid Chart.js.

SECURITY/CORRECTNESS IMPACT: Queued scans cannot replay under another signed-in
user. 401/429/5xx/network failures remain queued; definitive duplicate/expired
responses are removed. The database unique key preserves idempotency.

BEFORE: Unbounded pages, global Chart.js, misleading offline success, fragile
cursor continuation.

AFTER: Pagination, streamed-response, offline schema, scanner render, and all
Jinja templates have regression coverage. Production page p95 is not measured.

TEST: `test_csv_export_is_streamed`, template compilation, scanner page test,
and full pytest suite.

## Staging capacity gate

Install `requirements-loadtest.txt`, seed staging, and run every command in
`loadtest/README.md`. It covers 200/600/1,000/2,000 users at 10/25/50/100/200
spawn rates, exact 600 within 30 seconds, 20-way duplicate race, 5x600, 10x300,
and a separate login stampede. Compare 2x8, 4x8, 4x12, and 6x8 Gunicorn cases
using `loadtest/gunicorn-matrix.md`. Accept a configuration only when the scan
SLO (p50 <100 ms, p95 <300 ms, p99 <750 ms), error/expiry goals, pool budget,
Redis health, and background drain all pass.

PgBouncer is not added speculatively. Add transaction pooling when measured
direct connections exhaust the plan or scale-out connection math exceeds it.
No deployment-region manifest exists in this repository; the staging report
must record web/Postgres/Redis regions and RTT and co-locate them before tuning
worker counts.

## Final scorecard

`N/M` means not measured because the required device or staging infrastructure
was not supplied.

| Metric | Before | After / gate |
|---|---:|---:|
| Scanner camera startup | N/M | N/M; real-device gate |
| QR decode p50/p95 | N/M | N/M on device; adaptive/native path implemented |
| QR CPU usage | N/M | N/M; thermal/device gate |
| GPS acquisition p50/p95 | N/M | N/M; GPS prewarms with 10 s recent-fix policy |
| QR detected to request start | fixed +500 ms before GPS | N/M; artificial 500 ms removed |
| `mark_attendance` p50/p95/p99 | unavailable; original app import failed | 6.388/10.492/14.001 ms local sequential SQLite; staging gate required |
| Attendance SQL queries/request | old source had user + 2 point + relationship + duplicate + insert | <=5 in regression guard |
| Redis calls/successful scan | not instrumented | 2 on configured Redis path (location GET + feed invalidation DELETE), timed |
| DB pool wait | not instrumented | N/M live; `db.pool.wait` histogram added |
| Max scans/sec | N/M | 130.4/s local sequential only; N/M concurrent |
| 600-user error rate | N/M | 0/600 local sequential; concurrent staging gate |
| 2,000-user error rate | N/M | N/M staging gate |
| QR-expired-under-load rate | N/M | N/M staging gate |
| Projector recurring payload at 600 | 51,667 B/full poll | 98 B/no-change poll; max new-row batch 21,846 B |
| Projector recurring payload at 2,000 | 172,068 B/full poll | 100 B/no-change poll; max new-row batch 22,099 B |
| Projector DOM update time | N/M; rebuilt all rows | N/M; appends only new rows |
| Background queue depth | unbounded/unobservable | bounded 2,000; N/M live depth |
| CampOS delivery delay | N/M | N/M; queue age/delay metrics added |
| Student dashboard p95 | N/M | N/M; <=6 SQL guard at 21 courses |
| CampOS to ScanMark launch p95 | N/M | N/M; SSO boundary unchanged |

## Validation captured

- `72 passed` in 3.18 seconds.
- Python AST and Node syntax checks pass.
- All Jinja templates compile.
- `git diff --check` passes.
- 10k and 100k QR benchmarks pass.
- 600 sequential endpoint threshold passes with zero failures.
- 600 and 2,000 projector fixture benchmarks pass.
