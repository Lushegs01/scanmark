# ScanMark performance change report

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
