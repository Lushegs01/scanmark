# ScanMark Deployment Guide

Deployment and rehearsal guide for the 2,000-student lecture-hall target.
Capacity is accepted only from the staging matrix below.

## Required services

| Service | Why it's required in production |
|---|---|
| **PostgreSQL** (`DATABASE_URL`) | SQLite is single-writer and sits on ephemeral disk on Heroku/Render — concurrent scans lock up and **attendance data is wiped on every restart**. Production **refuses to boot** without it (override: `ALLOW_SQLITE_IN_PRODUCTION=true`). |
| **Redis** (`REDIS_URL`) | Sessions, rate limits, class locations, QR token + attendee-feed + QR-image caches. Production **refuses to boot** without it, and pings it at startup so a broken URL fails immediately rather than on the first request (override: `ALLOW_MISSING_REDIS=true`). Without Redis the pinned classroom lives in one worker's memory, so a scan is geofenced only if it happens to land on the same worker. Provision enough memory and prefer eviction policy `volatile-lru` (or `noeviction`) — arbitrary eviction of session keys logs people out mid-class. |
| **SMTP** (`MAIL_*`) | Signup confirmation links and password resets. That is all ScanMark sends — nothing goes out during a class, so provider quotas are no longer a capacity concern. |

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `SCANMARK_ENV` / `FLASK_ENV` | — (means production) | **ScanMark treats a deployment as production unless it positively says otherwise.** Recognised non-production names: `development`, `dev`, `local`, `test`, `testing`, `ci`, `debug`. An empty, missing or unrecognised value means production. The old rule recognised only `FLASK_ENV=production` and `RENDER=true`, so the same image on any other host ran with the development secret, cookies without `Secure`, no HSTS and email verification off. |
| `PUBLIC_ORIGIN` | — | The canonical origin, e.g. `https://scanmark.funaab.edu.ng`. Every link that leaves the process is built from this instead of the request's `Host` header — a request carrying `Host: evil.example` otherwise produces an emailed password-reset link on `evil.example`. Required in production (override: `ALLOW_HOST_HEADER_URLS=true`). Render's `RENDER_EXTERNAL_HOSTNAME` is used automatically when unset. |
| `TRUSTED_HOSTS` | — | Extra hostnames served, comma separated. Requests for any other host get `421`. `PUBLIC_ORIGIN`'s host is always trusted. |
| `SCANMARK_TIMEZONE` | `Africa/Lagos` | Timezone every displayed time is converted to, and the one "today" is decided in. Storage stays UTC. |
| `ACADEMIC_YEAR_START_MONTH` / `SECOND_SEMESTER_START_MONTH` | 9 / 2 | Where the academic calendar turns over. Courses carry a year, semester and optional section, so `CSC201` can run again next term without colliding with this term's offering or inheriting its class sessions. |
| `SECRET_KEY` | — | Required; app refuses to boot in production without it. |
| `DATABASE_URL` | SQLite (dev only) | Postgres URL in production. |
| `REDIS_URL` | — (dev fallback) | Required in production. |
| `WEB_CONCURRENCY` | 4 | Gunicorn workers. Sized for a 1 GB instance. |
| `GUNICORN_THREADS` | 8 | Threads per worker. workers × threads = concurrent requests. |
| `GUNICORN_TIMEOUT` | 60 | Above the 30s platform router timeout on purpose. |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | 5 / 5 | **Per worker.** Postgres sees up to `workers × (pool + overflow)` connections — 40 with defaults. Keep below your plan's connection cap, or put PgBouncer in front when scaling out. |
| `GEOFENCE_RADIUS_M` | 100 | Max metres between the pinned class location and a scanning student. Phone GPS inside buildings is often 20–50m off — don't set this too tight. |
| `GEOFENCE_REQUIRED` | **true** | What happens when a lecturer never pins a classroom (they dismissed the browser's GPS prompt). Defaults **on**: with nothing to measure against, the scan is refused. Off, the failure is silent and total — a lecturer who dismissed one prompt records a whole term of attendance that anyone could have submitted from anywhere, with nothing on the register saying so. Refusing is loud and fixable in ten seconds by granting location on the QR screen, which tells the lecturer which of the two applies. |
| `GEOFENCE_MAX_ACCURACY_M` | `GEOFENCE_RADIUS_M` | Reported GPS accuracy beyond which a fix proves nothing. The reading is refused rather than used to widen the fence — accuracy is self-reported, so treating it as an allowance would be a free pass for the asking. |
| `GEOFENCE_MAX_LOCATION_AGE_MS` | 30000 | Oldest position fix a scan may carry. Both this and `accuracy_m` are now **required** on a scan when a classroom is pinned; they used to be read only if present, so omitting them was the way past every proximity check. |
| `SCAN_ADMISSION_RATE` | 0 (off) | Scans per second per session that admission control lets through to the database. A token bucket in Redis smooths the burst a projected QR code creates — arrival rate rather than sustainable rate otherwise decides how much work Postgres is asked to do in the first second. **Set from the staging matrix**: the default is 0 because a number invented in code would be a guess with the authority of a default. Fails open if Redis is unreachable, so a limiter outage never becomes an attendance outage. |
| `SCAN_ADMISSION_BURST` | one second of `SCAN_ADMISSION_RATE` | Instantaneous burst allowed through untouched before shaping starts. A class arriving inside the sustainable rate never meets this code. |
| `SCAN_ADMISSION_RETRY_SECONDS` | 0.5 | `Retry-After` on a shed scan. Deliberately sub-second: this smooths microbursts, it does not queue attendance. |
| `BUDGET_*_MS` / `BUDGET_SCAN_TOTAL_MS` | see below | Per-stage response budget. Breaches increment `scan_budget_exceeded_<stage>_total`, which is what turns "scans are slow" into "db_insert is over budget and nothing else is". |
| `ATTENDEE_SUMMARY_TTL` | 2 | Seconds the lecturer's headcount is cached. This is the *only* thing bounding how stale the counter is — nothing invalidates it per scan any more. |
| `PROJECTOR_RECENT_ROWS` | 50 | Rows the live screen keeps in the DOM. The screen answers "how many are in, and who just scanned"; the full sheet is its own page. |
| `REDIS_MAX_CONNECTIONS` | `WEB_CONCURRENCY x GUNICORN_THREADS + 8` | Explicit Redis pool ceiling. Left implicit, every thread opens connections on demand with no limit, which multiplies against the Redis plan exactly when the class needs them. |
| `REDIS_CONNECT_TIMEOUT` / `REDIS_SOCKET_TIMEOUT` | 2 / 2 | Well inside the platform router timeout, so a scan never waits on a Redis command that will not answer. |
| `REDIS_HEALTH_CHECK_INTERVAL` | 30 | Recycles a connection idle across a proxy's idle cut. |
| `CLASS_LOCATION_TTL` | 14400 | How long a pinned classroom lives. Keyed per session, so it dies with the meeting. |
| `REQUIRE_CAPTURED_AT` | true | A scan must report when its camera read the code. Off only while offline scans queued by a pre-release service worker are still draining. |
| `DB_SATURATION_RETRY_SECONDS` | 2 | `Retry-After` when the connection pool is exhausted. |
| `ATTENDANCE_PREVIEW_ROWS` | 25 | Names rendered inline per session on the attendance page. The full sheet is a page of its own — ten sessions of a 2,000-student course is 20,000 rows in one document otherwise. |
| `CAMPOS_SSO_REQUIRE_STATE` | true | CampOS callbacks must carry a `state` value this browser was issued (set by `/sso/start`), so a hand-off code cannot be fed to somebody else's browser to sign it into the attacker's account. Turn off only for a CampOS that predates state support. |
| `REQUIRE_EMAIL_VERIFICATION` | on in production | Self-service signups must click an emailed link before their password works. **Do not turn this off in production** — the signup form accepts any address, including a `@staff` one the registrant does not own. CampOS SSO and Google sign-ins are pre-verified and unaffected. |
| `MIN_PASSWORD_LENGTH` | 10 | Enforced identically at signup and at password reset. |
| `ANON_RATE_LIMIT_PER_MINUTE` / `ANON_RATE_LIMIT_PER_DAY` | 20000 / 500000 | Default budget for *anonymous* requests, which are keyed by IP — one campus NAT is a single key for thousands of phones. Sensitive unauthenticated endpoints carry their own tight per-address limits on top of this. |
| `BACKGROUND_QUEUE_MAXSIZE` / `BACKGROUND_WORKERS` | 500 / 4 | Sizes the account-email pool (signup links, password resets). `ACCOUNT_EMAIL_WORKERS` overrides the worker count. Nothing is queued during a class, so this pool is idle under scan load. |
| `ATTENDANCE_TARGET_PERCENT` | 75 | Percentage shown as the target on student dashboards. Display only — nothing is sent when a student falls below it. |
| `HSTS_MAX_AGE` | 31536000 | `Strict-Transport-Security` max-age, sent in production only. |
| `CAMPOS_SSO_SECRET` | — | Shared secret for CampOS SSO; must match CampOS Core's `SSO_JWT_SECRET_SCANMARK`. SSO fails closed until it is set, and production additionally requires at least 32 bytes. `SSO_JWT_SECRET` is still read as a rollout fallback, but new deployments should set `CAMPOS_SSO_SECRET`. |
| `REMEMBER_COOKIE_DAYS` | 30 | How long "remember me" keeps students signed in. Longer = fewer morning login stampedes. |
| `STATIC_MAX_AGE` | 86400 | Cache-Control max-age (seconds) WhiteNoise puts on /static files. |
| `SENTRY_DSN` | — | Optional error monitoring. |
| `SENTRY_TRACES_SAMPLE_RATE` / `SENTRY_PROFILES_SAMPLE_RATE` | 0.1 | Raise temporarily for deep-dives; 1.0 during a burst burns quota and adds latency. |
| `METRICS_TOKEN` | — | Required to expose `/internal/metrics` in production. Use as `Authorization: Bearer ...`. |
| `CAMPOS_WORKERS` / `CAMPOS_QUEUE_SIZE` | 4 / 2000 | Separate bounded CampOS delivery path. |
| `SCAN_LOG_SAMPLE_RATE` | 0.02 | Fraction of *successful* scans that get a timing line. Every non-success outcome is always logged. Keeps a 2,000-scan class to ~40 lines rather than 2,000. |
| `QR_TOKEN_TTL` | 12 | Seconds a token is cached and displayed before the projector rotates to a new one. The countdown on the QR screen reads this value. |
| `QR_CODE_WINDOW` | 45 | How stale a scanned token may be when the request is **processed**, not when it was scanned. It must stay comfortably above your p99 scan latency or legitimate queued scans bounce as "expired" and their phones retry, amplifying the burst. It is also the outer bound on the replay window for a photographed code, narrowed in practice by three other checks: the session must still be open (ending a class kills every token for it at once), the client's reported capture time must fall within `QR_CAPTURE_WINDOW` of the token, and the geofence must be satisfied. The service worker reads this value from the server so the offline queue can never promise to redeem a token the server will refuse. |

## Health checks

| Path | Meaning | Use it for |
|---|---|---|
| `/livez` | The process is up. Answered by the WSGI middleware before Flask opens a session or an extension, so it stays cheap during a cold start. | Container liveness probes. |
| `/healthz` | This instance can actually serve: PostgreSQL and Redis were reachable. `204` when healthy, `503` with a JSON `checks` object naming the failed dependency when not. SMTP is checked and reported but does not fail the probe — losing signup mail should not pull an instance out of the pool. The result is cached for `READINESS_CACHE_SECONDS` (default 5) so a per-second probe does not add a query per second. | Platform health checks and load-balancer readiness. |

`/healthz` used to answer `204` from the WSGI layer without touching anything,
so a deployment whose database or Redis had gone stayed "healthy" while every
real request failed.

## Startup checks

Production **refuses to boot** rather than degrading silently when any of the
following is missing. Each has a named escape hatch, and using one prints a
warning naming the variable that allowed it.

| Missing | Override |
|---|---|
| `SECRET_KEY` | none — there is no safe fallback |
| PostgreSQL (`DATABASE_URL`) | `ALLOW_SQLITE_IN_PRODUCTION=true` |
| Redis (`REDIS_URL`), or a `REDIS_URL` that does not answer a ping | `ALLOW_MISSING_REDIS=true` |
| `PUBLIC_ORIGIN` | `ALLOW_HOST_HEADER_URLS=true` |

Schema migrations are fatal too. A failed index creation used to print
"will retry next boot" and let the worker serve without the unique attendance
index — every scan then hit `INSERT ... ON CONFLICT` with no constraint to
name, returning a 500 per student for the whole class.

## Capacity architecture

The objective is that 2,000 simultaneous scans are boring. The pieces that
make that true, in the order a scan meets them:

```
Phone
  |
  v
Load balancer / Cloudflare
  |
  v
Gunicorn  (WEB_CONCURRENCY x GUNICORN_THREADS request slots)
  |
  v
Redis admission control        <- token bucket per session; smooths the
  |                               microburst a projected QR code creates
  v
mark_attendance                <- cheap rejections first, then one INSERT
  |
  v
PostgreSQL                     <- the source of truth
```

Two rules hold the shape:

**Nothing external happens before the attendance commit.** The scan path is
authenticate -> verify the QR signature locally -> resolve the session ->
verify enrolment -> admission control -> verify the geofence -> INSERT ->
COMMIT -> respond. CampOS delivery is queued after the commit, on a bounded
executor, and cannot delay or fail a scan.

**Redis accelerates reads; it is not on the write path.** A successful scan
performs no Redis write at all. The lecturer's headcount is cached for
`ATTENDEE_SUMMARY_TTL` seconds, which bounds staleness without putting a
round trip inside every one of 2,000 requests — and the feed falls back to
PostgreSQL when Redis is unhealthy, because a cache failure must cost
database load, not the ability to see who is in the room.

Admission control fails **open**. If Redis is unreachable the scan is
admitted: without shaping the system behaves as it did before the bucket
existed, whereas a limiter that refuses would cost a whole class its register.

### Scan response budget

| Stage | Budget | What it is |
|---|---:|---|
| `qr_verify` | 1 ms | HMAC over a short string; local, no I/O |
| `session_course` | 10 ms | one indexed join |
| `enrollment` | 10 ms | one indexed existence check |
| `admission` | 5 ms | one Redis round trip |
| `geofence` | 5 ms | one Redis read plus a Haversine |
| `db_insert` | 20 ms | `INSERT ... ON CONFLICT DO NOTHING ... RETURNING` |
| `enqueue` | 5 ms | hand-off to the bounded CampOS executor |
| **total** | **100 ms** | an order of magnitude inside `QR_CODE_WINDOW` |

Calibrate these from your own staging run — `BUDGET_*_MS` override each.
Breaches are counted per stage, so a rehearsal tells you *which* component is
the problem instead of that something is.

### Database saturation

A request that waits out `pool_timeout` for a connection now returns **503
with `Retry-After`**, not 500. The distinction matters: 503 tells the phone
scanner to back off and retry, while 500 reads as "this will never work" and
is recorded as a server fault — and the usual reaction to those 500s, raising
the worker count, points *more* connections at the same exhausted database.

Do not raise `WEB_CONCURRENCY` blindly. Run the matrix in
`loadtest/gunicorn-matrix.md` and pick on throughput, p99 **and**
`db_pool_wait`, not CPU utilisation. The winner is often lower than expected.

### When to add PgBouncer

Not speculatively. One instance with a healthy measured pool does not need
it, and adding a queue without evidence makes diagnosis harder.

Add it when you run **two or more web instances**, because the connection
maths multiplies per instance:

```
instances x WEB_CONCURRENCY x (DB_POOL_SIZE + DB_MAX_OVERFLOW)
```

Two instances at the default 4 x (5 + 5) is 80 connections before anything
else connects. At that point:

```
Load balancer
  |
  +-> ScanMark instance x N --> PgBouncer (transaction pooling) --> PostgreSQL
  |
  +-> ScanMark instance x N --> Redis
```

Transaction pooling suits this workload: the scan path is short, autocommit-
shaped transactions with no session-level state to preserve.

## Roles

Only two roles can be self-assigned through the public signup form: **Lecturer**
and **Course Coordinator**, and only from a `@staff.funaab.edu.ng` address that
has confirmed its email. The supervisory roles — **HOD**, **Dean**, **DAP** —
read attendance beyond a single course, so they are never handed out by the
signup form. They arrive one of two ways:

1. **CampOS SSO**, from a signed launch identity whose scope names the faculty
   or department (see `campos_integration.py`); or
2. **a deliberate database change** by someone who already administers the
   deployment:

   ```sql
   UPDATE "user" SET role = 'hod', department = 'Computer Science'
    WHERE email = 'name@staff.funaab.edu.ng';
   ```

An HOD or Dean with no `department` / `faculty` recorded matches **no** courses —
placement has to be explicit.

## Scaling checklist

1. **One instance** (defaults): 32 request slots and an application-side
   Postgres ceiling of 40 connections. This is a staging candidate, not a
   capacity guarantee; accept it only after the checked-in 600/2,000 scenarios.
2. **Scaling out** (2+ instances): connection math multiplies per instance —
   add **PgBouncer** (transaction pooling) in front of Postgres, keep
   `DB_POOL_SIZE`/`DB_MAX_OVERFLOW` modest.
3. **Static/bandwidth**: WhiteNoise already serves /static compressed with
   cache headers. A CDN (e.g. Cloudflare free tier) in front additionally
   absorbs static traffic and TLS handshakes close to campus.
4. **Email at scale**: not a factor. ScanMark sends one confirmation link per
   signup and a password reset on request; nothing goes out during a class,
   so a free-tier SMTP quota is ample.

## Load-testing before the semester

Rehearse the burst against **staging** (never production), with CSRF, rate
limiting, Redis, Postgres, sessions and the geofence all enabled. Turning any
of them off produces a number describing a system nobody is running.

```bash
pip install -r requirements-loadtest.txt
export TARGET_SECRET_KEY=<staging SECRET_KEY>
export TARGET_SESSION_IDS=<open class session id(s)>
export STUDENT_PASSWORD=<seeded password>
# The pin for those sessions. Wrong values mean every scan is legitimately
# out of geofence and the run measures the rejection path.
export CLASS_LAT=7.2257 CLASS_LON=3.4372

./loadtest/run_matrix.sh https://staging.yourdomain
```

The matrix walks class size (200/600/1000/2000/3000) against arrival rate
(25..800/sec), then runs the headline burst — **2,000 students at 500/sec
against one session and one code**, which is what actually happens when a
lecturer puts the QR on the projector — plus the multi-room, projector-feed,
duplicate-race and login-stampede scenarios. Each is accepted or rejected by
`loadtest/check_slo.py`.

Burst matters more than duration: 2,000 users over four minutes is 8
scans/sec and tells you almost nothing.

Acceptance is not latency alone. After each run confirm in the database that
the row count equals the class, that no student has two rows, and that nobody
on the roster is missing — a run can hit every latency target and still have
lost somebody's attendance. `loadtest/README.md` has the queries.

Use the complete scenario commands in `loadtest/README.md` and the worker/thread
decision matrix in `loadtest/gunicorn-matrix.md`. Local reproducible guards live
under `benchmarks/`; their SQLite results are regression signals, not staging
capacity claims. The evidence and final scorecard are in `PERFORMANCE_REPORT.md`.
