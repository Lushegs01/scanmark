# ScanMark Deployment Guide

How to run ScanMark so it survives a full lecture hall (2000 students)
logging in and scanning within a couple of minutes.

## Required services

| Service | Why it's required in production |
|---|---|
| **PostgreSQL** (`DATABASE_URL`) | SQLite is single-writer and sits on ephemeral disk on Heroku/Render — concurrent scans lock up and **attendance data is wiped on every restart**. The app prints a loud warning if production boots without this. |
| **Redis** (`REDIS_URL`) | Sessions, rate limits, class locations, QR token + attendee-feed + QR-image caches. Provision enough memory and prefer eviction policy `volatile-lru` (or `noeviction`) — arbitrary eviction of session keys logs people out mid-class. |
| **SMTP** (`MAIL_*`) | Confirmation/warning/report emails. Mind provider quotas: Gmail allows ~500/day (free) or ~2,000/day (Workspace) — one big class can exceed that, see `SCAN_CONFIRMATION_EMAILS` below. |

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | — | Required; app refuses to boot in production without it. |
| `DATABASE_URL` | SQLite (dev only) | Postgres URL in production. |
| `REDIS_URL` | — (dev fallback) | Required in production. |
| `WEB_CONCURRENCY` | 4 | Gunicorn workers. Sized for a 1 GB instance. |
| `GUNICORN_THREADS` | 8 | Threads per worker. workers × threads = concurrent requests. |
| `GUNICORN_TIMEOUT` | 60 | Above the 30s platform router timeout on purpose. |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | 5 / 5 | **Per worker.** Postgres sees up to `workers × (pool + overflow)` connections — 40 with defaults. Keep below your plan's connection cap, or put PgBouncer in front when scaling out. |
| `SCAN_CONFIRMATION_EMAILS` | true | Set `false` during huge events to stop sending one email per scan. |
| `GEOFENCE_RADIUS_M` | 100 | Max metres between the pinned class location and a scanning student. Phone GPS inside buildings is often 20–50m off — don't set this too tight. |
| `REQUIRE_EMAIL_VERIFICATION` | on in production | Self-service signups must click an emailed link before their password works. **Do not turn this off in production** — the signup form accepts any address, including a `@staff` one the registrant does not own. CampOS SSO and Google sign-ins are pre-verified and unaffected. |
| `MIN_PASSWORD_LENGTH` | 10 | Enforced identically at signup and at password reset. |
| `ANON_RATE_LIMIT_PER_MINUTE` / `ANON_RATE_LIMIT_PER_DAY` | 20000 / 500000 | Default budget for *anonymous* requests, which are keyed by IP — one campus NAT is a single key for thousands of phones. Sensitive unauthenticated endpoints carry their own tight per-address limits on top of this. |
| `BACKGROUND_QUEUE_MAXSIZE` / `BACKGROUND_WORKERS` | 2000 / 10 | Pending background notifications before new ones are shed. Scans are never dropped — only the courtesy email/WhatsApp. A saturated queue logs a warning. |
| `HSTS_MAX_AGE` | 31536000 | `Strict-Transport-Security` max-age, sent in production only. |
| `SSO_JWT_SECRET` | — | Shared secret for CampOS SSO. **No fallback**: SSO token verification is disabled until this is set (must match CampOS Core). |
| `REMEMBER_COOKIE_DAYS` | 30 | How long "remember me" keeps students signed in. Longer = fewer morning login stampedes. |
| `STATIC_MAX_AGE` | 86400 | Cache-Control max-age (seconds) WhiteNoise puts on /static files. |
| `SENTRY_DSN` | — | Optional error monitoring. |
| `SENTRY_TRACES_SAMPLE_RATE` / `SENTRY_PROFILES_SAMPLE_RATE` | 0.1 | Raise temporarily for deep-dives; 1.0 during a burst burns quota and adds latency. |
| `QR window` | 45s (code) | `QR_CODE_WINDOW` in app.py — how stale a scanned token may be when *processed*. Tied to router timeout; change in code, not env. |

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

1. **One instance** (defaults): ~32 concurrent requests, Postgres ≥ 40
   connections. Handles a 2000-student class arriving over 1–2 minutes.
2. **Scaling out** (2+ instances): connection math multiplies per instance —
   add **PgBouncer** (transaction pooling) in front of Postgres, keep
   `DB_POOL_SIZE`/`DB_MAX_OVERFLOW` modest.
3. **Static/bandwidth**: WhiteNoise already serves /static compressed with
   cache headers. A CDN (e.g. Cloudflare free tier) in front additionally
   absorbs static traffic and TLS handshakes close to campus.
4. **Email at scale**: switch to a transactional provider (SES — `boto3` is
   already a dependency) or flip `SCAN_CONFIRMATION_EMAILS=false` and rely
   on the in-app record.

## Load-testing before the semester

Rehearse the burst against **staging** (never production):

```bash
pip install locust
export TARGET_SECRET_KEY=<staging SECRET_KEY>
export TARGET_SESSION_ID=<class session id>
export STUDENT_PASSWORD=<seeded password>
locust -f loadtest/locustfile.py --host https://staging.yourdomain \
       --users 2000 --spawn-rate 50 --headless --run-time 5m
```

Watch p95 latency on `/mark_attendance`, the 429/5xx rate, and
`token expired in queue` failures (those mean requests are queueing longer
than `QR_CODE_WINDOW`). See `loadtest/locustfile.py` for seeding details.

## Tests

```bash
pip install -r requirements.txt
python -m pytest -q        # runs on SQLite; no Postgres or Redis needed
```

`.github/workflows/ci.yml` runs this on every push, plus `pyflakes` over the
four source modules and a real `gunicorn` boot against Postgres + Redis. The
pyflakes step exists because a batch of undefined names (`selectinload`,
`joinedload`, `json`, `enrollments`, `IntegrityError`, `event`) once reached
`main` and 500'd three lecturer-facing endpoints; that step catches the whole
class of mistake in under a second.

`test_app.py::TestNoRouteExplodes` walks every GET route in the URL map and
asserts none returns 5xx. Add new routes and it covers them automatically.

## Backups and recovery

Attendance is the system of record for a student's eligibility to sit an exam,
so treat the database as irreplaceable.

**Backups**

- Turn on your provider's managed Postgres backups (Render and Heroku both do
  daily snapshots with point-in-time recovery on paid tiers) — confirm the
  retention window covers a full semester.
- Take an extra dump before every deploy that changes the schema, and keep it
  off the platform:

  ```bash
  pg_dump "$DATABASE_URL" --format=custom --file="scanmark-$(date +%F-%H%M).dump"
  ```

- **Rehearse the restore at least once before the semester**, into a scratch
  database. A backup nobody has restored is a guess:

  ```bash
  createdb scanmark_restore_test
  pg_restore --dbname=scanmark_restore_test --clean --if-exists scanmark-YYYY-MM-DD.dump
  psql scanmark_restore_test -c "SELECT count(*) FROM attendance;"
  ```

**What is and isn't recoverable**

| Store | Loss impact |
|---|---|
| **Postgres** | The attendance record itself. Restore from the most recent dump; scans between the dump and the failure are gone. |
| **Redis** | Sessions (everyone signs in again), live QR tokens, pinned class locations, rate-limit counters. Nothing durable — a lecturer re-pins the room and re-opens the QR page. Safe to flush. |
| **Instance disk** | Nothing. It holds only the checkout and generated static gzip files. |

**Schema changes.** Migrations are the idempotent `ALTER TABLE ... IF NOT
EXISTS` block at the bottom of `app.py`, run once in the gunicorn master at
boot. It only ever *adds* columns and indexes, so a rollback to the previous
release keeps working against the newer schema. There is no down-migration:
to undo a column you write the `ALTER TABLE ... DROP COLUMN` by hand, from a
fresh dump.
