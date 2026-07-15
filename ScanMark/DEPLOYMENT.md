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
| `SSO_JWT_SECRET` | — | Shared secret for CampOS SSO. **No fallback**: SSO token verification is disabled until this is set (must match CampOS Core). |
| `REMEMBER_COOKIE_DAYS` | 30 | How long "remember me" keeps students signed in. Longer = fewer morning login stampedes. |
| `STATIC_MAX_AGE` | 86400 | Cache-Control max-age (seconds) WhiteNoise puts on /static files. |
| `SENTRY_DSN` | — | Optional error monitoring. |
| `SENTRY_TRACES_SAMPLE_RATE` / `SENTRY_PROFILES_SAMPLE_RATE` | 0.1 | Raise temporarily for deep-dives; 1.0 during a burst burns quota and adds latency. |
| `QR window` | 45s (code) | `QR_CODE_WINDOW` in app.py — how stale a scanned token may be when *processed*. Tied to router timeout; change in code, not env. |

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
