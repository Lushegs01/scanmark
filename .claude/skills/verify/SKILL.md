---
name: verify
description: Build, launch and drive ScanMark (Flask + gunicorn + Redis + SQLite/Postgres) to verify changes end-to-end over HTTP.
---

# Verifying ScanMark

The app lives in `ScanMark/` (app root = where `Procfile` sits). Surface is HTTP.

## Build / launch

```bash
python3 -m venv /tmp/venv && /tmp/venv/bin/pip install -r ScanMark/requirements.txt
redis-server --port 6390 --dir /tmp --save '' --daemonize yes   # redis-server is preinstalled

cd ScanMark
export SECRET_KEY=verify-secret-key \
       DATABASE_URL="sqlite:////tmp/verify.db" \
       REDIS_URL=redis://127.0.0.1:6390/0 \
       MAIL_SERVER=127.0.0.1 MAIL_PORT=2525 \
       GUNICORN_CMD_ARGS="-b 127.0.0.1:8100"
/tmp/venv/bin/gunicorn --config gunicorn.conf.py app:app   # the real Procfile command
```

- `import app` runs `db.create_all()` + idempotent migrations + legacy backfill — seed
  data with a script that imports `app` under the same env.
- `MAIL_SERVER=127.0.0.1` makes background email sends fail instantly (connection
  refused) instead of hanging on Gmail; those `❌ Failed to send email` lines in the
  log are expected and prove sends are off the request path.
- Kill with `pkill -x gunicorn` — NEVER `pkill -f gunicorn` (matches your own shell).
  A `gunicorn.ctl` socket file appears in the app dir while running; don't commit it.

## Driving the scan flow

- Login: GET `/login`, scrape `name="csrf_token" value="..."`, POST `email`/`password`.
- JSON POSTs need header `X-CSRFToken`, scraped from any page's `CSRF_TOKEN = "..."`.
- QR token: lecturer GET `/api/qr_data/<session_id>` → `qr_text`, or forge one with the
  server's algorithm: `msg=f"S{sid}|{ts}"`, sig = first 16 hex chars of
  HMAC-SHA256(SECRET_KEY, msg), token = `msg|sig`. Tokens expire `QR_CODE_WINDOW`
  seconds after `ts` (checked at processing time).
- Student scan: POST `/mark_attendance` JSON `{qr_data, lat, lon}` (lat/lon only
  enforced when a class location is set in Redis).
- Live feed: lecturer GET `/api/session/<id>/attendees` (3s Redis cache,
  key `attendees_cache:<id>`).

## Gotchas

- `/static/*` is served by WhiteNoise at the WSGI layer (bypasses Flask
  routes); boot generates `.gz`/`.br` siblings in `ScanMark/static/`
  (gitignored). Dynamic responses are gzip'd by Flask-Compress — use
  `stream=True` + `response.raw.headers` to see `Content-Encoding`.
- The weekly-report cron job is exercised by calling `run_weekly_reports()`
  directly in a process with the same env (its surface is the scheduler);
  run it twice to check the already-sent dedupe.

- `/login` limit counts POSTs per (IP, email); `/mark_attendance` is 10/min per user.
  Limiter counters live in Redis under `LIMIT*` keys — delete only those to reset,
  never FLUSHDB (sessions share the same Redis).
- One attendance row per (student_id, session_id) is enforced by unique index
  `uq_attendance_student_session`; race-test with parallel scans and count rows.
- Booting with `FLASK_ENV=production` and no `DATABASE_URL` prints a SQLite warning
  and writes `ScanMark/instance/scanmark_v2.db*` — delete after.

## Flows worth driving after a change

scan success → duplicate scan → parallel duplicate race (assert 1 row) → stale-token
expiry → forged/malformed token → unenrolled student → rate-limit 429 (JSON body) →
attendees feed shape → second boot on the same DB (migration idempotency) →
remember-me survives dropping the session cookie → dashboard/lecturer views render →
CSV downloads → compression + cache headers on static → weekly reports twice.
