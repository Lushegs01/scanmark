# Browser end-to-end tests

`manual_code.e2e.cjs` drives the manual attendance code in real Chromium
(Playwright) against a real server — what only a browser can show:

- a phone with **no camera API and no QR decoder** marks attendance with the
  code alone, and the scanner's camera error points it there;
- the code path never calls `getUserMedia`;
- the input formats `XXXX XXXX`, keeps leading zeros, accepts pasted codes with
  spaces, ignores letters, and corrects cleanly at the separator;
- a double tap sends exactly one request; a dropped connection says "NOT
  recorded" after one quiet retry; an expired code clears and refocuses the
  box; a lockout counts down on the button;
- a student with two open classes must choose — the page never guesses;
- keyboard only: Tab reaches the box, focus is visible, Enter submits, the
  confirmation takes focus;
- the projector shows the code beside the QR in normal and full-screen
  layouts, its countdown matches the server's `expires_in_ms`, it rotates on
  its own once a minute, re-syncs when the tab returns, and blanks a code it
  cannot confirm;
- **QR scanning still works** (a canvas "camera" showing the live QR, decoded
  by jsQR) after the scanner's location code moved into
  `static/attendance-common.js`.

`qr_refresh.e2e.cjs` drives the projector's QR refresh: a dropped connection
or a proxy's 502 shows "Reconnecting…" in the QR's place (still in full
screen), retries with a growing backoff and brings the QR back by itself,
while a class really ended from another device still ends the projector and
stops it asking. It ends the seed's `ending_session_id` class, never the one
`manual_code.e2e.cjs` uses.

They create attendance and end a class, so use a disposable database.

```bash
# Server: the real Procfile command, on Postgres + Redis
export SECRET_KEY=e2e-secret SCANMARK_ENV=ci \
       DATABASE_URL=postgresql://…/scanmark_e2e REDIS_URL=redis://…/3 \
       GUNICORN_CMD_ARGS="-b 127.0.0.1:8100"
gunicorn --config gunicorn.conf.py app:app &

# Seed (same environment), then run
python e2e/seed_e2e.py > /tmp/e2e-seed.json
E2E_BASE=http://127.0.0.1:8100 E2E_SEED=/tmp/e2e-seed.json \
    node --test --test-concurrency=1 e2e/manual_code.e2e.cjs e2e/qr_refresh.e2e.cjs
```

`SCANMARK_ENV=ci` is only so the session cookie is sent over plain
`http://127.0.0.1`; nothing in the code path differs. Re-run `seed_e2e.py`
before each run: it opens fresh class sessions and sets a new random password
on the test accounts (printed in the seed JSON; set `E2E_PASSWORD` to choose
one), so no working credential is ever written in the repository.
