# The student journey on a bad network

`scan_burst.py` answers "how many scans per second can the server take".
This directory answers the other question: **how long does one student wait**,
on a 2G or 3G cell, from opening the app to seeing "Marked present" — and
does the scan survive the network dropping out halfway.

It drives a real Chromium through a TCP relay that behaves like a mobile
link, against a real gunicorn + Redis server.

| File | What it is |
|---|---|
| `throttle_proxy.py` | The link: round-trip latency, one shared bandwidth-limited radio per direction, connection set-up cost (TCP + TLS), and on demand a **stall** (everything held, nothing closed) or a **drop** (every connection reset, new ones refused). Applies to the page, the service worker and third-party CDNs alike — DevTools throttling does none of the last two and does not model connection set-up at all. |
| `projector.py` | The lecturer's screen: the current QR token as a PNG, rotating every 12 s with the server's own signing algorithm, so slow scans meet a real expiry window. |
| `seed_journey.py` | One open lecture in a saved classroom, N enrolled students. `count` prints the attendance rows. |
| `journey.cjs` | The driver. The camera is a canvas stream showing the projector's current code (blank for the first 1.5 s while the student aims); GPS is a fake that delivers a fix a second, optionally wandering like an indoor reading. |

## Running it

```bash
# server under test, with Redis (see .claude/skills/verify/SKILL.md)
python loadtest/journey/seed_journey.py seed --students 60 | tail -1 > seed.json
gunicorn --config gunicorn.conf.py app:app            # -b 127.0.0.1:8100

python loadtest/journey/throttle_proxy.py --app-listen 127.0.0.1:8200 \
    --app-target 127.0.0.1:8100 --proxy-listen 127.0.0.1:8201 \
    --proxy-target "$UPSTREAM_HTTP_PROXY_HOST:PORT" --control 127.0.0.1:8299
python loadtest/journey/projector.py --listen 127.0.0.1:8300 --secret "$SECRET_KEY"

node loadtest/journey/journey.cjs --base http://127.0.0.1:8200 \
    --control http://127.0.0.1:8299 --cdn-proxy http://127.0.0.1:8201 \
    --projector http://127.0.0.1:8300 --seed seed.json \
    --profile 2g --runs 3 --scenario journey
```

Each run uses a different seeded student (`--first-student`), because a
student can only be marked once per class.

Scenarios:

* `journey` — cold dashboard load (empty cache), warm load (service worker
  installed, connections reaped), then tap scan → confirmation on screen.
* `wander` — the same, with GPS alternating between a good reading (±12 m,
  25 m from the room) and a drifted one (±60 m, 125 m out), as phones do
  inside concrete halls.
* `outage --outage drop|stall --outage-seconds N` — the network goes away as
  the code is read. Was the scan recorded, and how long after the network
  came back?

Profiles (`--profile`): `3g` = 300 ms RTT, 1.6/0.75 Mbit/s; `2g` = 800 ms RTT,
250/100 kbit/s. Rough shapes of a decent cell and a loaded one, not carrier
measurements. `JOURNEY_DEBUG=1` prints the page's console.

These are **not** capacity numbers and the absolute values are this
emulation's, not FUNAAB's network. Use them to compare two versions of the
code under identical conditions.
