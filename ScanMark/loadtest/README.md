# ScanMark staging load test

The objective: **make 2,000 simultaneous scans boring**. Students scan,
attendance is written, the lecturer's screen updates, nobody notices the burst.

These scenarios require seeded staging students, open session ids, the staging
`SECRET_KEY`, and the classroom pin for those sessions. They intentionally
create attendance and **must not run against production**.

Use the [guarded benchmark procedure](STAGING_BENCHMARK.md) for the next
2,000-scan rehearsal, including prerequisites, fresh sessions, repeated scenarios
and evidence requirements. All `scan_burst.py` invocations now additionally require
`--staging-manifest`, `--confirm-staging-writes` and a unique `--json-out` path.
The latency SLO is checked automatically alongside write correctness.

## The rule this harness exists to enforce

Every request it sends is the request a real phone sends:

```json
{
  "qr_data":         "S<session>|<ts>|<hmac>",
  "lat":             7.2257,
  "lon":             3.4372,
  "accuracy_m":      18.4,
  "location_age_ms": 3200,
  "captured_at":     1786492845283,
  "user_marker":     "1417",
  "device_id":       "loadtest-3f2a…",
  "client_metrics":  { … }
}
```

The previous version sent `lat: null, lon: null` and omitted `accuracy_m`,
`location_age_ms` and `captured_at`. With the geofence on, those scans are
refused at the location check — *before* the database insert, the CampOS
enqueue and most of the work a real scan does. The run looked fast because it
was measuring the rejection path.

**Do not disable CSRF, rate limiting, Redis, Postgres, sessions or the
geofence for a capacity run.** A number produced with any of them off
describes a system nobody is running.

`benchmarks/` is a different thing: sequential, in-process, SQLite, no
concurrency. It is a regression signal and is labelled as one. Never quote it
as user capacity.

### What a passing scan burst now means

`scan_burst.py` requires database access and a **fresh cohort/session pairing**.
Preflight refuses missing/reused identities or existing attendance for that
cohort. After the burst it checks each expected student/session pair, ignoring
unrelated attendance in other classes. Missing or duplicate rows, unavailable
verification, failed logins, non-200 scan responses, and failed projector polls
all make the command exit nonzero. JSON includes `passed` and
`acceptance_errors`.

Every phone uses the same freshly projected token for its class. Each scan
has the browser's **20-second total request deadline**, not the old harness's
120-second socket timeout. This is a strict first-attempt rehearsal; it does
not hide overload behind automatic retries. `--burst-concurrency` below the
cohort size remains useful for diagnosis, but cannot pass simultaneous-burst
acceptance. The separate latency SLO is stricter and now gates `passed` and the exit code;
`correctness_passed` reports the correctness/deadline check independently.

The historical performance report predates these checks. Rerun on the actual
target infrastructure before treating its numbers as release evidence.

## Which tool, and why there are two

**`scan_burst.py` is the one to reach for first.** Every Locust scenario here
signs its virtual student in and *then* scans, so a 2,000-user run measures
`login + scan` and reports the sum under the scan's name. That is not a
detail: verifying one password costs ~100 ms of CPU (Werkzeug's scrypt), so a
2,000-user spawn spends over a minute of CPU on authentication while the scans
it is supposed to be measuring queue behind it. The published "scan p95" then
describes password hashing.

Real classes do not work that way. Students are signed in before the lecturer
projects the code. `scan_burst.py` splits the two — sign everyone in
(untimed), then release every scan at once against a barrier — and verifies,
against the database, that every admitted scan is on the register exactly
once.

```bash
python loadtest/scan_burst.py --host https://staging.example \
    --students 2000 --session-id 1 --secret "$TARGET_SECRET_KEY" \
    --database-url "$DATABASE_URL" \
    --staging-manifest /private/run/staging.json --confirm-staging-writes \
    --json-out /private/run/burst-01.json
```

Useful flags:

| Flag | What it rehearses |
|---|---|
| `--login-noise 40` | a sign-in rush running *through* the burst. The question that matters is what authentication does to scan latency, and this is the only way to see it. |
| `--projector-watchers 3` | the lecturer's screen polling every second while the class scans. |
| `--session-id 1,2,3,4,5` | concurrent classes; students are dealt round-robin across them. |
| `--warm-connections` | reuse the TCP connection from sign-in. Off by default, because a phone waits on the projector and whoever has the shortest idle timeout closes the socket first — so a real scan pays for a fresh handshake. |
| `--proxied-https` | the target is plain HTTP standing in for a deployment that terminates TLS at a load balancer. Keeps TLS CPU out of a measurement of the app without relaxing anything on the server. |
| `--burst-concurrency 1` | the uncontended serial cost of one scan — the baseline every other number should be read against. |

Use the Locust scenarios for sustained arrival-rate shapes, the login
stampede on its own, and the duplicate race.

## Prerequisites

| Variable | What it is |
|---|---|
| `TARGET_SECRET_KEY` | staging `SECRET_KEY`, so the harness can mint tokens the server accepts |
| `TARGET_SESSION_IDS` | the open session id(s) under test, comma-separated |
| `STUDENT_PASSWORD` | the seeded students' password |
| `CLASS_LAT` / `CLASS_LON` | **the pin for those sessions.** Wrong values mean every scan is legitimately out of geofence and the run measures nothing |
| `EMAIL_PATTERN` | defaults to `st{n}@student.funaab.edu.ng` |

Seed enough students that the run does not reuse identities: a student who is
already marked present gets `409 duplicate`, which the scenario counts as
success — correctly, from the student's point of view — so a short roster
silently turns a 2,000-scan run into far fewer rows.

## The whole matrix

```bash
export TARGET_SECRET_KEY=… TARGET_SESSION_IDS=1 STUDENT_PASSWORD=…
export CLASS_LAT=7.2257 CLASS_LON=3.4372
./loadtest/run_matrix.sh https://staging.example
```

It walks class size against arrival rate, runs the headline burst, the
multi-room scenarios, the projector feed, the duplicate race and the login
stampede, and checks each against the SLO. Non-zero exit means something
breached.

`PROCESSES` (default 4) sets both `--processes` and the student-slicing the
locustfile does, so they cannot drift apart. **They must match**: each Locust
process imports the file fresh, so without the slicing every process signs in
as `st1, st2, st3…` and three processes produce one student's scans three
times over. That fails silently — the duplicates come back `409` and count as
success, and the run reports 2,000 scans against 667 rows.

## Authentication burst

`auth_burst.py` measures **signup or login**, including actual scrypt work.
Unlike the scan burst's throttled preparation phase, it obtains all form/CSRF
tokens first and then releases every authentication POST together. Retries
match the browser's explicit-overload-only policy, with jitter and a 120-second
deadline. Each simulated phone has its own cookie session. All phones share
the load generator's public IP, exercising the carrier-NAT case without
spoofing forwarded headers.

Use a disposable **staging** database and mail sink, with the production
configuration and all security controls enabled. Install dependencies with
`pip install -r requirements-loadtest.txt`. Set `STUDENT_PASSWORD` securely in
the environment. For signup, choose an email domain accepted by staging and
delivered only to your sink; `{run}` creates a unique cohort on every run.

```bash
python loadtest/auth_burst.py --host https://staging.example --mode signup \
  --students 2000 --email-pattern 'burst-{run}-{n}@student.example.edu' \
  --output /tmp/signup-burst.json

# Seed 2,000 email-verified accounts using the existing load-test seed tools.
python loadtest/auth_burst.py --host https://staging.example --mode login \
  --students 2000 --email-pattern 'st{n}@student.example.edu' \
  --output /tmp/login-burst.json
```

The command exits nonzero unless all requested students complete successfully.
The JSON summary includes HTTP statuses (including intermediate overloads),
final failures and p50/p95/p99 completion times. Existing-account redirects do
not count as newly created accounts. Check the database count and verification
email delivery in the sink as well. Repeat through the actual staging proxy;
local SQLite or mocked password tests are not production-capacity evidence.

## The scenarios, and why each exists

| Scenario | What it answers |
|---|---|
| `grid-<users>-r<rate>` | the shape of the degradation across both axes, not just pass/fail at the target |
| `burst-2000-r500` | **the real event**: lecturer displays the code, the room scans, one session, one token |
| `multi-5x600`, `multi-10x300` | a university is not one room — per-session locks, buckets and caches instead of one hot key |
| `projector-feed` | the lecturer's screen is a client too, polling throughout the burst |
| `double-scan-20` | correctness under race: one student, N simultaneous scans, exactly one row |
| `login-600` | the pre-lecture rush; scrypt is CPU work scanning does not do, so mixing them hides both |

Burst matters more than duration. 2,000 users spread over four minutes is
8 scans/sec; 2,000 users at 500/sec is the thing that decides whether the
database sees 2,000 inserts in one second.

## Accepting a run

```bash
python loadtest/check_slo.py loadtest/results/burst-2000-r500
```

Exits non-zero on any of:

- **unexpected 4xx** — a legitimate scan the server turned away
- **any 5xx** — a fault, as distinct from deliberate shedding
- **token expiry** — the amplifying failure: expired scans make phones retry,
  which is the burst again but larger
- **admission shedding above tolerance** — shedding is a valid response to a
  burst, but a run that sheds a large share has not shown the class was marked
- **SLO breach** — p50 < 100 ms, p95 < 300 ms, p99 < 750 ms

Latency alone is not acceptance. After every run also confirm, in the
database:

```sql
SELECT count(*) FROM attendance;                              -- = the class
SELECT count(DISTINCT student_id) FROM attendance;            -- = the class
SELECT count(*) FROM (SELECT student_id, session_id FROM attendance
                      GROUP BY 1,2 HAVING count(*) > 1) d;    -- = 0
SELECT count(*) FROM session_roster r WHERE NOT EXISTS (      -- = 0
  SELECT 1 FROM attendance a
  WHERE a.student_id = r.student_id AND a.session_id = r.session_id);
```

A run can hit every latency target and still have lost a student's
attendance. The register is the product; latency is how it feels.

## While it runs

`/internal/metrics` carries the per-stage breakdown, which is what turns
"scans are slow" into a diagnosis:

```
scanmark_scan_stage_qr_verify_ms{stat="p95"}
scanmark_scan_stage_session_course_ms{stat="p95"}
scanmark_scan_stage_enrollment_ms{stat="p95"}
scanmark_scan_stage_admission_ms{stat="p95"}
scanmark_scan_stage_geofence_ms{stat="p95"}
scanmark_scan_stage_db_insert_ms{stat="p95"}
scanmark_scan_stage_enqueue_ms{stat="p95"}
scanmark_scan_response_ms{stat="p95"}

scanmark_scan_budget_exceeded_<stage>_total   which stage broke its contract
scanmark_db_pool_wait_ms{stat="p95"}          requests queueing for a connection
scanmark_db_pool_exhausted_total              requests that gave up waiting
scanmark_scan_admission_shed_total            smoothed by the token bucket
scanmark_redis_pool_in_use                    Redis connections in flight
```

Compare `scan_response` (what the app did) against the client-observed
latency Locust reports (what the student experienced). A large gap is
queueing *in front of* the application — gunicorn's backlog, or the load
generator itself — not the application being slow. Tune the worker matrix for
the first; get a bigger load box for the second.

## Setting the admission rate

`SCAN_ADMISSION_RATE` ships at `0`, meaning off, because any default here
would be a guess wearing the authority of a measured number. Set it from this
matrix:

1. Walk the arrival rate up with admission control off.
2. Find the rate at which `db_pool_wait` p95 climbs, or `db_insert` starts
   breaching its budget, or `token expired` appears. That is the sustainable
   rate for this database plan.
3. Set `SCAN_ADMISSION_RATE` to it and `SCAN_ADMISSION_BURST` to about one
   second's worth.
4. Re-run `burst-2000-r500`. Latency should stay flat where it previously
   climbed, and `scan_admission_shed_total` should be small and brief.

The bucket smooths microbursts. It does not hide sustained overload, and it
is not meant to: a shed scan is told to retry in well under a second, because
attendance is time-sensitive.
