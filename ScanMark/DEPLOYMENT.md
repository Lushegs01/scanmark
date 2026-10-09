# ScanMark Deployment Guide

Deployment and rehearsal guide for the 2,000-student lecture-hall target.
Capacity is accepted only from measured staging evidence. For the next concrete
2,000-scan rehearsal use the [guarded concurrent benchmark](loadtest/STAGING_BENCHMARK.md).
Historical scaling estimates below are not current capacity acceptance.

## Render free plan: 0.1 CPU / 512 MB

This allocation is not validated for 2,000 simultaneous scans. Increasing
request limits, workers, or timeouts does not increase CPU capacity. There is
no paid infrastructure upgrade within a $0 budget.

For this small instance, the following is a **conservative starting configuration**
to rehearse, not a 2,000-student capacity claim. Set these explicitly in the
Render service environment; `os.cpu_count()` may describe the host instead of
the service's CPU quota, making automatic worker sizing inappropriate:

```dotenv
WEB_CONCURRENCY=1
GUNICORN_THREADS=2
PASSWORD_HASH_CONCURRENCY=1
PASSWORD_HASH_MAX_WAIT_SECONDS=0.1
DB_POOL_SIZE=3
DB_MAX_OVERFLOW=0
REDIS_MAX_CONNECTIONS=16
```

One process limits memory growth; it does not create more throughput. Keep the
existing PostgreSQL and Redis URLs, secret key, security settings and proxy
configuration. The start command is `gunicorn --config gunicorn.conf.py app:app`
from the `ScanMark` root directory. Verify `/healthz` after changing configuration.
Do not replace durable services with SQLite or in-memory Redis substitutes.

Attendance's 10/minute limit is explicitly keyed by authenticated student, not
by the whole class or its public IP. Invalid scans and repeated submissions
still count. Server-side 429/5xx responses do not consume that allowance, so
overload retries cannot add a second student-level block. This protection
does not make an overloaded instance capable of accepting the whole class.

### Rehearsal and release evidence

Use a separate staging web service, PostgreSQL database and Redis service with
the **same plans, region, versions and application settings** as production.
Use separate credentials, synthetic verified students, a mail sink, and no
production CampOS integration. Keep CSRF, geofencing and the rate limiter on.
Do not connect a staging instance to the live database/Redis or load-test the
live attendance service. Record the deployed commit, resource plans, worker
settings and database connection limits alongside the result.

Run `loadtest/scan_burst.py` as described in [the load-test guide](loadtest/README.md),
first with a small fresh cohort to validate setup, then with 2,000 preauthenticated
students and fresh sessions. Run the generator on another machine. Record the
JSON report, CPU/memory peaks, restarts, database connections and Redis errors.
Repeat with projector polling and concurrent login traffic before accepting
the event workload. Do not reuse session/student pairs across runs.

If separate matching free staging resources are unavailable, mark capacity
**unverified**. Local unit tests or tests on a faster developer machine cannot
substitute for it. Until measured, students should log in in advance and scan
in staggered groups while the projector continues displaying fresh codes;
group size must come from measurements, not a claimed safe number.

## Signup and login bursts

Signup used to allow five POSTs per hour **per public IP**. Mobile-carrier
NAT and campus Wi-Fi can place thousands of students behind one IP. The tight
limit now belongs to each normalized email; a separate, configurable network
ceiling allows a cohort through. Raising `ANON_RATE_LIMIT_PER_MINUTE` never
changed the old route-specific signup limit.

The login and signup forms preserve their fields while retrying an explicit
`503 auth_overloaded`, with jitter and a two-minute deadline. Passwords stay
only in the page's memory. Credential errors, 429s and ambiguous network
failures are not automatically replayed. No-JavaScript forms still work.
429 responses report the actual bucket reset, including hour/day waits.

Before accepting a deployment for 2,000 students:

1. Set `SCANMARK_ENV=production`; do not deploy the example's development
   values. Confirm PostgreSQL and Redis are configured and healthy.
2. Set `TRUSTED_PROXY_COUNT` to the number of trusted proxies that actually
   rewrite forwarded headers. Check the addresses observed by the application
   using two independently connected devices. A proxy's address must not be
   treated as the client. Do not increase the count blindly or trust client-
   supplied forwarded headers. Separate mobile devices may still share a real
   public IP; the new limits accommodate that.
3. Run the [authentication burst rehearsal](loadtest/README.md#authentication-burst)
   against staging with the production worker count, CPU/RAM allocation,
   PostgreSQL and Redis. Keep CSRF and rate limiting on. The regression tests
   prove isolation between 2,000 email addresses, not password throughput.
4. Verify 2,000 distinct successful results and inspect completion latency,
   429s, 503s, CPU, memory and database connections. Scale instances before the
   event if the cohort cannot finish within the two-minute browser deadline;
   merely increasing hashing concurrency can exhaust RAM without improving
   throughput. Set `WEB_CONCURRENCY` explicitly when sizing the hash budget.
5. Use a mail sink for rehearsal, then verify real provider quotas and email
   delivery separately. Signup currently enqueues both confirmation and welcome
   mail in a bounded in-process queue. Check for `notification queue full` and
   delivery failures; creating an account does not prove its verification email
   arrived. Size `BACKGROUND_QUEUE_MAXSIZE`/`ACCOUNT_EMAIL_WORKERS` for the burst.

No infrastructure setting can be inferred from source code alone. Record the
deployed commit, proxy configuration and burst results when releasing.

## Required services

| Service | Why it's required in production |
|---|---|
| **PostgreSQL** (`DATABASE_URL`) | SQLite is single-writer and sits on ephemeral disk on Heroku/Render — concurrent scans lock up and **attendance data is wiped on every restart**. Production **refuses to boot** without it (override: `ALLOW_SQLITE_IN_PRODUCTION=true`). |
| **Redis** (`REDIS_URL`) | Sessions, rate limits, class locations, QR token + attendee-feed + QR-image caches. Production **refuses to boot** without it, and pings it at startup so a broken URL fails immediately rather than on the first request (override: `ALLOW_MISSING_REDIS=true`). Without Redis the pinned classroom lives in one worker's memory, so a scan is geofenced only if it happens to land on the same worker. Provision enough memory and prefer eviction policy `volatile-lru` (or `noeviction`) — arbitrary eviction of session keys logs people out mid-class. |
| **SMTP** (`MAIL_*`) | Signup confirmation links and password resets. That is all ScanMark sends — nothing goes out during a class, so provider quotas are no longer a capacity concern. Verify the settings with `python mail_selftest.py` (below) rather than by signing up and waiting. |

### Which universities can sign up

ScanMark is not tied to one university. An address is classified from its
domain:

| Address | Role |
|---|---|
| `x@staff.unilag.edu.ng` | staff — then chooses Lecturer or Course Coordinator |
| `x@student.gsu.edu.ng`, `x@ui.edu.ng`, `x@cs.unn.edu.ng` | student |
| `x@gmail.com` | student, always — a personal mailbox says nothing about who teaches |
| `x@staff.example.com` | refused — the `staff.` label alone proves nothing |

By default any domain under an academic suffix is served. Those suffixes are
registry-restricted to accredited institutions (NiRA vets `.edu.ng`, EDUCAUSE
vets `.edu`, Jisc vets `.ac.uk`), which is the only reason "any university" is
reasonable rather than "any domain at all".

**A staff address is still self-asserted.** Anyone who can receive mail at a
`staff.` address of any served institution can create a Lecturer or Course
Coordinator account — and staff accounts are not gated on email confirmation
(see `REQUIRE_EMAIL_VERIFICATION`). Set `INSTITUTION_DOMAINS` to the
universities you actually serve to bound who that can be.

### How institutions are kept apart

Every account and every course carries an **institution** — the domain its
address sits under (`funaab.edu.ng`). Users get it at signup, derived from the
address; courses inherit their coordinator's. Rows that predate the column are
backfilled at boot: accounts from their address, courses from their
coordinator. A personal-email account (`@gmail.com`) has none until it
registers for its first course, and is bound to that course's institution from
then on — clearing `User.institution` is what undoes it.

It is enforced at every point where rows meet somebody who did not create
them:

| Place | Rule |
|---|---|
| Registering for a course | Only offerings at the student's own institution. Both universities can run CSC201; a student sees theirs. |
| Course uniqueness | The offering key is (code, **institution**, year, semester, section), so two universities can each run CSC201 this term. |
| Adding an instructor | Must be a colleague at the same institution — an instructor gets the roster, the register and the live QR. |
| HOD dashboard and analytics | Department **and** institution. "Computer Science" names one at every university on the instance. |
| Dean dashboard | Faculty **and** institution, for both courses and the lecturer count. |
| DAP dashboard and analytics | "Institution-wide" means one institution, not every row on the instance. |

A test sweeps every GET route as each role at one institution and asserts no
row belonging to another appears in the response — including by guessing an
id. That is the test to extend when a route is added; it is what catches the
one place an author forgets.

`matric_no` is unique **per institution**, not across the instance: it
identifies a student within their own university, and two universities'
numbering formats can overlap. Staff rows hold no number and are exempt. On an
existing database the upgrade drops the old instance-wide UNIQUE — two
statements on Postgres, a `user` table rebuild on SQLite, since a
column-level UNIQUE is out of ALTER TABLE's reach there.

### Choosing how mail leaves

`MAIL_PROVIDER` is `smtp` or `brevo`; unset, it is `brevo` when `BREVO_API_KEY`
is set and `smtp` otherwise.

**Some hosts do not let SMTP out at all.** On Render's free instances the
connection to `smtp.gmail.com:587` fails with `[Errno 101] Network is
unreachable` — there is no route, so nothing about the credentials matters and
no SMTP setting can fix it. Brevo's HTTP API goes over HTTPS on 443, which a
PaaS always leaves open.

To use it: create a Brevo account, verify the sender address under **Senders,
Domains & Dedicated IPs**, take a v3 key from **Settings → SMTP & API → API
Keys**, and set

```
BREVO_API_KEY=xkeysib-...
MAIL_DEFAULT_SENDER="ScanMark <the-verified-address>"
```

`MAIL_*` SMTP settings can stay; they are simply not used. Nothing else in the
app changes — every message still goes through the same background pool, so
sending stays off the request path.

### When mail does not arrive

Configured is not the same as working, and a send fails in the background
where nobody sees it. Two things tell you which:

1. **`python mail_selftest.py`** — reads the same `MAIL_*` variables the app
   reads, through the same resolver, then connects, negotiates TLS, logs in,
   and (given an address) sends one real message. It names the cause instead
   of the symptom. Run it wherever the app runs; running it from a laptop as
   well is worth doing, because "works here, not there" means the network is
   blocking SMTP, not that the credentials are wrong.
2. **The logs.** Every failed send is now an `ERROR` line — `Email NOT sent
   (...)` — carrying the reason and the effective config, and the boot line
   `Mail configured: {...}` states the settings the process actually resolved.

The three causes that account for almost all of it:

| What you see | Cause |
|---|---|
| `authentication rejected (535)` | Gmail needs a 16-character **App Password** from an account with 2-Step Verification on; the account password has not worked since 2022. |
| `could not reach ...:587 at all (OSError: [Errno 101] Network is unreachable)` | The host has no route out on that port. Switch to Brevo (above); no SMTP setting will help. |
| `could not reach ...:587 within 15s` | Reachable but silently dropped. Try 465, or switch to Brevo. |
| `sender ... refused` | `MAIL_DEFAULT_SENDER` must normally be the mailbox `MAIL_USERNAME` authenticates as. |
| `Brevo rejected the API key (401)` | Brevo issues **two** credentials from Settings → SMTP & API: the v3 **API key** (`xkeysib-…`, API Keys tab) and the **SMTP key** (`xsmtpsib-…`, SMTP tab). This API only accepts the first; the second gets the same 401 as a key that does not exist. The message names which one is configured. |
| `Brevo has not activated this account for sending` | An account state, not configuration — finish the account details in the dashboard or ask Brevo support to enable transactional sending. |
| `Brevo sender problem: ... does not list ... as a validated sender` (at boot) | The send API answers `201` and rejects the message **afterwards** when the sender is not validated, so this never appears as a send failure. Add the address under Senders, Domains & Dedicated IPs → Senders and open the confirmation mail Brevo sends to it. Set `BREVO_SKIP_SENDER_CHECK=true` to skip the check. |

Note the wording in the log: a send is reported as **accepted**, not delivered,
and carries Brevo's `messageId`. Anything after acceptance — rejection,
bounce, spam filing — is visible only in Brevo's Transactional → Logs, and
that id is how you find the message there.
| `Brevo refused the sender ...` | That exact address is not verified in the Brevo dashboard. |
| `Brevo returned 429 / 402` | The account's sending limit, not a configuration problem. |

## Where the geofence gets its centre

Attendance is refused beyond `GEOFENCE_RADIUS_M` from the classroom. That
distance is measured from a **pin**, and where the pin comes from is the whole
question.

Originally the projector page asked its browser. Lecturers project from a
laptop, and a laptop has no GPS: it locates itself from Wi-Fi or its IP
address, which in practice lands tens of kilometres away. The pin is the
centre of the fence, so its error is added to everybody's — every student in
the hall is refused, and told *they* are too far away.

**Saved classrooms** are the fix. Under `/classrooms`, teaching staff pin each
lecture hall once — from a phone standing in the room, or by pasting the
coordinates off a map — and give it a name. That room is then picked from a
dropdown when a class is started, or attached to a class already running from
the projector page. The laptop never needs to know where it is.

Operationally:

- **Rooms are per institution.** Every university has an LT1; one deployment
  serves several, and neither may see or use another's.
- **A page with a saved room does not geolocate at all** — no permission
  prompt, and no chance of a worse answer overwriting a good one. The server
  enforces the same precedence, so a projector page left open across a deploy
  cannot drag the fence off the hall either.
- **A browser pin is still accepted when it is precise enough** — pinning from
  a phone in the room was never the broken case. `GEOFENCE_MAX_PIN_ACCURACY_M`
  is the threshold, and a pin that fails it is refused with a message naming
  saved classrooms as the way out.
- **A lost Redis pin rebuilds itself.** The live pin is a Redis key with
  `CLASS_LOCATION_TTL`; a restart or an eviction mid-lecture used to refuse
  every remaining scan. The room is recorded on the session row, so the pin is
  rebuilt from the database on the next scan — read in a join the scan path was
  already doing, so it costs no extra query.
- **A room can carry its own threshold.** `GEOFENCE_RADIUS_M` is the default,
  not a fixed rule: a room may be given a `Threshold` on `/classrooms`, and
  scans for a class held there are measured against that instead. One 100m
  number cannot fit both a seminar room and a 400-seat theatre with an
  overflow gallery. Left blank, the room stays on the server default — which
  is right for almost every room, so the field is optional. Values are
  bounded (5m–2000m): below that, ordinary indoor GPS drift refuses students
  sitting in the hall; above it, the fence stops fencing anything.
- **Deleting a room keeps its history.** Sessions held there lose only the
  ability to rebuild a lost pin; their attendance is untouched.

Before the first class of term, check that each hall a course meets in has a
row under `/classrooms`. A course whose lecturer never picks one falls back to
the browser pin, and with `GEOFENCE_REQUIRED` on (the default) an imprecise
laptop fix now refuses the class *loudly* on the projector screen rather than
quietly at every phone.

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
| `WEB_CONCURRENCY` | `2 × CPUs`, capped at 12 | Gunicorn workers. A scan is CPU-bound Python, so parallelism comes from processes. |
| `GUNICORN_THREADS` | 2 | Threads per worker — to overlap the wait on Postgres, not to add request slots. Measured: raising this to 8 or 16 *lowers* throughput and roughly doubles p95. See `loadtest/gunicorn-matrix.md`. |
| `GUNICORN_KEEPALIVE` | 75 | Seconds an idle connection is held. **Must exceed your router's idle timeout** (usually 60 s) or the router will reuse a socket the app has closed and hand clients 502s. Gunicorn's own default of 2 s also makes every scan pay a fresh TCP+TLS handshake, because the phone waits longer than that for the projector. |
| `GUNICORN_TIMEOUT` | 60 | Above the 30s platform router timeout on purpose. |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `threads + 1` / `threads` | **Per worker.** Postgres sees up to `instances × workers × (pool + overflow)` — 40 per instance with the defaults. A worker cannot use more connections at once than it has threads, so sizing above that only occupies slots another instance needs. Keep below your plan's cap, or put PgBouncer in front when scaling out. |
| `DB_POOL_TIMEOUT` | 10 | Seconds a request waits for a connection before returning a retryable 503. A scan that has waited 30 s has an expired QR token anyway; failing fast frees the request slot. |
| `PASSWORD_HASH_CONCURRENCY` | `min(4, CPUs)`, ≥2 | **Instance-wide** cap on simultaneous password hashes, shared out across workers. Verifying a password costs ~100 ms of CPU and ~32 MB of RAM (scrypt is memory-hard), and throughput stops improving past a handful. Derive yours with `python benchmarks/benchmark_password_hash.py`. |
| `PASSWORD_HASH_MAX_WAIT_SECONDS` | 2 | How long a login waits for a hashing slot before it is shed with 503 + `Retry-After`. |
| `TRUSTED_PROXY_COUNT` | 1 in production, 0 elsewhere | Reverse-proxy hops that rewrite `X-Forwarded-For`/`-Proto`. **Without this every per-IP rate limit becomes one global bucket**, because every request appears to come from the load balancer. Cloudflare in front of Render is 2. Set 0 only when gunicorn is directly exposed. |
| `SESSION_REFRESH_EACH_REQUEST` | false | Off, the session record is written to Redis only when it changes, instead of on every authenticated request. The window becomes fixed rather than sliding; the 30-day remember-me cookie re-establishes a user before the record can lapse. |
| `SESSION_STORE_BREAKER_SECONDS` | 10 | After a Redis failure, how long sessions are served from signed cookies before probing Redis again. |
| `CAMPOS_MAX_ATTEMPTS` | 8 | Delivery attempts before an attendance row is dead-lettered (`campos_state='failed'`). |
| `CAMPOS_SWEEP_INTERVAL_SECONDS` | 30 | How often the outbox sweeper runs. One sweeper per deployment, elected by a Redis lease. |
| `CAMPOS_BREAKER_FAILURES` / `CAMPOS_BREAKER_COOLDOWN_SECONDS` | 3 / 60 | After this many consecutive failures the immediate in-process delivery stands down and leaves everything to the sweeper, so a CampOS outage cannot take capacity from a live burst. |
| `GEOFENCE_RADIUS_M` | 100 | Default max metres between the pinned class location and a scanning student. Phone GPS inside buildings is often 20–50m off — don't set this too tight. A saved classroom may override it per room (see below), so this is the fallback rather than a ceiling. |
| `GEOFENCE_REQUIRED` | **true** | What happens when a lecturer never pins a classroom (they dismissed the browser's GPS prompt). Defaults **on**: with nothing to measure against, the scan is refused. Off, the failure is silent and total — a lecturer who dismissed one prompt records a whole term of attendance that anyone could have submitted from anywhere, with nothing on the register saying so. Refusing is loud and fixable in ten seconds by granting location on the QR screen, which tells the lecturer which of the two applies. |
| `GEOFENCE_MAX_ACCURACY_M` | `GEOFENCE_RADIUS_M` | Reported GPS accuracy beyond which a fix proves nothing. The reading is refused rather than used to widen the fence — accuracy is self-reported, so treating it as an allowance would be a free pass for the asking. |
| `GEOFENCE_MAX_LOCATION_AGE_MS` | 30000 | Oldest position fix a scan may carry. Both this and `accuracy_m` are now **required** on a scan when a classroom is pinned; they used to be read only if present, so omitting them was the way past every proximity check. |
| `GEOFENCE_MAX_PIN_ACCURACY_M` | `GEOFENCE_RADIUS_M` | Worst accuracy a **classroom pin** may report. The pin is the centre of the fence, so its error is added to every student's: a pin 36km out refuses the whole room and blames the students for it. Lecturers project from laptops, which have no GPS and locate themselves from Wi-Fi or their IP address, honestly reporting kilometres — that is what this catches. Safe to enforce only because of saved classrooms (below). |
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
| `REQUIRE_EMAIL_VERIFICATION` | on in production | Self-service **student** signups must click an emailed link before their password works. Lecturers and Course Coordinators are not gated — their account works as soon as it is created (they are still sent the link, but nothing waits on it), because a `@staff` signup is a handful of people known to their department who are needed in front of a class today, while a class is hundreds of self-registered strangers. **Do not turn this off in production** — the link is what stops one of those strangers registering in another student's name. CampOS SSO and Google sign-ins are pre-verified and unaffected. |
| `MIN_PASSWORD_LENGTH` | 10 | Enforced identically at signup and at password reset. |
| `INSTITUTION_DOMAINS` | — (any academic domain) | Comma-separated institutions this deployment serves, e.g. `funaab.edu.ng,unilag.edu.ng`. Empty accepts any address under `ACADEMIC_DOMAIN_SUFFIXES`, so another university's staff can sign up with no config change. Setting it also restores exact-institution matching — see "Which universities can sign up" below. |
| `ACADEMIC_DOMAIN_SUFFIXES` | `edu.ng,edu,ac.ng,ac.uk,ac.za,edu.gh,ac.ke,edu.au,ac.in` | What counts as academic when there is no allowlist. |
| `STAFF_SUBDOMAIN` | `staff` | The subdomain that makes an address a staff address: `lecturer@staff.<institution>`. Everyone else at an institution signs up as a student. |
| `PERSONAL_EMAIL_DOMAINS` | `gmail.com` | Accepted, but only ever as a student. |
| `MAIL_PROVIDER` | `brevo` when `BREVO_API_KEY` is set, else `smtp` | How mail leaves the process. See "Choosing how mail leaves" above — a host that blocks outbound SMTP cannot use `smtp` at any port. |
| `BREVO_API_KEY` | — | v3 API key. Its presence is what selects Brevo unless `MAIL_PROVIDER` says otherwise. The sender in `MAIL_DEFAULT_SENDER` must be verified in the Brevo dashboard. |
| `MAIL_PORT` | 587 | 587 negotiates STARTTLS, 465 is implicit SSL. The TLS mode follows the port, so 465 no longer opens a plaintext socket and then asks a server that only speaks TLS for STARTTLS. `MAIL_USE_TLS` / `MAIL_USE_SSL` override it. |
| `MAIL_TIMEOUT` | 15 | Seconds to wait on the mail server. Flask-Mail passes no timeout to smtplib, so without this a host that filters outbound SMTP parks a worker thread on connect indefinitely; four of those and every later message queues and then drops, with nothing in the log because nothing ever failed. |
| `LOG_LEVEL` | INFO | Level for the app logger. Flask inherits WARNING from the root logger unless something sets it, which silenced the audit trail, the sampled scan telemetry, and every "email sent" line. |
| `ANON_RATE_LIMIT_PER_MINUTE` / `ANON_RATE_LIMIT_PER_DAY` | 20000 / 500000 | Default budget for anonymous requests keyed by IP. Explicit route limits, including login/signup POST limits, override these defaults. |
| `SIGNUP_EMAIL_RATE_LIMIT` | `5 per hour;20 per day` | Signup POSTs per normalized email across IPs. Students on the same carrier no longer share this allowance. |
| `AUTH_NETWORK_RATE_LIMIT` | `10000 per minute;100000 per day` | Separate per-IP ceiling on each of login and signup POSTs. Size for carrier NAT, not one phone. Login also retains 10 attempts/minute per IP + normalized email. Server-error responses do not consume these auth allowances. |
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

Four rules hold the shape:

**Nothing external happens before the attendance commit.** The scan path is
authenticate -> verify the QR signature locally -> resolve session, course,
room and enrolment in ONE query -> admission control -> verify the geofence
-> INSERT -> COMMIT -> respond. That is **three SQL statements and three
Redis round trips** per successful scan; there is a regression test holding
the SQL count at three. CampOS delivery is recorded in the same INSERT and
carried out afterwards, and cannot delay or fail a scan.

**Redis accelerates; it is never the only path.** A successful scan performs
no Redis write. Every Redis read has a fallback: the classroom pin falls back
to the saved `Classroom` row, the headcount to a Postgres count, the QR token
to minting a fresh one, admission control to admitting, rate limiting to
allowing, and the session to a signed cookie. A total Redis outage costs one
automatic page reload per phone — measured, 29 of 29 scans were still
recorded — where it previously returned HTTP 500 to every request in the
application, because Flask-Session reads the session inside `ctx.push()`,
before any error handler exists.

**Delivery to CampOS is durable, and never at the expense of a scan.** The
attendance row carries its own outbox state (`campos_state`, `campos_attempts`,
`campos_next_attempt_at`), written by the same INSERT. An in-process attempt
makes the common case immediate; a sweeper — one per deployment, elected by a
Redis lease, claiming with `FOR UPDATE SKIP LOCKED` so it is safe across
instances — owns retries, exponential backoff with full jitter, and
dead-lettering. Measured: with CampOS completely unreachable, 2,000
simultaneous scans all succeeded at 304 scans/sec and all 2,000 were queued;
when CampOS came back the sweeper delivered exactly 2,000 distinct
`externalId`s in 30 seconds.

**Everything that sheds says when to come back.** 429 (rate limit or
admission control) and 503 (pool exhausted, or the password-hashing budget)
all carry `Retry-After`, and the scanner honours it — jittered, bounded to
three attempts — instead of inventing its own interval. That is what keeps
2,000 shed phones from becoming the burst again.

### Scan response budget

| Stage | Budget | What it is |
|---|---:|---|
| `qr_verify` | 1 ms | HMAC over a short string; local, no I/O |
| `session_course` | 10 ms | one indexed join |
| `enrollment` | 10 ms | one indexed existence check |
| `admission` | 5 ms | one Redis round trip |
| `geofence` | 5 ms | one Redis read plus a Haversine |
| `db_insert` | 20 ms | `INSERT ... ON CONFLICT DO NOTHING ... RETURNING`, outbox state included |
| `enqueue` | 5 ms | hand-off to the bounded CampOS executor |
| **total** | **100 ms** | an order of magnitude inside `QR_CODE_WINDOW` |

`enrollment` is now answered by the `session_course` join rather than by its
own statement, so its stage timing is ~0 and the budget is vestigial. It is
kept so a regression that reintroduces a second query is visible rather than
silently absorbed into the total.

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

0. **Know your instance's two ceilings before you plan anything.** They are
   different numbers and they fail differently:
   * *Scan throughput.* One 4-CPU instance sustained **~330 scans/sec** with
     everything on (CSRF, rate limiting, geofence, Redis, Postgres). A
     2,000-student burst therefore drains in ~6 seconds — comfortably inside
     `QR_CODE_WINDOW`, so nothing expires. Two instances halve that, three
     take it to ~2 seconds.
   * *Login throughput.* ~30 sign-ins/sec, and **no configuration changes
     it** — it is memory-bandwidth-bound scrypt. 2,000 students signing in at
     once is ~70 seconds of work. This is the number that surprises people,
     so plan for it: the 30-day remember-me cookie means the real pre-lecture
     rush is a fraction of the roster, and `PASSWORD_HASH_CONCURRENCY` keeps
     the rush from taking capacity away from scans (measured: with the bound
     on, scans under a login stampede ran 18% faster with 26% lower p95).
1. **One instance** (defaults on 4 CPUs): 8 workers × 2 threads = 16 request
   slots, and an application-side Postgres ceiling of 40 connections. Accept
   it only after the checked-in 600/2,000 scenarios pass on your own hardware.
2. **Scaling out** (2+ instances): connection math multiplies per instance —
   add **PgBouncer** (transaction pooling) in front of Postgres, keep
   `DB_POOL_SIZE`/`DB_MAX_OVERFLOW` modest. Nothing in the application holds
   cross-request state in process memory, so instances are interchangeable:
   sessions, rate limits, admission buckets and classroom pins are in Redis,
   and the CampOS outbox is in Postgres with `SKIP LOCKED` claiming.
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
