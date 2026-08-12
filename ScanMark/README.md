# ScanMark

## CampOS integration

ScanMark receives CampOS SSO hand-offs at `/sso/callback`. CampOS redirects the
browser with an opaque one-time `code`; ScanMark exchanges it server-to-server
at `POST /api/modules/sso/exchange`, validates the returned HS256 JWT for
issuer `campos-core` and audience `scanmark`, then creates or refreshes the
local Flask login session. The signed JWT is never placed in browser history.
Its signed `launchContext` selects the intended surface for multi-role users:
students reach the student dashboard, lecturers reach the lecturer dashboard,
and an institution owner/admin (or a time-limited CampOS support operator)
reaches ScanMark's institution-wide DAP dashboard. Faculty and department
administrator roles are not guessed into Dean/HOD privileges; those require a
future signed resource-scope contract.

Configure these variables in the ScanMark deployment:

- `CAMPOS_CORE_URL`: the public CampOS origin, such as
  `https://campos-core.vercel.app` (origin only; no API suffix or path).
- `CAMPOS_INSTITUTION_SLUG`: the exact CampOS institution slug served by this
  ScanMark deployment. `CAMPOS_INSTITUTION_ID` is an alternative immutable-ID
  lock. Production SSO refuses to run unless at least one lock is configured.
- `CAMPOS_SSO_SECRET`: the same value as CampOS Core's
  `SSO_JWT_SECRET_SCANMARK`. The legacy ScanMark name `SSO_JWT_SECRET` remains
  a temporary rollout fallback. This value is required in local development
  too; ScanMark never uses a published/default signing secret.
- `CAMPOS_API_KEY`: an institution-scoped key issued to the `scanmark` module
  with `write:attendance` permission.

CampOS must register ScanMark's base URL (or set `SSO_URL_SCANMARK`) to the
public ScanMark origin. It appends `/sso/callback` automatically. Keep Redis
enabled in both production deployments: CampOS stores single-use SSO codes in
Redis, while ScanMark uses Redis for server-side sessions and live QR state.

`HEAD /livez` is the process-only probe that performs no database or session
work. CampOS calls it without credentials while the admin shell is loading so
a possible Render cold start can complete before the signed SSO callback
arrives. (`/healthz` is now a readiness check that reaches PostgreSQL and
Redis — see "Health checks" in `DEPLOYMENT.md`.)

ScanMark begins its own CampOS sign-ins at `/sso/start`, which issues a
browser-bound nonce and passes it to CampOS as `state`. The callback refuses a
hand-off that cannot present it, so a code obtained elsewhere cannot be fed to
somebody else's browser to sign it into the attacker's account.

After a successful scan, ScanMark asynchronously sends the student identity,
course, class-session details, timestamp, and a stable external attendance ID
to CampOS. Transient network, rate-limit, and server failures are retried with
bounded backoff without delaying the student's scan response.

## Tests

```bash
pip install -r requirements.txt
python -m pytest -q
```

The suite runs on a throwaway SQLite file with no Redis, so it needs no
services. It covers the CampOS integration (`test_campos_integration.py`) and
every route in `app.py` (`test_app.py`) — the scan path, access control,
the geofence, email verification, the password-reset flow and the security
headers. `test_bugfixes.py` holds one test per fixed defect: the class-session
lifecycle, roster snapshots and academic terms, the supervisory dashboards'
scope and arithmetic, and the release-blocking security fixes. `.github/workflows/ci.yml` runs it on every push, alongside a
`pyflakes` pass and a real gunicorn boot against Postgres + Redis.

To run just the CampOS integration tests:

```bash
python -m pytest test_campos_integration.py -q
```

## Accounts and roles

The public signup form issues exactly three kinds of account: **student**
(any `funaab.edu.ng` address or Gmail), **Lecturer** and **Course
Coordinator** (a `@staff.funaab.edu.ng` address only). A self-service account
must confirm its email address before its password works, because the form
cannot tell whether the registrant owns the address they typed.

The supervisory roles — HOD, Dean, DAP — are never self-assigned. They come
from a signed CampOS launch identity, or from a deliberate database change;
see the "Roles" section of `DEPLOYMENT.md`.

## Attendance records

A **class session** is one meeting. It is opened deliberately, stays open until
somebody ends it, and ending it closes attendance on the server — every token
minted for it stops working at once, whatever its age. A course can hold as
many meetings in a day as it actually has: a lecture, the tutorial after it and
a makeup class are three separate record sets, not one.

Each meeting freezes a **roster snapshot** when it opens: the list of students
enrolled at that moment. That snapshot is the denominator for every percentage
involving the meeting, permanently. It is what stops a student who enrols in
week 6 being marked absent for weeks 1–5, and what stops a later roster change
pushing an old figure above 100%.

A **course** belongs to an academic year, a semester and an optional section,
so `CSC201` can run again next term as a separate offering with its own
roster, its own sessions and its own percentages. Finished terms are archived
rather than deleted: they keep every record and drop off the working
dashboards.

Every destructive action — deleting a course or a session, archiving, starting
and ending meetings — is written to an **append-only audit log**, readable per
course at `/course/<id>/audit`. The table deliberately carries no foreign keys
so an entry outlives the rows it describes.

All timestamps are stored as UTC and displayed in `SCANMARK_TIMEZONE`
(`Africa/Lagos` by default). "Today" is a local day, so an evening class near
midnight is filed on the date the people in the room would name.
