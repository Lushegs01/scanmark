# Repeatable simultaneous scan benchmark

Capacity for 2,000 simultaneous scans remains **unverified**. This procedure
builds on merged PR #41 (`2e5e488a615594abe6d9b6ecdd518925dd43abb2`). It changes
no production configuration and provisions nothing. Historical timings in
`PERFORMANCE_REPORT.md` and the deployment scaling checklist predate strict
verification and are not acceptance evidence for the current free plan.

## Prerequisites

1. Use separate staging web, PostgreSQL and Redis services with the same plans,
   region, versions, ingress and application settings as production. If these
   are unavailable, stop and record “capacity unverified.” Do not substitute a
   faster local machine, SQLite, or a production database/Redis connection.
2. Deploy the commit under test to staging with production security controls:
   CSRF, rate limiting, geofencing, verified accounts and secure sessions on.
   `SCANMARK_ENV=production` is appropriate for this isolated staging service;
   it enables production safeguards, not permission to target production.
   Use synthetic accounts, a mail sink and disabled production CampOS integration.
3. Check staging `/healthz`. Record actual worker/thread/hash/pool settings,
   CPU/RAM allocation, PostgreSQL connection ceiling and Redis configuration.
   The 0.1-CPU/512-MB starting settings in `DEPLOYMENT.md` are hypotheses to
   measure, not validated capacity. Do not apply changes to production.
4. Seed distinct verified students in staging and enroll them in the test
   course. Open a **fresh session for every run**, with a saved classroom pin.
   For mixed login traffic seed additional distinct students immediately after
   the scan cohort in the email numbering. The lecturer must teach the course.
   No seeding/deletion is performed by this harness.
5. Use a separate load-generator machine, synchronized clock, enough file
   descriptors (at least 8,192), CPU and network headroom for 2,000 sockets.
   Install `requirements-loadtest.txt`. Record Python/gevent/requests versions,
   machine size, location and file descriptor limit in `generator`.
6. Copy `staging.example.json` to a private run directory. Independently check
   both target service and PostgreSQL identity in your staging provider, fill
   the metadata, and set prerequisite booleans only after checking them.
   `database.port` is the explicit port in the URL, or null if omitted.
   Do not put passwords, secret keys or credential URLs in this file: it is
   embedded in the report. Use a read-only PostgreSQL verification account.

The manifest is an operator-reviewed allowlist, not remote attestation. It
prevents accidental target/DB mismatches; falsely identifying production as
staging defeats it. No hostname substring can establish environment isolation.
The CLI checks this file before networking, refuses cross-origin redirects,
requires HTTPS/PostgreSQL for staging, and requires an explicit write opt-in.
It does not disable application controls. Keep database and HTTP target paired.

## One measured run

From the `ScanMark` directory, supply secrets securely via environment variables
(`TARGET_SECRET_KEY`, `STUDENT_PASSWORD`, `DATABASE_URL`, and for polling
`PROJECTOR_PASSWORD`). Avoid putting credentials in shell arguments/history.
Set `TARGET_HOST`, `TARGET_SESSION_IDS`, `EMAIL_PATTERN`, `CLASS_LAT`, `CLASS_LON`
and `PROJECTOR_EMAIL` for the reviewed staging fixture. The database URL is for
read-only verification, not seeding.

```bash
python loadtest/scan_burst.py \
  --staging-manifest /private/run/staging.json --confirm-staging-writes \
  --students 20 --login-concurrency 1 \
  --label smoke-01 --json-out /private/run/smoke-01.json
```

The output path must not already exist. A started but interrupted/failed
preflight run leaves `run_incomplete`, never a stale passing report. Retain it
and use a new filename for the next attempt. Review stderr as well as JSON.
Preflight requires all scan students verified/enrolled, sessions open, and zero
existing attendance for every expected student/session pair.

After a passing smoke run, create fresh sessions and use the **same command**
with these scenario arguments and unique labels/output paths:

| Scenario | Arguments | Repetitions |
|---|---|---|
| Scan only | `--students 2000 --login-concurrency 1` | 3 |
| Projector | above plus `--projector-watchers 1` | 3 |
| Mixed event | above plus `--projector-watchers 1 --login-noise 4` | 3 |

Login concurrency 1 is a conservative preparation setting for the tiny plan;
preauthentication may take a long time. Preparation is reported separately.
Record why the chosen mixed-login concurrency represents the event; four is
an initial diagnostic workload, not a universal claim. Do not run overlapping
benchmarks against the same staging service. Stop the sequence on the first
failure, inspect evidence, and resume only after diagnosis with fresh sessions.
Do not automatically retry scans or reset attendance to make a result pass.
A capped `--burst-concurrency` is diagnostic and fails simultaneous acceptance.
Keep cold connections by default; label warm-connection experiments separately.

## Measurements and acceptance

JSON schema version 2 retains HTTP statuses/outcomes, exact cohort row checks,
authentication failures, request percentiles and throughput, and adds:

- `dispatch_ms`: elapsed time from releasing the barrier to starting requests.
- `completion_ms`: barrier-to-response percentiles, including generator delay.
  This is what the SLO gate uses: p50 <100 ms, p95 <300 ms, p99 <750 ms.
- `correctness_passed`: every student authenticated, every first attempt returned
  HTTP 200/success inside its 20-second deadline, exact expected attendance
  written once, projector checks and simultaneous-cohort checks passed.
- `passed`: correctness **and** the latency SLO passed; exit code 0 agrees.
- `capacity_accepted`: this individual 2,000-student staging scenario passed.
  It is not acceptance of the entire event matrix or production capacity.
- Projector poll count, login-noise attempts/failures, concurrency, session IDs,
  connection mode, target metadata and UTC start timestamp.

Verification queries the exact expected student/session pairs, so unrelated
attendance cannot replace missing students. Equal totals with a missing row
and duplicate row fail. Read failures, missing responses, duplicate responses,
429/5xx, background task crashes, incomplete watchers and absent measurements
fail. All expected rows are checked after traffic finishes; late writes after
a deadline do not turn a failed response into success. The harness never deletes
rows. Clean up only disposable staging fixtures after preserving evidence.

For **each** repetition retain JSON and collect time-aligned provider metrics:
CPU/RAM peaks for app and generator, app restarts/OOMs, database active/max
connections and pool waits, Redis errors/evictions, and ingress errors. Record
start/end UTC and links to metric exports in a companion results note. A high
dispatch delay or saturated generator makes the capacity conclusion inconclusive.
The harness cannot collect these provider metrics with only HTTP/DB credentials.
Only accept the event after all scenarios/repetitions and infrastructure evidence
are reviewed. Do not infer safe staggered group size without measurements.

## Local harness checks

```bash
python -m pytest -q test_scan_validation.py test_staging_guard.py loadtest/tests
# Optional 2,000-client validation against the synthetic HTTP fixture only:
HARNESS_FIXTURE_STUDENTS=2000 HARNESS_EVIDENCE_DIR=/tmp/harness-evidence \
  python -m pytest -q loadtest/tests/test_burst_cli.py -k success
```

The disposable loopback fixture writes SQLite rows but does not run ScanMark,
password hashing, Redis, PostgreSQL, CSRF or geofencing. Its report is marked
`local-harness-check` and can never set `capacity_accepted`. Its measured timings
prove only that the generator/report/verifier ran; they say nothing about staging
throughput. See `BENCHMARK_RESULTS.md` for work completed and outstanding evidence.
