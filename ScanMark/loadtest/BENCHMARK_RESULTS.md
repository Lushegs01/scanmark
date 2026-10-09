# Benchmark evidence — 2026-10-09

## Capacity conclusion

**Unverified for staging and production.** No staging host, isolated PostgreSQL/
Redis credentials or matching service-plan evidence was configured in this task.
No production traffic, infrastructure changes or staging load run occurred.
The next concrete step is the 20-student smoke run in
[STAGING_BENCHMARK.md](STAGING_BENCHMARK.md), after its prerequisites are satisfied.

## Measured local generator check (not ScanMark)

Source baseline: merged PR #41, `2e5e488a615594abe6d9b6ecdd518925dd43abb2`,
plus this change. Python 3.11.16, gevent 26.9.0, requests 2.32.5,
SQLAlchemy 2.0.46; managed Linux workspace. Fixture and generator ran on the
same machine using loopback HTTP and disposable SQLite. No application,
PostgreSQL, Redis, geofence, CSRF or password hashing was exercised.

[Raw 2,000-client report](evidence/success-2000.json), started `2026-10-09T10:57:32Z`:

| Measurement | Observed |
|---|---:|
| Requested/authenticated students | 2,000 / 2,000 |
| Peak client requests in flight | 2,000 |
| HTTP 200 / success outcomes | 2,000 / 2,000 |
| Verified distinct attendance pairs | 2,000 |
| Missing / duplicate rows | 0 / 0 |
| Burst wall time | 2.916 s |
| Completion p50 / p95 / p99 | 2053.3 / 2860.3 / 2903.9 ms |
| Dispatch p95 / max | 1214.2 / 1271.8 ms |
| Correctness passed | True |
| Latency SLO / capacity accepted | False / False |

The generator verified all expected writes but rejected the latency result.
Dispatch delay is material: a barrier is not proof of simultaneous arrival at
an application. These numbers are **not ScanMark throughput** and cannot size
its workers, predict free-plan capacity, or justify a production change.

## Regression validation

37 targeted checks passed: original exact-pair checks, staging identity and
prerequisite guards, eligibility checks, and seven real CLI/HTTP scenarios.
Static checks, compilation, CLI help and whitespace checks passed.
The separate 2,000-client fixture check also passed its correctness assertions;
its benchmark process correctly returned nonzero for the SLO breach.
Loopback tests required network-enabled execution because the default sandbox
refuses socket creation. An intermediate run using serial synthetic logins was
stopped during preparation; the final fixture command explicitly uses login
concurrency 32. Staging defaults to conservative login concurrency 1.

| Injected condition (20 students) | Result |
|---|---|
| Complete writes | Correctness passed |
| HTTP success but one row missing | Rejected; 19 rows, one missing pair |
| Extra duplicate row | Rejected; 21 rows, one duplicate |
| One failed login | Rejected; 19 authenticated |
| Projector returns invalid JSON | Rejected |
| Scan concurrency capped at two | Rejected as non-simultaneous |
| Cross-origin login redirect | Rejected; zero authenticated/writes |
| Existing report filename | Rejected before traffic; original report preserved |
| Reused cohort with fresh report path | Preflight rejected; no added rows |

Raw small-fixture reports are in [evidence/](evidence/). They are regression
artifacts, not staging measurements. Full application/PostgreSQL/Redis suites
were not rerun locally because application behavior is unchanged. CI now installs
the generator dependency and collects the new tests in both existing jobs.

## Evidence still required

- Reviewed staging manifest, deployed commit and matching web/DB/Redis plans.
- Smoke, three scan-only, three projector and three mixed-login runs, all using
  fresh sessions; retain failures and stop to investigate them.
- Time-aligned app/generator CPU and memory, restarts/OOMs, DB connections/pool
  waits, Redis errors/evictions and ingress metrics for every repetition.
- Review all correctness and latency gates plus generator headroom before any
  capacity claim. Do not change production based on these local results.
