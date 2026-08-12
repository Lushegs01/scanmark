#!/usr/bin/env bash
#
# The staging capacity matrix.
#
# Two axes matter and they are different questions:
#
#   USERS        how many students the class has
#   SPAWN RATE   how fast they arrive
#
# A 2,000-user run spread over four minutes says almost nothing about the
# event this system exists for, which is a lecturer putting the code on the
# projector and the whole room scanning inside thirty seconds. That is a
# BURST, and it is the burst that decides whether the database sees 2,000
# inserts in one second or 8 per second for four minutes.
#
#   ./loadtest/run_matrix.sh https://staging.example
#
# Required environment:
#   TARGET_SECRET_KEY   staging SECRET_KEY, to mint tokens the server accepts
#   TARGET_SESSION_IDS  the open session id(s) under test
#   STUDENT_PASSWORD    the seeded students' password
#   CLASS_LAT/CLASS_LON the classroom pin for those sessions — WITHOUT these
#                       matching, every scan is refused as out of geofence and
#                       the run measures the rejection path
#
# Never point this at production: successful runs create attendance rows.

set -uo pipefail

HOST="${1:?usage: run_matrix.sh <https://staging-host> [results-dir]}"
RESULTS="${2:-loadtest/results}"
LOCUSTFILE="${LOCUSTFILE:-loadtest/locustfile.py}"
# One value drives both --processes and the student-slicing the locustfile
# does, so they cannot drift apart and have two processes claim one student.
PROCESSES="${PROCESSES:-4}"

: "${TARGET_SECRET_KEY:?set TARGET_SECRET_KEY to the staging SECRET_KEY}"
: "${TARGET_SESSION_IDS:?set TARGET_SESSION_IDS to the open session id(s)}"
: "${CLASS_LAT:?set CLASS_LAT to the pinned classroom latitude}"
: "${CLASS_LON:?set CLASS_LON to the pinned classroom longitude}"

mkdir -p "$RESULTS"
FAILED=()

run() {
  local name="$1" users="$2" rate="$3" duration="$4"
  shift 4
  local prefix="$RESULTS/$name"

  echo
  echo "=============================================================="
  echo "  $name — $users users, $rate/sec arrival, $duration"
  echo "=============================================================="

  env LOCUST_WORKER_COUNT="$PROCESSES" "$@" \
      locust -f "$LOCUSTFILE" --host "$HOST" --headless \
      --users "$users" --spawn-rate "$rate" --run-time "$duration" \
      --processes "$PROCESSES" \
      --csv "$prefix" --only-summary \
    || echo "locust exited non-zero for $name"

  if python3 loadtest/check_slo.py "$prefix"; then
    echo "PASS  $name"
  else
    echo "FAIL  $name"
    FAILED+=("$name")
  fi
}

# ---------------------------------------------------------------------------
# 1. Baseline grid — class size against arrival rate.
#    Walk both axes so the shape of the degradation is visible, not just the
#    pass/fail at the target.
# ---------------------------------------------------------------------------
for users in 200 600 1000 2000 3000; do
  for rate in 25 50 100 200 400 800; do
    # An arrival rate above the class size is the same run as rate == users.
    [ "$rate" -gt "$users" ] && continue
    run "grid-${users}-r${rate}" "$users" "$rate" "90s" SCENARIO=scan
  done
done

# ---------------------------------------------------------------------------
# 2. THE test. The lecturer displays the QR and the room scans: 2,000 students
#    arriving at 500/sec against one session and one code. Everything else in
#    this file is context for this row.
# ---------------------------------------------------------------------------
run "burst-2000-r500" 2000 500 "60s" SCENARIO=scan

# ---------------------------------------------------------------------------
# 3. A university is not one room. Concurrent classes spread the same total
#    load across sessions, which exercises per-session locks, per-session
#    admission buckets and per-session caches rather than one hot key.
#    Set TARGET_SESSION_IDS to the matching number of open sessions first.
# ---------------------------------------------------------------------------
run "multi-5x600" 3000 300 "2m" SCENARIO=scan
run "multi-10x300" 3000 300 "2m" SCENARIO=scan

# ---------------------------------------------------------------------------
# 4. The projector is a client too. During the burst the lecturer's screen is
#    polling every second, and its cost belongs in the picture.
# ---------------------------------------------------------------------------
run "projector-feed" 10 5 "60s" SCENARIO=feed

# ---------------------------------------------------------------------------
# 5. Correctness under race, not throughput: one student, many simultaneous
#    scans, exactly one row.
# ---------------------------------------------------------------------------
run "double-scan-20" 1 1 "20s" SCENARIO=double_scan DOUBLE_SCAN_CONCURRENCY=20

# ---------------------------------------------------------------------------
# 6. The pre-lecture login rush, measured separately: scrypt hashing is CPU
#    work that scanning does not do, so mixing them hides both.
# ---------------------------------------------------------------------------
run "login-600" 600 100 "60s" SCENARIO=login

echo
echo "=============================================================="
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "  ALL SCENARIOS WITHIN SLO"
  exit 0
fi
echo "  ${#FAILED[@]} SCENARIO(S) OUTSIDE SLO:"
printf '    %s\n' "${FAILED[@]}"
echo "=============================================================="
exit 1
