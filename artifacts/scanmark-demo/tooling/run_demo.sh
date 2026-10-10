#!/usr/bin/env bash
# Build the ScanMark demo-asset package from scratch, against an isolated
# local copy of the real application.
#
#   1. a private Redis on its own port, persisting nothing;
#   2. a fresh SQLite file seeded with the fictional dataset (seed_demo.py);
#   3. the app booted with its real Procfile command (gunicorn + gunicorn.conf.py);
#   4. Playwright drives it and records the assets (capture_demo.cjs);
#   5. every on-screen figure is checked against the database (verify_demo.py).
#
# A random SECRET_KEY and demo password are generated per run and kept in the
# run directory (outside the package). Nothing here can reach a deployed
# database: the seed refuses anything but a local SQLite file.
#
# Environment (all optional):
#   PYTHON          interpreter with ScanMark/requirements.txt installed  [python3]
#   DEMO_RUN_DIR    scratch directory for the DB, secrets and frames     [mktemp -d]
#   DEMO_PORT       port for the app                                     [8100]
#   DEMO_REDIS_PORT port for the private Redis                           [6391]
#   NODE_PATH       where `playwright` resolves from, if not installed here
set -euo pipefail

TOOLING="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE="$(dirname "$TOOLING")"
APP_DIR="$(cd "$TOOLING/../../../ScanMark" && pwd)"
PYTHON="${PYTHON:-python3}"
DEMO_PORT="${DEMO_PORT:-8100}"
DEMO_REDIS_PORT="${DEMO_REDIS_PORT:-6391}"
DEMO_RUN_DIR="${DEMO_RUN_DIR:-$(mktemp -d -t scanmark-demo-XXXXXX)}"
mkdir -p "$DEMO_RUN_DIR"
DEMO_RUN_DIR="$(cd "$DEMO_RUN_DIR" && pwd)"

for tool in redis-server redis-cli ffmpeg ffprobe node curl; do
    command -v "$tool" >/dev/null || { echo "run_demo: $tool is required" >&2; exit 1; }
done
if redis-cli -p "$DEMO_REDIS_PORT" ping >/dev/null 2>&1; then
    echo "run_demo: something already answers on Redis port $DEMO_REDIS_PORT; set DEMO_REDIS_PORT" >&2
    exit 1
fi
if curl -s -o /dev/null "http://127.0.0.1:$DEMO_PORT/"; then
    echo "run_demo: port $DEMO_PORT is in use; set DEMO_PORT" >&2
    exit 1
fi

GUNICORN_PID=""
cleanup() {
    [ -n "$GUNICORN_PID" ] && kill "$GUNICORN_PID" 2>/dev/null && wait "$GUNICORN_PID" 2>/dev/null || true
    redis-cli -p "$DEMO_REDIS_PORT" shutdown nosave >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- Secrets for this run only ---------------------------------------------
umask 077
"$PYTHON" -c 'import secrets; print(secrets.token_hex(32))' > "$DEMO_RUN_DIR/secret_key"
"$PYTHON" -c 'import secrets; print("Demo-" + secrets.token_urlsafe(9) + "7")' > "$DEMO_RUN_DIR/demo_password"
umask 022

export SCANMARK_ENV=development
export SECRET_KEY="$(cat "$DEMO_RUN_DIR/secret_key")"
export DEMO_PASSWORD="$(cat "$DEMO_RUN_DIR/demo_password")"
export DATABASE_URL="sqlite:///$DEMO_RUN_DIR/scanmark-demo.db"
export REDIS_URL="redis://127.0.0.1:$DEMO_REDIS_PORT/0"
# A closed port: the app's background emails fail at once instead of leaving.
export MAIL_SERVER=127.0.0.1 MAIL_PORT=2525
export INSTITUTION_DOMAINS=demo-university.example
export PUBLIC_ORIGIN="http://127.0.0.1:$DEMO_PORT"
export WEB_CONCURRENCY=2
export GUNICORN_CMD_ARGS="-b 127.0.0.1:$DEMO_PORT"
# ScanMark/__pycache__ is tracked in git; do not rewrite it.
export PYTHONDONTWRITEBYTECODE=1

# --- 1. Redis ----------------------------------------------------------------
redis-server --port "$DEMO_REDIS_PORT" --bind 127.0.0.1 --save '' --appendonly no \
    --dir "$DEMO_RUN_DIR" --daemonize yes >/dev/null

# --- 2. Seed -----------------------------------------------------------------
rm -f "$DEMO_RUN_DIR/scanmark-demo.db"
"$PYTHON" "$TOOLING/seed_demo.py" --out "$DEMO_RUN_DIR/seed.json" \
    > "$DEMO_RUN_DIR/seed.log" 2>&1 || { cat "$DEMO_RUN_DIR/seed.log"; exit 1; }
grep '^seed_demo:' "$DEMO_RUN_DIR/seed.log"

# --- 3. The app, with its own Procfile command ---------------------------------
GUNICORN="$(dirname "$("$PYTHON" -c 'import sys; print(sys.executable)')")/gunicorn"
(cd "$APP_DIR" && exec "$GUNICORN" --config gunicorn.conf.py app:app) \
    > "$DEMO_RUN_DIR/gunicorn.log" 2>&1 &
GUNICORN_PID=$!
for _ in $(seq 1 60); do
    curl -sf -o /dev/null "http://127.0.0.1:$DEMO_PORT/livez" && break
    sleep 0.5
done
curl -sf -o /dev/null "http://127.0.0.1:$DEMO_PORT/livez" || { tail -40 "$DEMO_RUN_DIR/gunicorn.log"; exit 1; }
echo "run_demo: ScanMark is up on http://127.0.0.1:$DEMO_PORT (run dir $DEMO_RUN_DIR)"

# --- 4. Capture ----------------------------------------------------------------
export DEMO_BASE_URL="http://127.0.0.1:$DEMO_PORT"
export DEMO_OUT_DIR="$PACKAGE"
export DEMO_RUN_DIR
export DEMO_PASSWORD_FILE="$DEMO_RUN_DIR/demo_password"
export DEMO_SEED_FILE="$DEMO_RUN_DIR/seed.json"
node "$TOOLING/capture_demo.cjs"
cp "$DEMO_RUN_DIR/capture-log.json" "$PACKAGE/capture-log.json"

# --- 5. Verify -------------------------------------------------------------------
"$PYTHON" "$TOOLING/verify_demo.py"
