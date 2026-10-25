#!/usr/bin/env bash
# Deploy the latest main to this VM, which Render did on every push:
#   sudo /opt/scanmark/src/ScanMark/deploy/oracle/update.sh
# The restart runs the boot-time migrations and drops requests for the few
# seconds it takes, so deploy outside class hours.
set -euo pipefail

SRC=/opt/scanmark/src
DEPLOY=$SRC/ScanMark/deploy/oracle

if [[ $EUID -ne 0 ]]; then
    echo "Run this as root (sudo)." >&2
    exit 1
fi

sudo -u scanmark git -C "$SRC" pull --ff-only
sudo -u scanmark /opt/scanmark/venv/bin/pip install --quiet -r "$SRC/ScanMark/requirements.txt"
install -m 644 "$DEPLOY/scanmark.service" "$DEPLOY/scanmark-backup.service" \
    "$DEPLOY/scanmark-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl restart scanmark

# /healthz answers 204 once the app can reach PostgreSQL and Redis.
for _ in $(seq 30); do
    if curl -fs -o /dev/null http://127.0.0.1:8000/healthz; then
        echo "ScanMark is up on $(sudo -u scanmark git -C "$SRC" log -1 --format='%h %s')"
        exit 0
    fi
    sleep 2
done
echo "ScanMark did not come up. See: journalctl -u scanmark -n 100" >&2
exit 1
