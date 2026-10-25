#!/usr/bin/env bash
# Provision an Oracle Cloud Always Free VM (Ubuntu 24.04 on Ampere A1) for
# ScanMark: PostgreSQL and Redis on the VM, gunicorn under systemd, Caddy in
# front for HTTPS, and a nightly database backup.
#
#   sudo git clone https://github.com/Lushegs01/scanmark.git /opt/scanmark/src
#   sudo DOMAIN=scanmark.example.edu.ng PG_VERSION=17 \
#       /opt/scanmark/src/ScanMark/deploy/oracle/setup.sh
#
# Safe to run again. It never touches an existing database or settings file,
# and it does not start ScanMark: restore the data first (see README.md).
set -euo pipefail

: "${DOMAIN:?Set DOMAIN to the hostname ScanMark will be served from}"
# pg_dump refuses to dump a server newer than itself, so this has to be at
# least Neon's major version (SHOW server_version; on Neon).
: "${PG_VERSION:?Set PG_VERSION to the PostgreSQL major version Neon runs, e.g. 17}"

HOME_DIR=/opt/scanmark
SRC=$HOME_DIR/src
DEPLOY=$SRC/ScanMark/deploy/oracle
CONFIG_DIR=/etc/scanmark

if [[ $EUID -ne 0 ]]; then
    echo "Run this as root (sudo)." >&2
    exit 1
fi
if [[ ! -f $SRC/ScanMark/app.py ]]; then
    echo "Clone the repository to $SRC first." >&2
    exit 1
fi
if [[ ! $DOMAIN =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "DOMAIN must be a bare hostname, e.g. scanmark.example.edu.ng" >&2
    exit 1
fi
if [[ ! $PG_VERSION =~ ^[0-9]+$ ]]; then
    echo "PG_VERSION must be a major version number, e.g. 17" >&2
    exit 1
fi

# psql complains about a working directory the postgres user cannot read.
cd /
export DEBIAN_FRONTEND=noninteractive

echo "==> Packages"
apt-get update
apt-get install -y postgresql-common
# Ubuntu 24.04 carries PostgreSQL 16 only; the PostgreSQL project's own
# repository has every supported version, arm64 included.
/usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
apt-get install -y "postgresql-$PG_VERSION" redis-server caddy python3-venv \
    iptables-persistent

echo "==> Firewall"
# Oracle's Ubuntu images reject everything but SSH in iptables, on top of the
# VCN security list, so both have to let 80 and 443 in. The new rules go
# above the image's REJECT, which would otherwise match first.
for port in 80 443; do
    if ! iptables -C INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null; then
        reject=$(iptables -L INPUT -n --line-numbers | awk '$2 == "REJECT" { print $1; exit }')
        iptables -I INPUT "${reject:-1}" -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT
    fi
done
netfilter-persistent save

echo "==> Service account"
if ! id scanmark &>/dev/null; then
    useradd --system --home-dir "$HOME_DIR" --shell /usr/sbin/nologin scanmark
fi
chown -R scanmark:scanmark "$HOME_DIR"

echo "==> Python"
if [[ ! -x $HOME_DIR/venv/bin/python ]]; then
    sudo -u scanmark python3 -m venv "$HOME_DIR/venv"
fi
sudo -u scanmark "$HOME_DIR/venv/bin/pip" install --quiet -r "$SRC/ScanMark/requirements.txt"
# The backup upload gets its own environment, so it never depends on what the
# application happens to require.
if [[ ! -x $HOME_DIR/tools/bin/python ]]; then
    sudo -u scanmark python3 -m venv "$HOME_DIR/tools"
fi
sudo -u scanmark "$HOME_DIR/tools/bin/pip" install --quiet boto3==1.42.56

echo "==> PostgreSQL"
systemctl enable --now postgresql
port=$(pg_lsclusters -h | awk -v v="$PG_VERSION" '$1 == v && $2 == "main" { print $3 }')
if [[ $port != 5432 ]]; then
    echo "PostgreSQL $PG_VERSION is on port ${port:-?}, not 5432. This script expects a fresh VM." >&2
    exit 1
fi
# Peer authentication over the local socket: the scanmark OS user is the
# scanmark database role, so there is no database password to store or leak.
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = 'scanmark'" | grep -q 1; then
    sudo -u postgres createuser scanmark
fi
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname = 'scanmark'" | grep -q 1; then
    sudo -u postgres createdb --owner scanmark scanmark
fi

echo "==> Redis"
if ! grep -q '^# ScanMark' /etc/redis/redis.conf; then
    cat >> /etc/redis/redis.conf <<'EOF'

# ScanMark: cap Redis well inside the VM's memory, and evict only keys that
# carry an expiry (DEPLOYMENT.md, Required services).
maxmemory 1gb
maxmemory-policy volatile-lru
EOF
fi
systemctl enable redis-server
systemctl restart redis-server

echo "==> Settings"
install -d -m 750 -o root -g scanmark "$CONFIG_DIR"
if [[ ! -f $CONFIG_DIR/scanmark.env ]]; then
    install -m 640 -o root -g scanmark /dev/null "$CONFIG_DIR/scanmark.env"
    cat > "$CONFIG_DIR/scanmark.env" <<EOF
# ScanMark settings, read by scanmark.service. After editing:
#   sudo systemctl restart scanmark
#
# Copy every variable from the Render service's Environment page into this
# file, except the ones already set below and Render's free-plan sizing
# (WEB_CONCURRENCY, GUNICORN_THREADS, PASSWORD_HASH_CONCURRENCY,
# PASSWORD_HASH_MAX_WAIT_SECONDS, DB_POOL_SIZE, DB_MAX_OVERFLOW,
# REDIS_MAX_CONNECTIONS). Those were sized for 0.1 CPU; left unset, they are
# derived from this VM's real CPU count.
#
# SECRET_KEY is empty on purpose, and ScanMark will not start until it is
# set. Use the SAME value as on Render: it signs remember-me cookies and the
# emailed verification and reset links, so a new key logs everybody out and
# breaks every link already sent.
SCANMARK_ENV=production
SECRET_KEY=
PUBLIC_ORIGIN=https://$DOMAIN
DATABASE_URL=postgresql://scanmark@/scanmark?host=/var/run/postgresql
REDIS_URL=redis://127.0.0.1:6379/0
# Caddy is the one proxy in front of gunicorn.
TRUSTED_PROXY_COUNT=1
EOF
fi
if [[ ! -f $CONFIG_DIR/backup.env ]]; then
    install -m 640 -o root -g scanmark /dev/null "$CONFIG_DIR/backup.env"
    cat > "$CONFIG_DIR/backup.env" <<'EOF'
# Off-VM copies of the nightly database backup, read by
# scanmark-backup.service. A backup that lives only on the VM is lost with
# the VM. While BACKUP_S3_BUCKET is empty, dumps stay on the VM only.
#
# Oracle Object Storage, through its S3-compatible API:
#   endpoint  https://<namespace>.compat.objectstorage.<region>.oraclecloud.com
#   keys      Profile -> Customer secret keys -> Generate secret key
BACKUP_S3_BUCKET=
BACKUP_S3_ENDPOINT=
BACKUP_S3_REGION=
BACKUP_S3_ACCESS_KEY_ID=
BACKUP_S3_SECRET_ACCESS_KEY=
# Days of dumps kept on the VM itself.
BACKUP_KEEP_DAYS=14
EOF
fi
install -d -m 750 -o scanmark -g scanmark /var/backups/scanmark

echo "==> Services"
sed "s/SCANMARK_DOMAIN/$DOMAIN/" "$DEPLOY/Caddyfile" > /etc/caddy/Caddyfile
install -m 644 "$DEPLOY/scanmark.service" "$DEPLOY/scanmark-backup.service" \
    "$DEPLOY/scanmark-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now scanmark-backup.timer
systemctl enable caddy
systemctl restart caddy
# Picks up a changed unit when this is run again; does nothing before the
# first start.
systemctl try-restart scanmark

cat <<EOF

Installed. ScanMark is not running yet. Next (README.md has the detail):
  1. Fill in $CONFIG_DIR/scanmark.env from the Render service, SECRET_KEY first.
  2. Restore the Neon data into the local database.
  3. sudo systemctl enable --now scanmark
  4. curl -I https://$DOMAIN/healthz    (expect 204)
EOF
