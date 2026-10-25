#!/usr/bin/env bash
# Dump the ScanMark database, keep BACKUP_KEEP_DAYS of dumps on the VM, and
# copy each one to Oracle Object Storage when BACKUP_S3_BUCKET is set.
# Run by scanmark-backup.service as the scanmark user, which reaches the
# database through peer authentication.
set -euo pipefail
# Dumps hold password hashes and every student's record.
umask 077

BACKUP_DIR=/var/backups/scanmark
dump="$BACKUP_DIR/scanmark-$(date -u +%Y%m%dT%H%M%SZ).dump"

# Written under a temporary name, so an interrupted dump is never mistaken
# for a good one by the pruning below or by whoever restores.
pg_dump --format=custom --dbname=scanmark --file="$dump.partial"
mv "$dump.partial" "$dump"
echo "Wrote $dump ($(du -h "$dump" | cut -f1))"

find "$BACKUP_DIR" -name 'scanmark-*.dump' -mtime +"${BACKUP_KEEP_DAYS:-14}" -delete
find "$BACKUP_DIR" -name 'scanmark-*.dump.partial' -mtime +1 -delete

if [[ -n ${BACKUP_S3_BUCKET:-} ]]; then
    /opt/scanmark/tools/bin/python - "$dump" <<'PY'
import os
import sys

import boto3
from botocore.config import Config

path = sys.argv[1]
bucket = os.environ["BACKUP_S3_BUCKET"]
client = boto3.client(
    "s3",
    endpoint_url=os.environ["BACKUP_S3_ENDPOINT"],
    region_name=os.environ["BACKUP_S3_REGION"],
    aws_access_key_id=os.environ["BACKUP_S3_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["BACKUP_S3_SECRET_ACCESS_KEY"],
    # Oracle's S3-compatible API wants path-style addresses. Recent boto3
    # also adds checksum headers S3 itself does not require, which
    # S3-compatible stores can refuse, so send them only where required.
    config=Config(
        s3={"addressing_style": "path"},
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
    ),
)
client.upload_file(path, bucket, os.path.basename(path))
print(f"Copied {os.path.basename(path)} to bucket {bucket}")
PY
fi
