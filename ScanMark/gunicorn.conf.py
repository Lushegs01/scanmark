"""
Gunicorn configuration for ScanMark.

Sizing note: workers × threads = how many requests one dyno/instance can
work on at the same time. The defaults below (4 × 8 = 32) are tuned for a
1 GB instance and a 2000-student scan burst; override per-instance with the
WEB_CONCURRENCY / GUNICORN_THREADS env vars instead of editing this file.

Postgres note: each worker keeps its own connection pool, so the server
sees up to workers × (DB_POOL_SIZE + DB_MAX_OVERFLOW) connections
(4 × 10 = 40 with the app defaults). Size your database plan accordingly.
"""
import os

workers = int(os.environ.get("WEB_CONCURRENCY", 4))
threads = int(os.environ.get("GUNICORN_THREADS", 8))
worker_class = "gthread"

# Import the app once in the master, then fork. This makes the startup
# db.create_all()/migration block run exactly once instead of once per
# worker, and keeps the APScheduler weekly-report thread in the master so
# reports fire once. app.py calls db.engine.dispose() after init, so each
# forked worker opens fresh DB connections.
preload_app = True

# Slightly above the typical platform router timeout (30s) so gunicorn
# isn't the first to abandon a request that queued during a scan burst.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 60))

# Let the OS queue a burst of incoming connections instead of refusing them.
backlog = 2048
