"""
Gunicorn configuration for ScanMark.

Sizing note: workers x threads is the request-slot ceiling. The defaults below
(4 x 8 = 32) are a starting candidate, not a 2,000-student capacity claim.
Select 2x8, 4x8, 4x12, or 6x8 from measured staging results in
loadtest/gunicorn-matrix.md, then override with environment variables.

Postgres note: each worker keeps its own connection pool, so the server
sees up to workers x (DB_POOL_SIZE + DB_MAX_OVERFLOW) connections
(4 x 10 = 40 with the app defaults). Size your database plan accordingly.
"""
import os

workers = int(os.environ.get("WEB_CONCURRENCY", 4))
threads = int(os.environ.get("GUNICORN_THREADS", 8))
worker_class = "gthread"

# Import the app once in the master, then fork. This makes the startup
# db.create_all()/migration block run exactly once instead of once per
# worker. app.py calls db.engine.dispose() after init, so each forked
# worker opens fresh DB connections.
preload_app = True

# Slightly above the typical platform router timeout (30s) so gunicorn
# isn't the first to abandon a request that queued during a scan burst.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 60))

# Let the OS queue a burst of incoming connections instead of refusing them.
backlog = 2048
