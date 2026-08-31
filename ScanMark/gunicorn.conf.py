"""
Gunicorn configuration for ScanMark.

SIZING, AND WHY IT IS MOSTLY PROCESSES
--------------------------------------
`workers x threads` is the request-slot ceiling, and the instinct is to make
it large. Measured, that instinct is wrong here. A scan is dominated by
Python and SQLAlchemy work, not by waiting on the network: on this codebase
the database round trips are a fraction of a millisecond while the request
costs ~9 ms of CPU. Threads cannot run Python in parallel, so extra threads
per worker mostly add GIL contention and queueing — and the contention shows
up in the numbers as inflated *per-stage* timings for stages that perform no
I/O at all.

600 simultaneous scans, one 4-CPU box (app, Postgres, Redis and the load
generator all on it), measured with loadtest/scan_burst.py:

    workers x threads   pool   scans/sec   server p50   server p95   client p95
                2 x 8    5+5       160.5      24.3 ms      42.4 ms      3184 ms
                4 x 8    5+5       200.9      31.0 ms      64.6 ms      2387 ms
               4 x 16    8+8       219.3      49.4 ms     119.0 ms      2263 ms
                8 x 4    3+3       237.9      29.8 ms      66.9 ms      1941 ms
                4 x 4    5+5       255.7      15.4 ms      27.9 ms      1732 ms
                8 x 2    3+2       318.5      14.5 ms      29.4 ms      1455 ms   <- best

8x2 beats the previous 4x8 default by 59% on throughput and cuts server p95
from 64.6 ms to 29.4 ms. Note that 4x16 — the most slots of any row — is
close to the WORST: past the CPU count, slots buy latency, not capacity.

The shape that generalises: about two processes per core, two threads each.
The threads are there to overlap the one genuinely blocking thing a scan
does (waiting on Postgres), not to add parallelism Python cannot deliver.

RE-MEASURE ON YOUR OWN INSTANCE. The table above is one box; the ranking
should hold, the absolute numbers will not. loadtest/scan_burst.py prints
exactly these columns.

POSTGRES CONNECTIONS
--------------------
Every worker keeps its own pool, so one instance opens up to
`workers x (DB_POOL_SIZE + DB_MAX_OVERFLOW)` connections and N instances
open N times that. With the defaults here that is 8 x (3 + 2) = 40 per
instance. Check it against your plan's `max_connections` BEFORE scaling out;
this is the number that turns "add another instance" into "the database
refuses everyone". See DEPLOYMENT.md for the budget.
"""
import os

_cpus = os.cpu_count() or 2

# Two processes per core: the work is CPU-bound Python, so parallelism has to
# come from processes. Capped at 12 because each worker is also a database
# connection pool, and past this the constraint stops being CPU and becomes
# `max_connections`.
workers = int(os.environ.get("WEB_CONCURRENCY", max(2, min(12, _cpus * 2))))

# Two, deliberately. Threads here exist to keep a worker busy while one
# request waits on Postgres — not to add request slots. Raising this looks
# like more capacity and measures as less.
threads = int(os.environ.get("GUNICORN_THREADS", 2))
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

# How long an idle connection is held open between requests.
#
# Gunicorn's default is 2 SECONDS, and that default is wrong for this
# application in two separate ways.
#
# The student's way: the phone loads /scan_page, and then waits — for the
# lecturer to finish talking, for the projector to show the code, for the
# camera to focus. That wait is essentially never under two seconds, so the
# socket is always closed before the scan is posted, and every single scan
# pays for a fresh TCP handshake (and, at the router, a fresh TLS handshake).
# On a Nigerian mobile network that is 2-3 extra round trips — 200-600 ms
# added to a request the server answers in under 50. Measured directly: with
# the 2 s default, 165 of 300 scans posted after a 20 s wait came back
# `RemoteDisconnected` instead of a response, because the server had hung up
# on a connection the client still believed in.
#
# The load balancer's way, which is worse because it produces 502s: every
# platform router in front of this (ALB, Render, Fly, Railway) keeps its
# upstream connections pooled for ~60 s. If the app's keep-alive is SHORTER
# than the router's idle timeout, the router will eventually pick a socket
# out of its pool that gunicorn has already closed, write a request into it,
# and hand the client a 502 for a request the application never saw. The rule
# is that the app must hang up last, so this needs to sit ABOVE the router's
# idle timeout, not below it.
#
# 75 s clears the common 60 s router timeout with room to spare. Raise
# GUNICORN_KEEPALIVE if your router holds connections longer.
keepalive = int(os.environ.get("GUNICORN_KEEPALIVE", 75))


def post_fork(server, worker):
    """
    Restart per-process background threads in each forked worker.

    `preload_app` imports the application in the master and forks; Python
    threads do not cross fork, so anything started at import time exists only
    in the master — which never serves a request. The CampOS outbox sweeper is
    one of those, and without this it would appear to be running (the master
    has it) while no worker ever swept.
    """
    try:
        import app as scanmark
        scanmark.start_campos_sweeper()
    except Exception as error:                            # noqa: BLE001
        worker.log.warning("Could not start the CampOS sweeper: %s", error)
