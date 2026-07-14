"""Gunicorn entry point for load testing: the real app with CSRF and rate
limits disabled so the harness can drive thousands of scripted clients.

    gunicorn loadtest_app:app --chdir ScanMark/scripts -w 4 --threads 8

NEVER deploy this module — it exists only for scripts/load_test.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, limiter  # noqa: E402

app.config['WTF_CSRF_ENABLED'] = False
limiter.enabled = False
