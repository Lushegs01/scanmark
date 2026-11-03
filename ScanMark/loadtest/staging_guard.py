"""Offline target checks and evidence rules; never imports the application."""
import json
import math
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url


def origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ('', '/')):
        raise ValueError('Target must be an HTTP(S) origin without credentials or a path')
    return f'{parsed.scheme}://{parsed.netloc}'.rstrip('/')


def validate_target(path, host, database_url):
    """Require an operator-reviewed allowlist, independent of ambient DB settings."""
    with open(path, encoding='utf-8') as handle:
        manifest = json.load(handle)
    target = origin(host)
    if target != origin(manifest['origin']):
        raise ValueError('Target does not match the reviewed staging origin')
    db = make_url(database_url)
    identity = {'host': db.host, 'port': db.port, 'database': db.database}
    if identity != manifest['database']:
        raise ValueError('Database does not match the reviewed staging database')
    mode = manifest['mode']
    if mode == 'local-harness-check':
        if urlsplit(target).hostname not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('Local harness checks require loopback HTTP')
        if db.get_backend_name() != 'sqlite':
            raise ValueError('Local harness checks require disposable SQLite')
    elif mode == 'staging':
        if urlsplit(target).scheme != 'https' or db.get_backend_name() != 'postgresql':
            raise ValueError('Staging requires HTTPS and PostgreSQL')
        for field in ('deployed_commit', 'web_plan', 'region', 'postgres_version_plan',
                      'redis_version_plan', 'worker_settings', 'database_connection_limit',
                      'generator'):
            if not manifest.get(field):
                raise ValueError(f'Missing staging evidence: {field}')
        for field in ('isolated_services', 'synthetic_accounts', 'mail_sink',
                      'campos_disabled', 'security_controls_enabled'):
            if manifest.get(field) is not True:
                raise ValueError(f'Required staging prerequisite: {field}')
    else:
        raise ValueError('Manifest mode must be staging or local-harness-check')
    return manifest


def latency_errors(samples):
    """Use the deployment SLO, including dispatch delay after barrier release."""
    if not samples or any(not math.isfinite(x) or x < 0 for x in samples):
        return ['missing_or_invalid_completion_latency']
    ordered = sorted(samples)
    return [f'scan_{name}_slo_exceeded'
            for name, ratio, limit in (('p50', .50, 100), ('p95', .95, 300),
                                       ('p99', .99, 750))
            if ordered[math.ceil(len(ordered) * ratio) - 1] >= limit]
