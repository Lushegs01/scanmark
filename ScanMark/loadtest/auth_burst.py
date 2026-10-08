"""Staging-only simultaneous signup/login burst, including real password work.

Install requirements-loadtest.txt. Use a disposable staging database and mail
sink; signup creates accounts and sends mail. No security control is disabled.
"""
from gevent import monkey
monkey.patch_all()

import argparse
from collections import Counter
import json
import os
import random
import re
import time
import uuid

import gevent
from gevent.event import Event
from gevent.pool import Pool
import requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, help='Disposable staging origin')
    parser.add_argument('--mode', choices=('signup', 'login'), required=True)
    parser.add_argument('--students', type=int, default=2000)
    parser.add_argument('--email-pattern', required=True,
                        help='Use {n} for student number; signup also requires {run}')
    parser.add_argument('--deadline', type=float, default=120)
    parser.add_argument('--output', help='Write JSON summary here')
    args = parser.parse_args()
    password = os.environ.get('STUDENT_PASSWORD')
    if not password or args.students < 1 or args.deadline <= 0:
        parser.error('Set STUDENT_PASSWORD and use positive students/deadline values')
    if '{n}' not in args.email_pattern or (args.mode == 'signup' and '{run}' not in args.email_pattern):
        parser.error('email-pattern needs {n}, and signup also needs {run} for unique accounts')
    host = args.host.rstrip('/')
    path = '/' + args.mode
    run_id = uuid.uuid4().hex[:12]
    gate = Event()
    statuses, failures = Counter(), Counter()
    completed = []
    clients = []

    def prepare(number):
        client = requests.Session()
        clients.append(client)
        client.headers.update({'Referer': host + path})
        try:
            response = client.get(host + path, timeout=30)
            response.raise_for_status()
            match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
            if not match:
                failures['missing_csrf'] += 1
                return None
            data = {
                'csrf_token': match.group(1),
                'email': args.email_pattern.format(n=number, run=run_id),
                'password': password,
            }
            if args.mode == 'signup':
                data.update(full_name=f'Load Student {number}', level='300')
            return client, data
        except requests.RequestException:
            failures['form_request_failed'] += 1
            return None

    def submit(phone):
        client, data = phone
        gate.wait()
        started = time.monotonic()
        for attempt in range(12):
            remaining = args.deadline - (time.monotonic() - started)
            if remaining <= 0:
                break
            try:
                response = client.post(host + path, data=data,
                    headers={'Accept': 'application/json'}, timeout=min(30, remaining),
                    allow_redirects=False)
                statuses[str(response.status_code)] += 1
                payload = response.json()
            except (requests.RequestException, ValueError):
                # Match the browser: never replay an ambiguous write.
                failures['network_or_non_json_response'] += 1
                return
            if response.status_code == 503 and payload.get('outcome') == 'auth_overloaded':
                delay = max(float(response.headers.get('Retry-After', 3)),
                            min(20, 3 * 2 ** attempt)) + random.uniform(0, 5)
                if attempt == 11 or time.monotonic() - started + delay >= args.deadline:
                    break
                gevent.sleep(delay)
                continue
            if response.ok and payload.get('outcome') == 'success':
                if args.mode == 'signup' and payload.get('created') is not True:
                    failures['account_already_exists'] += 1
                    return
                completed.append(time.monotonic() - started)
                return
            failures[f"{response.status_code}:{payload.get('outcome', 'unknown')}"] += 1
            return
        failures['deadline_or_retry_budget'] += 1

    phones = [phone for phone in Pool(50).map(prepare, range(1, args.students + 1)) if phone]
    jobs = [gevent.spawn(submit, phone) for phone in phones]
    started = time.monotonic()
    gate.set()
    gevent.joinall(jobs, raise_error=True)
    elapsed = time.monotonic() - started
    for client in clients:
        client.close()
    ordered = sorted(completed)

    def percentile(fraction):
        return round(ordered[min(len(ordered) - 1, int(len(ordered) * fraction))], 3) if ordered else None

    result = dict(mode=args.mode, run=run_id, students=args.students,
                  prepared=len(phones), completed=len(completed),
                  failures=dict(failures), http_statuses=dict(statuses),
                  burst_seconds=round(elapsed, 3),
                  completion_p50_seconds=percentile(.5),
                  completion_p95_seconds=percentile(.95),
                  completion_p99_seconds=percentile(.99))
    encoded = json.dumps(result, indent=2)
    print(encoded)
    if args.output:
        with open(args.output, 'w') as output:
            output.write(encoded + '\n')
    return 0 if len(completed) == args.students and not failures else 1


if __name__ == '__main__':
    raise SystemExit(main())
