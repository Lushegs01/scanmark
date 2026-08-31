"""
Find this machine's password-hashing knee, so PASSWORD_HASH_CONCURRENCY is a
measured number rather than a guess.

Verifying a password is the most expensive thing ScanMark does per request,
and the cost is not only CPU. Werkzeug hashes with scrypt, which is
deliberately memory-HARD: every verification touches a ~32 MB working set at
random. Past a handful of concurrent hashes the limit is memory bandwidth,
not cores — so adding threads stops adding logins while it keeps adding
latency and resident memory.

Run it on the instance size you actually deploy, not on a laptop:

    python benchmarks/benchmark_password_hash.py

Read the table for the LAST concurrency at which verifies/sec is still
climbing. That is the knee, and it is the instance-wide value for
PASSWORD_HASH_CONCURRENCY. ScanMark divides it among gunicorn workers itself,
because the semaphore is per-process but the memory bus is not.

Sample run (4 CPUs visible to Python):

    concurrency  verifies/sec  per-verify ms  peak RSS delta
              1           9.9          100.6           32 MB
              2          19.6          102.0           64 MB
              4          38.5          103.6          128 MB   <- knee
              8          37.3          214.3          256 MB
             16          37.4          427.6          512 MB
             32          36.7          870.0         1024 MB

Everything from 8 down is strictly worse than 4: identical throughput, double
the latency, double the memory.
"""

import argparse
import os
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

SAMPLE_PASSWORD = 'benchmark-password-not-a-secret'


def measure(concurrency, verifies_each, password_hash):
    """(verifies/sec, worst per-verify ms) at this concurrency."""
    barrier = threading.Barrier(concurrency)
    per_thread = [0.0] * concurrency

    def worker(index):
        barrier.wait()
        started = time.perf_counter()
        for _ in range(verifies_each):
            check_password_hash(password_hash, SAMPLE_PASSWORD)
        per_thread[index] = time.perf_counter() - started

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(concurrency)]
    wall_started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.perf_counter() - wall_started
    return (concurrency * verifies_each / wall,
            max(per_thread) / verifies_each * 1000)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verifies-each', type=int, default=6,
                        help='verifications per thread per level')
    parser.add_argument('--levels', default='1,2,4,8,16,32')
    arguments = parser.parse_args()

    password_hash = generate_password_hash(SAMPLE_PASSWORD, method='scrypt')
    method = password_hash.split('$', 1)[0]
    # scrypt's working set is 128 * N * r bytes.
    working_set_mb = 0
    parts = method.split(':')
    if parts[0] == 'scrypt' and len(parts) >= 3:
        working_set_mb = 128 * int(parts[1]) * int(parts[2]) / (1024 * 1024)

    print(f'method            {method}')
    print(f'cores             {os.cpu_count()}')
    if working_set_mb:
        print(f'working set/hash  {working_set_mb:.0f} MB')
    print()
    print(f"{'concurrency':>11} {'verifies/sec':>13} {'per-verify ms':>14} "
          f"{'transient RAM':>14}")

    best_throughput = 0.0
    knee = 1
    for level in (int(value) for value in arguments.levels.split(',')):
        throughput, latency_ms = measure(level, arguments.verifies_each,
                                         password_hash)
        memory = f'{level * working_set_mb:.0f} MB' if working_set_mb else '-'
        # "Still climbing" = more than 5% better than the best so far.
        marker = ''
        if throughput > best_throughput * 1.05:
            best_throughput = throughput
            knee = level
            marker = ''
        else:
            marker = '  (no gain)'
        print(f'{level:>11} {throughput:>13.1f} {latency_ms:>14.1f} '
              f'{memory:>14}{marker}')

    print()
    print(f'Knee: {knee} concurrent verifications '
          f'({best_throughput:.1f} verifies/sec).')
    print(f'Set PASSWORD_HASH_CONCURRENCY={knee} (instance-wide).')
    print(f'A {knee}-wide budget signs {best_throughput:.0f} students in per '
          f'second, so a 2,000-student rush takes '
          f'~{2000 / max(best_throughput, 0.01):.0f}s — plan the lecture '
          f'start, and the autoscaling, around that number rather than '
          f'discovering it at 8am.')


if __name__ == '__main__':
    main()
