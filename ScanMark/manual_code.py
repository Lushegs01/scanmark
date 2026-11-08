"""
Rotating eight-digit manual attendance codes — the "can't scan the QR?" path.

Some students cannot read the projected QR code: a cracked or unfocusable
camera, a phone with no usable decoder, a seat too far from the screen, or a
browser that will not grant the camera at all. They get the same class session
and the same attendance record through a short numeric code instead, shown on
the projector beside the QR and typed into ScanMark.

This module is deliberately framework-free (no Flask, no database) so it can
be unit tested exactly, imported by the load-test harness, and reasoned about
on its own. It owns two things:

1. ``ManualCodeGenerator`` — which code is valid for which class session at
   which moment.
2. ``RedisAttemptGuard`` / ``LocalAttemptGuard`` — how many WRONG codes an
   account may try before it is made to wait.

Everything that decides whether a submission becomes an attendance record —
enrolment, institution, session state, the geofence, the atomic insert — is
NOT here. It is the same code the QR path uses, in app.py.

HOW A CODE IS DERIVED
---------------------
::

    key   = HMAC-SHA256(MANUAL_CODE_SECRET or SECRET_KEY,
                        "scanmark/manual-attendance-code/v1")
    step  = floor(unix_time / ROTATION_SECONDS)
    raw   = HMAC-SHA256(key, "scanmark-manual-code|v1|S<session_id>|T<step>|R<n>")
    code  = first 8 bytes of raw, big-endian, mod 10^8, zero-padded to 8 digits

* The key is PURPOSE-SEPARATED from the QR signing key. QR tokens are signed
  with SECRET_KEY itself; deriving a separate key means a code can never be
  mistaken for (or used to forge) anything else SECRET_KEY signs, and the
  derivation label versions the scheme.
* 64 bits reduced mod 10^8 has a modulo bias below 1e-11 — every 8-digit value
  is, for practical purposes, equally likely. Leading zeros are real digits
  and are preserved end to end (the code is a string, never an int, outside
  this module).
* Nothing is stored. Every worker on every instance computes the same code
  for the same (session, step) from the shared secret, so there is no state
  to synchronise, no Redis key per class, and no database write per rotation.
* The session id is an authenticated input, so two classes running at the
  same moment have independent codes, and a code for one class is
  meaningless for another.

ADJACENT WINDOWS NEVER SHOW THE SAME CODE
-----------------------------------------
Two consecutive windows of one session could, with probability 1e-8, derive
the same eight digits. Nothing would be insecure about that — each window's
code is still only valid in its own window — but the projector would appear
not to rotate, and the code would read as valid for two minutes. It is made
impossible by construction rather than improbable:

* EVEN steps take their first candidate (R0) unconditionally.
* ODD steps take the first candidate (R0, R1, R2) that differs from the codes
  of BOTH even neighbours. Two values are excluded at most, so three
  candidates always suffice.

An even step is only ever adjacent to odd steps, and every odd step differs
from both of its even neighbours, so no two adjacent windows are ever equal.
The rule is bounded (no recursion back through history) and exactly testable.

WHICH CODES ARE ACCEPTED, AND WHEN
----------------------------------
Server time is the only clock that matters. With R = ROTATION_SECONDS,
G = GRACE_SECONDS and K = CLOCK_SKEW_SECONDS, at server time ``t`` in step N
(``elapsed = t - N*R``):

* code(N) is accepted                          — the code on the screen now
* code(N-1) is accepted only while elapsed < G — typed as the screen changed
* code(N+1) is accepted only while R - elapsed <= K — another instance's
                                                  clock is slightly ahead
* code(N-1) after the grace and code(N-2) are reported as EXPIRED, which is
  not a guess (only a student who saw a real code can submit one)
* anything else is INVALID, and counts against the attempt guard

A whole previous window is never accepted just because it was recently valid.
The projector's countdown comes from the server's own ``expires_in_ms``, never
from the projector browser's wall clock, so a projector with a wrong clock
still shows the right code for the right length of time.

WHAT THIS DOES NOT PROVE
------------------------
A code can be read aloud, photographed or forwarded. Rotation bounds how long
a forwarded code is useful (≤ R + G seconds) and the classroom geofence —
the same one the QR path enforces — is the presence check. Neither proves a
body is in a seat: browser geolocation is self-reported. See DEPLOYMENT.md.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from dataclasses import dataclass

CODE_DIGITS = 8
CODE_MODULUS = 10 ** CODE_DIGITS
KEY_DERIVATION_LABEL = b'scanmark/manual-attendance-code/v1'
_MESSAGE_PREFIX = 'scanmark-manual-code|v1'

#: What a submitted code may look like before normalisation: digits with the
#: separators people actually type or paste ("4826 9137", "4826-9137").
#: Bounded so a hostile body cannot make normalisation do real work.
MAX_RAW_CODE_LENGTH = 32
_SEPARATORS = re.compile(r'[\s\-   .]')
# ASCII only. str.isdigit() also accepts '٣' and '³', which int() would then
# turn into something nobody typed.
_EIGHT_ASCII_DIGITS = re.compile(r'[0-9]{8}')

# Verification results.
VALID = 'valid'
EXPIRED = 'expired'
INVALID = 'invalid'


def derive_key(secret, label=KEY_DERIVATION_LABEL):
    """A key used for manual codes and nothing else."""
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    if not secret:
        raise ValueError('A non-empty secret is required to derive the manual-code key')
    return hmac.new(secret, label, hashlib.sha256).digest()


def normalize_code(raw):
    """
    The eight digits of a submitted code, or None if it is not one.

    Accepts the spaced form shown on the projector and pasted forms with
    hyphens or non-breaking spaces. Rejects anything else outright rather
    than "cleaning" it: a code with a letter in it was mistyped, and quietly
    dropping the letter would turn a typo into a different guess.
    """
    if not isinstance(raw, str) or len(raw) > MAX_RAW_CODE_LENGTH:
        return None
    digits = _SEPARATORS.sub('', raw)
    return digits if _EIGHT_ASCII_DIGITS.fullmatch(digits) else None


def format_code(code):
    """'48269137' -> '4826 9137', the grouping the projector shows."""
    return f'{code[:4]} {code[4:]}'


@dataclass(frozen=True)
class CodeWindow:
    """The code for one session in one time step."""
    code: str
    step: int
    starts_at: float
    expires_at: float

    def expires_in(self, now):
        return max(0.0, self.expires_at - now)


@dataclass(frozen=True)
class Verification:
    """
    How a submitted code compared with the session's codes.

    ``matched_step`` is which window it matched (None for an invalid code);
    ``reason`` says why a VALID code was accepted ('current', 'grace',
    'clock_skew') or how an EXPIRED one was recognised.
    """
    result: str
    matched_step: int | None
    reason: str

    @property
    def ok(self):
        return self.result == VALID


class ManualCodeGenerator:
    """Deterministic, stateless code derivation and verification."""

    def __init__(self, key, rotation_seconds=60, grace_seconds=5,
                 clock_skew_seconds=2, clock=time.time):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise ValueError('The manual-code key must be at least 16 bytes')
        rotation_seconds = int(rotation_seconds)
        if rotation_seconds < 10:
            raise ValueError('Codes must live at least 10 seconds')
        if not 0 <= grace_seconds < rotation_seconds / 2:
            raise ValueError('The grace period must be shorter than half a rotation')
        if not 0 <= clock_skew_seconds < rotation_seconds / 2:
            raise ValueError('The clock-skew tolerance must be shorter than half a rotation')
        self._key = bytes(key)
        self.rotation_seconds = rotation_seconds
        self.grace_seconds = float(grace_seconds)
        self.clock_skew_seconds = float(clock_skew_seconds)
        self._clock = clock

    # -- derivation -------------------------------------------------------

    def _candidate(self, session_id, step, attempt):
        message = f'{_MESSAGE_PREFIX}|S{int(session_id)}|T{int(step)}|R{int(attempt)}'
        digest = hmac.new(self._key, message.encode('ascii'), hashlib.sha256).digest()
        return int.from_bytes(digest[:8], 'big') % CODE_MODULUS

    def _value_for_step(self, session_id, step):
        if step % 2 == 0:
            return self._candidate(session_id, step, 0)
        # Odd steps sit between two even steps whose codes are fixed (R0).
        # Excluding both guarantees no adjacent pair is ever equal; two
        # exclusions mean the third candidate at the latest is accepted.
        neighbours = {self._candidate(session_id, step - 1, 0),
                      self._candidate(session_id, step + 1, 0)}
        for attempt in range(3):
            value = self._candidate(session_id, step, attempt)
            if value not in neighbours:
                return value
        raise AssertionError('unreachable: three candidates, two exclusions')

    def code_for_step(self, session_id, step):
        return f'{self._value_for_step(session_id, step):0{CODE_DIGITS}d}'

    def now(self):
        """Server time, as this generator sees it (injectable for tests)."""
        return self._clock()

    def step_at(self, now):
        return int(now // self.rotation_seconds)

    def window(self, session_id, now=None):
        """The code to display for this session right now, and its lifetime."""
        now = self._clock() if now is None else now
        step = self.step_at(now)
        starts_at = step * self.rotation_seconds
        return CodeWindow(self.code_for_step(session_id, step), step,
                          float(starts_at), float(starts_at + self.rotation_seconds))

    # -- verification ------------------------------------------------------

    def verify(self, session_id, submitted, now=None):
        """
        Compare a NORMALISED eight-digit code against this session's windows.

        Every candidate window is derived and compared in constant time, so
        how long a refusal takes says nothing about how close the guess was.
        """
        now = self._clock() if now is None else now
        step = self.step_at(now)
        elapsed = now - step * self.rotation_seconds
        remaining = self.rotation_seconds - elapsed
        submitted = submitted if isinstance(submitted, str) else ''
        encoded = submitted.encode('ascii', 'replace')

        def matches(candidate_step):
            return hmac.compare_digest(
                encoded, self.code_for_step(session_id, candidate_step).encode('ascii'))

        current = matches(step)
        previous = matches(step - 1)
        upcoming = matches(step + 1)
        older = matches(step - 2)

        if current:
            return Verification(VALID, step, 'current')
        if previous and elapsed < self.grace_seconds:
            return Verification(VALID, step - 1, 'grace')
        if upcoming and remaining <= self.clock_skew_seconds:
            return Verification(VALID, step + 1, 'clock_skew')
        if previous:
            return Verification(EXPIRED, step - 1, 'previous_window')
        if older:
            return Verification(EXPIRED, step - 2, 'older_window')
        return Verification(INVALID, None, 'no_match')


# ============================================================================
# FAILED-ATTEMPT GUARD
# ============================================================================
#
# Eight digits is 10^8 values. Online, with these limits, that is plenty:
# an account may try at most MAX_FAILURES_PER_ACCOUNT wrong codes per
# ACCOUNT_WINDOW across every class, so its chance of hitting a live code is
# about (failures x 2) / 10^8 per window — 4e-7 per hour at the defaults —
# and a hit still has to pass enrolment and the geofence.
#
# Keyed by ACCOUNT, never by IP: a whole lecture hall shares a handful of
# campus or carrier NAT addresses, and an IP limit tight enough to slow a
# guesser would lock out the room. One student's typos cannot block another.
#
# RESERVE BEFORE VERIFYING. A check-then-record limiter lets a script fire a
# hundred guesses at once: all of them pass the check before the first
# failure is recorded. Here every submission atomically takes an attempt
# BEFORE its code is compared, and gives it back afterwards unless the code
# was actually wrong. Concurrent guesses therefore cannot exceed the limit by
# even one.
#
# FAIL CLOSED. If Redis cannot answer, no code is verified. The QR path is
# unaffected (it does not depend on this guard), so the room keeps a way in.


class GuardUnavailable(Exception):
    """The attempt store could not be reached; refuse rather than guess."""


#: What an account is told when its remaining tries are all already in
#: flight (a script firing guesses concurrently). Short: they may yet be right.
IN_FLIGHT_RETRY_SECONDS = 2


@dataclass(frozen=True)
class Reservation:
    allowed: bool
    #: If allowed: wrong codes left before a lockout (counting this one).
    #: If refused: seconds until the account may try again.
    attempts_remaining: int = 0
    retry_after_seconds: int = 0
    scope: str = ''          # 'session' or 'account' when refused
    #: Refused because every remaining try is already being checked (a burst
    #: of simultaneous submissions), not because of a lockout.
    in_flight: bool = False


@dataclass(frozen=True)
class FailureRecord:
    attempts_remaining: int
    #: Non-zero when THIS failure triggered a lockout.
    locked_for_seconds: int = 0
    scope: str = ''


@dataclass(frozen=True)
class GuardLimits:
    max_failures_per_session: int = 5
    session_window_seconds: int = 600
    session_lockout_seconds: int = 120
    max_failures_per_account: int = 20
    account_window_seconds: int = 3600

    def __post_init__(self):
        for name in ('max_failures_per_session', 'session_window_seconds',
                     'session_lockout_seconds', 'max_failures_per_account',
                     'account_window_seconds'):
            if int(getattr(self, name)) < 1:
                raise ValueError(f'{name} must be at least 1')
        if self.max_failures_per_account < self.max_failures_per_session:
            raise ValueError('The account limit must be at least the per-session limit')


def _keys(user_id, session_id, prefix='manual_code'):
    user_id, session_id = int(user_id), int(session_id)
    return (f'{prefix}:fail:s:{user_id}:{session_id}',
            f'{prefix}:fail:a:{user_id}',
            f'{prefix}:lock:s:{user_id}:{session_id}',
            f'{prefix}:lock:a:{user_id}')


def _seconds(milliseconds):
    return max(1, -(-int(milliseconds) // 1000))


# KEYS: session_fail, account_fail, session_lock, account_lock
# ARGV: max_session, max_account, session_window_ms, account_window_ms,
#       busy_retry_ms
# Returns {allowed (0/1), value, scope}: scope 0 none, 1 session lock,
# 2 account lock, 3/4 the session/account allowance is all IN FLIGHT.
#   allowed -> value = wrong codes left including this one
#   refused -> value = milliseconds until retry
_RESERVE_LUA = """
local session_lock = redis.call('PTTL', KEYS[3])
if session_lock > 0 then return {0, session_lock, 1} end
local account_lock = redis.call('PTTL', KEYS[4])
if account_lock > 0 then return {0, account_lock, 2} end
local max_session = tonumber(ARGV[1])
local max_account = tonumber(ARGV[2])
-- Settled failures that reach a limit set a lock (see _SETTLE_LUA), so a
-- counter at its limit with no lock means the limit is taken up by attempts
-- still IN FLIGHT. Refuse this one briefly rather than let it be compared;
-- do not impose a lockout for attempts that may yet turn out to be right.
local account = tonumber(redis.call('GET', KEYS[2]) or '0')
if account >= max_account then return {0, ARGV[5], 4} end
local session = tonumber(redis.call('GET', KEYS[1]) or '0')
if session >= max_session then return {0, ARGV[5], 3} end
session = redis.call('INCR', KEYS[1])
if session == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[3]) end
account = redis.call('INCR', KEYS[2])
if account == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[4]) end
return {1, math.min(max_session - session, max_account - account) + 1, 0}
"""

# KEYS: as above.  ARGV: mode ('refund'|'fail'), max_session, max_account,
# session_lockout_ms.  Returns {locked_ms, scope, attempts_remaining}.
_SETTLE_LUA = """
if ARGV[1] == 'refund' then
  local session = redis.call('DECR', KEYS[1])
  if session <= 0 then redis.call('DEL', KEYS[1]) end
  local account = redis.call('DECR', KEYS[2])
  if account <= 0 then redis.call('DEL', KEYS[2]) end
  return {0, 0, 0}
end
local max_session = tonumber(ARGV[2])
local max_account = tonumber(ARGV[3])
local session = tonumber(redis.call('GET', KEYS[1]) or '0')
local account = tonumber(redis.call('GET', KEYS[2]) or '0')
if account >= max_account then
  local ttl = redis.call('PTTL', KEYS[2])
  if ttl < 1000 then ttl = 1000 end
  redis.call('SET', KEYS[4], '1', 'PX', ttl)
  return {ttl, 2, 0}
end
if session >= max_session then
  -- A bounded, fixed lockout for this class, after which the student gets a
  -- fresh set of tries. The account counter is NOT reset, so moving between
  -- classes (or waiting out lockouts) cannot buy unlimited guesses.
  redis.call('SET', KEYS[3], '1', 'PX', ARGV[4])
  redis.call('DEL', KEYS[1])
  return {tonumber(ARGV[4]), 1, 0}
end
return {0, 0, math.min(max_session - session, max_account - account)}
"""

_SCOPES = {0: '', 1: 'session', 2: 'account', 3: 'session', 4: 'account'}
_IN_FLIGHT = {3, 4}


class RedisAttemptGuard:
    """The distributed guard: one atomic script per reserve and per settle."""

    def __init__(self, client, limits=None, prefix='manual_code', timed=None):
        self._client = client
        self.limits = limits or GuardLimits()
        self._prefix = prefix
        self._reserve = client.register_script(_RESERVE_LUA)
        self._settle = client.register_script(_SETTLE_LUA)
        # Lets the application time each round trip without this module
        # knowing about its metrics.
        self._timed = timed or (lambda _name, function, *args, **kwargs:
                                function(*args, **kwargs))

    def _run(self, name, script, keys, args):
        import redis as _redis    # local: keeps the module importable without redis
        try:
            return self._timed(name, script, keys=keys, args=args)
        except _redis.RedisError as error:
            raise GuardUnavailable(str(error)) from error

    def reserve(self, user_id, session_id):
        limits = self.limits
        allowed, value, scope = self._run(
            'manual_guard_reserve', self._reserve, _keys(user_id, session_id, self._prefix),
            [limits.max_failures_per_session, limits.max_failures_per_account,
             limits.session_window_seconds * 1000, limits.account_window_seconds * 1000,
             IN_FLIGHT_RETRY_SECONDS * 1000])
        if int(allowed):
            return Reservation(True, attempts_remaining=int(value))
        return Reservation(False, retry_after_seconds=_seconds(value),
                           scope=_SCOPES.get(int(scope), ''),
                           in_flight=int(scope) in _IN_FLIGHT)

    def refund(self, user_id, session_id):
        """Give the reserved attempt back: the code was not a wrong guess."""
        self._run('manual_guard_settle', self._settle,
                  _keys(user_id, session_id, self._prefix),
                  ['refund', self.limits.max_failures_per_session,
                   self.limits.max_failures_per_account,
                   self.limits.session_lockout_seconds * 1000])

    def record_failure(self, user_id, session_id):
        """Keep the reserved attempt counted, locking out at the threshold."""
        locked_ms, scope, remaining = self._run(
            'manual_guard_settle', self._settle,
            _keys(user_id, session_id, self._prefix),
            ['fail', self.limits.max_failures_per_session,
             self.limits.max_failures_per_account,
             self.limits.session_lockout_seconds * 1000])
        locked_ms = int(locked_ms)
        return FailureRecord(int(remaining),
                             _seconds(locked_ms) if locked_ms > 0 else 0,
                             _SCOPES.get(int(scope), ''))


class LocalAttemptGuard:
    """
    The same rules in one process's memory.

    For development and the test suite, which run without Redis. Limits are
    per process, so this is NEVER the production guard: with several workers
    an account would get several sets of tries. The application refuses to
    use it in production and fails closed instead.
    """

    def __init__(self, limits=None, clock=time.monotonic):
        self.limits = limits or GuardLimits()
        self._clock = clock
        self._lock = threading.Lock()
        self._counters = {}      # key -> [count, expires_at]
        self._locks = {}         # key -> expires_at

    def _alive(self, table, key, now):
        entry = table.get(key)
        if entry is None:
            return None
        expires = entry[1] if isinstance(entry, list) else entry
        if expires <= now:
            table.pop(key, None)
            return None
        return entry

    def _count(self, key, now):
        entry = self._alive(self._counters, key, now)
        return entry[0] if entry else 0

    def _incr(self, key, now, window):
        entry = self._alive(self._counters, key, now)
        if entry is None:
            entry = self._counters[key] = [0, now + window]
        entry[0] += 1
        return entry[0]

    def _decr(self, key, now):
        entry = self._alive(self._counters, key, now)
        if entry is not None:
            entry[0] -= 1
            if entry[0] <= 0:
                self._counters.pop(key, None)

    def reserve(self, user_id, session_id):
        limits = self.limits
        session_fail, account_fail, session_lock, account_lock = _keys(user_id, session_id)
        with self._lock:
            now = self._clock()
            for lock_key, scope in ((session_lock, 'session'), (account_lock, 'account')):
                expires = self._alive(self._locks, lock_key, now)
                if expires is not None:
                    return Reservation(False, retry_after_seconds=_seconds((expires - now) * 1000),
                                       scope=scope)
            # At a limit with no lock: the limit is held by attempts still in
            # flight. Refuse briefly; see _RESERVE_LUA.
            if self._count(account_fail, now) >= limits.max_failures_per_account:
                return Reservation(False, retry_after_seconds=IN_FLIGHT_RETRY_SECONDS,
                                   scope='account', in_flight=True)
            if self._count(session_fail, now) >= limits.max_failures_per_session:
                return Reservation(False, retry_after_seconds=IN_FLIGHT_RETRY_SECONDS,
                                   scope='session', in_flight=True)
            session = self._incr(session_fail, now, limits.session_window_seconds)
            account = self._incr(account_fail, now, limits.account_window_seconds)
            return Reservation(True, attempts_remaining=min(
                limits.max_failures_per_session - session,
                limits.max_failures_per_account - account) + 1)

    def refund(self, user_id, session_id):
        session_fail, account_fail, _session_lock, _account_lock = _keys(user_id, session_id)
        with self._lock:
            now = self._clock()
            self._decr(session_fail, now)
            self._decr(account_fail, now)

    def record_failure(self, user_id, session_id):
        limits = self.limits
        session_fail, account_fail, session_lock, account_lock = _keys(user_id, session_id)
        with self._lock:
            now = self._clock()
            session = self._count(session_fail, now)
            account = self._count(account_fail, now)
            if account >= limits.max_failures_per_account:
                expires = self._counters[account_fail][1]
                self._locks[account_lock] = expires
                return FailureRecord(0, _seconds((expires - now) * 1000), 'account')
            if session >= limits.max_failures_per_session:
                self._locks[session_lock] = now + limits.session_lockout_seconds
                self._counters.pop(session_fail, None)
                return FailureRecord(0, limits.session_lockout_seconds, 'session')
            return FailureRecord(min(limits.max_failures_per_session - session,
                                     limits.max_failures_per_account - account))

    def reset(self):
        with self._lock:
            self._counters.clear()
            self._locks.clear()
