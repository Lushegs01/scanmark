"""Local-time helpers for a database whose datetime columns are naive UTC.

Every timestamp ScanMark stores is UTC with the tzinfo stripped (see
``models.utcnow_naive``). Rendering those numbers straight to a page shows a
Nigerian lecturer a UTC clock: a 08:30 lecture reads as 07:30, and anything
recorded between 23:00 and midnight local time is filed under *yesterday*.

Everything the user sees goes through here, and every "which day is it"
decision uses :func:`local_today` rather than ``datetime.utcnow().date()``.
"""

import os
from datetime import datetime, time as _time, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None


DEFAULT_TIMEZONE_NAME = 'Africa/Lagos'

# West Africa Time is a fixed +01:00 with no daylight saving, so a deployment
# whose base image ships without the IANA database still gets correct FUNAAB
# time rather than silently falling back to UTC.
FALLBACK_TIMEZONE = timezone(timedelta(hours=1), 'WAT')


def _resolve_timezone(name):
    if ZoneInfo is not None:
        try:
            return ZoneInfo(name)
        except Exception:
            pass
    return FALLBACK_TIMEZONE


LOCAL_TIMEZONE_NAME = (
    os.environ.get('SCANMARK_TIMEZONE', '').strip() or DEFAULT_TIMEZONE_NAME
)
LOCAL_TIMEZONE = _resolve_timezone(LOCAL_TIMEZONE_NAME)


def utcnow_naive():
    """Now, as the naive-UTC value the database columns hold."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_utc(value):
    """Read a stored value as an aware UTC datetime."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_local(value):
    """Convert a stored naive-UTC datetime to an aware local datetime."""
    utc_value = as_utc(value)
    return None if utc_value is None else utc_value.astimezone(LOCAL_TIMEZONE)


def local_now():
    return datetime.now(LOCAL_TIMEZONE)


def local_today():
    """Today's date *where the university is*, not where the server is."""
    return local_now().date()


def local_date(value):
    """The local calendar date a stored naive-UTC timestamp falls on."""
    local_value = to_local(value)
    return None if local_value is None else local_value.date()


def local_day_bounds_utc(day=None):
    """
    Naive-UTC half-open bounds ``[start, end)`` of one local calendar day.

    A local day is not a UTC day, so "sessions held today" has to be asked as
    a range in the units the column actually stores.
    """
    day = day or local_today()
    start_local = datetime.combine(day, _time.min, tzinfo=LOCAL_TIMEZONE)
    end_local = datetime.combine(day + timedelta(days=1), _time.min,
                                 tzinfo=LOCAL_TIMEZONE)
    return (start_local.astimezone(timezone.utc).replace(tzinfo=None),
            end_local.astimezone(timezone.utc).replace(tzinfo=None))


def format_local(value, fmt='%d %b %Y, %I:%M %p'):
    """Format a stored naive-UTC datetime in local time, or '' when absent."""
    local_value = to_local(value)
    return '' if local_value is None else local_value.strftime(fmt)


def local_time_only(value):
    return format_local(value, '%I:%M %p')


def local_date_only(value):
    return format_local(value, '%d %b %Y')


def iso_utc(value):
    """The stored value as an explicit UTC ISO-8601 string."""
    utc_value = as_utc(value)
    return None if utc_value is None else utc_value.isoformat().replace('+00:00', 'Z')


__all__ = [
    'DEFAULT_TIMEZONE_NAME', 'FALLBACK_TIMEZONE', 'LOCAL_TIMEZONE',
    'LOCAL_TIMEZONE_NAME', 'as_utc', 'format_local', 'iso_utc', 'local_date',
    'local_date_only', 'local_day_bounds_utc', 'local_now', 'local_time_only',
    'local_today', 'to_local', 'utcnow_naive',
]
