"""The academic calendar ScanMark files courses and attendance under.

A course code is not an identity. CSC201 runs again next year, and again the
year after, taught by somebody else to a different set of students. Without a
term attached, the second offering either collides with the first ("course code
is already taken") or inherits its class sessions and drags last year's
attendance into this year's percentages.

Everything here is derived from *local* dates (see ``localtime``), so a term
never flips over at 01:00 local time just because UTC has moved on.
"""

import os

from localtime import local_today


def _month_setting(name, default):
    try:
        month = int(os.environ.get(name, '').strip() or default)
    except ValueError:
        return default
    return month if 1 <= month <= 12 else default


#: Month the academic year rolls over in (FUNAAB starts around September).
ACADEMIC_YEAR_START_MONTH = _month_setting('ACADEMIC_YEAR_START_MONTH', 9)
#: Month the second semester begins in.
SECOND_SEMESTER_START_MONTH = _month_setting('SECOND_SEMESTER_START_MONTH', 2)

FIRST_SEMESTER = 'First'
SECOND_SEMESTER = 'Second'
SEMESTERS = (FIRST_SEMESTER, SECOND_SEMESTER)

#: Longest an academic-year label may be ("2025/2026").
ACADEMIC_YEAR_LENGTH = 9


def current_academic_year(day=None):
    """The academic year a local date falls in, as ``"2025/2026"``."""
    day = day or local_today()
    start_year = day.year if day.month >= ACADEMIC_YEAR_START_MONTH else day.year - 1
    return f"{start_year}/{start_year + 1}"


def current_semester(day=None):
    """Which semester a local date falls in."""
    day = day or local_today()
    if SECOND_SEMESTER_START_MONTH <= day.month < ACADEMIC_YEAR_START_MONTH:
        return SECOND_SEMESTER
    return FIRST_SEMESTER


def normalize_academic_year(value):
    """Return a well-formed ``YYYY/YYYY`` label, or None when unusable."""
    text = (value or '').strip()
    if not text:
        return None
    parts = text.replace('-', '/').split('/')
    if len(parts) != 2 or not all(part.strip().isdigit() for part in parts):
        return None
    first, second = (int(part) for part in parts)
    if second == first % 100 + 1:          # "2025/26" shorthand
        second = first + 1
    if second != first + 1 or not (2000 <= first <= 2999):
        return None
    return f"{first}/{second}"


def normalize_semester(value):
    """Map the spellings a form may submit onto a canonical semester name."""
    text = (value or '').strip().lower().rstrip('.')
    if text in ('1', '1st', 'first', 'one', 'harmattan'):
        return FIRST_SEMESTER
    if text in ('2', '2nd', 'second', 'two', 'rain', 'rainy'):
        return SECOND_SEMESTER
    return None


def academic_term_of(day=None):
    """``(academic_year, semester)`` for a local date."""
    day = day or local_today()
    return current_academic_year(day), current_semester(day)


def describe_term(academic_year, semester, section=''):
    """A human label such as ``2025/2026 First Semester (Section B)``."""
    label = f"{academic_year} {semester} Semester"
    section = (section or '').strip()
    return f"{label} (Section {section})" if section else label


__all__ = [
    'ACADEMIC_YEAR_LENGTH', 'ACADEMIC_YEAR_START_MONTH', 'FIRST_SEMESTER',
    'SECOND_SEMESTER', 'SECOND_SEMESTER_START_MONTH', 'SEMESTERS',
    'academic_term_of', 'current_academic_year', 'current_semester',
    'describe_term', 'normalize_academic_year', 'normalize_semester',
]
