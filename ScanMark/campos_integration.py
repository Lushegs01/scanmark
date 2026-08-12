"""Secure CampOS Core integration helpers for ScanMark.

The browser only receives an opaque, single-use hand-off code. ScanMark
redeems that code with CampOS Core over a server-to-server request and then
verifies the returned JWT locally before establishing a Flask session.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import random
import re
import time
from typing import Any, Mapping, NamedTuple
from urllib.parse import unquote, urlsplit

import requests


SSO_ISSUER = "campos-core"
SSO_AUDIENCE = "scanmark"
SSO_MAX_TOKEN_LIFETIME_SECONDS = 120
SSO_CLOCK_SKEW_SECONDS = 5

_SSO_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

# CampOS roles that carry institution-wide authority. A narrower post — a dean
# or an HOD — reaches ScanMark through the scope its grant is bound to, never
# through the role name alone.
CAMPOS_INSTITUTION_ADMIN_ROLES = frozenset(
    {"institution_owner", "institution_admin", "super_admin"}
)
CAMPOS_ADMIN_ROLES = CAMPOS_INSTITUTION_ADMIN_ROLES | frozenset({"faculty_admin"})
CAMPOS_SCOPE_TYPES = frozenset(
    {"INSTITUTION", "FACULTY", "DEPARTMENT", "PROGRAM", "COURSE", "SELF"}
)
CAMPOS_LAUNCH_CONTEXTS = frozenset({"student", "lecturer", "admin"})

# User.faculty and User.department are String(50).
SCOPE_NAME_MAX_LENGTH = 50


class CamposIntegrationError(ValueError):
    """A safe-to-log CampOS integration failure."""


# Names that positively declare a NON-production deployment. Anything else —
# including an unrecognised value and a completely undeclared environment —
# counts as production, because every protection keyed off this decision
# (secure cookies, HSTS, email confirmation, a real secret key, protected
# metrics) is one that hurts nobody in development and is load-bearing in
# production. Guessing wrong in the safe direction costs a developer one
# environment variable; guessing wrong in the other direction ships the
# public development secret to real students.
DEVELOPMENT_ENVIRONMENT_NAMES = frozenset(
    {"development", "dev", "local", "test", "testing", "ci", "debug"}
)

# Markers set by the platform itself. They cannot make a deployment
# non-production — only an explicit declaration does that — but they are what
# lets a misconfigured deployment be reported precisely.
PLATFORM_MARKERS = (
    "RENDER",              # Render
    "DYNO",                # Heroku
    "RAILWAY_ENVIRONMENT",  # Railway
    "FLY_APP_NAME",        # Fly.io
    "K_SERVICE",           # Google Cloud Run
    "WEBSITE_SITE_NAME",   # Azure App Service
    "AWS_EXECUTION_ENV",   # AWS (ECS/Lambda/App Runner)
    "ECS_CONTAINER_METADATA_URI",
    "KUBERNETES_SERVICE_HOST",
    "DOKKU_APP_NAME",
    "VERCEL",
)


def declared_environment(env: Mapping[str, str] | None = None) -> str:
    """The environment name this deployment declares, normalised."""
    values = os.environ if env is None else env
    return (
        values.get("SCANMARK_ENV", "").strip().lower()
        or values.get("FLASK_ENV", "").strip().lower()
    )


def detected_platform(env: Mapping[str, str] | None = None) -> str | None:
    """Name of the hosting platform marker present, if any."""
    values = os.environ if env is None else env
    for marker in PLATFORM_MARKERS:
        if (values.get(marker, "") or "").strip():
            return marker
    return None


def is_production_environment(env: Mapping[str, str] | None = None) -> bool:
    """
    True unless the deployment positively says it is not production.

    The previous rule recognised exactly ``FLASK_ENV=production`` and
    ``RENDER=true``, so the same image on any other host — or on Render with
    the variable spelled differently — quietly ran with development defaults.
    """
    return declared_environment(env) not in DEVELOPMENT_ENVIRONMENT_NAMES


def get_campos_core_url(env: Mapping[str, str] | None = None) -> str:
    """Return a validated CampOS origin used for server-to-server calls."""
    values = os.environ if env is None else env
    raw = (
        values.get("CAMPOS_CORE_URL", "").strip()
        # Backward compatibility for deployments that already configured the
        # attendance reporter under its former name.
        or values.get("CAMPOS_API_URL", "").strip()
    )
    if not raw:
        raise CamposIntegrationError("CampOS Core URL is not configured")

    parsed = urlsplit(raw)
    production = is_production_environment(values)
    is_local_http = parsed.scheme == "http" and parsed.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
    }
    if parsed.scheme != "https" and not (not production and is_local_http):
        raise CamposIntegrationError("CampOS Core URL must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password:
        raise CamposIntegrationError("CampOS Core URL is invalid")
    if parsed.query or parsed.fragment:
        raise CamposIntegrationError("CampOS Core URL must not contain a query or fragment")
    if parsed.path not in ("", "/"):
        raise CamposIntegrationError("CampOS Core URL must be an origin without a path")

    return raw.rstrip("/")


def get_sso_secret(env: Mapping[str, str] | None = None) -> str:
    """Load the dedicated shared SSO secret, failing closed in production."""
    values = os.environ if env is None else env
    secret = (
        values.get("CAMPOS_SSO_SECRET", "").strip()
        # Rollout fallback for the original ScanMark deployment variable.
        or values.get("SSO_JWT_SECRET", "").strip()
    )
    production = is_production_environment(values)

    if not secret:
        raise CamposIntegrationError("CAMPOS_SSO_SECRET is not configured")

    if production and len(secret.encode("utf-8")) < 32:
        raise CamposIntegrationError("CAMPOS_SSO_SECRET is too short")
    return secret


def exchange_campos_sso_code(
    code: str,
    *,
    env: Mapping[str, str] | None = None,
    post: Any = requests.post,
) -> str:
    """Atomically redeem a CampOS one-time code and return its signed JWT."""
    if not isinstance(code, str) or not _SSO_CODE_RE.fullmatch(code):
        raise CamposIntegrationError("invalid SSO hand-off code")

    exchange_url = f"{get_campos_core_url(env)}/api/modules/sso/exchange"
    try:
        response = post(
            exchange_url,
            json={"code": code, "module": SSO_AUDIENCE},
            headers={
                "Accept": "application/json",
                "User-Agent": "ScanMark/CampOS-SSO",
            },
            timeout=(3.05, 8),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise CamposIntegrationError("CampOS SSO exchange is unavailable") from exc

    if response.status_code != 200:
        if response.status_code == 400:
            raise CamposIntegrationError("SSO hand-off code is invalid or expired")
        raise CamposIntegrationError("CampOS SSO exchange failed")

    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise CamposIntegrationError("CampOS SSO exchange returned invalid JSON") from exc

    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or len(token) > 8192 or token.count(".") != 2:
        raise CamposIntegrationError("CampOS SSO exchange returned an invalid token")
    return token


def _decode_json_segment(segment: str, label: str) -> dict[str, Any]:
    if not segment or len(segment) > 8192:
        raise CamposIntegrationError(f"invalid JWT {label}")
    try:
        padding = "=" * (-len(segment) % 4)
        decoded = base64.b64decode(
            segment + padding,
            altchars=b"-_",
            validate=True,
        )
        value = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CamposIntegrationError(f"invalid JWT {label}") from exc
    if not isinstance(value, dict):
        raise CamposIntegrationError(f"invalid JWT {label}")
    return value


def _integer_claim(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CamposIntegrationError(f"missing or invalid {name} claim")
    integer = int(value)
    if integer != value:
        raise CamposIntegrationError(f"missing or invalid {name} claim")
    return integer


def verify_campos_sso_token(
    token: str,
    *,
    env: Mapping[str, str] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify CampOS' HS256 signature and strict one-time-token claims."""
    if not isinstance(token, str) or len(token) > 8192:
        raise CamposIntegrationError("malformed token")
    parts = token.split(".")
    if len(parts) != 3:
        raise CamposIntegrationError("malformed token")
    header_b64, payload_b64, signature_b64 = parts

    header = _decode_json_segment(header_b64, "header")
    if header.get("alg") != "HS256" or header.get("typ") not in (None, "JWT"):
        raise CamposIntegrationError("unexpected signing algorithm")

    try:
        padding = "=" * (-len(signature_b64) % 4)
        received_signature = base64.b64decode(
            signature_b64 + padding,
            altchars=b"-_",
            validate=True,
        )
    except binascii.Error as exc:
        raise CamposIntegrationError("invalid JWT signature") from exc
    if len(received_signature) != hashlib.sha256().digest_size:
        raise CamposIntegrationError("invalid JWT signature")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_signature = hmac.new(
        get_sso_secret(env).encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected_signature, received_signature):
        raise CamposIntegrationError("bad signature")

    claims = _decode_json_segment(payload_b64, "payload")
    current_time = int(time.time()) if now is None else int(now)
    issued_at = _integer_claim(claims, "iat")
    expires_at = _integer_claim(claims, "exp")

    if expires_at <= current_time - SSO_CLOCK_SKEW_SECONDS:
        raise CamposIntegrationError("token expired")
    if issued_at > current_time + SSO_CLOCK_SKEW_SECONDS:
        raise CamposIntegrationError("token issued in the future")
    if expires_at <= issued_at or expires_at - issued_at > SSO_MAX_TOKEN_LIFETIME_SECONDS:
        raise CamposIntegrationError("invalid token lifetime")
    if claims.get("iss") != SSO_ISSUER:
        raise CamposIntegrationError("bad issuer")
    if claims.get("aud") != SSO_AUDIENCE:
        raise CamposIntegrationError("bad audience")
    if (
        not isinstance(claims.get("sub"), str)
        or not claims["sub"].strip()
        or len(claims["sub"]) > 100
    ):
        raise CamposIntegrationError("missing subject")
    if (
        not isinstance(claims.get("jti"), str)
        or not claims["jti"].strip()
        or len(claims["jti"]) > 200
    ):
        raise CamposIntegrationError("missing token identifier")
    if not isinstance(claims.get("email"), str) or not claims["email"].strip():
        raise CamposIntegrationError("missing email")
    if (
        not isinstance(claims.get("institutionId"), str)
        or not claims["institutionId"].strip()
        or len(claims["institutionId"]) > 100
    ):
        raise CamposIntegrationError("missing institution")
    roles = claims.get("roles")
    if (
        not isinstance(roles, list)
        or len(roles) > 20
        or not all(
            isinstance(role, str) and 0 < len(role.strip()) <= 100
            for role in roles
        )
    ):
        raise CamposIntegrationError("invalid roles")

    validate_campos_institution(claims, env=env)

    return claims


def validate_campos_institution(
    claims: Mapping[str, Any],
    *,
    env: Mapping[str, str] | None = None,
) -> None:
    """Lock this ScanMark deployment to its configured CampOS tenant."""
    values = os.environ if env is None else env
    expected_slug = values.get("CAMPOS_INSTITUTION_SLUG", "").strip().lower()
    expected_id = values.get("CAMPOS_INSTITUTION_ID", "").strip()
    if is_production_environment(values) and not (expected_slug or expected_id):
        raise CamposIntegrationError("CampOS institution lock is not configured")

    claim_slug = str(claims.get("institutionSlug") or "").strip().lower()
    claim_id = str(claims.get("institutionId") or "").strip()
    if expected_slug and claim_slug != expected_slug:
        raise CamposIntegrationError("token belongs to another institution")
    if expected_id and claim_id != expected_id:
        raise CamposIntegrationError("token belongs to another institution")


def report_attendance_event(
    event: Mapping[str, Any],
    *,
    env: Mapping[str, str] | None = None,
    post: Any = requests.post,
    sleep: Any = time.sleep,
    attempts: int = 3,
) -> None:
    """Deliver an attendance event to CampOS with bounded transient retries."""
    values = os.environ if env is None else env
    api_key = values.get("CAMPOS_API_KEY", "").strip()
    if not api_key:
        raise CamposIntegrationError("CAMPOS_API_KEY is not configured")
    if attempts < 1 or attempts > 5:
        raise CamposIntegrationError("invalid attendance retry count")

    endpoint = f"{get_campos_core_url(values)}/api/modules/attendance"
    last_error = "CampOS attendance reporting failed"
    for attempt in range(attempts):
        try:
            response = post(
                endpoint,
                json=dict(event),
                headers={
                    "Accept": "application/json",
                    "X-API-Key": api_key,
                    "User-Agent": "ScanMark/CampOS-Attendance",
                },
                timeout=(3.05, 8),
                allow_redirects=False,
            )
        except requests.RequestException:
            response = None
            last_error = "CampOS attendance reporting is unavailable"

        if response is not None and 200 <= response.status_code < 300:
            return

        retryable = response is None or response.status_code == 429 or response.status_code >= 500
        if response is not None and not retryable:
            raise CamposIntegrationError(
                f"CampOS rejected attendance reporting with status {response.status_code}"
            )
        if attempt + 1 < attempts:
            delay = 0.5 * (2 ** attempt)
            # Production callers get full jitter so a class burst does not
            # retry CampOS in lock-step. Injected test sleepers stay exact.
            if sleep is time.sleep:
                delay *= random.uniform(0.75, 1.25)
            sleep(delay)

    raise CamposIntegrationError(last_error)


class CamposLaunchIdentity(NamedTuple):
    """The ScanMark placement a signed CampOS launch resolves to."""

    role: str
    faculty: str | None
    department: str | None
    #: True when CampOS signed an explicit identity rather than a bare role list.
    scoped: bool


def _normalized_launch_context(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CamposIntegrationError("CampOS launch context is invalid")
    context = value.strip().lower()
    if context not in CAMPOS_LAUNCH_CONTEXTS:
        raise CamposIntegrationError("CampOS launch context is invalid")
    return context


def _parse_launch_scope(value: Any) -> tuple[str, str | None]:
    """Validate the signed scope and return its type and display name."""
    if not isinstance(value, Mapping):
        raise CamposIntegrationError("CampOS launch scope is invalid")

    scope_type = value.get("scopeType")
    if not isinstance(scope_type, str):
        raise CamposIntegrationError("CampOS launch scope is invalid")
    scope_type = scope_type.strip().upper()
    if scope_type not in CAMPOS_SCOPE_TYPES:
        raise CamposIntegrationError("CampOS launch scope is invalid")

    scope_id = value.get("scopeId")
    if (
        not isinstance(scope_id, str)
        or not scope_id.strip()
        or len(scope_id) > 200
    ):
        raise CamposIntegrationError("CampOS launch scope is invalid")

    display_name = value.get("displayName")
    if display_name is not None and (
        not isinstance(display_name, str) or len(display_name) > 200
    ):
        raise CamposIntegrationError("CampOS launch scope is invalid")

    name = (display_name or "").strip()[:SCOPE_NAME_MAX_LENGTH] or None
    return scope_type, name


def map_campos_launch_identity(claims: Any) -> CamposLaunchIdentity:
    """Resolve which ScanMark surface a signed CampOS launch opens.

    CampOS asks the user which of their identities they are opening ScanMark
    with, then signs that single choice as `launchRole` and `launchScope`. The
    scope is what separates a dean from an HOD from the DAP — three people whose
    CampOS role names may be identical and who differ only in what slice of the
    institution their grant covers.

    Reading the flat `roles` list instead would land the most privileged surface
    every time, which is exactly the behaviour the picker exists to remove. A
    token minted by a CampOS that predates the picker carries neither claim and
    falls back to the previous mapping.
    """
    if not isinstance(claims, Mapping):
        raise CamposIntegrationError("CampOS role is not allowed by ScanMark")

    launch_role = claims.get("launchRole")
    launch_scope = claims.get("launchScope")
    context = _normalized_launch_context(claims.get("launchContext"))

    if launch_role is None and launch_scope is None:
        return CamposLaunchIdentity(
            role=map_campos_role(claims.get("roles"), context),
            faculty=None,
            department=None,
            scoped=False,
        )

    if not isinstance(launch_role, str) or not launch_role.strip():
        raise CamposIntegrationError("CampOS role is not allowed by ScanMark")
    role = launch_role.strip().lower()
    scope_type, scope_name = _parse_launch_scope(launch_scope)

    def require_context(expected: str) -> None:
        if context is not None and context != expected:
            raise CamposIntegrationError("CampOS launch context is invalid")

    if role in CAMPOS_ADMIN_ROLES:
        require_context("admin")

        if scope_type == "INSTITUTION":
            # A faculty-level post granted institution-wide is contradictory
            # data, not a promotion to the institution-wide surface.
            if role not in CAMPOS_INSTITUTION_ADMIN_ROLES:
                raise CamposIntegrationError("CampOS role is not allowed by ScanMark")
            return CamposLaunchIdentity("dap", None, None, True)

        # A dean's and an HOD's dashboards are filtered by the name of what they
        # preside over, so a scope CampOS could not name reaches no records.
        if scope_type == "FACULTY":
            if not scope_name:
                raise CamposIntegrationError("CampOS launch scope is unnamed")
            return CamposLaunchIdentity("dean", scope_name, None, True)

        if scope_type == "DEPARTMENT":
            if not scope_name:
                raise CamposIntegrationError("CampOS launch scope is unnamed")
            return CamposLaunchIdentity("hod", None, scope_name, True)

        # ScanMark has no administrative surface below a department.
        raise CamposIntegrationError("CampOS role is not allowed by ScanMark")

    if role == "lecturer":
        require_context("lecturer")
        return CamposLaunchIdentity(
            "lecturer",
            scope_name if scope_type == "FACULTY" else None,
            scope_name if scope_type == "DEPARTMENT" else None,
            True,
        )

    if role == "student":
        require_context("student")
        return CamposLaunchIdentity("student", None, None, True)

    raise CamposIntegrationError("CampOS role is not allowed by ScanMark")


def map_campos_role(roles: Any, launch_context: Any = None) -> str:
    """Map a signed CampOS workspace launch to the least privileged local role.

    ScanMark's existing institution-wide administrative surface is the DAP
    dashboard. Faculty/department roles are deliberately not guessed here:
    those require a signed resource scope before they may become dean or HOD.
    """
    if (
        not isinstance(roles, (list, tuple))
        or not all(isinstance(role, str) for role in roles)
    ):
        raise CamposIntegrationError("CampOS role is not allowed by ScanMark")
    normalized = {
        role.lower().strip()
        for role in roles
        if role.strip()
    }
    context = (
        launch_context.lower().strip()
        if isinstance(launch_context, str)
        else None
    )
    if context not in {None, "student", "lecturer", "admin"}:
        raise CamposIntegrationError("CampOS launch context is invalid")

    institution_admin_roles = {
        "institution_owner",
        "institution_admin",
        "super_admin",
    }
    if context == "admin":
        if normalized.intersection(institution_admin_roles):
            return "dap"
        raise CamposIntegrationError("CampOS role is not allowed by ScanMark")
    if context == "lecturer":
        if "lecturer" in normalized:
            return "lecturer"
        raise CamposIntegrationError("CampOS role is not allowed by ScanMark")
    if context == "student":
        if "student" in normalized:
            return "student"
        raise CamposIntegrationError("CampOS role is not allowed by ScanMark")

    # Receiver-first deployment compatibility for tokens issued by the
    # preceding Core version, which did not yet sign a launch context.
    if normalized.intersection(institution_admin_roles):
        return "dap"
    if "lecturer" in normalized:
        return "lecturer"
    if "student" in normalized:
        return "student"
    raise CamposIntegrationError("CampOS role is not allowed by ScanMark")


def validate_account_binding(
    *,
    existing_campos_user_id: str | None,
    existing_institution_id: str | None,
    existing_role: str | None,
    incoming_campos_user_id: str,
    incoming_institution_id: str,
) -> None:
    """Prevent email-based SSO from inheriting another tenant or local admin."""
    if existing_campos_user_id and existing_campos_user_id != incoming_campos_user_id:
        raise CamposIntegrationError("local account is linked to another CampOS identity")
    if existing_institution_id and existing_institution_id != incoming_institution_id:
        raise CamposIntegrationError("local account is linked to another institution")

    role = (existing_role or "").strip().lower()
    if not existing_campos_user_id and role not in {"student", "lecturer"}:
        raise CamposIntegrationError(
            "privileged local account requires explicit CampOS identity linking"
        )


def protect_sso_response(response: Any) -> Any:
    """Prevent a callback response or its one-time code from being retained."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def rotate_flask_session(session_interface: Any, session_state: Any) -> None:
    """Rotate a Flask-Session SID before clearing pre-authentication state."""
    regenerate = getattr(session_interface, "regenerate", None)
    if callable(regenerate):
        # Flask-Session intentionally skips regeneration for an empty session,
        # so add a disposable marker to guarantee an anonymous empty session
        # also receives a fresh SID. It is removed immediately below.
        if not session_state:
            session_state["_campos_sso_rotation"] = True
        regenerate(session_state)
    session_state.clear()


def sanitize_next_path(value: str | None) -> str | None:
    """Accept a same-origin absolute path and reject redirect ambiguity."""
    if not value:
        return None

    candidates = [value]
    try:
        for _ in range(2):
            decoded = unquote(candidates[-1], errors="strict")
            candidates.append(decoded)
    except (UnicodeDecodeError, ValueError):
        return None

    for candidate in candidates:
        if not candidate.startswith("/") or candidate.startswith("//"):
            return None
        if "\\" in candidate or any(ord(character) < 32 for character in candidate):
            return None
        parsed = urlsplit(candidate)
        if parsed.scheme or parsed.netloc:
            return None
    return value
