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
import re
import time
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

import requests


SSO_ISSUER = "campos-core"
SSO_AUDIENCE = "scanmark"
SSO_MAX_TOKEN_LIFETIME_SECONDS = 120
SSO_CLOCK_SKEW_SECONDS = 5

_SSO_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class CamposIntegrationError(ValueError):
    """A safe-to-log CampOS integration failure."""


def is_production_environment(env: Mapping[str, str] | None = None) -> bool:
    values = os.environ if env is None else env
    return (
        values.get("FLASK_ENV", "").strip().lower() == "production"
        or values.get("RENDER", "").strip().lower() == "true"
    )


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
            sleep(0.5 * (2 ** attempt))

    raise CamposIntegrationError(last_error)


def map_campos_role(roles: Any) -> str:
    """Map an explicitly supported CampOS role, rejecting every other role."""
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
