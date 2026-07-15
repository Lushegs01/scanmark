import base64
import hashlib
import hmac
import json

import pytest
import requests

from campos_integration import (
    CamposIntegrationError,
    exchange_campos_sso_code,
    get_campos_core_url,
    get_sso_secret,
    map_campos_role,
    protect_sso_response,
    report_attendance_event,
    rotate_flask_session,
    sanitize_next_path,
    validate_account_binding,
    verify_campos_sso_token,
)


SECRET = "a-dedicated-campos-sso-secret-with-more-than-32-bytes"
PRODUCTION_ENV = {
    "FLASK_ENV": "production",
    "CAMPOS_CORE_URL": "https://campos.example",
    "CAMPOS_SSO_SECRET": SECRET,
    "CAMPOS_INSTITUTION_SLUG": "demo-university",
}


def _encode(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(**overrides):
    claims = {
        "sub": "user-1",
        "jti": "handoff-1",
        "iss": "campos-core",
        "aud": "scanmark",
        "iat": 1_000,
        "exp": 1_060,
        "email": "student@example.edu",
        "institutionId": "institution-1",
        "institutionSlug": "demo-university",
        "roles": ["student"],
        **overrides,
    }
    header = _encode({"alg": "HS256", "typ": "JWT"})
    payload = _encode(claims)
    signature = hmac.new(
        SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{header}.{payload}.{encoded_signature}"


class _Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def test_exchange_redeems_module_bound_code_server_to_server():
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return _Response(payload={"token": _token()})

    code = "a" * 43
    token = exchange_campos_sso_code(code, env=PRODUCTION_ENV, post=post)

    assert token == _token()
    assert calls[0][0] == "https://campos.example/api/modules/sso/exchange"
    assert calls[0][1]["json"] == {"code": code, "module": "scanmark"}
    assert calls[0][1]["allow_redirects"] is False


@pytest.mark.parametrize("code", ["", "short", "a" * 42, "!" * 43])
def test_exchange_rejects_malformed_codes_without_network_call(code):
    def unexpected_post(*_args, **_kwargs):
        raise AssertionError("network must not be called")

    with pytest.raises(CamposIntegrationError, match="invalid SSO hand-off code"):
        exchange_campos_sso_code(code, env=PRODUCTION_ENV, post=unexpected_post)


def test_exchange_maps_network_and_expired_code_failures_to_safe_errors():
    def network_failure(*_args, **_kwargs):
        raise requests.Timeout("sensitive network detail")

    with pytest.raises(CamposIntegrationError, match="exchange is unavailable"):
        exchange_campos_sso_code("a" * 43, env=PRODUCTION_ENV, post=network_failure)

    with pytest.raises(CamposIntegrationError, match="invalid or expired"):
        exchange_campos_sso_code(
            "a" * 43,
            env=PRODUCTION_ENV,
            post=lambda *_args, **_kwargs: _Response(status_code=400, payload={}),
        )


def test_verifier_accepts_only_the_expected_short_lived_token():
    claims = verify_campos_sso_token(_token(), env=PRODUCTION_ENV, now=1_001)
    assert claims["sub"] == "user-1"
    assert claims["aud"] == "scanmark"


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"aud": "nada"}, "bad audience"),
        ({"iss": "other"}, "bad issuer"),
        ({"iat": 900, "exp": 960}, "token expired"),
        ({"exp": 1_500}, "invalid token lifetime"),
        ({"iat": 1_010}, "issued in the future"),
        ({"jti": ""}, "missing token identifier"),
        ({"institutionId": None}, "missing institution"),
    ],
)
def test_verifier_rejects_wrong_or_unsafe_claims(overrides, error):
    with pytest.raises(CamposIntegrationError, match=error):
        verify_campos_sso_token(_token(**overrides), env=PRODUCTION_ENV, now=1_001)


def test_verifier_rejects_tampering():
    token = _token(email="first@example.edu")
    header, _payload, signature = token.split(".")
    tampered_payload = _encode({
        "sub": "user-1",
        "jti": "handoff-1",
        "iss": "campos-core",
        "aud": "scanmark",
        "iat": 1_000,
        "exp": 1_060,
        "email": "attacker@example.edu",
        "institutionId": "institution-1",
        "institutionSlug": "demo-university",
        "roles": ["student"],
    })
    with pytest.raises(CamposIntegrationError, match="bad signature"):
        verify_campos_sso_token(
            f"{header}.{tampered_payload}.{signature}",
            env=PRODUCTION_ENV,
            now=1_001,
        )


def test_production_configuration_fails_closed():
    with pytest.raises(CamposIntegrationError, match="not configured"):
        get_sso_secret({"FLASK_ENV": "production"})
    with pytest.raises(CamposIntegrationError, match="must use HTTPS"):
        get_campos_core_url({
            "FLASK_ENV": "production",
            "CAMPOS_CORE_URL": "http://campos.example",
        })
    with pytest.raises(CamposIntegrationError, match="without a path"):
        get_campos_core_url({
            "FLASK_ENV": "production",
            "CAMPOS_CORE_URL": "https://campos.example/prefix",
        })


def test_development_sso_also_requires_an_explicit_shared_secret():
    with pytest.raises(CamposIntegrationError, match="not configured"):
        get_sso_secret({"FLASK_ENV": "development"})


def test_verifier_rejects_another_institution_and_requires_a_production_lock():
    with pytest.raises(CamposIntegrationError, match="another institution"):
        verify_campos_sso_token(
            _token(institutionSlug="other-university"),
            env=PRODUCTION_ENV,
            now=1_001,
        )
    unlocked_env = {
        key: value
        for key, value in PRODUCTION_ENV.items()
        if key != "CAMPOS_INSTITUTION_SLUG"
    }
    with pytest.raises(CamposIntegrationError, match="lock is not configured"):
        verify_campos_sso_token(_token(), env=unlocked_env, now=1_001)


def test_attendance_reporting_uses_the_module_key_and_retries_transient_errors():
    calls = []
    delays = []
    responses = [_Response(status_code=503), _Response(status_code=200)]

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return responses.pop(0)

    event = {
        "email": "student@example.edu",
        "courseCode": "CSC401",
        "externalId": "scanmark-attendance:42",
    }
    report_attendance_event(
        event,
        env={**PRODUCTION_ENV, "CAMPOS_API_KEY": "campos_api_private"},
        post=post,
        sleep=delays.append,
    )

    assert len(calls) == 2
    assert calls[0][0] == "https://campos.example/api/modules/attendance"
    assert calls[0][1]["json"] == event
    assert calls[0][1]["headers"]["X-API-Key"] == "campos_api_private"
    assert calls[0][1]["allow_redirects"] is False
    assert delays == [0.5]


def test_attendance_reporting_does_not_retry_permanent_rejection():
    with pytest.raises(CamposIntegrationError, match="status 403"):
        report_attendance_event(
            {"courseCode": "CSC401"},
            env={**PRODUCTION_ENV, "CAMPOS_API_KEY": "campos_api_private"},
            post=lambda *_args, **_kwargs: _Response(status_code=403),
            sleep=lambda _delay: None,
        )


def test_role_mapping_requires_an_explicit_supported_role_and_lecturer_wins():
    assert map_campos_role(["student"]) == "student"
    assert map_campos_role(["student", "lecturer"]) == "lecturer"
    assert map_campos_role([" Lecturer "]) == "lecturer"


@pytest.mark.parametrize(
    "roles",
    [
        None,
        "student",
        [],
        ["institution_admin"],
        ["faculty_admin"],
        ["course coordinator"],
        ["student", 42],
    ],
)
def test_role_mapping_rejects_unsupported_or_missing_roles(roles):
    with pytest.raises(CamposIntegrationError, match="role is not allowed"):
        map_campos_role(roles)


def test_sso_response_is_always_non_cacheable_and_sends_no_referrer():
    class Response:
        headers = {"Cache-Control": "public, max-age=300"}

    response = Response()
    assert protect_sso_response(response) is response
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.parametrize(
    "value",
    [
        "//evil.example",
        "/\\evil.example",
        "https://evil.example",
        "/%5C%5Cevil.example",
        "/%2F%2Fevil.example",
        "/%252F%252Fevil.example",
    ],
)
def test_next_path_rejects_cross_origin_or_ambiguous_redirects(value):
    assert sanitize_next_path(value) is None


def test_next_path_accepts_same_origin_paths():
    assert sanitize_next_path("/student/dashboard?tab=attendance") == "/student/dashboard?tab=attendance"


def test_unlinked_privileged_local_account_cannot_be_inherited_by_email():
    with pytest.raises(CamposIntegrationError, match="requires explicit"):
        validate_account_binding(
            existing_campos_user_id=None,
            existing_institution_id=None,
            existing_role="dean",
            incoming_campos_user_id="campos-student-1",
            incoming_institution_id="institution-1",
        )


def test_account_binding_rejects_cross_identity_and_cross_tenant_reuse():
    with pytest.raises(CamposIntegrationError, match="another CampOS identity"):
        validate_account_binding(
            existing_campos_user_id="campos-user-1",
            existing_institution_id="institution-1",
            existing_role="student",
            incoming_campos_user_id="campos-user-2",
            incoming_institution_id="institution-1",
        )
    with pytest.raises(CamposIntegrationError, match="another institution"):
        validate_account_binding(
            existing_campos_user_id="campos-user-1",
            existing_institution_id="institution-1",
            existing_role="student",
            incoming_campos_user_id="campos-user-1",
            incoming_institution_id="institution-2",
        )


def test_explicitly_linked_privileged_account_is_allowed_for_same_identity_and_tenant():
    validate_account_binding(
        existing_campos_user_id="campos-admin-1",
        existing_institution_id="institution-1",
        existing_role="dean",
        incoming_campos_user_id="campos-admin-1",
        incoming_institution_id="institution-1",
    )


def test_server_side_session_rotates_before_pre_auth_state_is_cleared():
    state = {"csrf_token": "old"}
    events = []

    class Interface:
        @staticmethod
        def regenerate(session_state):
            events.append(("regenerate", dict(session_state)))

    rotate_flask_session(Interface(), state)

    assert events == [("regenerate", {"csrf_token": "old"})]
    assert state == {}


def test_empty_server_side_session_is_still_forced_to_rotate():
    state = {}
    events = []

    class Interface:
        @staticmethod
        def regenerate(session_state):
            events.append(("regenerate", dict(session_state)))

    rotate_flask_session(Interface(), state)

    assert events == [("regenerate", {"_campos_sso_rotation": True})]
    assert state == {}
