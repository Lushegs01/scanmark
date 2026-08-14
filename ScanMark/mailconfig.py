"""
The one place the mail environment is read.

Both the app and ``mail_selftest.py`` resolve their settings here, so a
self-test cannot pass against a different configuration than the one the
running server uses — which is the only way a self-test is worth anything.
"""
import os
from dataclasses import dataclass

DEFAULT_SERVER = 'smtp.gmail.com'
DEFAULT_PORT = 587
DEFAULT_TIMEOUT = 15.0

#: Implicit TLS: encrypted from the first byte, and the server never speaks
#: plain SMTP on it, so STARTTLS on this port is a conversation with nobody.
IMPLICIT_SSL_PORT = 465

FALSEY = ('false', '0', 'no', 'off')


def _flag(environ, name):
    """None when unset, so 'not configured' stays distinct from 'off'."""
    raw = environ.get(name)
    if raw is None or not raw.strip():
        return None
    return raw.strip().lower() not in FALSEY


SMTP = 'smtp'
BREVO = 'brevo'


@dataclass(frozen=True)
class MailSettings:
    server: str
    port: int
    use_ssl: bool
    use_tls: bool
    username: str | None
    password: str | None
    sender: str | None
    timeout: float
    #: 'smtp' or 'brevo' — how the message actually leaves the process.
    provider: str = SMTP
    brevo_api_key: str | None = None
    brevo_endpoint: str | None = None
    #: True when MAIL_PASSWORD arrived with the spaces Gmail displays.
    password_had_spaces: bool = False

    @property
    def security(self):
        return 'SSL' if self.use_ssl else 'STARTTLS' if self.use_tls else 'none'

    @property
    def uses_smtp(self):
        return self.provider == SMTP

    @property
    def is_configured(self):
        """Whether this provider has what it needs to send anything."""
        if self.provider == BREVO:
            return bool(self.brevo_api_key and self.sender)
        return bool(self.server and self.username and self.password)

    @property
    def summary(self):
        """Safe to log: says whether the secrets exist, never what they are."""
        if self.provider == BREVO:
            return {
                'provider': BREVO,
                'endpoint': self.brevo_endpoint or '(default)',
                'api_key_set': bool(self.brevo_api_key),
                'sender': self.sender or '(unset)',
                'timeout': self.timeout,
            }
        return {
            'provider': SMTP,
            'server': self.server,
            'port': self.port,
            'security': self.security,
            'username_set': bool(self.username),
            'password_set': bool(self.password),
            'sender': self.sender or '(unset)',
            'timeout': self.timeout,
        }


def resolve_mail_settings(environ=None):
    """Read MAIL_* from the environment and settle the ambiguous parts."""
    environ = os.environ if environ is None else environ

    port = int(environ.get('MAIL_PORT') or DEFAULT_PORT)

    # MAIL_USE_TLS used to be pinned True with no MAIL_USE_SSL at all, so
    # MAIL_PORT=465 opened a plaintext socket and then asked for STARTTLS.
    # Nothing raised — the send just sat there. Derive both from the port,
    # and let either be overridden outright.
    ssl_flag, tls_flag = _flag(environ, 'MAIL_USE_SSL'), _flag(environ, 'MAIL_USE_TLS')
    use_ssl = (port == IMPLICIT_SSL_PORT) if ssl_flag is None else ssl_flag
    use_tls = (not use_ssl) if tls_flag is None else tls_flag

    username = environ.get('MAIL_USERNAME') or None
    # Gmail shows an app password as four groups of four ("abcd efgh ijkl
    # mnop"). Pasted verbatim it authenticates as a 19-character password and
    # is refused, which reads as "wrong password" rather than "lose the
    # spaces".
    raw_password = environ.get('MAIL_PASSWORD') or ''
    password = raw_password.replace(' ', '') or None

    # Which way the mail leaves. Named explicitly by MAIL_PROVIDER, otherwise
    # inferred: a host that blocks outbound SMTP is why the key is there at
    # all, so a configured key means it is meant to be used.
    brevo_api_key = (environ.get('BREVO_API_KEY') or '').strip() or None
    provider = (environ.get('MAIL_PROVIDER') or '').strip().lower()
    if not provider:
        provider = BREVO if brevo_api_key else SMTP

    return MailSettings(
        server=environ.get('MAIL_SERVER') or DEFAULT_SERVER,
        port=port,
        use_ssl=use_ssl,
        use_tls=use_tls,
        username=username,
        password=password,
        sender=environ.get('MAIL_DEFAULT_SENDER') or username,
        timeout=float(environ.get('MAIL_TIMEOUT') or DEFAULT_TIMEOUT),
        provider=provider,
        brevo_api_key=brevo_api_key,
        brevo_endpoint=(environ.get('BREVO_API_URL') or '').strip() or None,
        password_had_spaces=' ' in raw_password.strip(),
    )
