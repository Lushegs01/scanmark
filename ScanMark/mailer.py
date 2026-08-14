"""
Delivery over Brevo's HTTP API, for hosts that do not let SMTP out.

Render's free instances have no route to smtp.gmail.com:587 at all — the
connection fails with ENETUNREACH before a single SMTP verb is spoken, so no
amount of correct credentials helps. This talks to Brevo over HTTPS on 443
instead, which is the one port a PaaS always leaves open.

Nothing here knows about Flask: app.py adapts its Message objects at the one
place that actually sends.
"""
from email.utils import parseaddr

import requests

#: Overridable only so the tests can point at a local stand-in.
DEFAULT_BREVO_ENDPOINT = 'https://api.brevo.com/v3/smtp/email'

#: Brevo issues two credentials from one settings page and only one works
#: here. The SMTP key is for its SMTP relay; this endpoint refuses it with the
#: same 401 it gives a key that does not exist, so say which one is configured.
V3_KEY_PREFIX = 'xkeysib-'
SMTP_KEY_PREFIX = 'xsmtpsib-'


class MailSendError(Exception):
    """A send that failed, carrying the one line worth logging."""


def split_sender(sender):
    """'ScanMark <a@b.test>' -> ('ScanMark', 'a@b.test')."""
    name, address = parseaddr(sender or '')
    return (name or None), (address or None)


def describe_key_shape(api_key):
    """Say which of Brevo's two credentials BREVO_API_KEY actually holds."""
    if not api_key or api_key.startswith(V3_KEY_PREFIX):
        return ''
    if api_key.startswith(SMTP_KEY_PREFIX):
        return (f' The configured key starts "{SMTP_KEY_PREFIX}", which is the '
                f'SMTP relay key — this API needs the v3 key starting '
                f'"{V3_KEY_PREFIX}" from the API Keys tab.')
    return (f' The configured key does not start "{V3_KEY_PREFIX}", so it is '
            f'probably not a v3 API key.')


def _describe_http_failure(status, payload, sender_address, api_key=None):
    """Turn Brevo's reply into the sentence that says what to change."""
    message = ''
    if isinstance(payload, dict):
        message = str(payload.get('message') or payload.get('code') or '')

    if status in (401, 403):
        # Brevo's own words separate "this key is not real" from "this account
        # has not been activated yet", and only the first is worth re-copying
        # a key over.
        if 'activat' in message.lower():
            return (f'Brevo has not activated this account for sending '
                    f'({status}: {message}) — that is an account state, not a '
                    f'configuration problem: finish the account details in the '
                    f'dashboard, or ask Brevo support to enable transactional '
                    f'sending')
        return (f'Brevo rejected the API key ({status}: '
                f'{message or "no message"}).{describe_key_shape(api_key)} '
                f'Take a v3 key from Settings → SMTP & API → API Keys and set '
                f'it whole as BREVO_API_KEY')
    if status == 400 and 'sender' in message.lower():
        return (f'Brevo refused the sender {sender_address!r} (400: {message}) '
                f'— verify that exact address under Senders, Domains & '
                f'Dedicated IPs, and make MAIL_DEFAULT_SENDER match it')
    if status in (402, 429):
        return (f'Brevo would not accept the message ({status}: {message}) — '
                f'this is the account\'s sending limit, not a configuration '
                f'problem')
    return f'Brevo returned {status}: {message or "no message"}'


def send_via_brevo(settings, *, subject, recipients, text, html=None,
                   sender=None, endpoint=None):
    """
    Hand one message to Brevo. Raises MailSendError with a usable reason.

    Called from the background email pool, never from a request.
    """
    if not settings.brevo_api_key:
        raise MailSendError('BREVO_API_KEY is not set, so nothing can be sent')

    sender_name, sender_address = split_sender(sender or settings.sender)
    if not sender_address:
        raise MailSendError(
            'MAIL_DEFAULT_SENDER has no address in it, so Brevo has no From')

    payload = {
        'sender': {'email': sender_address},
        'to': [{'email': address} for address in recipients],
        'subject': subject,
        'textContent': text or '',
    }
    if sender_name:
        payload['sender']['name'] = sender_name
    if html:
        payload['htmlContent'] = html

    try:
        response = requests.post(
            endpoint or settings.brevo_endpoint or DEFAULT_BREVO_ENDPOINT,
            json=payload,
            headers={'api-key': settings.brevo_api_key,
                     'accept': 'application/json'},
            timeout=settings.timeout,
        )
    except requests.RequestException as exc:
        # HTTPS on 443 is the point of using this at all, so a failure here
        # is worth distinguishing from the SMTP block it replaced.
        raise MailSendError(
            f'could not reach Brevo ({type(exc).__name__}: {exc})') from exc

    if response.status_code >= 400:
        try:
            body = response.json()
        except ValueError:
            body = {'message': response.text[:200]}
        raise MailSendError(_describe_http_failure(
            response.status_code, body, sender_address,
            api_key=settings.brevo_api_key))

    return response
