#!/usr/bin/env python3
"""
Prove — or disprove — that ScanMark's mail settings can actually send.

    python mail_selftest.py                 # connect, negotiate TLS, log in
    python mail_selftest.py you@example.com # ...and send one real message

It reads the same MAIL_* variables the app reads, through the same
mailconfig.resolve_mail_settings(), so a pass here means the running server
has what it needs. It never prints the password.

Exit status is 0 when mail can be sent, 1 when it cannot.
"""
import smtplib
import ssl
import sys
from email.message import EmailMessage

from dotenv import load_dotenv

from mailconfig import resolve_mail_settings

load_dotenv()


def line(label, value):
    print(f"  {label:<22} {value}")


def fail(headline, *advice):
    print(f"\n✗ {headline}")
    for item in advice:
        print(f"  → {item}")
    return 1


def main(argv):
    recipient = argv[1] if len(argv) > 1 else None
    settings = resolve_mail_settings()

    print("ScanMark mail self-test\n")
    print("Configuration (as the app resolves it):")
    for label, value in settings.summary.items():
        line(label, value)
    if settings.password_had_spaces:
        line('note', 'MAIL_PASSWORD had spaces; they were stripped')
    if settings.password:
        line('password length', f'{len(settings.password)} characters')
    print()

    if not settings.username or not settings.password:
        return fail(
            "MAIL_USERNAME and MAIL_PASSWORD are not both set.",
            "Without them the server starts fine and silently sends nothing.")

    if settings.password and len(settings.password) != 16 \
            and 'gmail' in settings.server:
        print("! A Gmail App Password is exactly 16 characters. This one is "
              f"{len(settings.password)} — if login fails below, that is why.\n")

    # 1. Connect.
    print(f"1. Connecting to {settings.server}:{settings.port} "
          f"({settings.security}, {settings.timeout}s timeout)...")
    try:
        if settings.use_ssl:
            smtp = smtplib.SMTP_SSL(settings.server, settings.port,
                                    timeout=settings.timeout)
        else:
            smtp = smtplib.SMTP(settings.server, settings.port,
                                timeout=settings.timeout)
    except (TimeoutError, OSError) as exc:
        return fail(
            f"Could not reach the mail server ({type(exc).__name__}: {exc}).",
            "If this times out rather than being refused, something between "
            "this process and the server is dropping outbound SMTP — some "
            "hosting plans block it. Try the provider's alternative port "
            "(465 with MAIL_PORT=465, or 2525 where offered), or send "
            "through an HTTP email API instead of SMTP.",
            "If you are running this from your laptop and it works here but "
            "not on the server, the network is the difference, not the "
            "credentials.")
    print("   connected.")

    with smtp:
        # 2. Negotiate TLS.
        try:
            smtp.ehlo()
            if settings.use_tls:
                print("2. STARTTLS...")
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                print("   encrypted.")
            elif settings.use_ssl:
                print("2. Session already encrypted (implicit SSL).")
            else:
                print("2. No encryption — MAIL_USE_TLS is off. The password "
                      "crosses the network in the clear.")
        except smtplib.SMTPException as exc:
            return fail(
                f"TLS negotiation failed ({type(exc).__name__}: {exc}).",
                "Port 465 wants MAIL_PORT=465 (implicit SSL); port 587 wants "
                "STARTTLS. Mixing them hangs or errors exactly here.")

        # 3. Log in — the step that catches a wrong or non-app password.
        print(f"3. Logging in as {settings.username}...")
        try:
            smtp.login(settings.username, settings.password)
        except smtplib.SMTPAuthenticationError as exc:
            return fail(
                f"The server refused the credentials ({exc.smtp_code} "
                f"{exc.smtp_error!r}).",
                "Gmail: turn on 2-Step Verification, create an App Password, "
                "and use those 16 characters as MAIL_PASSWORD. The account "
                "password itself has not worked since 2022.",
                "Check MAIL_USERNAME is the full address, not the local part.")
        except smtplib.SMTPException as exc:
            return fail(f"Login failed ({type(exc).__name__}: {exc}).")
        print("   authenticated.")

        if not recipient:
            print("\n✓ ScanMark can send mail with these settings.")
            print("  Pass an address to send a real test message:")
            print("      python mail_selftest.py you@example.com")
            return 0

        # 4. Send one real message.
        print(f"4. Sending a test message to {recipient}...")
        message = EmailMessage()
        message['Subject'] = 'ScanMark mail self-test'
        message['From'] = settings.sender
        message['To'] = recipient
        message.set_content(
            'If you are reading this, ScanMark can send mail: confirmation '
            'links and password resets will arrive the same way.')
        try:
            smtp.send_message(message)
        except smtplib.SMTPSenderRefused as exc:
            return fail(
                f"The sender address was refused ({exc.smtp_code} "
                f"{exc.smtp_error!r}).",
                f"MAIL_DEFAULT_SENDER is {settings.sender!r}. Most providers "
                f"require it to be the mailbox MAIL_USERNAME authenticates "
                f"as, or an address verified against it.")
        except smtplib.SMTPRecipientsRefused as exc:
            return fail(f"The recipient was refused: {exc.recipients}.")
        except smtplib.SMTPException as exc:
            return fail(f"Send failed ({type(exc).__name__}: {exc}).")

    print("\n✓ Sent. Check that inbox (and its spam folder).")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
