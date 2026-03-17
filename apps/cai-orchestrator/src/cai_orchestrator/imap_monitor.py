"""IMAP polling monitor — stdlib imaplib only, no third-party deps."""

from __future__ import annotations

import imaplib
import os
import ssl
from dataclasses import dataclass


@dataclass(frozen=True)
class ImapMonitorSettings:
    """Runtime configuration for the IMAP monitor."""

    imap_host: str
    imap_port: int
    username: str
    password: str
    mailbox: str = "INBOX"
    poll_interval: int = 30
    mark_seen: bool = True
    use_ssl: bool = True


class ImapMonitorConfigError(Exception):
    """Raised when required IMAP environment variables are missing or invalid."""


def load_imap_monitor_settings() -> ImapMonitorSettings:
    """Load IMAP settings from environment variables.

    Required:
        IMAP_HOST, IMAP_PORT, IMAP_USERNAME, IMAP_PASSWORD

    Optional:
        IMAP_MAILBOX (default: INBOX)
        IMAP_POLL_INTERVAL (default: 30 seconds)
        IMAP_MARK_SEEN (default: true)
        IMAP_SSL (default: true)
    """
    missing = [k for k in ("IMAP_HOST", "IMAP_PORT", "IMAP_USERNAME", "IMAP_PASSWORD") if not os.environ.get(k)]
    if missing:
        raise ImapMonitorConfigError(f"missing required IMAP environment variables: {', '.join(missing)}")

    try:
        port = int(os.environ["IMAP_PORT"])
    except ValueError:
        raise ImapMonitorConfigError(f"IMAP_PORT must be an integer, got: {os.environ['IMAP_PORT']!r}")

    try:
        poll_interval = int(os.environ.get("IMAP_POLL_INTERVAL", "30"))
    except ValueError:
        raise ImapMonitorConfigError("IMAP_POLL_INTERVAL must be an integer")

    mark_seen = os.environ.get("IMAP_MARK_SEEN", "true").lower() not in ("false", "0", "no")
    use_ssl = os.environ.get("IMAP_SSL", "true").lower() not in ("false", "0", "no")

    return ImapMonitorSettings(
        imap_host=os.environ["IMAP_HOST"],
        imap_port=port,
        username=os.environ["IMAP_USERNAME"],
        password=os.environ["IMAP_PASSWORD"],
        mailbox=os.environ.get("IMAP_MAILBOX", "INBOX"),
        poll_interval=poll_interval,
        mark_seen=mark_seen,
        use_ssl=use_ssl,
    )


def poll_unseen_messages(settings: ImapMonitorSettings) -> list[bytes]:
    """Connect to the mailbox and fetch all UNSEEN RFC 822 messages.

    Returns a list of raw RFC 822 email bytes (one per unseen message).
    If mark_seen is True, marks each fetched message as \\Seen.
    """
    connection = _connect(settings)
    try:
        connection.select(settings.mailbox)
        _, data = connection.search(None, "UNSEEN")
        if not data or not data[0]:
            return []
        message_ids = data[0].split()
        messages: list[bytes] = []
        for msg_id in message_ids:
            _, msg_data = connection.fetch(msg_id, "(RFC822)")
            if msg_data and msg_data[0] is not None:
                raw = msg_data[0][1] if isinstance(msg_data[0], tuple) else None
                if isinstance(raw, bytes):
                    messages.append(raw)
                    if settings.mark_seen:
                        connection.store(msg_id, "+FLAGS", "\\Seen")
        return messages
    finally:
        try:
            connection.logout()
        except Exception:
            pass


def _connect(settings: ImapMonitorSettings) -> imaplib.IMAP4:
    if settings.use_ssl:
        ctx = ssl.create_default_context()
        conn = imaplib.IMAP4_SSL(settings.imap_host, settings.imap_port, ssl_context=ctx)
    else:
        conn = imaplib.IMAP4(settings.imap_host, settings.imap_port)
    conn.login(settings.username, settings.password)
    return conn
