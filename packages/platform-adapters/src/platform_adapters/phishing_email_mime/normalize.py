"""MIME email normalization — stdlib only, no third-party deps."""

from __future__ import annotations

import email
import email.policy
import re
from email.message import EmailMessage, Message
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from platform_adapters.phishing_email.types import PhishingEmailAttachment, PhishingEmailParty

from platform_adapters.phishing_email_mime.errors import MimeParseError
from platform_adapters.phishing_email_mime.types import (
    PHISHING_EMAIL_MIME_INPUT_SHAPE,
    AuthenticationResult,
    NormalizedMimeEmail,
    ReceivedHop,
)


class _LinkExtractor(HTMLParser):
    """Minimal HTML parser that collects href and src attribute values."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for attr, value in attrs:
            if attr in ("href", "src") and value:
                self.links.append(value)


def normalize_mime_email_bytes(raw: bytes) -> NormalizedMimeEmail:
    """Parse raw RFC 822 bytes and return a NormalizedMimeEmail."""
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        raise MimeParseError(f"failed to parse MIME email: {exc}") from exc
    return _build_normalized(msg)


def normalize_mime_email_string(raw: str) -> NormalizedMimeEmail:
    """Parse a raw RFC 822 string and return a NormalizedMimeEmail."""
    try:
        msg = email.message_from_string(raw, policy=email.policy.default)
    except Exception as exc:
        raise MimeParseError(f"failed to parse MIME email: {exc}") from exc
    return _build_normalized(msg)


def _build_normalized(msg: Message) -> NormalizedMimeEmail:
    subject = _header_str(msg.get("Subject")) or ""
    message_id = _header_str(msg.get("Message-ID"))
    date_str = _header_str(msg.get("Date"))
    x_originating_ip = _header_str(msg.get("X-Originating-IP"))
    x_mailer = _header_str(msg.get("X-Mailer"))

    sender_party = _parse_party(msg.get("From") or "")
    reply_to_raw = msg.get("Reply-To")
    reply_to_party = _parse_party(reply_to_raw) if reply_to_raw else None

    plain_text_body, html_body = _extract_bodies(msg)
    text = plain_text_body or ""

    html_urls = _extract_urls_from_html(html_body) if html_body else []
    attachments = _extract_attachments(msg)

    # Collect all inline URLs from text body
    inline_urls = _extract_urls_from_text(text)
    urls = tuple(_dedupe_preserve_order(html_urls + inline_urls))

    received_chain = _parse_received_chain(msg)
    auth_results = _parse_authentication_results(msg)
    all_headers = _collect_all_headers(msg)

    return NormalizedMimeEmail(
        subject=subject,
        sender=sender_party,
        reply_to=reply_to_party,
        urls=urls,
        text=text,
        attachments=attachments,
        input_shape=PHISHING_EMAIL_MIME_INPUT_SHAPE,
        message_id=message_id,
        date=date_str,
        html_body=html_body,
        plain_text_body=plain_text_body,
        received_chain=received_chain,
        authentication_results=auth_results,
        x_originating_ip=x_originating_ip,
        x_mailer=x_mailer,
        all_headers=all_headers,
    )


def _header_str(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _parse_party(raw: str) -> PhishingEmailParty:
    """Parse a From/Reply-To header into a PhishingEmailParty."""
    raw = str(raw).strip()
    display_name: str | None = None
    email_addr = raw

    # "Display Name <email@domain>" pattern
    angle_match = re.match(r'^(.*?)\s*<([^>]+)>\s*$', raw)
    if angle_match:
        dn = angle_match.group(1).strip().strip('"').strip("'")
        display_name = dn if dn else None
        email_addr = angle_match.group(2).strip()
    else:
        # bare address or "email (display name)" — take just the address
        email_addr = raw.split()[0].strip("<>") if raw else ""

    email_addr = email_addr.lower()
    domain = email_addr.split("@")[-1] if "@" in email_addr else ""
    return PhishingEmailParty(
        email=email_addr,
        domain=domain,
        display_name=display_name,
    )


def _extract_bodies(msg: Message) -> tuple[str | None, str | None]:
    plain: str | None = None
    html: str | None = None
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            if ct == "text/plain" and plain is None:
                plain = _decode_part(part)
            elif ct == "text/html" and html is None:
                html = _decode_part(part)
    else:
        ct = msg.get_content_type()
        decoded = _decode_part(msg)
        if ct == "text/html":
            html = decoded
        else:
            plain = decoded
    return plain, html


def _decode_part(part: Message) -> str | None:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return None
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return None


def _extract_urls_from_html(html: str) -> list[str]:
    extractor = _LinkExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    seen: set[str] = set()
    result: list[str] = []
    for link in extractor.links:
        link = link.strip()
        if link and link not in seen:
            seen.add(link)
            result.append(link)
    return result


_URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def _extract_urls_from_text(text: str) -> list[str]:
    return list(dict.fromkeys(_URL_RE.findall(text)))


def _extract_attachments(msg: Message) -> tuple[PhishingEmailAttachment, ...]:
    attachments: list[PhishingEmailAttachment] = []
    for part in msg.walk():
        disposition = part.get_content_disposition()
        if disposition == "attachment":
            filename = part.get_filename() or ""
            content_type = part.get_content_type()
            attachments.append(PhishingEmailAttachment(filename=filename, content_type=content_type))
    return tuple(attachments)


def _parse_received_chain(msg: Message) -> tuple[ReceivedHop, ...]:
    """Parse all Received headers into an ordered chain (outermost first)."""
    hops: list[ReceivedHop] = []
    for raw_received in msg.get_all("Received") or []:
        raw_str = str(raw_received)
        from_host = _re_group(r'\bfrom\s+(\S+)', raw_str)
        by_host = _re_group(r'\bby\s+(\S+)', raw_str)
        with_protocol = _re_group(r'\bwith\s+([A-Za-z0-9_-]+)', raw_str)
        timestamp = _re_group(r';\s*(.+)$', raw_str)
        hops.append(ReceivedHop(
            from_host=from_host,
            by_host=by_host,
            with_protocol=with_protocol,
            timestamp=timestamp.strip() if timestamp else None,
            raw=raw_str,
        ))
    return tuple(hops)


def _parse_authentication_results(msg: Message) -> AuthenticationResult | None:
    raw = msg.get("Authentication-Results")
    if not raw:
        return None
    raw_str = str(raw)
    spf = _re_group(r'\bspf=(\w+)', raw_str, flags=re.IGNORECASE)
    dkim = _re_group(r'\bdkim=(\w+)', raw_str, flags=re.IGNORECASE)
    dmarc = _re_group(r'\bdmarc=(\w+)', raw_str, flags=re.IGNORECASE)
    return AuthenticationResult(spf=spf, dkim=dkim, dmarc=dmarc, raw=raw_str)


def _collect_all_headers(msg: Message) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for key in msg.keys():
        values = msg.get_all(key) or []
        headers.setdefault(key.lower(), []).extend(str(v) for v in values)
    return headers


def _re_group(pattern: str, text: str, flags: int = 0) -> str | None:
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result
