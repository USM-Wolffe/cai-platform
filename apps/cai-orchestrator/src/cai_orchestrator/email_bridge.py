"""Bridge between raw RFC 822 .eml bytes and platform-api structured_email_v2 payloads.

The user forwards suspicious emails to the dedicated CAI mailbox as an .eml attachment
("Forward as attachment" in Outlook/Thunderbird/Gmail). This module:
1. Extracts the attached .eml from the container email.
2. Parses it using stdlib only (no external adapter imports — boundary constraint).
3. Serializes the result to the structured_email_v2 wire format used by platform-api.
"""

from __future__ import annotations

import email
import email.policy
import io
import re
from email.generator import BytesGenerator
from email.message import Message
from html.parser import HTMLParser
from typing import Any


class EmlExtractionError(Exception):
    """Raised when no .eml attachment can be found in the container email."""


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_eml_attachment(raw_container: bytes) -> bytes:
    """Find and return the first .eml attachment from a container RFC 822 message.

    The container is the email received at the dedicated CAI mailbox — the original
    suspicious email arrives as a MIME attachment (message/rfc822 or *.eml filename).

    Raises EmlExtractionError if no suitable attachment is found.
    """
    msg = email.message_from_bytes(raw_container, policy=email.policy.default)
    for part in msg.walk():
        ct = part.get_content_type()
        fn = (part.get_filename() or "").lower()
        if ct == "message/rfc822" or fn.endswith(".eml"):
            payload = part.get_payload(decode=True)
            if payload:
                return payload
            # message/rfc822 parts may expose a sub-Message object
            sub_payload = part.get_payload()
            if isinstance(sub_payload, list) and sub_payload:
                buf = io.BytesIO()
                gen = BytesGenerator(buf)
                gen.flatten(sub_payload[0])
                return buf.getvalue()
    raise EmlExtractionError(
        "No .eml attachment found in the forwarded container email. "
        "Make sure the email was forwarded as an attachment (not inline)."
    )


# ---------------------------------------------------------------------------
# Top-level bridge
# ---------------------------------------------------------------------------

def eml_bytes_to_structured_email_v2_payload(raw_eml: bytes) -> dict[str, Any]:
    """Parse raw .eml bytes and return a structured_email_v2 dict for platform-api.

    This is the wire format accepted by POST /cases/{case_id}/artifacts/input
    when the payload will later be used with phishing-email-header-analysis.
    Uses stdlib only — no external adapter imports (boundary constraint).
    """
    return _parse_eml_to_payload_dict(raw_eml)


# ---------------------------------------------------------------------------
# Inline MIME parsing (stdlib only — mirrors phishing_email_mime adapter)
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Minimal HTML parser that collects href and src attribute values."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for attr, value in attrs:
            if attr in ("href", "src") and value:
                self.links.append(value)


_URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def _parse_eml_to_payload_dict(raw: bytes) -> dict[str, Any]:
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    subject = _header_str(msg.get("Subject")) or ""
    message_id = _header_str(msg.get("Message-ID"))
    date_str = _header_str(msg.get("Date"))
    x_originating_ip = _header_str(msg.get("X-Originating-IP"))
    x_mailer = _header_str(msg.get("X-Mailer"))

    sender = _parse_party(str(msg.get("From") or ""))
    reply_to_raw = msg.get("Reply-To")
    reply_to = _parse_party(str(reply_to_raw)) if reply_to_raw else None

    plain_text_body, html_body = _extract_bodies(msg)
    text = plain_text_body or ""

    html_urls = _extract_urls_from_html(html_body) if html_body else []
    inline_urls = list(dict.fromkeys(_URL_RE.findall(text)))
    urls = list(_dedupe_preserve_order(html_urls + inline_urls))

    attachments = _extract_attachments(msg)
    received_chain = _parse_received_chain(msg)
    auth_results = _parse_authentication_results(msg)
    all_headers = _collect_all_headers(msg)

    return {
        "input_shape": "structured_email_v2",
        "subject": subject,
        "sender": sender,
        "reply_to": reply_to,
        "urls": urls,
        "text": text,
        "attachments": attachments,
        "message_id": message_id,
        "date": date_str,
        "html_body": html_body,
        "plain_text_body": plain_text_body,
        "received_chain": received_chain,
        "authentication_results": auth_results,
        "x_originating_ip": x_originating_ip,
        "x_mailer": x_mailer,
        "all_headers": all_headers,
    }


def _header_str(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _parse_party(raw: str) -> dict[str, Any]:
    raw = str(raw).strip()
    display_name: str | None = None
    email_addr = raw

    angle_match = re.match(r'^(.*?)\s*<([^>]+)>\s*$', raw)
    if angle_match:
        dn = angle_match.group(1).strip().strip('"').strip("'")
        display_name = dn if dn else None
        email_addr = angle_match.group(2).strip()
    else:
        email_addr = raw.split()[0].strip("<>") if raw else ""

    email_addr = email_addr.lower()
    domain = email_addr.split("@")[-1] if "@" in email_addr else ""
    return {"email": email_addr, "domain": domain, "display_name": display_name}


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


def _extract_attachments(msg: Message) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append({
                "filename": part.get_filename() or "",
                "content_type": part.get_content_type(),
            })
    return attachments


def _parse_received_chain(msg: Message) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for raw_received in msg.get_all("Received") or []:
        raw_str = str(raw_received)
        from_host = _re_group(r'\bfrom\s+(\S+)', raw_str)
        by_host = _re_group(r'\bby\s+(\S+)', raw_str)
        with_protocol = _re_group(r'\bwith\s+([A-Za-z0-9_-]+)', raw_str)
        timestamp = _re_group(r';\s*(.+)$', raw_str)
        hops.append({
            "from_host": from_host,
            "by_host": by_host,
            "with_protocol": with_protocol,
            "timestamp": timestamp.strip() if timestamp else None,
            "raw": raw_str,
        })
    return hops


def _parse_authentication_results(msg: Message) -> dict[str, Any] | None:
    raw = msg.get("Authentication-Results")
    if not raw:
        return None
    raw_str = str(raw)
    spf = _re_group(r'\bspf=(\w+)', raw_str, flags=re.IGNORECASE)
    dkim = _re_group(r'\bdkim=(\w+)', raw_str, flags=re.IGNORECASE)
    dmarc = _re_group(r'\bdmarc=(\w+)', raw_str, flags=re.IGNORECASE)
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "raw": raw_str}


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
