"""Header-based phishing detection rules for structured_email_v2 inputs."""

from __future__ import annotations

import ipaddress
import re

from platform_adapters.phishing_email_mime.types import NormalizedMimeEmail

from platform_backends.phishing_email.models import PhishingTriggeredRule


def evaluate_header_rules(normalized: NormalizedMimeEmail) -> list[PhishingTriggeredRule]:
    """Evaluate authentication and routing header rules over a normalized MIME email."""
    rules: list[PhishingTriggeredRule] = []

    auth = normalized.authentication_results
    if auth is not None:
        if auth.spf is not None and auth.spf.lower() in ("fail", "softfail"):
            rules.append(PhishingTriggeredRule(
                rule_id="spf_fail",
                category="headers",
                weight=3,
                message=f"SPF check failed ({auth.spf}).",
                evidence={"spf": auth.spf, "raw": auth.raw},
            ))
        if auth.dkim is not None and auth.dkim.lower() == "fail":
            rules.append(PhishingTriggeredRule(
                rule_id="dkim_fail",
                category="headers",
                weight=3,
                message=f"DKIM signature failed ({auth.dkim}).",
                evidence={"dkim": auth.dkim, "raw": auth.raw},
            ))
        if auth.dmarc is not None and auth.dmarc.lower() == "fail":
            rules.append(PhishingTriggeredRule(
                rule_id="dmarc_fail",
                category="headers",
                weight=4,
                message=f"DMARC policy failed ({auth.dmarc}).",
                evidence={"dmarc": auth.dmarc, "raw": auth.raw},
            ))

    chain = normalized.received_chain
    if len(chain) < 2:
        rules.append(PhishingTriggeredRule(
            rule_id="short_received_chain",
            category="headers",
            weight=1,
            message=f"Received chain has only {len(chain)} hop(s) — unusually short.",
            evidence={"hop_count": len(chain)},
        ))

    if chain:
        first_hop = chain[0]
        if first_hop.from_host is not None and _is_ip_literal(first_hop.from_host):
            rules.append(PhishingTriggeredRule(
                rule_id="first_hop_ip_literal",
                category="headers",
                weight=2,
                message="First Received hop originates from a bare IP address.",
                evidence={"from_host": first_hop.from_host},
            ))

    hop_hosts = [h.by_host for h in chain if h.by_host]
    seen: set[str] = set()
    duplicates: list[str] = []
    for host in hop_hosts:
        if host in seen and host not in duplicates:
            duplicates.append(host)
        seen.add(host)
    if duplicates:
        rules.append(PhishingTriggeredRule(
            rule_id="received_chain_loop",
            category="headers",
            weight=2,
            message="Received chain contains repeated hosts — possible loop or forged headers.",
            evidence={"duplicate_hosts": duplicates},
        ))

    return rules


def _is_ip_literal(value: str) -> bool:
    # Strip surrounding brackets for IPv6 like [::1]
    stripped = value.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        return False
