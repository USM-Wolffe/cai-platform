"""Detection algorithms operating on lists of NormalizedLogRecord."""

from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from platform_backends.multi_source_logs.models import MultiSourceDetectionFinding, NormalizedLogRecord

# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(ts: str) -> datetime | None:
    """Parse ISO-8601 timestamp to datetime. Returns None on failure."""
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(ts[:26], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _bucket_5min(dt: datetime) -> int:
    """Return a 5-minute bucket key as Unix timestamp rounded down."""
    epoch = int(dt.timestamp())
    return epoch - (epoch % 300)


def _bucket_10min(dt: datetime) -> int:
    """Return a 10-minute bucket key as Unix timestamp rounded down."""
    epoch = int(dt.timestamp())
    return epoch - (epoch % 600)


def _bucket_1hour(dt: datetime) -> int:
    """Return an hourly bucket key as Unix timestamp rounded down."""
    epoch = int(dt.timestamp())
    return epoch - (epoch % 3600)


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values() if count > 0)


# ── Failed auth detection ─────────────────────────────────────────────────────

AUTH_FAIL_TYPES = frozenset({
    "failed_logon", "kerberos_preauth_failed", "kerberos_tgt_request",
    "account_locked",
})


def detect_failed_auth(records: list[NormalizedLogRecord]) -> list[MultiSourceDetectionFinding]:
    """Detect brute force, spray, and lockout patterns.

    Rules:
    - Brute force: same source_ip + same user with >5 failures in any 5-min window
    - Spray: same source_ip targeting >5 distinct users in any 5-min window
    - Lockout: any account_locked event
    """
    findings: list[MultiSourceDetectionFinding] = []

    fail_records = [r for r in records if r.event_type in AUTH_FAIL_TYPES]
    locked_records = [r for r in records if r.event_type == "account_locked"]

    # Brute force: group by (source_ip, user, 5min bucket)
    bf: dict[tuple[str, str, int], list[NormalizedLogRecord]] = defaultdict(list)
    for r in fail_records:
        if r.source_ip and r.user:
            dt = _parse_ts(r.timestamp)
            if dt:
                bf[(r.source_ip, r.user, _bucket_5min(dt))].append(r)

    for (ip, user, _bucket), recs in bf.items():
        if len(recs) > 5:
            findings.append(MultiSourceDetectionFinding(
                rule_id="brute_force_same_user",
                category="brute_force",
                severity="high",
                count=len(recs),
                evidence={"source_ip": ip, "targeted_user": user, "failures": len(recs)},
                summary=f"Brute force: {ip} made {len(recs)} failed login attempts against user '{user}' in a 5-minute window.",
            ))

    # Spray: group by (source_ip, 5min bucket) → count distinct users
    spray: dict[tuple[str, int], set[str]] = defaultdict(set)
    for r in fail_records:
        if r.source_ip and r.user:
            dt = _parse_ts(r.timestamp)
            if dt:
                spray[(r.source_ip, _bucket_5min(dt))].add(r.user)

    for (ip, _bucket), users in spray.items():
        if len(users) > 5:
            findings.append(MultiSourceDetectionFinding(
                rule_id="password_spray",
                category="spray",
                severity="high",
                count=len(users),
                evidence={"source_ip": ip, "distinct_users_targeted": len(users),
                          "sample_users": sorted(users)[:5]},
                summary=f"Password spray: {ip} targeted {len(users)} distinct users in a 5-minute window.",
            ))

    # Lockouts
    if locked_records:
        locked_users = {r.user for r in locked_records if r.user}
        findings.append(MultiSourceDetectionFinding(
            rule_id="account_lockout",
            category="account_locked",
            severity="medium",
            count=len(locked_records),
            evidence={"locked_accounts": sorted(locked_users)},
            summary=f"Account lockouts detected for {len(locked_users)} account(s): {', '.join(sorted(locked_users)[:5])}.",
        ))

    return findings


# ── Lateral movement detection ────────────────────────────────────────────────

LATERAL_LOGON_TYPES = frozenset({"logon", "explicit_credential_use", "kerberos_service_request"})


def detect_lateral_movement(records: list[NormalizedLogRecord]) -> list[MultiSourceDetectionFinding]:
    """Detect lateral movement and internal scanning patterns.

    Rules:
    - Lateral movement: same user accessing >3 distinct dest_hosts in any 10-min window
    - Internal scanning: same source_ip connecting to >5 distinct dest_ips in any 5-min window
    """
    findings: list[MultiSourceDetectionFinding] = []

    logon_records = [r for r in records if r.event_type in LATERAL_LOGON_TYPES]

    # Lateral movement by user
    user_hops: dict[tuple[str, int], set[str]] = defaultdict(set)
    for r in logon_records:
        if r.user and r.dest_host:
            dt = _parse_ts(r.timestamp)
            if dt:
                user_hops[(r.user, _bucket_10min(dt))].add(r.dest_host)

    for (user, _bucket), hosts in user_hops.items():
        if len(hosts) > 3:
            findings.append(MultiSourceDetectionFinding(
                rule_id="lateral_movement_user",
                category="lateral_movement",
                severity="high",
                count=len(hosts),
                evidence={"user": user, "distinct_hosts": len(hosts),
                          "sample_hosts": sorted(hosts)[:5]},
                summary=f"Lateral movement: user '{user}' accessed {len(hosts)} distinct hosts in a 10-minute window.",
            ))

    # Internal scanning by source IP
    ip_dests: dict[tuple[str, int], set[str]] = defaultdict(set)
    for r in records:
        if r.source_ip and r.dest_ip:
            dt = _parse_ts(r.timestamp)
            if dt:
                ip_dests[(r.source_ip, _bucket_5min(dt))].add(r.dest_ip)

    for (ip, _bucket), dests in ip_dests.items():
        if len(dests) > 5:
            findings.append(MultiSourceDetectionFinding(
                rule_id="internal_scanning",
                category="scanning",
                severity="medium",
                count=len(dests),
                evidence={"source_ip": ip, "distinct_destinations": len(dests),
                          "sample_dests": sorted(dests)[:5]},
                summary=f"Scanning detected: {ip} connected to {len(dests)} distinct destinations in a 5-minute window.",
            ))

    return findings


# ── Privilege escalation detection ────────────────────────────────────────────

PRIV_ESC_TYPES = frozenset({
    "special_privilege_use", "explicit_credential_use", "sudo_use", "su_use",
})

_SERVICE_ACCOUNT_RE = re.compile(r"^(system|LOCAL SERVICE|NETWORK SERVICE|svc_|_svc|service$)",
                                  re.IGNORECASE)


def detect_privilege_escalation(records: list[NormalizedLogRecord]) -> list[MultiSourceDetectionFinding]:
    """Detect privilege escalation events.

    Rules:
    - Any priv_esc event outside business hours (UTC 08:00–20:00)
    - sudo/su to root by non-standard users
    - Explicit credential use (pass-the-hash style)
    """
    import re as _re
    findings: list[MultiSourceDetectionFinding] = []

    priv_records = [r for r in records if r.event_type in PRIV_ESC_TYPES]
    if not priv_records:
        return findings

    after_hours: list[NormalizedLogRecord] = []
    root_escalations: list[NormalizedLogRecord] = []
    explicit_creds: list[NormalizedLogRecord] = []

    for r in priv_records:
        dt = _parse_ts(r.timestamp)
        if dt and not (8 <= dt.hour < 20):
            after_hours.append(r)

        if r.event_type in {"sudo_use", "su_use"}:
            cmd = r.process_name or ""
            if "root" in cmd.lower() or (r.user and r.user.lower() not in {"root", "admin"}):
                root_escalations.append(r)

        if r.event_type == "explicit_credential_use":
            explicit_creds.append(r)

    if after_hours:
        users = {r.user for r in after_hours if r.user}
        findings.append(MultiSourceDetectionFinding(
            rule_id="priv_esc_after_hours",
            category="priv_esc",
            severity="high",
            count=len(after_hours),
            evidence={"affected_users": sorted(users)[:5], "event_count": len(after_hours)},
            summary=f"Privilege use outside business hours: {len(after_hours)} events from {len(users)} account(s).",
        ))

    if root_escalations:
        users = {r.user for r in root_escalations if r.user}
        findings.append(MultiSourceDetectionFinding(
            rule_id="sudo_su_to_root",
            category="priv_esc",
            severity="high",
            count=len(root_escalations),
            evidence={"affected_users": sorted(users)[:5]},
            summary=f"Sudo/su escalation: {len(root_escalations)} attempts by {len(users)} user(s).",
        ))

    if explicit_creds:
        users = {r.user for r in explicit_creds if r.user}
        findings.append(MultiSourceDetectionFinding(
            rule_id="explicit_credential_use",
            category="priv_esc",
            severity="medium",
            count=len(explicit_creds),
            evidence={"affected_users": sorted(users)[:5]},
            summary=f"Explicit credential use (potential pass-the-hash): {len(explicit_creds)} events.",
        ))

    return findings


# We need re for _SERVICE_ACCOUNT_RE above
import re


# ── DNS anomaly detection ─────────────────────────────────────────────────────

_DGA_ENTROPY_THRESHOLD = 3.5
_DGA_DOMAIN_COUNT_THRESHOLD = 50
_BEACONING_TOLERANCE = 0.10   # 10% jitter tolerance


def detect_dns_anomaly(records: list[NormalizedLogRecord]) -> list[MultiSourceDetectionFinding]:
    """Detect DGA and beaconing patterns in DNS query records.

    Rules:
    - DGA indicator: source_ip queries >50 unique domains/hour with avg Shannon entropy > 3.5
    - Beaconing: same source_ip queries same domain repeatedly with low interval variance (<10%)
    """
    import json as _json
    findings: list[MultiSourceDetectionFinding] = []

    dns_records = [r for r in records if r.event_type == "dns_query"]
    if not dns_records:
        return findings

    # DGA detection: group by (source_ip, hour bucket)
    dga: dict[tuple[str, int], list[str]] = defaultdict(list)
    for r in dns_records:
        if not r.source_ip:
            continue
        dt = _parse_ts(r.timestamp)
        if not dt:
            continue
        try:
            details = _json.loads(r.details_json)
            domain = details.get("domain") or ""
        except Exception:
            domain = ""
        if domain:
            label = domain.split(".")[0]
            dga[(r.source_ip, _bucket_1hour(dt))].append(label)

    for (ip, _bucket), labels in dga.items():
        unique_labels = set(labels)
        if len(unique_labels) > _DGA_DOMAIN_COUNT_THRESHOLD:
            avg_entropy = sum(_shannon_entropy(l) for l in unique_labels) / len(unique_labels)
            if avg_entropy > _DGA_ENTROPY_THRESHOLD:
                findings.append(MultiSourceDetectionFinding(
                    rule_id="dga_indicator",
                    category="dns_anomaly",
                    severity="high",
                    count=len(unique_labels),
                    evidence={"source_ip": ip, "unique_domains_per_hour": len(unique_labels),
                              "avg_entropy": round(avg_entropy, 2)},
                    summary=(
                        f"DGA indicator: {ip} queried {len(unique_labels)} unique high-entropy "
                        f"domains in one hour (avg entropy: {avg_entropy:.2f})."
                    ),
                ))

    # Beaconing detection: group by (source_ip, domain)
    beacon: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    for r in dns_records:
        if not r.source_ip:
            continue
        dt = _parse_ts(r.timestamp)
        if not dt:
            continue
        try:
            details = _json.loads(r.details_json)
            domain = details.get("domain") or ""
        except Exception:
            domain = ""
        if domain:
            beacon[(r.source_ip, domain)].append(dt)

    for (ip, domain), timestamps in beacon.items():
        if len(timestamps) < 5:
            continue
        timestamps_sorted = sorted(timestamps)
        intervals = [(b - a).total_seconds()
                     for a, b in zip(timestamps_sorted, timestamps_sorted[1:])]
        if not intervals:
            continue
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < 1:
            continue
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        cv = math.sqrt(variance) / avg_interval  # coefficient of variation
        if cv < _BEACONING_TOLERANCE:
            findings.append(MultiSourceDetectionFinding(
                rule_id="dns_beaconing",
                category="dns_beaconing",
                severity="medium",
                count=len(timestamps),
                evidence={"source_ip": ip, "domain": domain,
                          "query_count": len(timestamps),
                          "avg_interval_seconds": round(avg_interval, 1),
                          "coefficient_of_variation": round(cv, 3)},
                summary=(
                    f"DNS beaconing: {ip} queried '{domain}' {len(timestamps)} times "
                    f"at ~{avg_interval:.0f}s intervals (CV={cv:.3f})."
                ),
            ))

    return findings


# ── Cross-source correlation ──────────────────────────────────────────────────

def correlate_cross_source(
    findings_by_operation: dict[str, list[MultiSourceDetectionFinding]],
) -> list[MultiSourceDetectionFinding]:
    """Correlate findings across multiple detection operations.

    Rules:
    - Multi-stage attack: same source_ip appears as attacker in ≥2 distinct detection categories
    - Insider/compromised account: same user appears in both priv_esc and lateral_movement findings
    """
    findings: list[MultiSourceDetectionFinding] = []

    # Collect attacker IPs per category
    ip_to_categories: dict[str, set[str]] = defaultdict(set)
    user_to_categories: dict[str, set[str]] = defaultdict(set)

    for operation, op_findings in findings_by_operation.items():
        for f in op_findings:
            ev = f.evidence
            ip = ev.get("source_ip")
            if ip:
                ip_to_categories[ip].add(f.category)
            # Also check attacker fields
            for ip_key in ("attacker_ip", "top_attacker_ip"):
                if ev.get(ip_key):
                    ip_to_categories[ev[ip_key]].add(f.category)

            user = ev.get("targeted_user") or ev.get("user")
            if user:
                user_to_categories[user].add(f.category)
            for u_key in ("affected_users",):
                for u in (ev.get(u_key) or []):
                    user_to_categories[u].add(f.category)

    # Multi-stage by IP
    multi_stage_ips = {ip: cats for ip, cats in ip_to_categories.items() if len(cats) >= 2}
    if multi_stage_ips:
        top_ip = max(multi_stage_ips, key=lambda ip: len(multi_stage_ips[ip]))
        findings.append(MultiSourceDetectionFinding(
            rule_id="multi_stage_attack",
            category="multi_stage",
            severity="high",
            count=len(multi_stage_ips),
            evidence={
                "multi_stage_ips": {ip: sorted(cats) for ip, cats in list(multi_stage_ips.items())[:5]},
                "top_attacker_ip": top_ip,
            },
            summary=(
                f"Multi-stage attack indicators: {len(multi_stage_ips)} IP(s) appear in multiple "
                f"detection categories. Top attacker: {top_ip} "
                f"({', '.join(sorted(multi_stage_ips[top_ip]))})."
            ),
        ))

    # Compromised/insider account
    priv_users = set()
    lateral_users = set()
    for f in findings_by_operation.get("multi_source_logs.privilege_escalation_detect", []):
        for u in (f.evidence.get("affected_users") or []):
            priv_users.add(u)
    for f in findings_by_operation.get("multi_source_logs.lateral_movement_detect", []):
        user = f.evidence.get("user")
        if user:
            lateral_users.add(user)

    compromised = priv_users & lateral_users
    if compromised:
        findings.append(MultiSourceDetectionFinding(
            rule_id="compromised_or_insider",
            category="multi_stage",
            severity="high",
            count=len(compromised),
            evidence={"accounts": sorted(compromised)},
            summary=(
                f"Possible compromised/insider account(s): {', '.join(sorted(compromised))} "
                f"appear in both privilege escalation and lateral movement findings."
            ),
        ))

    return findings
