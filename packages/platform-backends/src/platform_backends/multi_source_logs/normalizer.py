"""Log normalization — converts raw log lines from each source type to NormalizedLogRecord."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Callable

from platform_backends.multi_source_logs.errors import MultiSourceLogsBackendError
from platform_backends.multi_source_logs.models import NormalizedLogRecord

VALID_SOURCE_TYPES = frozenset({
    "windows_events",
    "linux_auth",
    "dns_logs",
    "firewall_csv",
    "web_proxy",
})


def normalize_log_lines(source_type: str, lines: list[str]) -> list[NormalizedLogRecord]:
    """Dispatch to the appropriate parser based on source_type."""
    if source_type not in VALID_SOURCE_TYPES:
        raise MultiSourceLogsBackendError(
            f"source_type must be one of {sorted(VALID_SOURCE_TYPES)}, got '{source_type}'"
        )
    parsers: dict[str, Callable[[list[str]], list[NormalizedLogRecord]]] = {
        "windows_events": _parse_windows_events,
        "linux_auth": _parse_linux_auth,
        "dns_logs": _parse_dns_logs,
        "firewall_csv": _parse_firewall_csv,
        "web_proxy": _parse_web_proxy,
    }
    return parsers[source_type](lines)


def download_s3_lines(s3_uri: str) -> list[str]:
    """Download a text object from S3 and return its lines."""
    try:
        import boto3
    except ImportError as exc:
        raise MultiSourceLogsBackendError(
            "boto3 is required to download logs from S3. Install it or pass raw_log_lines instead."
        ) from exc
    if not s3_uri.startswith("s3://"):
        raise MultiSourceLogsBackendError(f"Invalid S3 URI: {s3_uri!r}")
    bucket, _, key = s3_uri[5:].partition("/")
    obj = boto3.client("s3").get_object(Bucket=bucket, Key=key)
    return obj["Body"].read().decode("utf-8", errors="replace").splitlines()


# ── Windows Events ─────────────────────────────────────────────────────────────

_WINDOWS_EVENT_TYPE_MAP = {
    4624: "logon",
    4625: "failed_logon",
    4634: "logoff",
    4647: "logoff",
    4648: "explicit_credential_use",
    4672: "special_privilege_use",
    4740: "account_locked",
    4768: "kerberos_tgt_request",
    4769: "kerberos_service_request",
    4771: "kerberos_preauth_failed",
}


def _parse_windows_events(lines: list[str]) -> list[NormalizedLogRecord]:
    """Parse Windows Security event log lines in JSON format (e.g. from Winlogbeat)."""
    records: list[NormalizedLogRecord] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Support both raw event dict and Winlogbeat envelope
        event = obj.get("winlog", obj.get("event_data", obj))
        event_id = int(obj.get("EventID", obj.get("event_id", event.get("EventID", 0))) or 0)
        event_type = _WINDOWS_EVENT_TYPE_MAP.get(event_id, "unknown")

        ts = obj.get("TimeCreated", obj.get("@timestamp", obj.get("timestamp", "")))
        ts_iso = _normalize_timestamp(ts)

        records.append(NormalizedLogRecord(
            timestamp=ts_iso,
            event_type=event_type,
            source_host=obj.get("Computer", obj.get("source_host")),
            dest_host=event.get("TargetServerName") or event.get("WorkstationName"),
            source_ip=event.get("IpAddress") or event.get("IPAddress"),
            dest_ip=None,
            user=event.get("TargetUserName") or event.get("SubjectUserName") or obj.get("user"),
            action=str(event_id) if event_id else None,
            status=event.get("Status") or event.get("FailureReason"),
            process_name=event.get("ProcessName") or event.get("CallerProcessName"),
            details_json=json.dumps({"event_id": event_id, "logon_type": event.get("LogonType")}),
        ))
    return records


# ── Linux auth ────────────────────────────────────────────────────────────────

_LINUX_AUTH_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+\S+(?:\[\d+\])?:\s+(.+)$"
)
_LINUX_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
_LINUX_ACCEPTED_RE = re.compile(r"Accepted \S+ for (\S+) from (\S+)")
_LINUX_SUDO_RE = re.compile(r"(\S+)\s*:\s+.*COMMAND=(.+)$")
_LINUX_SU_RE = re.compile(r"su\S*:\s+(Successful|FAILED) su for (\S+) by (\S+)")
_LINUX_LOCKED_RE = re.compile(r"pam_tally\S*.*user (\S+) \(account locked out\)")


def _parse_linux_auth(lines: list[str]) -> list[NormalizedLogRecord]:
    """Parse /var/log/auth.log syslog lines."""
    records: list[NormalizedLogRecord] = []
    current_year = datetime.now(timezone.utc).year

    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = _LINUX_AUTH_RE.match(line)
        if not m:
            continue
        ts_str, host, msg = m.group(1), m.group(2), m.group(3)
        ts_iso = _parse_syslog_timestamp(ts_str, current_year)

        event_type = "unknown"
        user = source_ip = process_name = None
        status = None

        if mf := _LINUX_FAILED_RE.search(msg):
            event_type = "failed_logon"
            user, source_ip = mf.group(1), mf.group(2)
        elif ma := _LINUX_ACCEPTED_RE.search(msg):
            event_type = "logon"
            user, source_ip = ma.group(1), ma.group(2)
        elif ms := _LINUX_SUDO_RE.search(msg):
            event_type = "sudo_use"
            user = ms.group(1)
            process_name = ms.group(2).strip()
        elif msu := _LINUX_SU_RE.search(msg):
            event_type = "su_use"
            status = msu.group(1)
            user = msu.group(2)
        elif _LINUX_LOCKED_RE.search(msg):
            event_type = "account_locked"
            ml = _LINUX_LOCKED_RE.search(msg)
            user = ml.group(1) if ml else None

        records.append(NormalizedLogRecord(
            timestamp=ts_iso,
            event_type=event_type,
            source_host=host,
            dest_host=None,
            source_ip=source_ip,
            dest_ip=None,
            user=user,
            action=event_type,
            status=status,
            process_name=process_name,
            details_json=json.dumps({"raw": msg[:200]}),
        ))
    return records


# ── DNS logs ──────────────────────────────────────────────────────────────────

def _parse_dns_logs(lines: list[str]) -> list[NormalizedLogRecord]:
    """Parse DNS query logs (TSV or CSV with headers: timestamp,src_ip,domain,query_type,ttl)."""
    records: list[NormalizedLogRecord] = []
    if not lines:
        return records

    # Detect delimiter
    first = lines[0]
    delimiter = "\t" if "\t" in first else ","

    reader = csv.DictReader(io.StringIO("\n".join(lines)), delimiter=delimiter)
    # Normalize field names
    field_aliases = {
        "timestamp": ["timestamp", "time", "ts", "query_time"],
        "src_ip": ["src_ip", "source_ip", "client_ip", "client"],
        "domain": ["domain", "qname", "query_name", "name"],
        "query_type": ["query_type", "qtype", "type", "rtype"],
        "ttl": ["ttl", "response_ttl"],
    }

    for row in reader:
        row_lower = {k.lower().strip(): v for k, v in row.items()}

        def get_field(key: str) -> str | None:
            for alias in field_aliases.get(key, [key]):
                if alias in row_lower:
                    return row_lower[alias] or None
            return None

        ts_iso = _normalize_timestamp(get_field("timestamp") or "")
        src_ip = get_field("src_ip")
        domain = get_field("domain")
        query_type = get_field("query_type")
        ttl_str = get_field("ttl")
        ttl = int(ttl_str) if ttl_str and ttl_str.isdigit() else None

        records.append(NormalizedLogRecord(
            timestamp=ts_iso,
            event_type="dns_query",
            source_host=None,
            dest_host=None,
            source_ip=src_ip,
            dest_ip=None,
            user=None,
            action=query_type,
            status=None,
            process_name=None,
            details_json=json.dumps({"domain": domain, "query_type": query_type, "ttl": ttl}),
        ))
    return records


# ── Firewall CSV ──────────────────────────────────────────────────────────────

def _parse_firewall_csv(lines: list[str]) -> list[NormalizedLogRecord]:
    """Parse generic firewall CSV logs. First line must be a header row."""
    records: list[NormalizedLogRecord] = []
    if not lines:
        return records

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    field_aliases = {
        "timestamp": ["timestamp", "time", "date_time", "datetime", "date"],
        "source_ip": ["src_ip", "source_ip", "src", "srcip"],
        "dest_ip": ["dst_ip", "dest_ip", "dst", "dstip", "destination_ip"],
        "source_host": ["src_host", "source_host", "srchost"],
        "dest_host": ["dst_host", "dest_host", "dsthost"],
        "action": ["action", "disposition", "verdict", "result"],
        "user": ["user", "username", "src_user"],
        "status": ["status", "reason"],
        "process_name": ["application", "app", "process"],
    }

    for row in reader:
        row_lower = {k.lower().strip(): v for k, v in row.items()}

        def get_field(key: str) -> str | None:
            for alias in field_aliases.get(key, [key]):
                if alias in row_lower:
                    return row_lower[alias] or None
            return None

        action = get_field("action") or "unknown"
        event_type = "logon" if action.lower() in {"allow", "permitted"} else (
            "failed_logon" if action.lower() in {"deny", "block", "drop", "reject"} else "unknown"
        )

        records.append(NormalizedLogRecord(
            timestamp=_normalize_timestamp(get_field("timestamp") or ""),
            event_type=event_type,
            source_host=get_field("source_host"),
            dest_host=get_field("dest_host"),
            source_ip=get_field("source_ip"),
            dest_ip=get_field("dest_ip"),
            user=get_field("user"),
            action=action,
            status=get_field("status"),
            process_name=get_field("process_name"),
            details_json=json.dumps({k: v for k, v in row_lower.items() if v}),
        ))
    return records


# ── Web proxy ─────────────────────────────────────────────────────────────────

# Squid native format: timestamp(epoch.ms) elapsed client_ip action/status bytes method uri
_SQUID_RE = re.compile(
    r"^(\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\S+)/(\d+)\s+(\d+)\s+(\S+)\s+(\S+)"
)


def _parse_web_proxy(lines: list[str]) -> list[NormalizedLogRecord]:
    """Parse squid-style web proxy access logs."""
    records: list[NormalizedLogRecord] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _SQUID_RE.match(line)
        if not m:
            continue
        epoch_str, _elapsed, client_ip, action, status_code, _bytes, method, uri = m.groups()
        try:
            ts = datetime.fromtimestamp(float(epoch_str), tz=timezone.utc)
            ts_iso = ts.isoformat()
        except (ValueError, OSError):
            ts_iso = ""

        records.append(NormalizedLogRecord(
            timestamp=ts_iso,
            event_type="http_request",
            source_host=None,
            dest_host=None,
            source_ip=client_ip,
            dest_ip=None,
            user=None,
            action=f"{method} {action}",
            status=status_code,
            process_name=None,
            details_json=json.dumps({"uri": uri[:300], "method": method, "action": action}),
        ))
    return records


# ── Timestamp helpers ─────────────────────────────────────────────────────────

def _normalize_timestamp(ts: str) -> str:
    """Best-effort normalization of various timestamp formats to ISO-8601."""
    if not ts:
        return ""
    # Already ISO-ish
    if "T" in ts and len(ts) >= 19:
        return ts[:26]  # truncate microseconds if too long
    # Try common formats
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            dt = datetime.strptime(ts[:len(fmt) + 5], fmt)
            return dt.isoformat()
        except ValueError:
            continue
    return ts  # return as-is if unparseable


def _parse_syslog_timestamp(ts_str: str, year: int) -> str:
    """Parse syslog timestamp like 'Jan 15 14:32:01' → ISO-8601."""
    try:
        dt = datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return ts_str
