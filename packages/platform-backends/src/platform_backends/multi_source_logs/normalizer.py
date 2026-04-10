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
    "watchguard_traffic",
    "watchguard_alarm",
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
        "watchguard_traffic": _parse_watchguard_traffic,
        "watchguard_alarm": _parse_watchguard_alarm,
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


# ── WatchGuard Traffic CSV ────────────────────────────────────────────────────

# Positional columns (no headers):
# 0=timestamp, 1=event_subtype(FWAllow/FWDeny/FWAllowEnd), 5=action(Allow/Deny),
# 8=protocol(dns/udp/https/tcp), 11=src_ip, 12=src_port, 13=dst_ip, 14=dst_port,
# 21=dns_type, 22=dns_domain

_WG_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _parse_watchguard_traffic(lines: list[str]) -> list[NormalizedLogRecord]:
    """Parse WatchGuard traffic CSV (positional, no header row)."""
    records: list[NormalizedLogRecord] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        cols = line.split(",")
        if len(cols) < 14:
            continue
        ts_raw = cols[0].strip()
        event_subtype = cols[1].strip() if len(cols) > 1 else ""
        action = cols[5].strip() if len(cols) > 5 else ""
        protocol = cols[8].strip().lower() if len(cols) > 8 else ""
        src_ip = cols[11].strip() if len(cols) > 11 else None
        src_port = cols[12].strip() if len(cols) > 12 else None
        dst_ip = cols[13].strip() if len(cols) > 13 else None
        dst_port = cols[14].strip() if len(cols) > 14 else None
        dns_domain = cols[22].strip() if len(cols) > 22 else None

        ts_iso = _normalize_timestamp(ts_raw)

        # Map event_subtype/protocol to event_type understood by detection algorithms:
        # - dns queries → dns_query (picked up by detect_dns_anomaly)
        # - FWDeny/Deny → failed_logon (picked up by detect_failed_auth for flood detection)
        # - FWAllow/Allow → logon (picked up by detect_lateral_movement for scanning)
        if protocol == "dns" and dns_domain:
            event_type = "dns_query"
        elif event_subtype == "FWDeny" or action.lower() == "deny":
            event_type = "failed_logon"
        elif event_subtype in ("FWAllow", "FWAllowEnd") or action.lower() == "allow":
            event_type = "logon"
        else:
            event_type = "unknown"

        details: dict[str, object] = {
            "event_subtype": event_subtype,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "action": action,
        }
        if dns_domain:
            details["domain"] = dns_domain
            details["query_type"] = cols[21].strip() if len(cols) > 21 else None

        records.append(NormalizedLogRecord(
            timestamp=ts_iso,
            event_type=event_type,
            source_host=None,
            dest_host=None,
            source_ip=src_ip or None,
            dest_ip=dst_ip or None,
            user=None,
            action=action or None,
            status=None,
            process_name=None,
            details_json=json.dumps(details),
        ))
    return records


# ── WatchGuard Alarm CSV ──────────────────────────────────────────────────────

# Positional columns (no headers):
# 0=timestamp, 10=alarm_type(udp_flood_dos/ddos_attack_src_dos/ip_scan_dos/Block-Site-Notif),
# 13=description(free text — may contain IP addresses)

def _parse_watchguard_alarm(lines: list[str]) -> list[NormalizedLogRecord]:
    """Parse WatchGuard alarm CSV (positional, no header row)."""
    records: list[NormalizedLogRecord] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        cols = line.split(",")
        if len(cols) < 11:
            continue
        ts_raw = cols[0].strip()
        alarm_type = cols[10].strip() if len(cols) > 10 else "unknown"
        description = cols[13].strip() if len(cols) > 13 else ""

        ts_iso = _normalize_timestamp(ts_raw)

        # Extract IPs from the free-text description field
        extracted_ips = _WG_IP_RE.findall(description)

        details: dict[str, object] = {
            "alarm_type": alarm_type,
            "description": description[:300],
            "extracted_ips": extracted_ips[:10],
        }

        records.append(NormalizedLogRecord(
            timestamp=ts_iso,
            event_type="threat_alert",
            source_host=None,
            dest_host=None,
            source_ip=extracted_ips[0] if extracted_ips else None,
            dest_ip=extracted_ips[1] if len(extracted_ips) > 1 else None,
            user=None,
            action=alarm_type,
            status=None,
            process_name=None,
            details_json=json.dumps(details),
        ))
    return records


# ── Staged S3 workspace reader ────────────────────────────────────────────────

def download_staging_lines(
    staging_prefix: str,
    source_type: str,
    bucket: str,
    region: str,
    max_rows: int = 50_000,
) -> list[str]:
    """Read log lines from a staged WatchGuard S3 workspace.

    For watchguard_traffic: uses DuckDB to sample up to max_rows rows from
    all CSVs under {staging_prefix}/traffic/ (files can be 300 MB+ each).
    For watchguard_alarm: reads all CSVs under {staging_prefix}/alarm/ via
    boto3 (files are typically < 1 MB).

    Returns raw CSV lines (no header) as a list of strings.
    """
    try:
        import boto3
    except ImportError as exc:
        raise MultiSourceLogsBackendError(
            "boto3 is required to read staged workspace data from S3."
        ) from exc

    s3 = boto3.client("s3", region_name=region)

    if source_type == "watchguard_traffic":
        return _download_traffic_staging(s3, staging_prefix, bucket, region, max_rows)
    elif source_type == "watchguard_alarm":
        return _download_alarm_staging(s3, staging_prefix, bucket)
    else:
        raise MultiSourceLogsBackendError(
            f"download_staging_lines only supports watchguard_traffic and watchguard_alarm, "
            f"got '{source_type}'"
        )


def _download_traffic_staging(s3, staging_prefix: str, bucket: str, region: str, max_rows: int) -> list[str]:
    """Sample traffic CSV lines from staged workspace using DuckDB.

    Files are stored under {staging_prefix}/traffic/{date}/*.csv (date sub-folders),
    so we enumerate them via boto3 first, then pass the explicit list to DuckDB.
    """
    try:
        import duckdb
    except ImportError as exc:
        raise MultiSourceLogsBackendError(
            "duckdb is required to read staged traffic data. Install it or use raw_log_lines."
        ) from exc

    # Enumerate all CSV files recursively under traffic/
    prefix = f"{staging_prefix}/traffic/"
    paginator = s3.get_paginator("list_objects_v2")
    files: list[str] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith((".csv", ".txt")):
                files.append(f"s3://{bucket}/{key}")

    if not files:
        raise MultiSourceLogsBackendError(
            f"No traffic CSV files found under s3://{bucket}/{prefix}"
        )

    con = duckdb.connect()
    try:
        con.execute("INSTALL httpfs; LOAD httpfs;")
        con.execute(f"SET s3_region='{region}';")
        # Propagate boto3 credentials (IAM role, env vars, ~/.aws/credentials)
        try:
            import boto3 as _boto3
            _creds = _boto3.Session().get_credentials()
            if _creds is not None:
                _frozen = _creds.get_frozen_credentials()
                con.execute(f"SET s3_access_key_id='{_frozen.access_key}';")
                con.execute(f"SET s3_secret_access_key='{_frozen.secret_key}';")
                if _frozen.token:
                    con.execute(f"SET s3_session_token='{_frozen.token}';")
        except Exception:
            pass
        result = con.execute(
            f"SELECT * FROM read_csv({files!r}, header=false, "
            f"ignore_errors=true) LIMIT {max_rows}"
        ).fetchall()
    except Exception as exc:
        raise MultiSourceLogsBackendError(
            f"DuckDB failed to read traffic CSV files: {exc}"
        ) from exc
    finally:
        con.close()

    lines: list[str] = []
    for row in result:
        lines.append(",".join("" if v is None else str(v) for v in row))
    return lines


def _download_alarm_staging(s3, staging_prefix: str, bucket: str) -> list[str]:
    """Read all alarm CSV lines from staged workspace via boto3."""
    prefix = f"{staging_prefix}/alarm/"
    paginator = s3.get_paginator("list_objects_v2")
    lines: list[str] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".csv"):
                continue
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            lines.extend(body.decode("utf-8", errors="replace").splitlines())
    return lines


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
