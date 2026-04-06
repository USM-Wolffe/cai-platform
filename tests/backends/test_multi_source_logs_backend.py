from __future__ import annotations

from platform_contracts import Artifact, ArtifactKind, EntityKind, EntityRef, ObservationRequest, ObservationStatus, Run
from platform_backends.multi_source_logs import (
    MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION,
    MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION,
    MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION,
    MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION,
    MULTI_SOURCE_LOGS_NORMALIZE_OPERATION,
    MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION,
    MultiSourceDetectionFinding,
    NormalizedLogRecord,
    execute_predefined_observation,
)
from platform_backends.multi_source_logs.detections import (
    correlate_cross_source,
    detect_dns_anomaly,
    detect_failed_auth,
    detect_lateral_movement,
    detect_privilege_escalation,
)
from platform_backends.multi_source_logs.normalizer import normalize_log_lines


def _make_run() -> Run:
    return Run(
        run_id="run_multi_source",
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="multi_source_logs"),
        case_ref=EntityRef(entity_type=EntityKind.CASE, id="case_multi_source"),
    )


def _make_input_artifact() -> Artifact:
    return Artifact(
        artifact_id="artifact_input",
        kind=ArtifactKind.INPUT,
        format="json",
        storage_ref="memory://artifact_input.json",
        content_hash="sha256:artifact_input",
    )


def _make_observation_request(operation_kind: str) -> ObservationRequest:
    return ObservationRequest(
        observation_id=f"observation_{operation_kind.split('.')[-1]}",
        case_ref=EntityRef(entity_type=EntityKind.CASE, id="case_multi_source"),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id="multi_source_logs"),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id="run_multi_source"),
        operation_kind=operation_kind,
        requested_by="tester",
    )


def _make_record(
    *,
    timestamp: str,
    event_type: str,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    dest_host: str | None = None,
    user: str | None = None,
    process_name: str | None = None,
    details_json: str = "{}",
) -> NormalizedLogRecord:
    return NormalizedLogRecord(
        timestamp=timestamp,
        event_type=event_type,
        source_host=None,
        dest_host=dest_host,
        source_ip=source_ip,
        dest_ip=dest_ip,
        user=user,
        action=event_type,
        status=None,
        process_name=process_name,
        details_json=details_json,
    )


def test_normalize_log_lines_supports_each_source_type():
    cases = [
        (
            "windows_events",
            ['{"EventID":4625,"TimeCreated":"2026-03-15T10:00:00Z","Computer":"dc-1","winlog":{"TargetUserName":"alice","IpAddress":"203.0.113.10"}}'],
            "failed_logon",
        ),
        (
            "linux_auth",
            ["Mar 15 10:00:00 bastion sshd[1001]: Failed password for invalid user alice from 203.0.113.10 port 22 ssh2"],
            "failed_logon",
        ),
        (
            "dns_logs",
            ["timestamp,src_ip,domain,query_type,ttl", "2026-03-15T10:00:00Z,10.0.0.44,alpha.example.com,A,60"],
            "dns_query",
        ),
        (
            "firewall_csv",
            ["timestamp,src_ip,dst_ip,action,user", "2026-03-15T10:00:00Z,10.0.0.10,10.0.0.20,allow,alice"],
            "logon",
        ),
        (
            "web_proxy",
            ["1710496800.123 200 10.0.0.44 TCP_MISS/200 512 GET http://example.com/login"],
            "http_request",
        ),
    ]

    for source_type, lines, expected_event_type in cases:
        records = normalize_log_lines(source_type, lines)

        assert len(records) == 1
        assert records[0].event_type == expected_event_type


def test_detect_failed_auth_identifies_brute_force_and_lockout():
    records = [
        _make_record(
            timestamp=f"2026-03-15T10:00:0{idx}Z",
            event_type="failed_logon",
            source_ip="203.0.113.10",
            user="alice",
        )
        for idx in range(6)
    ]
    records.append(
        _make_record(
            timestamp="2026-03-15T10:00:30Z",
            event_type="account_locked",
            source_ip="203.0.113.10",
            user="alice",
        )
    )

    findings = detect_failed_auth(records)
    rule_ids = {finding.rule_id for finding in findings}

    assert "brute_force_same_user" in rule_ids
    assert "account_lockout" in rule_ids


def test_detect_lateral_movement_identifies_host_hopping():
    records = [
        _make_record(
            timestamp=f"2026-03-15T10:0{idx}:00Z",
            event_type="logon",
            source_ip="10.0.0.10",
            user="alice",
            dest_host=f"srv-{idx}",
        )
        for idx in range(4)
    ]

    findings = detect_lateral_movement(records)

    assert findings[0].rule_id == "lateral_movement_user"
    assert findings[0].evidence["user"] == "alice"


def test_detect_privilege_escalation_identifies_after_hours_sudo_use():
    records = [
        _make_record(
            timestamp="2026-03-15T01:10:00Z",
            event_type="sudo_use",
            source_ip="10.0.0.10",
            user="analyst",
            process_name="/bin/bash root",
        )
    ]

    findings = detect_privilege_escalation(records)
    rule_ids = {finding.rule_id for finding in findings}

    assert "priv_esc_after_hours" in rule_ids
    assert "sudo_su_to_root" in rule_ids


def test_detect_dns_anomaly_identifies_dga_activity():
    records = [
        _make_record(
            timestamp=f"2026-03-15T11:{minute:02d}:{second:02d}Z",
            event_type="dns_query",
            source_ip="10.0.0.44",
            details_json=f'{{"domain":"{idx:02d}a1b2c3d4e5f6.example.com"}}',
        )
        for idx, (minute, second) in enumerate(((i // 60, i % 60) for i in range(51)), start=1)
    ]

    findings = detect_dns_anomaly(records)

    assert findings[0].rule_id == "dga_indicator"
    assert findings[0].evidence["source_ip"] == "10.0.0.44"


def test_correlate_cross_source_identifies_multi_stage_attack():
    findings = correlate_cross_source(
        {
            MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION: [
                MultiSourceDetectionFinding(
                    rule_id="brute_force_same_user",
                    category="brute_force",
                    severity="high",
                    count=6,
                    evidence={"source_ip": "203.0.113.10", "targeted_user": "alice"},
                )
            ],
            MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION: [
                MultiSourceDetectionFinding(
                    rule_id="sudo_su_to_root",
                    category="priv_esc",
                    severity="high",
                    count=1,
                    evidence={"source_ip": "203.0.113.10", "affected_users": ["alice"]},
                )
            ],
            MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION: [
                MultiSourceDetectionFinding(
                    rule_id="lateral_movement_user",
                    category="lateral_movement",
                    severity="high",
                    count=4,
                    evidence={"user": "alice"},
                )
            ],
        }
    )
    rule_ids = {finding.rule_id for finding in findings}

    assert "multi_stage_attack" in rule_ids
    assert "compromised_or_insider" in rule_ids


def test_execute_predefined_observation_supports_all_multi_source_operations():
    cases = [
        (
            MULTI_SOURCE_LOGS_NORMALIZE_OPERATION,
            {
                "source_type": "linux_auth",
                "raw_log_lines": [
                    "Mar 15 10:00:00 bastion sshd[1001]: Failed password for invalid user alice from 203.0.113.10 port 22 ssh2",
                ],
            },
        ),
        (
            MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION,
            {
                "source_type": "linux_auth",
                "raw_log_lines": [
                    "Mar 15 10:00:00 bastion sshd[1001]: Failed password for invalid user alice from 203.0.113.10 port 22 ssh2",
                    "Mar 15 10:00:10 bastion sshd[1002]: Failed password for invalid user alice from 203.0.113.10 port 22 ssh2",
                    "Mar 15 10:00:20 bastion sshd[1003]: Failed password for invalid user alice from 203.0.113.10 port 22 ssh2",
                    "Mar 15 10:00:30 bastion sshd[1004]: Failed password for invalid user alice from 203.0.113.10 port 22 ssh2",
                    "Mar 15 10:00:40 bastion sshd[1005]: Failed password for invalid user alice from 203.0.113.10 port 22 ssh2",
                    "Mar 15 10:00:50 bastion sshd[1006]: Failed password for invalid user alice from 203.0.113.10 port 22 ssh2",
                ],
            },
        ),
        (
            MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION,
            {
                "source_type": "windows_events",
                "raw_log_lines": [
                    '{"EventID":4624,"TimeCreated":"2026-03-15T10:00:00Z","Computer":"ws-1","winlog":{"TargetUserName":"alice","TargetServerName":"srv-1","IpAddress":"10.0.0.10"}}',
                    '{"EventID":4624,"TimeCreated":"2026-03-15T10:02:00Z","Computer":"ws-1","winlog":{"TargetUserName":"alice","TargetServerName":"srv-2","IpAddress":"10.0.0.10"}}',
                    '{"EventID":4624,"TimeCreated":"2026-03-15T10:04:00Z","Computer":"ws-1","winlog":{"TargetUserName":"alice","TargetServerName":"srv-3","IpAddress":"10.0.0.10"}}',
                    '{"EventID":4624,"TimeCreated":"2026-03-15T10:06:00Z","Computer":"ws-1","winlog":{"TargetUserName":"alice","TargetServerName":"srv-4","IpAddress":"10.0.0.10"}}',
                ],
            },
        ),
        (
            MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION,
            {
                "source_type": "linux_auth",
                "raw_log_lines": [
                    "Mar 15 01:10:00 bastion sudo: analyst : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
                ],
            },
        ),
        (
            MULTI_SOURCE_LOGS_DNS_ANOMALY_OPERATION,
            {
                "source_type": "dns_logs",
                "raw_log_lines": ["timestamp,src_ip,domain,query_type,ttl"]
                + [
                    f"2026-03-15T11:{minute:02d}:{second:02d}Z,10.0.0.44,{idx:02d}a1b2c3d4e5f6.example.com,A,60"
                    for idx, (minute, second) in enumerate(((i // 60, i % 60) for i in range(51)), start=1)
                ],
            },
        ),
        (
            MULTI_SOURCE_LOGS_CROSS_SOURCE_OPERATION,
            {
                "prior_findings": {
                    MULTI_SOURCE_LOGS_FAILED_AUTH_OPERATION: [
                        {
                            "rule_id": "brute_force_same_user",
                            "category": "brute_force",
                            "severity": "high",
                            "count": 6,
                            "evidence": {"source_ip": "203.0.113.10", "targeted_user": "alice"},
                        }
                    ],
                    MULTI_SOURCE_LOGS_PRIV_ESC_OPERATION: [
                        {
                            "rule_id": "sudo_su_to_root",
                            "category": "priv_esc",
                            "severity": "high",
                            "count": 1,
                            "evidence": {"source_ip": "203.0.113.10", "affected_users": ["alice"]},
                        }
                    ],
                    MULTI_SOURCE_LOGS_LATERAL_MOVEMENT_OPERATION: [
                        {
                            "rule_id": "lateral_movement_user",
                            "category": "lateral_movement",
                            "severity": "high",
                            "count": 4,
                            "evidence": {"user": "alice"},
                        }
                    ],
                }
            },
        ),
    ]

    for operation_kind, input_payload in cases:
        outcome = execute_predefined_observation(
            run=_make_run(),
            input_artifact=_make_input_artifact(),
            input_payload=input_payload,
            observation_request=_make_observation_request(operation_kind),
        )

        assert outcome.observation_result.status in {
            ObservationStatus.SUCCEEDED,
            ObservationStatus.SUCCEEDED_NO_FINDINGS,
        }
        assert outcome.artifacts[0].subtype == operation_kind
