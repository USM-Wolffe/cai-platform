import pytest

from platform_contracts import RunStatus

from .support import (
    build_watchguard_workspace_zip_bytes,
    build_watchguard_traffic_csv_payload,
    build_watchguard_traffic_csv_row,
    build_workspace_s3_zip_payload,
    create_test_client,
)


def _create_watchguard_case_run(client, payload):
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "WatchGuard query case",
            "summary": "Case for guarded custom query execution.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": payload,
        },
    ).json()["artifact"]["artifact_id"]
    run_id = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "watchguard_logs",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]
    return case_id, artifact_id, run_id


def _create_multi_source_case_run(client, payload):
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
            "workflow_type": "log_investigation",
            "title": "Multi-source case",
            "summary": "Case for multi-source backend execution.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": payload,
        },
    ).json()["artifact"]["artifact_id"]
    run_id = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "multi_source_logs",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]
    return case_id, artifact_id, run_id


def _build_linux_auth_payload() -> dict[str, object]:
    return {
        "source_type": "linux_auth",
        "raw_log_lines": [
            "Mar 15 00:00:01 bastion sshd[1001]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2",
            "Mar 15 00:00:21 bastion sshd[1002]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2",
            "Mar 15 00:00:41 bastion sshd[1003]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2",
            "Mar 15 00:01:01 bastion sshd[1004]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2",
            "Mar 15 00:01:21 bastion sshd[1005]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2",
            "Mar 15 00:01:41 bastion sshd[1006]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2",
        ],
    }


def _build_windows_lateral_payload() -> dict[str, object]:
    return {
        "source_type": "windows_events",
        "raw_log_lines": [
            '{"EventID":4624,"TimeCreated":"2026-03-15T10:00:00Z","Computer":"ws-1","winlog":{"TargetUserName":"alice","TargetServerName":"srv-1","IpAddress":"10.0.0.10"}}',
            '{"EventID":4624,"TimeCreated":"2026-03-15T10:02:00Z","Computer":"ws-1","winlog":{"TargetUserName":"alice","TargetServerName":"srv-2","IpAddress":"10.0.0.10"}}',
            '{"EventID":4624,"TimeCreated":"2026-03-15T10:04:00Z","Computer":"ws-1","winlog":{"TargetUserName":"alice","TargetServerName":"srv-3","IpAddress":"10.0.0.10"}}',
            '{"EventID":4624,"TimeCreated":"2026-03-15T10:06:00Z","Computer":"ws-1","winlog":{"TargetUserName":"alice","TargetServerName":"srv-4","IpAddress":"10.0.0.10"}}',
        ],
    }


def _build_linux_priv_esc_payload() -> dict[str, object]:
    return {
        "source_type": "linux_auth",
        "raw_log_lines": [
            "Mar 15 00:10:00 bastion sudo: analyst : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
        ],
    }


def _build_dns_logs_payload() -> dict[str, object]:
    rows = ["timestamp,src_ip,domain,query_type,ttl"]
    rows.extend(
        f"2026-03-15T11:{minute:02d}:{second:02d}Z,10.0.0.44,{idx:02d}abcdefghi.example.com,A,60"
        for idx, (minute, second) in enumerate(((i // 60, i % 60) for i in range(51)), start=1)
    )
    return {
        "source_type": "dns_logs",
        "raw_log_lines": rows,
    }


def _build_cross_source_payload() -> dict[str, object]:
    return {
        "prior_findings": {
            "multi_source_logs.failed_auth_detect": [
                {
                    "rule_id": "brute_force_same_user",
                    "category": "brute_force",
                    "severity": "high",
                    "count": 6,
                    "evidence": {"source_ip": "203.0.113.10", "targeted_user": "admin"},
                    "summary": "Brute force detected.",
                }
            ],
            "multi_source_logs.privilege_escalation_detect": [
                {
                    "rule_id": "sudo_su_to_root",
                    "category": "priv_esc",
                    "severity": "high",
                    "count": 1,
                    "evidence": {"source_ip": "203.0.113.10", "affected_users": ["alice"]},
                    "summary": "Privilege escalation detected.",
                }
            ],
            "multi_source_logs.lateral_movement_detect": [
                {
                    "rule_id": "lateral_movement_user",
                    "category": "lateral_movement",
                    "severity": "high",
                    "count": 4,
                    "evidence": {"user": "alice"},
                    "summary": "Lateral movement detected.",
                }
            ],
        }
    }


def test_health_endpoint_works():
    client = create_test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "backend_ids": ["multi_source_logs", "phishing_email", "watchguard_logs"],
    }


def test_case_creation_works():
    client = create_test_client()

    response = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "API-created case",
            "summary": "Case created through the API.",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["case"]["workflow_type"] == "log_investigation"
    assert body["artifacts"] == []


def test_input_artifact_attachment_works():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Attach case",
            "summary": "Case for artifact attachment.",
        },
    ).json()["case"]["case_id"]

    response = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="TCP",
                        src_ip="10.0.0.1",
                        src_port=51514,
                        dst_ip="8.8.8.8",
                        dst_port=53,
                        question="dns-allow",
                    )
                ]
            ),
            "summary": "Input log payload",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["artifact"]["kind"] == "input"
    assert body["case"]["artifact_refs"][0]["id"] == body["artifact"]["artifact_id"]


def test_workspace_zip_reference_attachment_enriches_artifact_metadata():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Workspace ZIP attach case",
            "summary": "Case for S3 ZIP attachment.",
        },
    ).json()["case"]["case_id"]

    response = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_workspace_s3_zip_payload(
                workspace="acme-lab",
                s3_uri="s3://egslatam-cai-dev/workspaces/acme-lab/input/uploads/20260316_abc/logs.zip",
            ),
            "summary": "Workspace ZIP reference",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["artifact"]["metadata"]["workspace"] == "acme-lab"
    assert body["artifact"]["metadata"]["bucket"] == "egslatam-cai-dev"
    assert body["artifact"]["metadata"]["object_key"].endswith("/logs.zip")


def test_run_creation_works_for_supported_backend():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Run case",
            "summary": "Case for run creation.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="TCP",
                        src_ip="10.0.0.1",
                        src_port=51514,
                        dst_ip="8.8.8.8",
                        dst_port=53,
                        question="dns-allow",
                    )
                ]
            ),
        },
    ).json()["artifact"]["artifact_id"]

    response = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "watchguard_logs",
            "input_artifact_ids": [artifact_id],
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["run"]["backend_ref"]["id"] == "watchguard_logs"
    assert body["input_artifacts"][0]["artifact_id"] == artifact_id


def test_run_creation_works_for_multi_source_logs_backend():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
            "workflow_type": "log_investigation",
            "title": "Multi-source run case",
            "summary": "Case for multi-source run creation.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": _build_linux_auth_payload(),
        },
    ).json()["artifact"]["artifact_id"]

    response = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "multi_source_logs",
            "input_artifact_ids": [artifact_id],
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["run"]["backend_ref"]["id"] == "multi_source_logs"
    assert body["input_artifacts"][0]["artifact_id"] == artifact_id


def test_unsupported_backend_fails_clearly():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Unsupported backend case",
            "summary": "Case for unsupported backend.",
        },
    ).json()["case"]["case_id"]

    response = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "missing_backend",
        },
    )

    assert response.status_code == 404
    assert response.json()["error"]["type"] == "not_found"


def test_first_predefined_observation_executes_through_the_api_path():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Execute observation case",
            "summary": "Case for the first backend slice.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="TCP",
                        src_ip="10.0.0.1",
                        src_port=51514,
                        dst_ip="8.8.8.8",
                        dst_port=53,
                        question="dns-allow",
                    )
                ]
            ),
        },
    ).json()["artifact"]["artifact_id"]
    run_id = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "watchguard_logs",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]

    execute_response = client.post(
        f"/runs/{run_id}/observations/watchguard-normalize",
        json={"requested_by": "test_client"},
    )

    assert execute_response.status_code == 200
    execute_body = execute_response.json()
    assert execute_body["observation_result"]["status"] == "succeeded"
    assert execute_body["observation_result"]["structured_summary"]["input_shape"] == "traffic_csv_export"
    assert execute_body["artifacts"][0]["kind"] == "normalized"
    assert execute_body["artifacts"][0]["metadata"]["input_shape"] == "traffic_csv_export"

    case_response = client.get(f"/cases/{case_id}")
    run_response = client.get(f"/runs/{run_id}")

    assert case_response.status_code == 200
    assert run_response.status_code == 200
    case_body = case_response.json()
    run_body = run_response.json()
    assert len(case_body["artifacts"]) == 2
    assert len(run_body["output_artifacts"]) == 1
    assert run_body["observation_results"][0]["status"] == "succeeded"


def test_run_completion_endpoint_marks_run_completed_and_is_idempotent():
    client = create_test_client()
    _, _, run_id = _create_watchguard_case_run(
        client,
        build_watchguard_traffic_csv_payload(
            [
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:00",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="TCP",
                    src_ip="10.0.0.1",
                    src_port=51514,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    question="dns-allow",
                )
            ]
        ),
    )

    response = client.post(
        f"/runs/{run_id}/complete",
        json={"requested_by": "tester", "reason": "Manual triage finished."},
    )
    second_response = client.post(
        f"/runs/{run_id}/complete",
        json={"requested_by": "tester", "reason": "Manual triage finished."},
    )

    assert response.status_code == 200
    assert response.json()["run"]["status"] == "completed"
    assert response.json()["case"]["timeline"][-1]["kind"] == "run_completed"
    assert second_response.status_code == 200
    assert second_response.json()["run"]["status"] == "completed"


def test_run_completion_endpoint_rejects_invalid_terminal_status():
    client = create_test_client()
    _, _, run_id = _create_watchguard_case_run(
        client,
        build_watchguard_traffic_csv_payload(
            [
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:00",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="TCP",
                    src_ip="10.0.0.1",
                    src_port=51514,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    question="dns-allow",
                )
            ]
        ),
    )

    runtime = client.app.state.runtime
    run = runtime.run_repository.get_run(run_id)
    runtime.run_repository.save_run(run.model_copy(update={"status": RunStatus.CANCELLED}))

    response = client.post(
        f"/runs/{run_id}/complete",
        json={"requested_by": "tester", "reason": "Should fail."},
    )

    assert response.status_code == 409
    assert response.json()["error"]["type"] == "invalid_state"


@pytest.mark.parametrize(
    ("payload_builder", "path_suffix", "expected_subtype"),
    [
        (_build_linux_auth_payload, "multi-source-logs-normalize", "multi_source_logs.normalize"),
        (_build_linux_auth_payload, "multi-source-logs-failed-auth-detect", "multi_source_logs.failed_auth_detect"),
        (_build_windows_lateral_payload, "multi-source-logs-lateral-movement-detect", "multi_source_logs.lateral_movement_detect"),
        (_build_linux_priv_esc_payload, "multi-source-logs-privilege-escalation-detect", "multi_source_logs.privilege_escalation_detect"),
        (_build_dns_logs_payload, "multi-source-logs-dns-anomaly-detect", "multi_source_logs.dns_anomaly_detect"),
        (_build_cross_source_payload, "multi-source-logs-cross-source-correlate", "multi_source_logs.cross_source_correlate"),
    ],
)
def test_multi_source_log_routes_execute_through_the_api_path(payload_builder, path_suffix, expected_subtype):
    client = create_test_client()
    case_id, _, run_id = _create_multi_source_case_run(client, payload_builder())

    execute_response = client.post(
        f"/runs/{run_id}/observations/{path_suffix}",
        json={"requested_by": "test_client"},
    )

    assert execute_response.status_code == 200
    execute_body = execute_response.json()
    assert execute_body["run"]["backend_ref"]["id"] == "multi_source_logs"
    assert execute_body["artifacts"][0]["subtype"] == expected_subtype

    case_response = client.get(f"/cases/{case_id}")
    run_response = client.get(f"/runs/{run_id}")

    assert case_response.status_code == 200
    assert run_response.status_code == 200
    assert run_response.json()["run"]["run_id"] == run_id


def test_workspace_zip_ingestion_executes_through_the_api_path(monkeypatch):
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Workspace ZIP case",
            "summary": "Case for workspace ZIP ingestion.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_workspace_s3_zip_payload(
                workspace="acme-lab",
                s3_uri="s3://egslatam-cai-dev/workspaces/acme-lab/input/uploads/20260316_abc/logs.zip",
            ),
        },
    ).json()["artifact"]["artifact_id"]
    run_id = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "watchguard_logs",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]

    monkeypatch.setattr(
        "platform_backends.watchguard_logs.execute._download_s3_object",
        lambda bucket, object_key: build_watchguard_workspace_zip_bytes(
            traffic_rows=[
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:00",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="TCP",
                    src_ip="10.0.0.1",
                    src_port=51514,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                ),
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:01",
                    action="DENY",
                    policy="deny-web",
                    protocol="UDP",
                    src_ip="10.0.0.2",
                    src_port=51515,
                    dst_ip="1.1.1.1",
                    dst_port=53,
                ),
            ],
            event_rows=[
                "2025-10-23T09:26:52,FWStatus,ev,FW_PL1_CL_PRI,FW_XTM_PRI,loggerd,\\N,10976070,3D01-0003,Archived log file /var/log/traffic.log which reached max size",
            ],
            alarm_rows=[
                "2025-10-22T09:00:03,Notify,al,FW_PL1_CL_PRI,FW_XTM_PRI,firewall,6,\\N,39632546,3000-0155,udp_flood_dos,email,Wed Oct 22 06:00:03 2025 (-03),UDP flood attack against 8.8.8.8 from 172.26.25.56 detected.",
            ],
        ),
    )

    ingest_response = client.post(
        f"/runs/{run_id}/observations/watchguard-ingest-workspace-zip",
        json={"requested_by": "test_client"},
    )

    assert ingest_response.status_code == 200
    ingest_body = ingest_response.json()
    assert ingest_body["observation_result"]["status"] == "succeeded"
    assert ingest_body["observation_result"]["structured_summary"]["family_counts"]["traffic"]["record_count"] == 2
    assert len(ingest_body["artifacts"]) == 4
    traffic_artifact_id = next(
        artifact["artifact_id"] for artifact in ingest_body["artifacts"] if artifact["subtype"] == "watchguard.workspace_zip.traffic"
    )

    analytics_response = client.post(
        f"/runs/{run_id}/observations/watchguard-analytics-basic",
        json={"requested_by": "test_client", "input_artifact_id": traffic_artifact_id},
    )

    assert analytics_response.status_code == 200
    analytics_body = analytics_response.json()
    assert analytics_body["observation_result"]["structured_summary"]["record_count"] == 2


def test_invalid_payload_shape_fails_clearly():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Invalid payload case",
            "summary": "Case for invalid payload testing.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_watchguard_traffic_csv_payload(
                [
                    "15/03/2026 00:00,,,,,ALLOW,allow-web,,TCP,,,10.0.0.1,not-a-port,8.8.8.8,53"
                ]
            ),
        },
    ).json()["artifact"]["artifact_id"]
    run_id = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "watchguard_logs",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]

    response = client.post(f"/runs/{run_id}/observations/watchguard-normalize")

    assert response.status_code == 400
    body = response.json()
    assert body["error"]["type"] == "backend_execution_failed"
    assert body["observation_result"]["status"] == "failed"
    assert "invalid 'src_port'" in body["observation_result"]["errors"][0]


def test_second_predefined_observation_executes_through_the_api_path():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Execute denied filter case",
            "summary": "Case for the second backend slice.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="TCP",
                        src_ip="10.0.0.1",
                        src_port=51514,
                        dst_ip="8.8.8.8",
                        dst_port=53,
                        question="dns-allow",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:01",
                        action="DENY",
                        policy="deny-dns",
                        protocol="UDP",
                        src_ip="10.0.0.2",
                        src_port=51515,
                        dst_ip="1.1.1.1",
                        dst_port=53,
                        question="dns-blocked",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:02",
                        action="blocked",
                        policy="block-rdp",
                        protocol="TCP",
                        src_ip="10.0.0.3",
                        src_port=51516,
                        dst_ip="9.9.9.9",
                        dst_port=3389,
                        question="rdp-blocked",
                    ),
                ]
            ),
        },
    ).json()["artifact"]["artifact_id"]
    run_id = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "watchguard_logs",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]

    execute_response = client.post(
        f"/runs/{run_id}/observations/watchguard-filter-denied",
        json={"requested_by": "test_client"},
    )

    assert execute_response.status_code == 200
    execute_body = execute_response.json()
    assert execute_body["observation_result"]["status"] == "succeeded"
    assert execute_body["observation_result"]["structured_summary"]["record_count"] == 2
    assert execute_body["observation_result"]["structured_summary"]["summary"] == "Filtered 2 denied WatchGuard log records."
    assert execute_body["observation_result"]["structured_summary"]["input_shape"] == "traffic_csv_export"
    assert execute_body["artifacts"][0]["kind"] == "normalized"
    assert execute_body["artifacts"][0]["subtype"] == "watchguard.denied_events"


def test_basic_analytics_bundle_executes_through_the_api_path():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Execute analytics case",
            "summary": "Case for the analytics bundle slice.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="TCP",
                        src_ip="10.0.0.1",
                        src_port=51514,
                        dst_ip="8.8.8.8",
                        dst_port=53,
                        question="dns-allow",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:01",
                        action="DENY",
                        policy="deny-dns",
                        protocol="UDP",
                        src_ip="10.0.0.2",
                        src_port=51515,
                        dst_ip="9.9.9.9",
                        dst_port=53,
                        question="dns-blocked",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:02",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="UDP",
                        src_ip="10.0.0.1",
                        src_port=51516,
                        dst_ip="9.9.9.9",
                        dst_port=443,
                        question="https-allow",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:03",
                        action="blocked",
                        policy="block-rdp",
                        protocol="TCP",
                        src_ip="10.0.0.2",
                        src_port=51517,
                        dst_ip="8.8.8.8",
                        dst_port=3389,
                        question="rdp-blocked",
                    ),
                ]
            ),
        },
    ).json()["artifact"]["artifact_id"]
    run_id = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "watchguard_logs",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]

    execute_response = client.post(
        f"/runs/{run_id}/observations/watchguard-analytics-basic",
        json={"requested_by": "test_client"},
    )

    assert execute_response.status_code == 200
    execute_body = execute_response.json()
    assert execute_body["observation_result"]["status"] == "succeeded"
    assert execute_body["observation_result"]["structured_summary"]["record_count"] == 4
    assert execute_body["observation_result"]["structured_summary"]["top_source_ip"] == {
        "ip": "10.0.0.1",
        "count": 2,
    }
    assert execute_body["artifacts"][0]["kind"] == "analysis_output"
    assert execute_body["artifacts"][0]["subtype"] == "watchguard.analytics_bundle_basic"
    assert execute_body["artifacts"][0]["metadata"]["protocol_breakdown"] == [
        {"protocol": "tcp", "count": 2},
        {"protocol": "udp", "count": 2},
    ]

    run_response = client.get(f"/runs/{run_id}")
    assert run_response.status_code == 200
    assert run_response.json()["output_artifacts"][0]["kind"] == "analysis_output"


def test_top_talkers_basic_executes_through_the_api_path():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Execute top talkers case",
            "summary": "Case for the top talkers slice.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="TCP",
                        src_ip="10.0.0.2",
                        src_port=51514,
                        dst_ip="8.8.8.8",
                        dst_port=53,
                        question="dns-allow",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:01",
                        action="DENY",
                        policy="deny-dns",
                        protocol="UDP",
                        src_ip="10.0.0.1",
                        src_port=51515,
                        dst_ip="1.1.1.1",
                        dst_port=53,
                        question="dns-blocked",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:02",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="UDP",
                        src_ip="10.0.0.1",
                        src_port=51516,
                        dst_ip="9.9.9.9",
                        dst_port=443,
                        question="https-allow",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:03",
                        action="blocked",
                        policy="block-rdp",
                        protocol="TCP",
                        src_ip="10.0.0.2",
                        src_port=51517,
                        dst_ip="1.1.1.1",
                        dst_port=3389,
                        question="rdp-blocked",
                    ),
                ]
            ),
        },
    ).json()["artifact"]["artifact_id"]
    run_id = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "watchguard_logs",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]

    execute_response = client.post(
        f"/runs/{run_id}/observations/watchguard-top-talkers-basic",
        json={"requested_by": "test_client"},
    )

    assert execute_response.status_code == 200
    execute_body = execute_response.json()
    assert execute_body["observation_result"]["status"] == "succeeded"
    assert execute_body["observation_result"]["structured_summary"]["record_count"] == 4
    assert execute_body["observation_result"]["structured_summary"]["top_source_ip"] == {
        "ip": "10.0.0.1",
        "count": 2,
    }
    assert execute_body["observation_result"]["structured_summary"]["top_pair"] == {
        "src_ip": "10.0.0.1",
        "dst_ip": "1.1.1.1",
        "count": 1,
    }
    assert execute_body["artifacts"][0]["kind"] == "analysis_output"
    assert execute_body["artifacts"][0]["subtype"] == "watchguard.top_talkers_basic"
    assert execute_body["artifacts"][0]["metadata"]["top_destination_ips"] == [
        {"ip": "1.1.1.1", "count": 2},
        {"ip": "8.8.8.8", "count": 1},
        {"ip": "9.9.9.9", "count": 1},
    ]


def test_run_status_artifacts_and_artifact_content_are_readable_for_current_slice():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
            "client_id": "test-client",
                "workflow_type": "log_investigation",
            "title": "Operational surface case",
            "summary": "Case for status and artifact inspection.",
        },
    ).json()["case"]["case_id"]
    artifact_id = client.post(
        f"/cases/{case_id}/artifacts/input",
        json={
            "format": "json",
            "payload": build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="TCP",
                        src_ip="10.0.0.1",
                        src_port=51514,
                        dst_ip="8.8.8.8",
                        dst_port=53,
                        question="dns-allow",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:01",
                        action="DENY",
                        policy="deny-dns",
                        protocol="UDP",
                        src_ip="10.0.0.2",
                        src_port=51515,
                        dst_ip="1.1.1.1",
                        dst_port=53,
                        question="dns-blocked",
                    ),
                ]
            ),
        },
    ).json()["artifact"]["artifact_id"]
    run_id = client.post(
        "/runs",
        json={
            "case_id": case_id,
            "backend_id": "watchguard_logs",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]

    execute_response = client.post(
        f"/runs/{run_id}/observations/watchguard-analytics-basic",
        json={"requested_by": "test_client"},
    )
    produced_artifact_id = execute_response.json()["artifacts"][0]["artifact_id"]

    status_response = client.get(f"/runs/{run_id}/status")
    artifacts_response = client.get(f"/runs/{run_id}/artifacts")
    content_response = client.get(f"/artifacts/{produced_artifact_id}/content")

    assert status_response.status_code == 200
    assert status_response.json()["run"]["status"] == "running"
    assert status_response.json()["summary"] == {
        "input_artifact_count": 1,
        "output_artifact_count": 1,
        "observation_result_count": 1,
    }

    assert artifacts_response.status_code == 200
    artifacts_body = artifacts_response.json()
    assert artifacts_body["run"]["run_id"] == run_id
    assert artifacts_body["input_artifacts"][0]["artifact_id"] == artifact_id
    assert artifacts_body["output_artifacts"][0]["artifact_id"] == produced_artifact_id
    assert artifacts_body["output_artifacts"][0]["kind"] == "analysis_output"

    assert content_response.status_code == 200
    content_body = content_response.json()
    assert content_body["artifact"]["artifact_id"] == produced_artifact_id
    assert content_body["content_source"] == "derived_artifact_payload"
    assert content_body["content"]["record_count"] == 2
    assert content_body["content"]["top_source_ips"][0] == {"ip": "10.0.0.1", "count": 1}


def test_invalid_run_or_artifact_ids_fail_clearly_for_operational_surface():
    client = create_test_client()

    status_response = client.get("/runs/missing_run/status")
    artifacts_response = client.get("/runs/missing_run/artifacts")
    content_response = client.get("/artifacts/missing_artifact/content")

    assert status_response.status_code == 404
    assert status_response.json()["error"]["type"] == "not_found"
    assert artifacts_response.status_code == 404
    assert artifacts_response.json()["error"]["type"] == "not_found"
    assert content_response.status_code == 404
    assert content_response.json()["error"]["type"] == "not_found"


def test_guarded_custom_query_executes_through_the_api_path():
    client = create_test_client()
    _, _, run_id = _create_watchguard_case_run(
        client,
        build_watchguard_traffic_csv_payload(
            [
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:00",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="TCP",
                    src_ip="10.0.0.1",
                    src_port=51514,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    question="dns-allow",
                ),
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:01",
                    action="DENY",
                    policy="deny-dns",
                    protocol="UDP",
                    src_ip="10.0.0.1",
                    src_port=51515,
                    dst_ip="1.1.1.1",
                    dst_port=53,
                    question="dns-blocked",
                ),
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:02",
                    action="ALLOW",
                    policy="allow-https",
                    protocol="TCP",
                    src_ip="10.0.0.3",
                    src_port=51516,
                    dst_ip="9.9.9.9",
                    dst_port=443,
                    question="https-allow",
                ),
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:03",
                    action="ALLOW",
                    policy="allow-dns",
                    protocol="UDP",
                    src_ip="10.0.0.1",
                    src_port=51517,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    question="dns-allow-late",
                ),
            ]
        ),
    )

    response = client.post(
        f"/runs/{run_id}/queries/watchguard-guarded-filtered-rows",
        json={
            "requested_by": "test_client",
            "reason": "Investigate one source IP through the guarded query slice.",
            "query": {
                "filters": [
                    {
                        "field": "src_ip",
                        "op": "eq",
                        "value": "10.0.0.1",
                    }
                ],
                "limit": 2,
            },
            "approval": {
                "status": "approved",
                "reason": "Human approved this narrow guarded query.",
                "approver_kind": "human_operator",
                "approver_ref": "operator_123",
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["run"]["status"] == "running"
    assert body["query_request"]["query_mode"] == "custom_guarded"
    assert body["approval_decision"]["status"] == "approved"
    assert body["artifacts"][0]["kind"] == "query_result"
    assert body["artifacts"][0]["subtype"] == "watchguard.guarded_filtered_rows"
    assert body["query_summary"] == {
        "query_class": "watchguard_logs.guarded_filtered_rows",
        "record_count": 3,
        "returned_row_count": 2,
        "limit": 2,
        "truncated": True,
        "top_row": {
            "timestamp": "2026-03-15T00:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "action": "allow",
            "protocol": "tcp",
            "policy": "allow-web",
            "src_port": 51514,
            "dst_port": 53,
            "question": "dns-allow",
            "record_type": "traffic",
        },
        "summary": "Returned 2 WatchGuard rows for the guarded custom query (matched 3, limit 2).",
    }

    artifact_id = body["artifacts"][0]["artifact_id"]
    content_response = client.get(f"/artifacts/{artifact_id}/content")

    assert content_response.status_code == 200
    content_body = content_response.json()
    assert content_body["content_source"] == "derived_artifact_payload"
    assert content_body["content"]["returned_row_count"] == 2
    assert [row["timestamp"] for row in content_body["content"]["rows"]] == [
        "2026-03-15T00:00:00Z",
        "2026-03-15T00:01:00Z",
    ]


def test_guarded_custom_query_requires_explicit_approval():
    client = create_test_client()
    _, _, run_id = _create_watchguard_case_run(
        client,
        build_watchguard_traffic_csv_payload(
            [
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:00",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="TCP",
                    src_ip="10.0.0.1",
                    src_port=51514,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    question="dns-allow",
                )
            ]
        ),
    )

    response = client.post(
        f"/runs/{run_id}/queries/watchguard-guarded-filtered-rows",
        json={
            "requested_by": "test_client",
            "reason": "Try running guarded query without approval.",
            "query": {
                "filters": [
                    {
                        "field": "src_ip",
                        "op": "eq",
                        "value": "10.0.0.1",
                    }
                ],
                "limit": 5,
            },
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["type"] == "approval_required"


def test_guarded_custom_query_rejects_invalid_approval_status():
    client = create_test_client()
    _, _, run_id = _create_watchguard_case_run(
        client,
        build_watchguard_traffic_csv_payload(
            [
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:00",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="TCP",
                    src_ip="10.0.0.1",
                    src_port=51514,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    question="dns-allow",
                )
            ]
        ),
    )

    response = client.post(
        f"/runs/{run_id}/queries/watchguard-guarded-filtered-rows",
        json={
            "requested_by": "test_client",
            "reason": "Try running guarded query with rejected approval.",
            "query": {
                "filters": [
                    {
                        "field": "src_ip",
                        "op": "eq",
                        "value": "10.0.0.1",
                    }
                ],
                "limit": 5,
            },
            "approval": {
                "status": "rejected",
                "reason": "Not allowed.",
                "approver_kind": "human_operator",
            },
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["type"] == "approval_required"


def test_guarded_custom_query_rejects_disallowed_field():
    client = create_test_client()
    _, _, run_id = _create_watchguard_case_run(
        client,
        build_watchguard_traffic_csv_payload(
            [
                build_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:00",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="TCP",
                    src_ip="10.0.0.1",
                    src_port=51514,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    question="dns-allow",
                )
            ]
        ),
    )

    response = client.post(
        f"/runs/{run_id}/queries/watchguard-guarded-filtered-rows",
        json={
            "requested_by": "test_client",
            "reason": "Try a disallowed guarded query field.",
            "query": {
                "filters": [
                    {
                        "field": "dst_port",
                        "op": "eq",
                        "value": "53",
                    }
                ],
                "limit": 5,
            },
            "approval": {
                "status": "approved",
                "reason": "Approved for validation.",
                "approver_kind": "human_operator",
            },
        },
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"]["type"] == "backend_execution_error"
    assert "field 'dst_port' is not allowed" in body["error"]["message"]
