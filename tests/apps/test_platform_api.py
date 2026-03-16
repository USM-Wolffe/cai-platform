from .support import (
    build_watchguard_traffic_csv_payload,
    build_watchguard_traffic_csv_row,
    create_test_client,
)


def _create_watchguard_case_run(client, payload):
    case_id = client.post(
        "/cases",
        json={
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


def test_health_endpoint_works():
    client = create_test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "backend_ids": ["phishing_email", "watchguard_logs"],
    }


def test_case_creation_works():
    client = create_test_client()

    response = client.post(
        "/cases",
        json={
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


def test_run_creation_works_for_supported_backend():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
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


def test_unsupported_backend_fails_clearly():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
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


def test_invalid_payload_shape_fails_clearly():
    client = create_test_client()
    case_id = client.post(
        "/cases",
        json={
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
