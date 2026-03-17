import pytest

from cai_orchestrator import (
    InvalidOperatorInputError,
    OrchestrationFlowError,
    PlatformApiClient,
    WatchGuardGuardedQueryRequest,
    WatchGuardInvestigationRequest,
    create_orchestrator_app,
)

from .support import (
    FakeResponse,
    QueuedSession,
    build_watchguard_traffic_csv_payload,
    build_watchguard_traffic_csv_row,
    create_test_client,
)


def test_platform_api_client_calls_expected_endpoints_for_the_first_slice():
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"status": "ok"}),
            FakeResponse(201, {"case": {"case_id": "case_123"}}),
            FakeResponse(201, {"case": {"case_id": "case_123"}, "artifact": {"artifact_id": "artifact_123"}}),
            FakeResponse(201, {"run": {"run_id": "run_123"}}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
            FakeResponse(200, {"case": {"case_id": "case_123"}}),
            FakeResponse(200, {"run": {"run_id": "run_123"}}),
        ]
    )
    client = PlatformApiClient(base_url="http://platform-api.local", session=session)

    client.health()
    client.create_case(
        workflow_type="log_investigation",
        title="Case",
        summary="Summary",
    )
    client.attach_input_artifact(
        case_id="case_123",
        payload=build_watchguard_traffic_csv_payload(
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
    client.create_run(case_id="case_123", backend_id="watchguard_logs", input_artifact_ids=["artifact_123"])
    client.execute_watchguard_normalize(run_id="run_123", requested_by="tester")
    client.get_case(case_id="case_123")
    client.get_run(run_id="run_123")

    assert session.calls == [
        ("GET", "/health", None),
        (
            "POST",
            "/cases",
            {"workflow_type": "log_investigation", "title": "Case", "summary": "Summary", "metadata": {}},
        ),
        (
            "POST",
            "/cases/case_123/artifacts/input",
            {
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
                "summary": None,
                "labels": [],
                "metadata": {},
            },
        ),
        (
            "POST",
            "/runs",
            {
                "case_id": "case_123",
                "backend_id": "watchguard_logs",
                "input_artifact_ids": ["artifact_123"],
                "scope": {},
            },
        ),
        (
            "POST",
            "/runs/run_123/observations/watchguard-normalize",
            {"requested_by": "tester"},
        ),
        ("GET", "/cases/case_123", None),
        ("GET", "/runs/run_123", None),
    ]


def test_platform_api_client_calls_expected_endpoint_for_denied_filter_slice():
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
        ]
    )
    client = PlatformApiClient(base_url="http://platform-api.local", session=session)

    client.execute_watchguard_filter_denied(run_id="run_123", requested_by="tester")

    assert session.calls == [
        (
            "POST",
            "/runs/run_123/observations/watchguard-filter-denied",
            {"requested_by": "tester"},
        ),
    ]


def test_platform_api_client_calls_expected_endpoint_for_workspace_zip_ingestion_slice():
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
        ]
    )
    client = PlatformApiClient(base_url="http://platform-api.local", session=session)

    client.execute_watchguard_workspace_zip_ingestion(run_id="run_123", requested_by="tester")

    assert session.calls == [
        (
            "POST",
            "/runs/run_123/observations/watchguard-ingest-workspace-zip",
            {"requested_by": "tester"},
        ),
    ]


def test_platform_api_client_calls_expected_endpoint_for_basic_analytics_slice():
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
        ]
    )
    client = PlatformApiClient(base_url="http://platform-api.local", session=session)

    client.execute_watchguard_analytics_basic(run_id="run_123", requested_by="tester")

    assert session.calls == [
        (
            "POST",
            "/runs/run_123/observations/watchguard-analytics-basic",
            {"requested_by": "tester"},
        ),
    ]


def test_platform_api_client_calls_expected_endpoint_for_top_talkers_slice():
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
        ]
    )
    client = PlatformApiClient(base_url="http://platform-api.local", session=session)

    client.execute_watchguard_top_talkers_basic(run_id="run_123", requested_by="tester")

    assert session.calls == [
        (
            "POST",
            "/runs/run_123/observations/watchguard-top-talkers-basic",
            {"requested_by": "tester"},
        ),
    ]


def test_platform_api_client_calls_expected_endpoint_for_guarded_custom_query_slice():
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"query_summary": {"record_count": 2}}),
        ]
    )
    client = PlatformApiClient(base_url="http://platform-api.local", session=session)

    client.execute_watchguard_guarded_custom_query(
        run_id="run_123",
        query={
            "filters": [{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}],
            "limit": 5,
        },
        reason="Investigate one source IP.",
        approval={
            "status": "approved",
            "reason": "Human approved this query.",
            "approver_kind": "human_operator",
        },
        requested_by="tester",
    )

    assert session.calls == [
        (
            "POST",
            "/runs/run_123/queries/watchguard-guarded-filtered-rows",
            {
                "requested_by": "tester",
                "query": {
                    "filters": [{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}],
                    "limit": 5,
                },
                "reason": "Investigate one source IP.",
                "approval": {
                    "status": "approved",
                    "reason": "Human approved this query.",
                    "approver_kind": "human_operator",
                },
            },
        ),
    ]


def test_platform_api_client_calls_expected_operational_endpoints():
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"run": {"run_id": "run_123", "status": "running"}}),
            FakeResponse(200, {"input_artifacts": [], "output_artifacts": []}),
            FakeResponse(200, {"artifact": {"artifact_id": "artifact_123"}, "content": {"record_count": 2}}),
        ]
    )
    client = PlatformApiClient(base_url="http://platform-api.local", session=session)

    client.get_run_status(run_id="run_123")
    client.list_run_artifacts(run_id="run_123")
    client.read_artifact_content(artifact_id="artifact_123")

    assert session.calls == [
        ("GET", "/runs/run_123/status", None),
        ("GET", "/runs/run_123/artifacts", None),
        ("GET", "/artifacts/artifact_123/content", None),
    ]


def test_first_orchestration_flow_performs_the_correct_ordered_api_calls():
    session = QueuedSession(
        responses=[
            FakeResponse(201, {"case": {"case_id": "case_123", "title": "Case"}}),
            FakeResponse(
                201,
                {
                    "case": {"case_id": "case_123"},
                    "artifact": {"artifact_id": "artifact_123", "kind": "input"},
                },
            ),
            FakeResponse(201, {"run": {"run_id": "run_123", "backend_ref": {"id": "watchguard_logs"}}}),
            FakeResponse(
                200,
                {
                    "case": {"case_id": "case_123"},
                    "run": {
                        "run_id": "run_123",
                        "backend_ref": {"id": "watchguard_logs"},
                        "status": "running",
                        "observation_refs": [{"id": "observation_123"}],
                        "output_artifact_refs": [{"id": "artifact_norm"}],
                    },
                    "artifacts": [{"artifact_id": "artifact_norm"}],
                    "observation_result": {"status": "succeeded"},
                },
            ),
        ]
    )
    app = create_orchestrator_app(
        platform_api_base_url="http://platform-api.local",
        session=session,
    )

    result = app.start_watchguard_log_investigation(
        WatchGuardInvestigationRequest(
            title="Case",
            summary="Summary",
            payload=build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="TCP",
                        src_ip="1.1.1.1",
                        src_port=51514,
                        dst_ip="2.2.2.2",
                        dst_port=443,
                        question="https-allow",
                    )
                ]
            ),
        )
    )

    assert [call[1] for call in session.calls] == [
        "/cases",
        "/cases/case_123/artifacts/input",
        "/runs",
        "/runs/run_123/observations/watchguard-normalize",
    ]
    assert result.case["case_id"] == "case_123"
    assert result.input_artifact["artifact_id"] == "artifact_123"
    assert result.run["run_id"] == "run_123"
    assert result.run == result.execution["run"]
    assert result.run["status"] == "running"
    assert result.run["observation_refs"][0]["id"] == "observation_123"
    assert result.run["output_artifact_refs"][0]["id"] == "artifact_norm"
    assert result.execution["observation_result"]["status"] == "succeeded"


def test_structured_failure_from_platform_api_is_surfaced_clearly():
    session = QueuedSession(
        responses=[
            FakeResponse(201, {"case": {"case_id": "case_123"}}),
            FakeResponse(201, {"case": {"case_id": "case_123"}, "artifact": {"artifact_id": "artifact_123"}}),
            FakeResponse(201, {"run": {"run_id": "run_123"}}),
            FakeResponse(
                400,
                {
                    "error": {
                        "type": "backend_execution_failed",
                        "message": "missing required fields",
                    },
                    "observation_result": {"status": "failed"},
                },
            ),
        ]
    )
    app = create_orchestrator_app(
        platform_api_base_url="http://platform-api.local",
        session=session,
    )

    with pytest.raises(OrchestrationFlowError) as exc_info:
        app.start_watchguard_log_investigation(
            WatchGuardInvestigationRequest(
                title="Case",
                summary="Summary",
                payload=build_watchguard_traffic_csv_payload(
                    [
                        "15/03/2026 00:00,,,,,ALLOW,allow-web,,TCP,,,10.0.0.1,not-a-port,8.8.8.8,53"
                    ]
                ),
            )
        )

    error = exc_info.value
    assert error.phase == "execute_observation"
    assert error.status_code == 400
    assert error.details["error"]["type"] == "backend_execution_failed"


def test_second_orchestration_flow_performs_the_correct_ordered_api_calls():
    session = QueuedSession(
        responses=[
            FakeResponse(201, {"case": {"case_id": "case_123", "title": "Case"}}),
            FakeResponse(
                201,
                {
                    "case": {"case_id": "case_123"},
                    "artifact": {"artifact_id": "artifact_123", "kind": "input"},
                },
            ),
            FakeResponse(201, {"run": {"run_id": "run_123", "backend_ref": {"id": "watchguard_logs"}}}),
            FakeResponse(
                200,
                {
                    "case": {"case_id": "case_123"},
                    "run": {
                        "run_id": "run_123",
                        "backend_ref": {"id": "watchguard_logs"},
                        "status": "running",
                        "observation_refs": [{"id": "observation_123"}],
                        "output_artifact_refs": [{"id": "artifact_denied"}],
                    },
                    "artifacts": [{"artifact_id": "artifact_denied", "subtype": "watchguard.denied_events"}],
                    "observation_result": {
                        "status": "succeeded",
                        "structured_summary": {"record_count": 2},
                    },
                },
            ),
        ]
    )
    app = create_orchestrator_app(
        platform_api_base_url="http://platform-api.local",
        session=session,
    )

    result = app.start_watchguard_denied_events_investigation(
        WatchGuardInvestigationRequest(
            title="Case",
            summary="Summary",
            payload=build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="DENY",
                        policy="deny-web",
                        protocol="TCP",
                        src_ip="1.1.1.1",
                        src_port=51514,
                        dst_ip="2.2.2.2",
                        dst_port=443,
                        question="https-denied",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:01",
                        action="ALLOW",
                        policy="allow-dns",
                        protocol="UDP",
                        src_ip="3.3.3.3",
                        src_port=51515,
                        dst_ip="4.4.4.4",
                        dst_port=53,
                        question="dns-allow",
                    ),
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:02",
                        action="blocked",
                        policy="block-rdp",
                        protocol="TCP",
                        src_ip="5.5.5.5",
                        src_port=51516,
                        dst_ip="6.6.6.6",
                        dst_port=3389,
                        question="rdp-blocked",
                    ),
                ]
            ),
        )
    )

    assert [call[1] for call in session.calls] == [
        "/cases",
        "/cases/case_123/artifacts/input",
        "/runs",
        "/runs/run_123/observations/watchguard-filter-denied",
    ]
    assert result.run == result.execution["run"]
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.denied_events"
    assert result.execution["observation_result"]["structured_summary"]["record_count"] == 2


def test_third_orchestration_flow_performs_the_correct_ordered_api_calls():
    session = QueuedSession(
        responses=[
            FakeResponse(201, {"case": {"case_id": "case_123", "title": "Case"}}),
            FakeResponse(
                201,
                {
                    "case": {"case_id": "case_123"},
                    "artifact": {"artifact_id": "artifact_123", "kind": "input"},
                },
            ),
            FakeResponse(201, {"run": {"run_id": "run_123", "backend_ref": {"id": "watchguard_logs"}}}),
            FakeResponse(
                200,
                {
                    "case": {"case_id": "case_123"},
                    "run": {
                        "run_id": "run_123",
                        "backend_ref": {"id": "watchguard_logs"},
                        "status": "running",
                        "observation_refs": [{"id": "observation_123"}],
                        "output_artifact_refs": [{"id": "artifact_analytics"}],
                    },
                    "artifacts": [
                        {
                            "artifact_id": "artifact_analytics",
                            "subtype": "watchguard.analytics_bundle_basic",
                            "kind": "analysis_output",
                        }
                    ],
                    "observation_result": {
                        "status": "succeeded",
                        "structured_summary": {
                            "record_count": 4,
                            "top_source_ip": {"ip": "10.0.0.1", "count": 2},
                        },
                    },
                },
            ),
        ]
    )
    app = create_orchestrator_app(
        platform_api_base_url="http://platform-api.local",
        session=session,
    )

    result = app.start_watchguard_analytics_bundle_investigation(
        WatchGuardInvestigationRequest(
            title="Case",
            summary="Summary",
            payload=build_watchguard_traffic_csv_payload(
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
    )

    assert [call[1] for call in session.calls] == [
        "/cases",
        "/cases/case_123/artifacts/input",
        "/runs",
        "/runs/run_123/observations/watchguard-analytics-basic",
    ]
    assert result.run == result.execution["run"]
    assert result.execution["artifacts"][0]["kind"] == "analysis_output"
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.analytics_bundle_basic"
    assert result.execution["observation_result"]["structured_summary"]["top_source_ip"] == {
        "ip": "10.0.0.1",
        "count": 2,
    }


def test_fourth_orchestration_flow_performs_the_correct_ordered_api_calls():
    session = QueuedSession(
        responses=[
            FakeResponse(201, {"case": {"case_id": "case_123", "title": "Case"}}),
            FakeResponse(
                201,
                {
                    "case": {"case_id": "case_123"},
                    "artifact": {"artifact_id": "artifact_123", "kind": "input"},
                },
            ),
            FakeResponse(201, {"run": {"run_id": "run_123", "backend_ref": {"id": "watchguard_logs"}}}),
            FakeResponse(
                200,
                {
                    "case": {"case_id": "case_123"},
                    "run": {
                        "run_id": "run_123",
                        "backend_ref": {"id": "watchguard_logs"},
                        "status": "running",
                        "observation_refs": [{"id": "observation_123"}],
                        "output_artifact_refs": [{"id": "artifact_top_talkers"}],
                    },
                    "artifacts": [
                        {
                            "artifact_id": "artifact_top_talkers",
                            "subtype": "watchguard.top_talkers_basic",
                            "kind": "analysis_output",
                        }
                    ],
                    "observation_result": {
                        "status": "succeeded",
                        "structured_summary": {
                            "record_count": 4,
                            "top_source_ip": {"ip": "10.0.0.1", "count": 2},
                            "top_pair": {"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "count": 1},
                        },
                    },
                },
            ),
        ]
    )
    app = create_orchestrator_app(
        platform_api_base_url="http://platform-api.local",
        session=session,
    )

    result = app.start_watchguard_top_talkers_basic_investigation(
        WatchGuardInvestigationRequest(
            title="Case",
            summary="Summary",
            payload=build_watchguard_traffic_csv_payload(
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
                ]
            ),
        )
    )

    assert [call[1] for call in session.calls] == [
        "/cases",
        "/cases/case_123/artifacts/input",
        "/runs",
        "/runs/run_123/observations/watchguard-top-talkers-basic",
    ]
    assert result.run == result.execution["run"]
    assert result.execution["artifacts"][0]["kind"] == "analysis_output"
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.top_talkers_basic"
    assert result.execution["observation_result"]["structured_summary"]["top_pair"] == {
        "src_ip": "10.0.0.1",
        "dst_ip": "1.1.1.1",
        "count": 1,
    }


def test_guarded_custom_query_flow_performs_the_correct_ordered_api_calls():
    session = QueuedSession(
        responses=[
            FakeResponse(201, {"case": {"case_id": "case_123", "title": "Case"}}),
            FakeResponse(
                201,
                {
                    "case": {"case_id": "case_123"},
                    "artifact": {"artifact_id": "artifact_123", "kind": "input"},
                },
            ),
            FakeResponse(201, {"run": {"run_id": "run_123", "backend_ref": {"id": "watchguard_logs"}}}),
            FakeResponse(
                200,
                {
                    "case": {"case_id": "case_123"},
                    "run": {
                        "run_id": "run_123",
                        "backend_ref": {"id": "watchguard_logs"},
                        "status": "running",
                        "output_artifact_refs": [{"id": "artifact_query"}],
                    },
                    "query_request": {
                        "query_request_id": "queryreq_123",
                        "query_mode": "custom_guarded",
                    },
                    "approval_decision": {
                        "approval_id": "approval_123",
                        "status": "approved",
                    },
                    "artifacts": [{"artifact_id": "artifact_query", "kind": "query_result"}],
                    "query_summary": {
                        "query_class": "watchguard_logs.guarded_filtered_rows",
                        "record_count": 2,
                        "returned_row_count": 2,
                    },
                },
            ),
        ]
    )
    app = create_orchestrator_app(
        platform_api_base_url="http://platform-api.local",
        session=session,
    )

    result = app.start_watchguard_guarded_query_investigation(
        WatchGuardGuardedQueryRequest(
            title="Case",
            summary="Summary",
            payload=build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="ALLOW",
                        policy="allow-web",
                        protocol="TCP",
                        src_ip="10.0.0.1",
                        src_port=51514,
                        dst_ip="2.2.2.2",
                        dst_port=443,
                        question="https-allow",
                    )
                ]
            ),
            query={
                "filters": [{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}],
                "limit": 5,
            },
            reason="Investigate one source IP.",
            approval_reason="Human approved this narrow query.",
        )
    )

    assert [call[1] for call in session.calls] == [
        "/cases",
        "/cases/case_123/artifacts/input",
        "/runs",
        "/runs/run_123/queries/watchguard-guarded-filtered-rows",
    ]
    assert session.calls[-1][2]["approval"]["status"] == "approved"
    assert result.run == result.execution["run"]
    assert result.execution["artifacts"][0]["kind"] == "query_result"
    assert result.execution["query_summary"]["query_class"] == "watchguard_logs.guarded_filtered_rows"


def test_orchestrator_can_drive_the_real_platform_api_vertical_slice():
    test_client = create_test_client()
    app = create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=test_client,
    )

    result = app.start_watchguard_log_investigation(
        WatchGuardInvestigationRequest(
            title="CAI orchestrator case",
            summary="Drive the first platform slice through platform-api.",
            payload=build_watchguard_traffic_csv_payload(
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
    )

    assert result.case["workflow_type"] == "log_investigation"
    assert result.input_artifact["kind"] == "input"
    assert result.run["backend_ref"]["id"] == "watchguard_logs"
    assert result.run == result.execution["run"]
    assert result.run["status"] == result.execution["run"]["status"]
    assert len(result.run["observation_refs"]) == 1
    assert len(result.run["output_artifact_refs"]) == 1
    assert result.execution["observation_result"]["status"] == "succeeded"
    assert result.execution["observation_result"]["structured_summary"]["input_shape"] == "traffic_csv_export"
    assert result.execution["artifacts"][0]["kind"] == "normalized"


def test_orchestrator_can_drive_the_real_denied_filter_vertical_slice():
    test_client = create_test_client()
    app = create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=test_client,
    )

    result = app.start_watchguard_denied_events_investigation(
        WatchGuardInvestigationRequest(
            title="CAI denied filter case",
            summary="Drive the denied-event filter slice through platform-api.",
            payload=build_watchguard_traffic_csv_payload(
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
        )
    )

    assert result.run["backend_ref"]["id"] == "watchguard_logs"
    assert result.run == result.execution["run"]
    assert result.execution["observation_result"]["status"] == "succeeded"
    assert result.execution["observation_result"]["structured_summary"]["record_count"] == 2
    assert result.execution["observation_result"]["structured_summary"]["input_shape"] == "traffic_csv_export"
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.denied_events"


def test_orchestrator_can_drive_the_real_basic_analytics_vertical_slice():
    test_client = create_test_client()
    app = create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=test_client,
    )

    result = app.start_watchguard_analytics_bundle_investigation(
        WatchGuardInvestigationRequest(
            title="CAI analytics case",
            summary="Drive the basic analytics slice through platform-api.",
            payload=build_watchguard_traffic_csv_payload(
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
        )
    )

    assert result.run["backend_ref"]["id"] == "watchguard_logs"
    assert result.run == result.execution["run"]
    assert result.execution["observation_result"]["status"] == "succeeded"
    assert result.execution["observation_result"]["structured_summary"]["top_source_ip"] == {
        "ip": "10.0.0.1",
        "count": 2,
    }
    assert result.execution["artifacts"][0]["kind"] == "analysis_output"
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.analytics_bundle_basic"


def test_orchestrator_can_drive_the_real_top_talkers_vertical_slice():
    test_client = create_test_client()
    app = create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=test_client,
    )

    result = app.start_watchguard_top_talkers_basic_investigation(
        WatchGuardInvestigationRequest(
            title="CAI top talkers case",
            summary="Drive the top talkers slice through platform-api.",
            payload=build_watchguard_traffic_csv_payload(
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
        )
    )

    assert result.run["backend_ref"]["id"] == "watchguard_logs"
    assert result.run == result.execution["run"]
    assert result.execution["observation_result"]["status"] == "succeeded"
    assert result.execution["observation_result"]["structured_summary"]["top_source_ip"] == {
        "ip": "10.0.0.1",
        "count": 2,
    }
    assert result.execution["observation_result"]["structured_summary"]["top_pair"] == {
        "src_ip": "10.0.0.1",
        "dst_ip": "1.1.1.1",
        "count": 1,
    }
    assert result.execution["artifacts"][0]["kind"] == "analysis_output"
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.top_talkers_basic"


def test_orchestrator_can_drive_the_real_guarded_custom_query_vertical_slice():
    test_client = create_test_client()
    app = create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=test_client,
    )

    result = app.start_watchguard_guarded_query_investigation(
        WatchGuardGuardedQueryRequest(
            title="CAI guarded query case",
            summary="Drive the guarded custom query slice through platform-api.",
            payload=build_watchguard_traffic_csv_payload(
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
                ]
            ),
            query={
                "filters": [{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}],
                "limit": 5,
            },
            reason="Investigate source IP 10.0.0.1.",
            approval_reason="Human approved this narrow guarded query.",
        )
    )

    assert result.run["backend_ref"]["id"] == "watchguard_logs"
    assert result.run == result.execution["run"]
    assert result.execution["query_request"]["query_mode"] == "custom_guarded"
    assert result.execution["approval_decision"]["status"] == "approved"
    assert result.execution["query_summary"]["query_class"] == "watchguard_logs.guarded_filtered_rows"
    assert result.execution["query_summary"]["record_count"] == 2
    assert result.execution["artifacts"][0]["kind"] == "query_result"
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.guarded_filtered_rows"


def test_orchestrator_can_read_operational_surface_through_platform_api():
    test_client = create_test_client()
    app = create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=test_client,
    )

    result = app.start_watchguard_analytics_bundle_investigation(
        WatchGuardInvestigationRequest(
            title="Operational read case",
            summary="Create a run and inspect it through operational endpoints.",
            payload=build_watchguard_traffic_csv_payload(
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
    )

    status_payload = app.get_run_status(run_id=result.run["run_id"])
    artifacts_payload = app.list_run_artifacts(run_id=result.run["run_id"])
    content_payload = app.read_artifact_content(
        artifact_id=result.execution["artifacts"][0]["artifact_id"]
    )

    assert status_payload["run"]["run_id"] == result.run["run_id"]
    assert status_payload["summary"]["output_artifact_count"] == 1
    assert artifacts_payload["output_artifacts"][0]["artifact_id"] == result.execution["artifacts"][0]["artifact_id"]
    assert content_payload["artifact"]["artifact_id"] == result.execution["artifacts"][0]["artifact_id"]
    assert content_payload["content_source"] == "derived_artifact_payload"


def test_invalid_operator_input_fails_before_any_api_call():
    session = QueuedSession(responses=[])
    app = create_orchestrator_app(
        platform_api_base_url="http://platform-api.local",
        session=session,
    )

    with pytest.raises(InvalidOperatorInputError):
        app.start_watchguard_log_investigation(
            WatchGuardInvestigationRequest(
                title=" ",
                summary="Summary",
                payload={"records": []},
            )
        )

    assert session.calls == []
