import json

from cai_orchestrator import (
    PhishingEmailAssessmentRequest,
    PhishingEmailAssessmentResult,
    PlatformApiClient,
    create_orchestrator_app,
)

from .support import (
    FakeResponse,
    QueuedSession,
    build_phishing_email_attachment,
    build_phishing_email_payload,
    create_test_client,
)


def _make_demo_payload() -> dict[str, object]:
    return build_phishing_email_payload(
        subject="Urgent action required: verify now",
        sender_email="security.alerts@gmail.com",
        sender_display_name="Security Support",
        reply_to_email="billing@corp-payments.example",
        reply_to_display_name="Billing Desk",
        urls=["http://198.51.100.7/login?verify=1"],
        text="Immediately update your account. Payment required today.",
        attachments=[
            build_phishing_email_attachment(
                filename="invoice.zip",
                content_type="application/zip",
            )
        ],
    )


def test_platform_api_client_calls_expected_endpoint_for_phishing_email_assessment():
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
        ]
    )
    client = PlatformApiClient(base_url="http://platform-api.local", session=session)

    client.execute_phishing_email_basic_assessment(run_id="run_123", requested_by="tester")

    assert session.calls == [
        (
            "POST",
            "/runs/run_123/observations/phishing-email-basic-assessment",
            {"requested_by": "tester"},
        ),
    ]


def test_phishing_email_orchestration_flow_performs_the_correct_ordered_api_calls():
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
            FakeResponse(201, {"run": {"run_id": "run_123", "backend_ref": {"id": "phishing_email"}}}),
            FakeResponse(
                200,
                {
                    "case": {"case_id": "case_123"},
                    "run": {
                        "run_id": "run_123",
                        "backend_ref": {"id": "phishing_email"},
                        "status": "running",
                        "observation_refs": [{"id": "observation_123"}],
                        "output_artifact_refs": [{"id": "artifact_assessment"}],
                    },
                    "artifacts": [
                        {
                            "artifact_id": "artifact_assessment",
                            "subtype": "phishing_email.basic_assessment",
                        }
                    ],
                    "observation_result": {
                        "status": "succeeded",
                        "structured_summary": {"risk_level": "high"},
                    },
                },
            ),
        ]
    )
    app = create_orchestrator_app(
        platform_api_base_url="http://platform-api.local",
        session=session,
    )

    result = app.start_phishing_email_basic_assessment(
        PhishingEmailAssessmentRequest(
            title="Case",
            summary="Summary",
            payload=_make_demo_payload(),
        )
    )

    assert [call[1] for call in session.calls] == [
        "/cases",
        "/cases/case_123/artifacts/input",
        "/runs",
        "/runs/run_123/observations/phishing-email-basic-assessment",
    ]
    assert session.calls[0][2]["workflow_type"] == "defensive_analysis"
    assert session.calls[2][2]["backend_id"] == "phishing_email"
    assert session.calls[3][2] == {
        "requested_by": "cai_orchestrator",
        "input_artifact_id": "artifact_123",
    }
    assert result.case["case_id"] == "case_123"
    assert result.run["backend_ref"]["id"] == "phishing_email"
    assert result.execution["artifacts"][0]["subtype"] == "phishing_email.basic_assessment"


def test_orchestrator_can_drive_the_real_phishing_email_vertical_slice():
    test_client = create_test_client()
    app = create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=test_client,
    )

    result = app.start_phishing_email_basic_assessment(
        PhishingEmailAssessmentRequest(
            title="CAI phishing case",
            summary="Drive the phishing slice through platform-api.",
            payload=_make_demo_payload(),
        )
    )

    assert result.case["workflow_type"] == "defensive_analysis"
    assert result.input_artifact["kind"] == "input"
    assert result.run["backend_ref"]["id"] == "phishing_email"
    assert result.run == result.execution["run"]
    assert len(result.run["observation_refs"]) == 1
    assert len(result.run["output_artifact_refs"]) == 1
    assert result.execution["observation_result"]["status"] == "succeeded"
    assert result.execution["observation_result"]["structured_summary"]["risk_level"] == "high"
    assert result.execution["artifacts"][0]["subtype"] == "phishing_email.basic_assessment"


def test_orchestrator_cli_runs_the_phishing_email_basic_assessment_flow(tmp_path, monkeypatch, capsys):
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps(_make_demo_payload()), encoding="utf-8")
    captured_requests = []

    class FakeApp:
        def start_phishing_email_basic_assessment(self, request):
            captured_requests.append(request)
            return PhishingEmailAssessmentResult(
                case={"case_id": "case_123"},
                input_artifact={"artifact_id": "artifact_123"},
                run={"run_id": "run_123"},
                execution={"observation_result": {"status": "succeeded"}},
            )

        def close(self) -> None:
            return None

    import cai_orchestrator
    import cai_orchestrator.app as cai_orchestrator_app

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "run-phishing-email-basic-assessment",
            "--title",
            "CLI phishing case",
            "--summary",
            "CLI phishing summary",
            "--payload-file",
            str(payload_path),
        ]
    )

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert captured_requests[0].title == "CLI phishing case"
    assert captured_requests[0].summary == "CLI phishing summary"
    assert captured_requests[0].payload["sender"]["email"] == "security.alerts@gmail.com"
    assert json.loads(stdout)["case"]["case_id"] == "case_123"
