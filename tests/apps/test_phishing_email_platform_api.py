from .support import (
    build_phishing_email_attachment,
    build_phishing_email_payload,
    create_test_client,
)


def _create_phishing_case_run(client, payload):
    case_id = client.post(
        "/cases",
        json={
            "workflow_type": "defensive_analysis",
            "title": "Phishing query case",
            "summary": "Case for phishing assessment execution.",
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
            "backend_id": "phishing_email",
            "input_artifact_ids": [artifact_id],
        },
    ).json()["run"]["run_id"]
    return case_id, artifact_id, run_id


def test_phishing_email_basic_assessment_executes_through_the_api_path():
    client = create_test_client()
    payload = build_phishing_email_payload(
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
    case_id, artifact_id, run_id = _create_phishing_case_run(client, payload)

    execute_response = client.post(
        f"/runs/{run_id}/observations/phishing-email-basic-assessment",
        json={"requested_by": "test_client", "input_artifact_id": artifact_id},
    )

    assert execute_response.status_code == 200
    execute_body = execute_response.json()
    assert execute_body["observation_result"]["status"] == "succeeded"
    assert execute_body["observation_result"]["structured_summary"]["risk_level"] == "high"
    assert execute_body["observation_result"]["structured_summary"]["risk_score"] == 12
    assert execute_body["artifacts"][0]["kind"] == "analysis_output"
    assert execute_body["artifacts"][0]["subtype"] == "phishing_email.basic_assessment"
    assert execute_body["artifacts"][0]["metadata"]["signal_count"] == 6
    assert execute_body["artifacts"][0]["metadata"]["triggered_rules"][0]["rule_id"] == "sender_reply_to_mismatch"
    assert execute_body["artifacts"][0]["metadata"]["suspicious_urls"][0]["reasons"] == [
        "uses a non-https scheme",
        "uses an IP-literal host",
        "contains 'login' in the path or query",
        "contains 'verify' in the path or query",
    ]

    case_response = client.get(f"/cases/{case_id}")
    run_response = client.get(f"/runs/{run_id}")

    assert case_response.status_code == 200
    assert run_response.status_code == 200
    assert len(case_response.json()["artifacts"]) == 2
    assert len(run_response.json()["output_artifacts"]) == 1
    assert run_response.json()["output_artifacts"][0]["subtype"] == "phishing_email.basic_assessment"


def test_phishing_email_basic_assessment_returns_no_findings_through_the_api_path():
    client = create_test_client()
    payload = build_phishing_email_payload(
        subject="Quarterly planning notes",
        sender_email="teammate@example.com",
        sender_display_name="Teammate",
        reply_to_email="teammate@example.com",
        reply_to_display_name="Teammate",
        urls=["https://portal.example.com/team-notes"],
        text="Please review the attached planning notes before tomorrow's meeting.",
        attachments=[
            build_phishing_email_attachment(
                filename="planning-notes.pdf",
                content_type="application/pdf",
            )
        ],
    )
    _, artifact_id, run_id = _create_phishing_case_run(client, payload)

    execute_response = client.post(
        f"/runs/{run_id}/observations/phishing-email-basic-assessment",
        json={"requested_by": "test_client", "input_artifact_id": artifact_id},
    )

    assert execute_response.status_code == 200
    execute_body = execute_response.json()
    assert execute_body["observation_result"]["status"] == "succeeded_no_findings"
    assert execute_body["observation_result"]["structured_summary"] == {
        "risk_level": "none",
        "risk_score": 0,
        "signal_count": 0,
        "triggered_rule_ids": [],
        "suspicious_url_count": 0,
        "summary": "No phishing signals were detected in the provided email artifact.",
    }
    assert execute_body["artifacts"][0]["metadata"]["triggered_rules"] == []


def test_phishing_email_basic_assessment_invalid_shape_fails_clearly_through_the_api_path():
    client = create_test_client()
    _, artifact_id, run_id = _create_phishing_case_run(
        client,
        {
            "subject": "Broken payload",
            "sender": {"email": "sender@example.com"},
            "reply_to": None,
            "urls": [],
            "text": "Body",
            "attachments": "invoice.zip",
        },
    )

    response = client.post(
        f"/runs/{run_id}/observations/phishing-email-basic-assessment",
        json={"requested_by": "test_client", "input_artifact_id": artifact_id},
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"]["type"] == "backend_execution_failed"
    assert body["observation_result"]["status"] == "failed"
    assert "'attachments' must be a list" in body["observation_result"]["errors"][0]
