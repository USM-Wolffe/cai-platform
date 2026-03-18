from __future__ import annotations

import builtins
import json
import sys
import types

import pytest

import cai_orchestrator

from .support import (
    FakeResponse,
    QueuedSession,
    build_watchguard_traffic_csv_payload,
    build_watchguard_traffic_csv_row,
    build_workspace_s3_zip_payload,
)


def test_cai_integration_settings_defaults_and_env_overrides(monkeypatch):
    monkeypatch.delenv("PLATFORM_API_BASE_URL", raising=False)
    monkeypatch.delenv("CAI_AGENT_TYPE", raising=False)
    monkeypatch.delenv("CAI_MODEL", raising=False)

    defaults = cai_orchestrator.load_cai_integration_settings()

    assert defaults.platform_api_base_url == cai_orchestrator.DEFAULT_PLATFORM_API_BASE_URL
    assert defaults.cai_agent_type == cai_orchestrator.DEFAULT_CAI_AGENT_TYPE
    assert defaults.cai_model is None

    monkeypatch.setenv("PLATFORM_API_BASE_URL", "http://platform-api.local")
    monkeypatch.setenv("CAI_AGENT_TYPE", "platform_investigation_agent")
    monkeypatch.setenv("CAI_MODEL", "gpt-5.4-mini")

    configured = cai_orchestrator.load_cai_integration_settings()

    assert configured.platform_api_base_url == "http://platform-api.local"
    assert configured.cai_agent_type == "platform_investigation_agent"
    assert configured.cai_model == "gpt-5.4-mini"


def test_platform_api_tool_service_calls_expected_endpoints(tmp_path):
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(
        json.dumps(
            build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="16/03/2026 00:00",
                        action="DENY",
                        policy="deny-dns",
                        protocol="UDP",
                        src_ip="10.0.0.1",
                        src_port=51514,
                        dst_ip="8.8.8.8",
                        dst_port=53,
                        question="dns-blocked",
                    )
                ]
            )
        ),
        encoding="utf-8",
    )
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"status": "ok"}),
            FakeResponse(201, {"case": {"case_id": "case_123"}}),
            FakeResponse(201, {"artifact": {"artifact_id": "artifact_123"}}),
            FakeResponse(201, {"run": {"run_id": "run_123"}}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
            FakeResponse(200, {"query_summary": {"record_count": 1}}),
            FakeResponse(200, {"case": {"case_id": "case_123"}}),
            FakeResponse(200, {"run": {"run_id": "run_123"}}),
            FakeResponse(200, {"run": {"run_id": "run_123", "status": "running"}}),
            FakeResponse(200, {"input_artifacts": [], "output_artifacts": []}),
            FakeResponse(200, {"artifact": {"artifact_id": "artifact_123"}, "content": {"record_count": 2}}),
        ]
    )
    service = cai_orchestrator.PlatformApiToolService(
        platform_api_client=cai_orchestrator.PlatformApiClient(
            base_url="http://platform-api.local",
            session=session,
        )
    )

    service.health()
    service.create_case(
        workflow_type="log_investigation",
        title="Case",
        summary="Summary",
    )
    service.attach_input_artifact(
        case_id="case_123",
        payload_path=str(payload_path),
        summary="CAI payload",
        labels=["demo"],
        metadata={"source": "test"},
    )
    service.create_run(
        case_id="case_123",
        backend_id="watchguard_logs",
        input_artifact_ids=["artifact_123"],
    )
    service.execute_watchguard_workspace_zip_ingestion(run_id="run_123", requested_by="cai_terminal")
    service.execute_watchguard_normalize(run_id="run_123", requested_by="cai_terminal")
    service.execute_watchguard_filter_denied(run_id="run_123", requested_by="cai_terminal")
    service.execute_watchguard_analytics_basic(run_id="run_123", requested_by="cai_terminal")
    service.execute_watchguard_top_talkers_basic(run_id="run_123", requested_by="cai_terminal")
    service.execute_watchguard_guarded_custom_query(
        run_id="run_123",
        query={"filters": [{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}], "limit": 5},
        reason="Investigate one source IP.",
        approval_reason="Human approved this narrow query.",
        requested_by="cai_terminal",
    )
    service.get_case(case_id="case_123")
    service.get_run(run_id="run_123")
    service.get_run_status(run_id="run_123")
    service.list_run_artifacts(run_id="run_123")
    service.read_artifact_content(artifact_id="artifact_123")

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
                            timestamp="16/03/2026 00:00",
                            action="DENY",
                            policy="deny-dns",
                            protocol="UDP",
                            src_ip="10.0.0.1",
                            src_port=51514,
                            dst_ip="8.8.8.8",
                            dst_port=53,
                            question="dns-blocked",
                        )
                    ]
                ),
                "summary": "CAI payload",
                "labels": ["demo"],
                "metadata": {"source": "test"},
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
            "/runs/run_123/observations/watchguard-ingest-workspace-zip",
            {"requested_by": "cai_terminal"},
        ),
        (
            "POST",
            "/runs/run_123/observations/watchguard-normalize",
            {"requested_by": "cai_terminal"},
        ),
        (
            "POST",
            "/runs/run_123/observations/watchguard-filter-denied",
            {"requested_by": "cai_terminal"},
        ),
        (
            "POST",
            "/runs/run_123/observations/watchguard-analytics-basic",
            {"requested_by": "cai_terminal"},
        ),
        (
            "POST",
            "/runs/run_123/observations/watchguard-top-talkers-basic",
            {"requested_by": "cai_terminal"},
        ),
        (
            "POST",
            "/runs/run_123/queries/watchguard-guarded-filtered-rows",
            {
                "requested_by": "cai_terminal",
                "query": {"filters": [{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}], "limit": 5},
                "reason": "Investigate one source IP.",
                "approval": {
                    "status": "approved",
                    "reason": "Human approved this narrow query.",
                    "approver_kind": "human_operator",
                    "approver_ref": None,
                },
            },
        ),
        ("GET", "/cases/case_123", None),
        ("GET", "/runs/run_123", None),
        ("GET", "/runs/run_123/status", None),
        ("GET", "/runs/run_123/artifacts", None),
        ("GET", "/artifacts/artifact_123/content", None),
    ]


def test_build_agent_from_settings_rejects_unsupported_agent_type_before_cai_import():
    settings = cai_orchestrator.CaiIntegrationSettings(
        platform_api_base_url="http://platform-api.local",
        cai_agent_type="security_investigator_agent",
    )

    with pytest.raises(ValueError, match="unsupported CAI_AGENT_TYPE"):
        cai_orchestrator.build_agent_from_settings(settings)


def test_build_platform_investigation_agent_exposes_expected_tool_surface(monkeypatch):
    recorded = _install_fake_cai_sdk(monkeypatch)

    agent = cai_orchestrator.build_platform_investigation_agent(
        platform_api_base_url="http://platform-api.local",
        model="gpt-5.4-mini",
    )

    assert agent.name == "egs-analist"
    assert agent.model == "gpt-5.4-mini"
    assert "platform-api" in agent.instructions
    assert [tool.__name__ for tool in agent.tools] == [
        "health",
        "create_case",
        "attach_input_artifact",
        "attach_workspace_s3_zip_reference",
        "create_run",
        "execute_watchguard_workspace_zip_ingestion",
        "execute_watchguard_normalize",
        "execute_watchguard_filter_denied",
        "execute_watchguard_analytics_basic",
        "execute_watchguard_top_talkers_basic",
        "execute_phishing_email_basic_assessment",
        "execute_watchguard_guarded_custom_query",
        "get_case",
        "get_run",
        "get_run_status",
        "list_run_artifacts",
        "read_artifact_content",
    ]
    # egs-analist plus the phishing-investigator sub-agents (triage, specialists, synthesis)
    assert agent in recorded["agents"]
    assert agent.name == "egs-analist"


def test_run_cai_terminal_cli_one_shot_uses_expected_settings_and_runner(monkeypatch, capsys):
    recorded = _install_fake_cai_sdk(monkeypatch)
    monkeypatch.setenv("PLATFORM_API_BASE_URL", "http://platform-api.local")
    monkeypatch.setenv("CAI_AGENT_TYPE", "egs-analist")
    monkeypatch.setenv("CAI_MODEL", "gpt-5.4-mini")

    exit_code = cai_orchestrator.run_cli(
        [
            "run-cai-terminal",
            "--prompt",
            "Check the platform health.",
        ]
    )

    stdout = capsys.readouterr().out

    assert exit_code == 0
    assert recorded["tracing_disabled"] == [True]
    assert recorded["runner_calls"][0]["input"] == "Check the platform health."
    assert recorded["runner_calls"][0]["agent"].name == "egs-analist"
    assert recorded["runner_calls"][0]["agent"].model == "gpt-5.4-mini"

    body = json.loads(stdout)
    assert body["agent_name"] == "egs-analist"
    assert body["tool_names"] == [
        "health",
        "create_case",
        "attach_input_artifact",
        "attach_workspace_s3_zip_reference",
        "create_run",
        "execute_watchguard_workspace_zip_ingestion",
        "execute_watchguard_normalize",
        "execute_watchguard_filter_denied",
        "execute_watchguard_analytics_basic",
        "execute_watchguard_top_talkers_basic",
        "execute_phishing_email_basic_assessment",
        "execute_watchguard_guarded_custom_query",
        "get_case",
        "get_run",
        "get_run_status",
        "list_run_artifacts",
        "read_artifact_content",
    ]


def test_platform_api_tool_service_can_call_the_phishing_email_endpoint():
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"observation_result": {"status": "succeeded"}}),
        ]
    )
    service = cai_orchestrator.PlatformApiToolService(
        platform_api_client=cai_orchestrator.PlatformApiClient(
            base_url="http://platform-api.local",
            session=session,
        )
    )

    service.execute_phishing_email_basic_assessment(run_id="run_123", requested_by="cai_terminal")

    assert session.calls == [
        (
            "POST",
            "/runs/run_123/observations/phishing-email-basic-assessment",
            {"requested_by": "cai_terminal"},
        ),
    ]


def test_run_cai_terminal_cli_reports_missing_cai_dependency(monkeypatch, capsys):
    real_import = builtins.__import__
    monkeypatch.setenv("CAI_AGENT_TYPE", "egs-analist")

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
        if name == "cai.sdk.agents":
            raise ImportError("cai not installed for test")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    exit_code = cai_orchestrator.run_cli(
        [
            "run-cai-terminal",
            "--prompt",
            "Check the platform health.",
        ]
    )

    stderr = capsys.readouterr().err
    body = json.loads(stderr)

    assert exit_code == 1
    assert body["error"]["type"] == "missing_cai_dependency"


def test_run_cai_terminal_cli_rejects_unsupported_agent_type(monkeypatch, capsys):
    monkeypatch.setenv("CAI_AGENT_TYPE", "security_investigator_agent")

    exit_code = cai_orchestrator.run_cli(
        [
            "run-cai-terminal",
            "--prompt",
            "Check the platform health.",
        ]
    )

    stderr = capsys.readouterr().err
    body = json.loads(stderr)

    assert exit_code == 1
    assert body["error"]["type"] == "invalid_cai_configuration"
    assert "unsupported CAI_AGENT_TYPE" in body["error"]["message"]


def test_platform_api_tool_service_can_attach_workspace_s3_zip_reference():
    session = QueuedSession(
        responses=[
            FakeResponse(201, {"artifact": {"artifact_id": "artifact_123"}}),
        ]
    )
    service = cai_orchestrator.PlatformApiToolService(
        platform_api_client=cai_orchestrator.PlatformApiClient(
            base_url="http://platform-api.local",
            session=session,
        )
    )

    service.attach_workspace_s3_zip_reference(
        case_id="case_123",
        workspace="acme-lab",
        s3_uri="s3://egslatam-cai-dev/workspaces/acme-lab/input/uploads/20260316_abc/logs.zip",
        upload_prefix="workspaces/acme-lab/input/uploads/20260316_abc",
    )

    assert session.calls == [
        (
            "POST",
            "/cases/case_123/artifacts/input",
            {
                "format": "json",
                "payload": build_workspace_s3_zip_payload(
                    workspace="acme-lab",
                    s3_uri="s3://egslatam-cai-dev/workspaces/acme-lab/input/uploads/20260316_abc/logs.zip",
                    upload_prefix="workspaces/acme-lab/input/uploads/20260316_abc",
                ),
                "summary": None,
                "labels": [],
                "metadata": {},
            },
        ),
    ]


def _install_fake_cai_sdk(monkeypatch) -> dict[str, object]:
    recorded: dict[str, object] = {
        "agents": [],
        "runner_calls": [],
        "tracing_disabled": [],
    }
    cai_module = types.ModuleType("cai")
    sdk_module = types.ModuleType("cai.sdk")
    agents_module = types.ModuleType("cai.sdk.agents")

    class FakeAgent:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)
            recorded["agents"].append(self)

    def function_tool(func=None, **kwargs):
        # Supports both @function_tool and @function_tool(strict_mode=False)
        if func is not None:
            return func
        def decorator(f):
            return f
        return decorator

    class FakeResult:
        def __init__(self, *, final_output):
            self.final_output = final_output

        def to_input_list(self):
            return [{"role": "assistant", "content": "done"}]

    class Runner:
        @staticmethod
        async def run(agent, input):
            recorded["runner_calls"].append({"agent": agent, "input": input})
            return FakeResult(
                final_output={
                    "agent_name": agent.name,
                    "input": input,
                    "tool_names": [tool.__name__ for tool in agent.tools],
                }
            )

    def set_tracing_disabled(value):
        recorded["tracing_disabled"].append(value)

    def set_default_openai_api(value):
        pass  # no-op in tests

    agents_module.Agent = FakeAgent
    agents_module.Runner = Runner
    agents_module.function_tool = function_tool
    agents_module.set_tracing_disabled = set_tracing_disabled
    agents_module.set_default_openai_api = set_default_openai_api
    sdk_module.agents = agents_module
    cai_module.sdk = sdk_module

    monkeypatch.setitem(sys.modules, "cai", cai_module)
    monkeypatch.setitem(sys.modules, "cai.sdk", sdk_module)
    monkeypatch.setitem(sys.modules, "cai.sdk.agents", agents_module)

    return recorded
