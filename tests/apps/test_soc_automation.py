from __future__ import annotations

import asyncio
import json
import sys
import types

import cai_orchestrator
from cai_orchestrator.blueteam_agents import (
    BlueteamSetupOutput,
    BlueteamSynthesisOutput,
    build_blueteam_synthesizer_agent,
    run_blueteam_investigation,
)
from cai_orchestrator.log_monitor import LogMonitorSettings, S3LogRef

from .support import FakeResponse, QueuedSession


def test_run_blueteam_investigation_completes_run_without_slack(monkeypatch):
    recorded = _install_fake_blueteam_cai_sdk(monkeypatch)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    session = QueuedSession(
        responses=[
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "artifact_norm"}]}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "artifact_failed_auth"}]}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "artifact_lateral"}]}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "artifact_priv_esc"}]}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "artifact_dns"}]}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "artifact_cross_source"}]}),
            FakeResponse(200, {"run": {"run_id": "run_123", "status": "completed"}}),
        ]
    )

    result = asyncio.run(
        run_blueteam_investigation(
            s3_uri="s3://logs-bucket/auth.log",
            source_type="linux_auth",
            client_id="acme",
            platform_api_base_url="http://platform-api.local",
            session=session,
        )
    )

    assert result.run_id == "run_123"
    assert [call[1] for call in session.calls] == [
        "/runs/run_123/observations/multi-source-logs-normalize",
        "/runs/run_123/observations/multi-source-logs-failed-auth-detect",
        "/runs/run_123/observations/multi-source-logs-lateral-movement-detect",
        "/runs/run_123/observations/multi-source-logs-privilege-escalation-detect",
        "/runs/run_123/observations/multi-source-logs-dns-anomaly-detect",
        "/runs/run_123/observations/multi-source-logs-cross-source-correlate",
        "/runs/run_123/complete",
    ]
    assert recorded["runner_calls"][0]["run_config"].workflow_name == "blueteam-setup"
    assert recorded["runner_calls"][1]["run_config"].workflow_name == "blueteam-synthesis"


def test_blueteam_synthesizer_can_post_optional_slack_notification(monkeypatch):
    _install_fake_blueteam_cai_sdk(monkeypatch)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.example/services/test")
    sent = {}

    class FakeRequests:
        @staticmethod
        def post(url, json=None, timeout=None):  # type: ignore[no-untyped-def]
            sent["url"] = url
            sent["json"] = json
            sent["timeout"] = timeout
            return types.SimpleNamespace(status_code=200)

    monkeypatch.setitem(sys.modules, "requests", FakeRequests)

    agent = build_blueteam_synthesizer_agent(
        platform_api_base_url="http://platform-api.local",
    )
    notify_slack = next(tool for tool in agent.tools if getattr(tool, "__name__", "") == "notify_slack")

    result = notify_slack(
        case_id="case_123",
        severity="high",
        incident_categories=["brute_force", "priv_esc"],
        summary="Hybrid blue team pipeline detected a multi-stage incident.",
    )

    assert result == {"notified": True}
    assert sent["url"] == "https://hooks.slack.example/services/test"
    assert "case_123" in sent["json"]["text"]


def test_run_blueteam_investigate_cli_prints_structured_output(monkeypatch, capsys):
    async def fake_run_blueteam_investigation(**kwargs):  # type: ignore[no-untyped-def]
        return BlueteamSynthesisOutput(
            case_id="case_123",
            run_id="run_123",
            source_type=kwargs["source_type"],
            overall_severity="high",
            confidence=0.92,
            incident_detected=True,
            incident_categories=["brute_force"],
            multi_stage_attack=False,
            top_attacker_ip="203.0.113.10",
            top_targeted_user="alice",
            nist_phase="analysis",
            recommended_actions=["Reset the compromised account password."],
            evidence_summary="Multiple failed logins were detected from one source IP.",
        )

    monkeypatch.setattr(
        "cai_orchestrator.blueteam_agents.run_blueteam_investigation",
        fake_run_blueteam_investigation,
    )

    exit_code = cai_orchestrator.run_cli(
        [
            "run-blueteam-investigate",
            "--s3-uri",
            "s3://logs-bucket/auth.log",
            "--source-type",
            "linux_auth",
            "--client-id",
            "acme",
        ]
    )

    stdout = capsys.readouterr().out
    body = json.loads(stdout)

    assert exit_code == 0
    assert body["case_id"] == "case_123"
    assert body["run_id"] == "run_123"


def test_run_log_monitor_cli_processes_one_file_and_exits(monkeypatch, capsys):
    async def fake_run_blueteam_investigation(**kwargs):  # type: ignore[no-untyped-def]
        return BlueteamSynthesisOutput(
            case_id="case_123",
            run_id="run_123",
            source_type=kwargs["source_type"],
            overall_severity="medium",
            confidence=0.81,
            incident_detected=True,
            incident_categories=["dns_anomaly"],
            multi_stage_attack=False,
            top_attacker_ip="10.0.0.44",
            top_targeted_user=None,
            nist_phase="analysis",
            recommended_actions=["Inspect the host for malware persistence."],
            evidence_summary="Repeated high-entropy DNS queries were detected.",
        )

    monkeypatch.setattr(
        "cai_orchestrator.blueteam_agents.run_blueteam_investigation",
        fake_run_blueteam_investigation,
    )
    monkeypatch.setattr(
        "cai_orchestrator.log_monitor.load_log_monitor_settings",
        lambda: LogMonitorSettings(
            s3_bucket="logs-bucket",
            s3_prefix="incoming",
            source_type="dns_logs",
            poll_interval=5,
            state_file_path=".log-monitor-state.json",
        ),
    )
    monkeypatch.setattr(
        "cai_orchestrator.log_monitor.poll_new_log_files",
        lambda settings: [
            S3LogRef(
                s3_uri="s3://logs-bucket/incoming/dns.log",
                source_type="dns_logs",
                bucket="logs-bucket",
                key="incoming/dns.log",
                last_modified_iso="2026-03-15T11:00:00+00:00",
            )
        ],
    )

    exit_code = cai_orchestrator.run_cli(
        [
            "run-log-monitor",
            "--source-type",
            "dns_logs",
            "--client-id",
            "acme",
            "--once",
        ]
    )

    stdout = capsys.readouterr().out

    assert exit_code == 0
    assert '"status": "processing"' in stdout
    assert '"run_id": "run_123"' in stdout


def _install_fake_blueteam_cai_sdk(monkeypatch) -> dict[str, object]:
    recorded: dict[str, object] = {
        "agents": [],
        "runner_calls": [],
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
        if func is not None:
            return func

        def decorator(inner):
            return inner

        return decorator

    class FakeResult:
        def __init__(self, *, final_output):
            self.final_output = final_output

    class RunConfig:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    class Runner:
        @staticmethod
        async def run(agent, input, run_config=None):  # type: ignore[no-untyped-def]
            recorded["runner_calls"].append(
                {"agent_name": agent.name, "input": input, "run_config": run_config}
            )
            if agent.name == "blueteam-orchestrator":
                return FakeResult(
                    final_output=(
                        "SETUP_COMPLETE\n"
                        "case_id=case_123\n"
                        "run_id=run_123\n"
                        "input_artifact_id=artifact_123"
                    )
                )
            return FakeResult(
                final_output=BlueteamSynthesisOutput(
                    case_id="case_123",
                    run_id="run_123",
                    source_type="linux_auth",
                    overall_severity="high",
                    confidence=0.95,
                    incident_detected=True,
                    incident_categories=["brute_force", "priv_esc"],
                    multi_stage_attack=True,
                    top_attacker_ip="203.0.113.10",
                    top_targeted_user="alice",
                    nist_phase="containment",
                    recommended_actions=["Disable the attacking IP and lock the account."],
                    evidence_summary="Correlated failed auth and privilege escalation indicators.",
                )
            )

    agents_module.Agent = FakeAgent
    agents_module.RunConfig = RunConfig
    agents_module.Runner = Runner
    agents_module.function_tool = function_tool
    sdk_module.agents = agents_module
    cai_module.sdk = sdk_module

    monkeypatch.setitem(sys.modules, "cai", cai_module)
    monkeypatch.setitem(sys.modules, "cai.sdk", sdk_module)
    monkeypatch.setitem(sys.modules, "cai.sdk.agents", agents_module)
    return recorded
