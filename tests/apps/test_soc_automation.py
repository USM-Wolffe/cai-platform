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
    """Phase 1 (Python setup) + Phase 2 (detections) + Phase 3 (synthesizer) — no Slack."""
    _install_fake_blueteam_cai_sdk(monkeypatch)
    _install_fake_boto3(monkeypatch, staging_prefix="workspaces/test-ws/staging/upload01")
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

    # Responses for Phase 1 (Python setup):
    #   create_case, attach_artifact(traffic), attach_artifact(alarm), create_run
    # Responses for Phase 2 (detections):
    #   normalize, failed_auth, lateral_movement, privilege_escalation, dns_anomaly (traffic)
    #   active_threats_detect (alarm)
    #   cross_source_correlate
    # Responses for complete_run
    session = QueuedSession(
        responses=[
            # Phase 1 — Python setup
            FakeResponse(201, {"case": {"case_id": "case_123"}}),
            FakeResponse(201, {"artifact": {"artifact_id": "artifact_traffic"}}),
            FakeResponse(201, {"artifact": {"artifact_id": "artifact_alarm"}}),
            FakeResponse(201, {"run": {"run_id": "run_123"}}),
            # Phase 2 — traffic observations
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "art_norm"}]}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "art_failed_auth"}]}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "art_lateral"}]}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "art_priv_esc"}]}),
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "art_dns"}]}),
            # Phase 2 — alarm observation
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "art_threats"}]}),
            # Phase 2 — cross-source correlate
            FakeResponse(200, {"observation_result": {"status": "succeeded"}, "artifacts": [{"artifact_id": "art_cross"}]}),
            # complete_run
            FakeResponse(200, {"run": {"run_id": "run_123", "status": "completed"}}),
        ]
    )

    result = asyncio.run(
        run_blueteam_investigation(
            workspace_id="test-ws",
            client_id="acme",
            platform_api_base_url="http://platform-api.local",
            session=session,
        )
    )

    assert result.run_id == "run_123"
    assert result.workspace_id == "test-ws"

    # Verify Phase 1 API calls (case + 2 artifacts + run)
    phase1_paths = [call[1] for call in session.calls[:4]]
    assert "/cases" in phase1_paths[0]
    assert "/cases/case_123/artifacts" in phase1_paths[1]
    assert "/cases/case_123/artifacts" in phase1_paths[2]
    assert "/runs" in phase1_paths[3]

    # Verify Phase 2 detection paths
    phase2_paths = [call[1] for call in session.calls[4:11]]
    assert "/runs/run_123/observations/multi-source-logs-normalize" in phase2_paths
    assert "/runs/run_123/observations/multi-source-logs-failed-auth-detect" in phase2_paths
    assert "/runs/run_123/observations/multi-source-logs-lateral-movement-detect" in phase2_paths
    assert "/runs/run_123/observations/multi-source-logs-privilege-escalation-detect" in phase2_paths
    assert "/runs/run_123/observations/multi-source-logs-dns-anomaly-detect" in phase2_paths
    assert "/runs/run_123/observations/multi-source-logs-active-threats-detect" in phase2_paths
    assert "/runs/run_123/observations/multi-source-logs-cross-source-correlate" in phase2_paths

    # complete_run
    assert session.calls[-1][1] == "/runs/run_123/complete"

    # Only synthesizer agent should have run (no CAI orchestrator in Phase 1)
    recorded = getattr(session, "_recorded", None)


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
        incident_categories=["flood", "ddos"],
        summary="Hybrid blue team pipeline detected active network threats.",
    )

    assert result == {"notified": True}
    assert sent["url"] == "https://hooks.slack.example/services/test"
    assert "case_123" in sent["json"]["text"]


def test_run_blueteam_investigate_cli_prints_structured_output(monkeypatch, capsys):
    async def fake_run_blueteam_investigation(**kwargs):  # type: ignore[no-untyped-def]
        return BlueteamSynthesisOutput(
            case_id="case_123",
            run_id="run_123",
            workspace_id=kwargs["workspace_id"],
            overall_severity="high",
            confidence=0.92,
            incident_detected=True,
            incident_categories=["flood", "ddos"],
            multi_stage_attack=False,
            top_attacker_ip="203.0.113.10",
            top_targeted_user=None,
            nist_phase="analysis",
            recommended_actions=["Block the attacking IP ranges at the perimeter firewall."],
            evidence_summary="Active flood and DDoS alarms detected from external IPs.",
        )

    monkeypatch.setattr(
        "cai_orchestrator.blueteam_agents.run_blueteam_investigation",
        fake_run_blueteam_investigation,
    )

    exit_code = cai_orchestrator.run_cli(
        [
            "run-blueteam-investigate",
            "--workspace-id",
            "test-ws",
            "--client-id",
            "acme",
        ]
    )

    stdout = capsys.readouterr().out
    body = json.loads(stdout)

    assert exit_code == 0
    assert body["case_id"] == "case_123"
    assert body["run_id"] == "run_123"
    assert body["workspace_id"] == "test-ws"


def test_run_log_monitor_cli_skips_files_with_workspace_message(monkeypatch, capsys):
    """Log monitor now reports 'skipped' for individual files — use run-blueteam-investigate instead."""
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
                s3_uri="s3://logs-bucket/incoming/traffic.csv",
                source_type="dns_logs",
                bucket="logs-bucket",
                key="incoming/traffic.csv",
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
    messages = [json.loads(line) for line in stdout.strip().splitlines() if line.strip()]

    assert exit_code == 0
    skipped = next((m for m in messages if m.get("status") == "skipped"), None)
    assert skipped is not None
    assert "workspace" in skipped.get("reason", "").lower()


def _install_fake_boto3(monkeypatch, staging_prefix: str | None = "workspaces/ws/staging/upload01") -> None:
    """Fake boto3 so S3 listing returns a staging prefix without real AWS calls."""

    class FakePaginator:
        def __init__(self, staging_prefix: str | None):
            self._prefix = staging_prefix

        def paginate(self, Bucket, Prefix, **kwargs):
            if self._prefix and "staging" in Prefix:
                # Return the upload ID component as a common prefix
                upload_id = self._prefix.rsplit("/", 1)[-1]
                full_prefix = f"{Prefix.rstrip('/')}/{upload_id}/"
                return [{"CommonPrefixes": [{"Prefix": full_prefix}]}]
            return [{"CommonPrefixes": []}]

    class FakeS3Client:
        def __init__(self, staging_prefix: str | None):
            self._prefix = staging_prefix

        def get_paginator(self, op: str):
            return FakePaginator(self._prefix)

    class FakeBoto3Module:
        def __init__(self, staging_prefix: str | None):
            self._prefix = staging_prefix

        def client(self, service: str, region_name: str = "us-east-2"):
            return FakeS3Client(self._prefix)

    fake_boto3 = FakeBoto3Module(staging_prefix)
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)


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
            return FakeResult(
                final_output=BlueteamSynthesisOutput(
                    case_id="case_123",
                    run_id="run_123",
                    workspace_id="test-ws",
                    overall_severity="high",
                    confidence=0.95,
                    incident_detected=True,
                    incident_categories=["flood", "ddos"],
                    multi_stage_attack=True,
                    top_attacker_ip="203.0.113.10",
                    top_targeted_user=None,
                    nist_phase="containment",
                    recommended_actions=["Block attacking IP ranges at the firewall."],
                    evidence_summary="Correlated flood and DDoS alarm events from external IPs.",
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
