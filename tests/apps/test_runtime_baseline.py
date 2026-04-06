from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import cai_orchestrator
import cai_orchestrator.app as cai_orchestrator_app
import platform_api
from cai_orchestrator import OrchestrationFlowError, WatchGuardInvestigationResult

from .support import (
    build_watchguard_traffic_csv_payload,
    build_watchguard_traffic_csv_row,
    create_test_client,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def _completed_run_response(
    *,
    run_id: str = "run_123",
    case_id: str = "case_123",
) -> dict[str, object]:
    return {
        "case": {"case_id": case_id},
        "run": {"run_id": run_id, "status": "completed"},
    }


def test_platform_api_runtime_defaults(monkeypatch):
    monkeypatch.delenv("PLATFORM_API_HOST", raising=False)
    monkeypatch.delenv("PLATFORM_API_PORT", raising=False)

    assert platform_api.get_runtime_host() == "0.0.0.0"
    assert platform_api.get_runtime_port() == 8000


def test_platform_api_main_uses_uvicorn_with_expected_defaults(monkeypatch):
    calls: list[dict[str, object]] = []

    def fake_run(app: str, *, factory: bool, host: str, port: int) -> None:
        calls.append(
            {
                "app": app,
                "factory": factory,
                "host": host,
                "port": port,
            }
        )

    monkeypatch.setitem(sys.modules, "uvicorn", type("FakeUvicorn", (), {"run": staticmethod(fake_run)}))
    monkeypatch.delenv("PLATFORM_API_HOST", raising=False)
    monkeypatch.delenv("PLATFORM_API_PORT", raising=False)

    platform_api.main()

    assert calls == [
        {
            "app": "platform_api.app:create_app",
            "factory": True,
            "host": "0.0.0.0",
            "port": 8000,
        }
    ]


def test_orchestrator_cli_runs_the_first_flow(tmp_path, monkeypatch, capsys):
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(
        json.dumps(
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
            )
        ),
        encoding="utf-8",
    )
    captured_requests = []

    class FakeApp:
        def start_watchguard_log_investigation(self, request):
            captured_requests.append(request)
            return WatchGuardInvestigationResult(
                case={"case_id": "case_123"},
                input_artifact={"artifact_id": "artifact_123"},
                run={"run_id": "run_123"},
                execution={"observation_result": {"status": "succeeded"}},
            )

        def complete_run(self, *, run_id, requested_by, reason=None):
            return _completed_run_response(run_id=run_id)

        def close(self) -> None:
            return None

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "run-watchguard",
            "--client-id",
            "test-client",
            "--title",
            "CLI case",
            "--summary",
            "CLI summary",
            "--payload-file",
            str(payload_path),
        ]
    )

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert captured_requests[0].title == "CLI case"
    assert captured_requests[0].summary == "CLI summary"
    assert captured_requests[0].payload["log_type"] == "traffic"
    assert json.loads(stdout)["case"]["case_id"] == "case_123"
    assert json.loads(stdout)["run"]["status"] == "completed"


def test_orchestrator_cli_runs_the_denied_filter_flow(tmp_path, monkeypatch, capsys):
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(
        json.dumps(
            build_watchguard_traffic_csv_payload(
                [
                    build_watchguard_traffic_csv_row(
                        timestamp="15/03/2026 00:00",
                        action="DENY",
                        policy="deny-web",
                        protocol="TCP",
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
    captured_requests = []

    class FakeApp:
        def start_watchguard_denied_events_investigation(self, request):
            captured_requests.append(request)
            return WatchGuardInvestigationResult(
                case={"case_id": "case_123"},
                input_artifact={"artifact_id": "artifact_123"},
                run={"run_id": "run_123"},
                execution={"observation_result": {"status": "succeeded"}},
            )

        def complete_run(self, *, run_id, requested_by, reason=None):
            return _completed_run_response(run_id=run_id)

        def close(self) -> None:
            return None

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "run-watchguard-filter-denied",
            "--client-id",
            "test-client",
            "--title",
            "CLI case",
            "--summary",
            "CLI summary",
            "--payload-file",
            str(payload_path),
        ]
    )

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert captured_requests[0].title == "CLI case"
    assert captured_requests[0].summary == "CLI summary"
    assert captured_requests[0].payload["log_type"] == "traffic"
    assert json.loads(stdout)["case"]["case_id"] == "case_123"
    assert json.loads(stdout)["run"]["status"] == "completed"


def test_orchestrator_cli_runs_the_basic_analytics_flow(tmp_path, monkeypatch, capsys):
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(
        json.dumps(
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
            )
        ),
        encoding="utf-8",
    )
    captured_requests = []

    class FakeApp:
        def start_watchguard_analytics_bundle_investigation(self, request):
            captured_requests.append(request)
            return WatchGuardInvestigationResult(
                case={"case_id": "case_123"},
                input_artifact={"artifact_id": "artifact_123"},
                run={"run_id": "run_123"},
                execution={"observation_result": {"status": "succeeded"}},
            )

        def complete_run(self, *, run_id, requested_by, reason=None):
            return _completed_run_response(run_id=run_id)

        def close(self) -> None:
            return None

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "run-watchguard-analytics-basic",
            "--client-id",
            "test-client",
            "--title",
            "CLI case",
            "--summary",
            "CLI summary",
            "--payload-file",
            str(payload_path),
        ]
    )

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert captured_requests[0].title == "CLI case"
    assert captured_requests[0].summary == "CLI summary"
    assert captured_requests[0].payload["log_type"] == "traffic"
    assert json.loads(stdout)["case"]["case_id"] == "case_123"
    assert json.loads(stdout)["run"]["status"] == "completed"


def test_orchestrator_cli_runs_the_top_talkers_flow(tmp_path, monkeypatch, capsys):
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(
        json.dumps(
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
            )
        ),
        encoding="utf-8",
    )
    captured_requests = []

    class FakeApp:
        def start_watchguard_top_talkers_basic_investigation(self, request):
            captured_requests.append(request)
            return WatchGuardInvestigationResult(
                case={"case_id": "case_123"},
                input_artifact={"artifact_id": "artifact_123"},
                run={"run_id": "run_123"},
                execution={"observation_result": {"status": "succeeded"}},
            )

        def complete_run(self, *, run_id, requested_by, reason=None):
            return _completed_run_response(run_id=run_id)

        def close(self) -> None:
            return None

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "run-watchguard-top-talkers-basic",
            "--client-id",
            "test-client",
            "--title",
            "CLI case",
            "--summary",
            "CLI summary",
            "--payload-file",
            str(payload_path),
        ]
    )

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert captured_requests[0].title == "CLI case"
    assert captured_requests[0].summary == "CLI summary"
    assert captured_requests[0].payload["log_type"] == "traffic"
    assert json.loads(stdout)["case"]["case_id"] == "case_123"
    assert json.loads(stdout)["run"]["status"] == "completed"


def test_orchestrator_cli_runs_the_guarded_query_flow(tmp_path, monkeypatch, capsys):
    payload_path = tmp_path / "payload.json"
    query_path = tmp_path / "query.json"
    payload_path.write_text(
        json.dumps(
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
            )
        ),
        encoding="utf-8",
    )
    query_path.write_text(
        json.dumps(
            {
                "filters": [{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}],
                "limit": 5,
            }
        ),
        encoding="utf-8",
    )
    captured_requests = []

    class FakeApp:
        def start_watchguard_guarded_query_investigation(self, request):
            captured_requests.append(request)
            return WatchGuardInvestigationResult(
                case={"case_id": "case_123"},
                input_artifact={"artifact_id": "artifact_123"},
                run={"run_id": "run_123"},
                execution={"query_summary": {"record_count": 1}},
            )

        def complete_run(self, *, run_id, requested_by, reason=None):
            return _completed_run_response(run_id=run_id)

        def close(self) -> None:
            return None

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "run-watchguard-guarded-query",
            "--client-id",
            "test-client",
            "--title",
            "CLI case",
            "--summary",
            "CLI summary",
            "--payload-file",
            str(payload_path),
            "--query-file",
            str(query_path),
            "--reason",
            "Investigate one source IP.",
            "--approval-reason",
            "Human approved this narrow query.",
        ]
    )

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert captured_requests[0].title == "CLI case"
    assert captured_requests[0].query["filters"][0]["field"] == "src_ip"
    assert captured_requests[0].reason == "Investigate one source IP."
    assert captured_requests[0].approval_reason == "Human approved this narrow query."
    assert json.loads(stdout)["case"]["case_id"] == "case_123"
    assert json.loads(stdout)["run"]["status"] == "completed"


def test_orchestrator_cli_can_read_operational_run_status(monkeypatch, capsys):
    class FakeApp:
        def get_run_status(self, *, run_id):
            return {"run": {"run_id": run_id, "status": "running"}}

        def close(self) -> None:
            return None

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "get-run-status",
            "--run-id",
            "run_123",
        ]
    )

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert json.loads(stdout)["run"]["run_id"] == "run_123"


def test_orchestrator_cli_can_list_run_artifacts(monkeypatch, capsys):
    class FakeApp:
        def list_run_artifacts(self, *, run_id):
            return {"run": {"run_id": run_id}, "input_artifacts": [], "output_artifacts": []}

        def close(self) -> None:
            return None

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "list-run-artifacts",
            "--run-id",
            "run_123",
        ]
    )

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert json.loads(stdout)["run"]["run_id"] == "run_123"


def test_orchestrator_cli_can_read_artifact_content(monkeypatch, capsys):
    class FakeApp:
        def read_artifact_content(self, *, artifact_id):
            return {"artifact": {"artifact_id": artifact_id}, "content": {"record_count": 2}}

        def close(self) -> None:
            return None

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "read-artifact-content",
            "--artifact-id",
            "artifact_123",
        ]
    )

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert json.loads(stdout)["artifact"]["artifact_id"] == "artifact_123"


def test_demo_watchguard_payload_is_valid_for_top_talkers_flow():
    payload_path = REPO_ROOT / "examples/watchguard/minimal_payload.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    app = cai_orchestrator.create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=create_test_client(),
    )

    try:
        result = app.start_watchguard_top_talkers_basic_investigation(
            cai_orchestrator.WatchGuardInvestigationRequest(
                client_id="test-client",
                title="Top talkers demo payload case",
                summary="Validate the checked-in demo payload for top talkers.",
                payload=payload,
            )
        )
    finally:
        app.close()

    assert result.run["backend_ref"]["id"] == "watchguard_logs"
    assert result.execution["observation_result"]["status"] == "succeeded"
    assert result.execution["artifacts"][0]["kind"] == "analysis_output"
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.top_talkers_basic"


def test_orchestrator_cli_reports_invalid_json_payload(tmp_path, capsys):
    payload_path = tmp_path / "payload.json"
    payload_path.write_text("{invalid", encoding="utf-8")

    exit_code = cai_orchestrator.run_cli(
        [
            "run-watchguard",
            "--client-id",
            "test-client",
            "--title",
            "CLI case",
            "--summary",
            "CLI summary",
            "--payload-file",
            str(payload_path),
        ]
    )

    stderr = capsys.readouterr().err
    body = json.loads(stderr)
    assert exit_code == 1
    assert body["error"]["type"] == "invalid_payload_json"


def test_orchestrator_cli_reports_flow_failure(tmp_path, monkeypatch, capsys):
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(
        json.dumps(
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
            )
        ),
        encoding="utf-8",
    )

    class FakeApp:
        def start_watchguard_log_investigation(self, request):
            raise OrchestrationFlowError(
                phase="execute_observation",
                message="execution failed",
                status_code=400,
                details={"error": {"type": "backend_execution_failed"}},
            )

        def close(self) -> None:
            return None

    monkeypatch.setattr(cai_orchestrator_app, "create_orchestrator_app", lambda **_: FakeApp())

    exit_code = cai_orchestrator.run_cli(
        [
            "run-watchguard",
            "--client-id",
            "test-client",
            "--title",
            "CLI case",
            "--summary",
            "CLI summary",
            "--payload-file",
            str(payload_path),
        ]
    )

    stderr = capsys.readouterr().err
    body = json.loads(stderr)
    assert exit_code == 1
    assert body["error"]["type"] == "orchestration_flow_failed"
    assert body["error"]["phase"] == "execute_observation"
    assert body["error"]["status_code"] == 400


def test_compose_file_defines_only_platform_api_service():
    compose_path = REPO_ROOT / "compose.yml"
    content = compose_path.read_text(encoding="utf-8")

    assert "platform-api:" in content
    assert "dockerfile: apps/platform-api/Dockerfile" in content
    assert "${PLATFORM_API_PORT:-8000}:8000" in content
    for forbidden in ("collector", "analyzer", "data-runner", "platform-orchestrator:"):
        assert forbidden not in content


def test_platform_api_dockerfile_references_only_current_local_packages():
    dockerfile_path = REPO_ROOT / "apps/platform-api/Dockerfile"
    content = dockerfile_path.read_text(encoding="utf-8")

    assert "packages/platform-contracts" in content
    assert "packages/platform-core" in content
    assert "packages/platform-adapters" in content
    assert "packages/platform-backends" in content
    assert "apps/platform-api" in content
    for forbidden in ("cai-project", "collector", "analyzer", "data-runner", "COPY cai "):
        assert forbidden not in content


def test_make_help_includes_runtime_targets():
    result = subprocess.run(
        ["make", "help"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    output = result.stdout
    for target in (
        "help",
        "install-dev",
        "build",
        "up",
        "down",
        "test",
        "test-apps",
        "api-dev",
        "health",
        "demo-watchguard",
        "demo-phishing-email",
    ):
        assert target in output


def test_phishing_cli_help_describes_the_phishing_payload():
    result = subprocess.run(
        [sys.executable, "-m", "cai_orchestrator", "run-phishing-email-basic-assessment", "--help"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    output = " ".join(result.stdout.split())
    assert "phishing email input artifact payload" in output
    assert "WatchGuard input payload" not in output


def test_demo_watchguard_payload_is_valid_for_the_current_flow():
    payload_path = REPO_ROOT / "examples/watchguard/minimal_payload.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    app = cai_orchestrator.create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=create_test_client(),
    )

    try:
        result = app.start_watchguard_log_investigation(
            cai_orchestrator.WatchGuardInvestigationRequest(
                client_id="test-client",
                title="Demo payload case",
                summary="Validate the checked-in demo payload.",
                payload=payload,
            )
        )
    finally:
        app.close()

    assert result.run["backend_ref"]["id"] == "watchguard_logs"
    assert result.execution["observation_result"]["status"] == "succeeded"
    assert result.execution["observation_result"]["structured_summary"]["input_shape"] == "traffic_csv_export"
    assert result.execution["artifacts"][0]["kind"] == "normalized"


def test_demo_watchguard_payload_is_valid_for_denied_filter_flow():
    payload_path = REPO_ROOT / "examples/watchguard/minimal_payload.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    app = cai_orchestrator.create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=create_test_client(),
    )

    try:
        result = app.start_watchguard_denied_events_investigation(
            cai_orchestrator.WatchGuardInvestigationRequest(
                client_id="test-client",
                title="Denied demo payload case",
                summary="Validate the checked-in demo payload for denied filtering.",
                payload=payload,
            )
        )
    finally:
        app.close()

    assert result.run["backend_ref"]["id"] == "watchguard_logs"
    assert result.execution["observation_result"]["status"] == "succeeded"
    assert result.execution["observation_result"]["structured_summary"]["record_count"] == 1
    assert result.execution["observation_result"]["structured_summary"]["input_shape"] == "traffic_csv_export"
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.denied_events"


def test_demo_watchguard_payload_is_valid_for_basic_analytics_flow():
    payload_path = REPO_ROOT / "examples/watchguard/minimal_payload.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    app = cai_orchestrator.create_orchestrator_app(
        platform_api_base_url="http://testserver",
        session=create_test_client(),
    )

    try:
        result = app.start_watchguard_analytics_bundle_investigation(
            cai_orchestrator.WatchGuardInvestigationRequest(
                client_id="test-client",
                title="Analytics demo payload case",
                summary="Validate the checked-in demo payload for analytics.",
                payload=payload,
            )
        )
    finally:
        app.close()

    assert result.run["backend_ref"]["id"] == "watchguard_logs"
    assert result.execution["observation_result"]["status"] == "succeeded"
    assert result.execution["observation_result"]["structured_summary"]["record_count"] == 2
    assert result.execution["artifacts"][0]["kind"] == "analysis_output"
    assert result.execution["artifacts"][0]["subtype"] == "watchguard.analytics_bundle_basic"


def test_runtime_files_have_no_old_repo_or_vendored_cai_assumptions():
    runtime_paths = [
        REPO_ROOT / "Makefile",
        REPO_ROOT / "compose.yml",
        REPO_ROOT / "apps/platform-api/Dockerfile",
    ]

    forbidden_fragments = [
        "/home/seba/work/proyects/cai-project",
        "collector",
        "analyzer",
        "data-runner",
        "COPY cai ",
        "FROM cai",
    ]

    for path in runtime_paths:
        content = path.read_text(encoding="utf-8")
        for fragment in forbidden_fragments:
            assert fragment not in content
