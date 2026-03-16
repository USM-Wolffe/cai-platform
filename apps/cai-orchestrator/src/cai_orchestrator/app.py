"""Thin app/runtime wiring for the first CAI-facing orchestration slice."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, replace
from typing import Any

from cai_orchestrator.cai_terminal import (
    build_platform_investigation_agent,
    run_cai_terminal,
)
from cai_orchestrator.client import PlatformApiClient, SyncHttpSession
from cai_orchestrator.config import load_cai_integration_settings
from cai_orchestrator.errors import MissingCaiDependencyError, OrchestrationFlowError
from cai_orchestrator.flows import (
    PhishingEmailAssessmentRequest,
    PhishingEmailAssessmentResult,
    WatchGuardGuardedQueryRequest,
    WatchGuardInvestigationRequest,
    WatchGuardInvestigationResult,
    run_phishing_email_basic_assessment,
    run_watchguard_analytics_bundle_basic,
    run_watchguard_filter_denied_events,
    run_watchguard_guarded_custom_query,
    run_watchguard_log_investigation,
    run_watchguard_top_talkers_basic,
)


@dataclass
class CaiOrchestratorApp:
    """Small orchestration app wrapper around the platform-api client."""

    platform_api_client: PlatformApiClient

    def start_watchguard_log_investigation(
        self,
        request: WatchGuardInvestigationRequest,
    ) -> WatchGuardInvestigationResult:
        """Run the first narrow WatchGuard orchestration flow."""
        return run_watchguard_log_investigation(self.platform_api_client, request)

    def start_watchguard_denied_events_investigation(
        self,
        request: WatchGuardInvestigationRequest,
    ) -> WatchGuardInvestigationResult:
        """Run the denied-event WatchGuard orchestration flow."""
        return run_watchguard_filter_denied_events(self.platform_api_client, request)

    def start_watchguard_analytics_bundle_investigation(
        self,
        request: WatchGuardInvestigationRequest,
    ) -> WatchGuardInvestigationResult:
        """Run the basic analytics WatchGuard orchestration flow."""
        return run_watchguard_analytics_bundle_basic(self.platform_api_client, request)

    def start_watchguard_top_talkers_basic_investigation(
        self,
        request: WatchGuardInvestigationRequest,
    ) -> WatchGuardInvestigationResult:
        """Run the basic top-talkers WatchGuard orchestration flow."""
        return run_watchguard_top_talkers_basic(self.platform_api_client, request)

    def start_watchguard_guarded_query_investigation(
        self,
        request: WatchGuardGuardedQueryRequest,
    ) -> WatchGuardInvestigationResult:
        """Run the first guarded WatchGuard custom-query flow."""
        return run_watchguard_guarded_custom_query(self.platform_api_client, request)

    def start_phishing_email_basic_assessment(
        self,
        request: PhishingEmailAssessmentRequest,
    ) -> PhishingEmailAssessmentResult:
        """Run the phishing email basic assessment flow."""
        return run_phishing_email_basic_assessment(self.platform_api_client, request)

    def close(self) -> None:
        """Close owned client resources when needed."""
        self.platform_api_client.close()

    def get_run_status(self, *, run_id: str) -> dict[str, Any]:
        """Read current run status through platform-api."""
        return self.platform_api_client.get_run_status(run_id=run_id)

    def list_run_artifacts(self, *, run_id: str) -> dict[str, Any]:
        """List run artifacts through platform-api."""
        return self.platform_api_client.list_run_artifacts(run_id=run_id)

    def read_artifact_content(self, *, artifact_id: str) -> dict[str, Any]:
        """Read artifact content through platform-api."""
        return self.platform_api_client.read_artifact_content(artifact_id=artifact_id)


def create_orchestrator_app(
    *,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
) -> CaiOrchestratorApp:
    """Create the first thin orchestration app instance."""
    return CaiOrchestratorApp(
        platform_api_client=PlatformApiClient(
            base_url=platform_api_base_url,
            session=session,
        )
    )


def get_platform_api_base_url() -> str:
    """Return the platform-api base URL for local orchestration."""
    return os.getenv("PLATFORM_API_BASE_URL", "http://127.0.0.1:8000")


def run_cli(argv: list[str] | None = None) -> int:
    """Run the first thin orchestrator CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "run-cai-terminal":
        settings = load_cai_integration_settings()
        settings = replace(
            settings,
            platform_api_base_url=args.api_base_url or settings.platform_api_base_url,
            cai_agent_type=args.agent_type or settings.cai_agent_type,
            cai_model=args.model or settings.cai_model,
        )
        try:
            return run_cai_terminal(
                settings=settings,
                prompt=args.prompt,
            )
        except MissingCaiDependencyError as exc:
            _print_error(
                {
                    "error": {
                        "type": "missing_cai_dependency",
                        "message": str(exc),
                    }
                }
            )
            return 1
        except ValueError as exc:
            _print_error(
                {
                    "error": {
                        "type": "invalid_cai_configuration",
                        "message": str(exc),
                    }
                }
            )
            return 1

    if args.command in {"get-run-status", "list-run-artifacts", "read-artifact-content"}:
        try:
            orchestrator = create_orchestrator_app(
                platform_api_base_url=args.api_base_url or get_platform_api_base_url(),
            )
            try:
                if args.command == "get-run-status":
                    payload = orchestrator.get_run_status(run_id=args.run_id)
                elif args.command == "list-run-artifacts":
                    payload = orchestrator.list_run_artifacts(run_id=args.run_id)
                else:
                    payload = orchestrator.read_artifact_content(artifact_id=args.artifact_id)
            finally:
                orchestrator.close()
        except OrchestrationFlowError as exc:
            _print_error(
                {
                    "error": {
                        "type": "orchestration_flow_failed",
                        "message": str(exc),
                        "phase": exc.phase,
                        "status_code": exc.status_code,
                        "details": exc.details,
                    }
                }
            )
            return 1
        except Exception as exc:  # noqa: BLE001
            from cai_orchestrator.errors import PlatformApiRequestError, PlatformApiUnavailableError

            if isinstance(exc, PlatformApiUnavailableError):
                error_type = "platform_api_unavailable"
            elif isinstance(exc, PlatformApiRequestError):
                error_type = "platform_api_request_failed"
            else:
                raise

            _print_error(
                {
                    "error": {
                        "type": error_type,
                        "message": str(exc),
                    }
                }
            )
            return 1

        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.command not in {
        "run-watchguard",
        "run-watchguard-filter-denied",
        "run-watchguard-analytics-basic",
        "run-watchguard-top-talkers-basic",
        "run-watchguard-guarded-query",
        "run-phishing-email-basic-assessment",
    }:
        parser.error("a command is required")

    try:
        payload = _load_json_object(args.payload_file, value_name="payload")
        orchestrator = create_orchestrator_app(
            platform_api_base_url=args.api_base_url or get_platform_api_base_url(),
        )
        try:
            if args.command == "run-watchguard-filter-denied":
                result = orchestrator.start_watchguard_denied_events_investigation(
                    _build_watchguard_request(args, payload)
                )
            elif args.command == "run-watchguard-analytics-basic":
                result = orchestrator.start_watchguard_analytics_bundle_investigation(
                    _build_watchguard_request(args, payload)
                )
            elif args.command == "run-watchguard-top-talkers-basic":
                result = orchestrator.start_watchguard_top_talkers_basic_investigation(
                    _build_watchguard_request(args, payload)
                )
            elif args.command == "run-watchguard-guarded-query":
                result = orchestrator.start_watchguard_guarded_query_investigation(
                    _build_watchguard_guarded_query_request(
                        args,
                        payload,
                        _load_json_object(args.query_file, value_name="query"),
                    )
                )
            elif args.command == "run-phishing-email-basic-assessment":
                result = orchestrator.start_phishing_email_basic_assessment(
                    _build_phishing_email_request(args, payload)
                )
            else:
                result = orchestrator.start_watchguard_log_investigation(
                    _build_watchguard_request(args, payload)
                )
        finally:
            orchestrator.close()
    except FileNotFoundError as exc:
        file_type = "query_file_not_found" if getattr(exc, "filename", "") == getattr(args, "query_file", None) else "payload_file_not_found"
        _print_error(
            {
                "error": {
                    "type": file_type,
                    "message": str(exc),
                }
            }
        )
        return 1
    except json.JSONDecodeError as exc:
        error_type = "invalid_query_json" if getattr(exc, "filename", "") == getattr(args, "query_file", None) else "invalid_payload_json"
        message_prefix = "query file" if error_type == "invalid_query_json" else "payload file"
        _print_error(
            {
                "error": {
                    "type": error_type,
                    "message": f"{message_prefix} is not valid JSON: {exc.msg}",
                }
            }
        )
        return 1
    except ValueError as exc:
        error_type = "invalid_query_shape" if args.command == "run-watchguard-guarded-query" and "query" in str(exc) else "invalid_payload_shape"
        _print_error(
            {
                "error": {
                    "type": error_type,
                    "message": str(exc),
                }
            }
        )
        return 1
    except OrchestrationFlowError as exc:
        _print_error(
            {
                "error": {
                    "type": "orchestration_flow_failed",
                    "message": str(exc),
                    "phase": exc.phase,
                    "status_code": exc.status_code,
                    "details": exc.details,
                }
            }
        )
        return 1
    except Exception as exc:  # noqa: BLE001
        from cai_orchestrator.errors import (
            InvalidOperatorInputError,
            PlatformApiRequestError,
            PlatformApiUnavailableError,
        )

        if isinstance(exc, InvalidOperatorInputError):
            error_type = "invalid_operator_input"
        elif isinstance(exc, PlatformApiUnavailableError):
            error_type = "platform_api_unavailable"
        elif isinstance(exc, PlatformApiRequestError):
            error_type = "platform_api_request_failed"
        else:
            raise

        _print_error(
            {
                "error": {
                    "type": error_type,
                    "message": str(exc),
                }
            }
        )
        return 1

    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


def main() -> None:
    """Run the CLI and exit with its status code."""
    raise SystemExit(run_cli())


def build_cai_watchguard_agent(
    *,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> Any:
    """Compatibility wrapper that now returns the platform investigation agent."""
    return build_platform_investigation_agent(
        platform_api_base_url=platform_api_base_url,
        session=session,
        model=model,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cai-orchestrator",
        description="Run the current thin CAI-facing orchestration CLI against platform-api.",
    )
    subparsers = parser.add_subparsers(dest="command")
    watchguard = subparsers.add_parser(
        "run-watchguard",
        help="Run the baseline WatchGuard normalize/summarize slice.",
    )
    watchguard_filter_denied = subparsers.add_parser(
        "run-watchguard-filter-denied",
        help="Run the WatchGuard denied-event filtering slice.",
    )
    watchguard_analytics_basic = subparsers.add_parser(
        "run-watchguard-analytics-basic",
        help="Run the WatchGuard basic analytics bundle slice.",
    )
    watchguard_top_talkers_basic = subparsers.add_parser(
        "run-watchguard-top-talkers-basic",
        help="Run the WatchGuard basic top-talkers exploration slice.",
    )
    watchguard_guarded_query = subparsers.add_parser(
        "run-watchguard-guarded-query",
        help="Run the current guarded WatchGuard custom-query slice.",
    )
    phishing_email_basic_assessment = subparsers.add_parser(
        "run-phishing-email-basic-assessment",
        help="Run the phishing email basic assessment slice.",
    )
    cai_terminal = subparsers.add_parser(
        "run-cai-terminal",
        help="Run the current CAI terminal integration over platform-api.",
    )
    get_run_status = subparsers.add_parser(
        "get-run-status",
        help="Read current run status through platform-api.",
    )
    list_run_artifacts = subparsers.add_parser(
        "list-run-artifacts",
        help="List artifacts for a run through platform-api.",
    )
    read_artifact_content = subparsers.add_parser(
        "read-artifact-content",
        help="Read stored content for one artifact through platform-api.",
    )
    for subparser in (
        watchguard,
        watchguard_filter_denied,
        watchguard_analytics_basic,
        watchguard_top_talkers_basic,
        watchguard_guarded_query,
        phishing_email_basic_assessment,
    ):
        subparser.add_argument("--title", required=True, help="Case title.")
        subparser.add_argument("--summary", required=True, help="Case summary.")
        subparser.add_argument(
            "--api-base-url",
            default=None,
            help="Override the platform-api base URL. Defaults to PLATFORM_API_BASE_URL or http://127.0.0.1:8000.",
        )
    for subparser in (
        watchguard,
        watchguard_filter_denied,
        watchguard_analytics_basic,
        watchguard_top_talkers_basic,
        watchguard_guarded_query,
    ):
        subparser.add_argument(
            "--payload-file",
            required=True,
            help="Path to a JSON payload file containing the WatchGuard input artifact payload.",
        )
    phishing_email_basic_assessment.add_argument(
        "--payload-file",
        required=True,
        help="Path to a JSON payload file containing the phishing email input artifact payload.",
    )
    watchguard_guarded_query.add_argument(
        "--query-file",
        required=True,
        help="Path to a JSON query file containing the guarded filtered-rows request.",
    )
    watchguard_guarded_query.add_argument(
        "--reason",
        required=True,
        help="Operator reason for running the guarded custom query.",
    )
    watchguard_guarded_query.add_argument(
        "--approval-reason",
        required=True,
        help="Explicit approval reason recorded with the approval decision.",
    )
    watchguard_guarded_query.add_argument(
        "--approver-kind",
        default="human_operator",
        help="Approver kind recorded with the approval decision.",
    )
    watchguard_guarded_query.add_argument(
        "--approver-ref",
        default=None,
        help="Optional approver reference recorded with the approval decision.",
    )
    cai_terminal.add_argument(
        "--api-base-url",
        default=None,
        help="Override the platform-api base URL. Defaults to PLATFORM_API_BASE_URL.",
    )
    cai_terminal.add_argument(
        "--agent-type",
        default=None,
        help="Override CAI_AGENT_TYPE. Only platform_investigation_agent is supported.",
    )
    cai_terminal.add_argument(
        "--model",
        default=None,
        help="Override CAI_MODEL for this session.",
    )
    cai_terminal.add_argument(
        "--prompt",
        default=None,
        help="Run one CAI prompt and exit instead of entering interactive terminal mode.",
    )
    for subparser in (get_run_status, list_run_artifacts):
        subparser.add_argument("--run-id", required=True, help="Run identifier.")
        subparser.add_argument(
            "--api-base-url",
            default=None,
            help="Override the platform-api base URL. Defaults to PLATFORM_API_BASE_URL or http://127.0.0.1:8000.",
        )
    read_artifact_content.add_argument("--artifact-id", required=True, help="Artifact identifier.")
    read_artifact_content.add_argument(
        "--api-base-url",
        default=None,
        help="Override the platform-api base URL. Defaults to PLATFORM_API_BASE_URL or http://127.0.0.1:8000.",
    )
    return parser


def _load_json_object(path: str, *, value_name: str) -> dict[str, object]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{value_name} JSON must be an object")
    return payload


def _print_error(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True), file=sys.stderr)


def _build_watchguard_request(
    args: argparse.Namespace,
    payload: dict[str, object],
) -> WatchGuardInvestigationRequest:
    return WatchGuardInvestigationRequest(
        title=args.title,
        summary=args.summary,
        payload=payload,
    )


def _build_watchguard_guarded_query_request(
    args: argparse.Namespace,
    payload: dict[str, object],
    query: dict[str, object],
) -> WatchGuardGuardedQueryRequest:
    return WatchGuardGuardedQueryRequest(
        title=args.title,
        summary=args.summary,
        payload=payload,
        query=query,
        reason=args.reason,
        approval_reason=args.approval_reason,
        approver_kind=args.approver_kind,
        approver_ref=args.approver_ref,
    )


def _build_phishing_email_request(
    args: argparse.Namespace,
    payload: dict[str, object],
) -> PhishingEmailAssessmentRequest:
    return PhishingEmailAssessmentRequest(
        title=args.title,
        summary=args.summary,
        payload=payload,
    )
