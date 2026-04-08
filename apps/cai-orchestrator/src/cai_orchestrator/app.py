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
    run_phishing_monitor_single_email,
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

    def complete_run(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_orchestrator",
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Explicitly complete an active run through platform-api."""
        return self.platform_api_client.complete_run(
            run_id=run_id,
            requested_by=requested_by,
            reason=reason,
        )

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

    if args.command == "run-ddos-investigate":
        return _run_ddos_investigate_command(args)

    if args.command == "run-blueteam-investigate":
        return _run_blueteam_investigate_command(args)

    if args.command == "run-log-monitor":
        return _run_log_monitor_command(args)

    if args.command == "run-phishing-monitor":
        return _run_phishing_monitor_command(args)

    if args.command == "run-phishing-investigate":
        return _run_phishing_investigate_command(args)

    if args.command == "report-collect":
        return _run_report_collect_command(args)

    if args.command == "report-generate":
        return _run_report_generate_command(args)

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
    except FileNotFoundError as exc:
        _print_error({"error": {"type": "payload_file_not_found", "message": str(exc)}})
        return 1
    except json.JSONDecodeError as exc:
        _print_error({"error": {"type": "invalid_payload_json", "message": f"payload file is not valid JSON: {exc.msg}"}})
        return 1

    query: dict[str, object] | None = None
    if args.command == "run-watchguard-guarded-query":
        try:
            query = _load_json_object(args.query_file, value_name="query")
        except FileNotFoundError as exc:
            _print_error({"error": {"type": "query_file_not_found", "message": str(exc)}})
            return 1
        except json.JSONDecodeError as exc:
            _print_error({"error": {"type": "invalid_query_json", "message": f"query file is not valid JSON: {exc.msg}"}})
            return 1

    try:
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
                    _build_watchguard_guarded_query_request(args, payload, query)  # type: ignore[arg-type]
                )
            elif args.command == "run-phishing-email-basic-assessment":
                result = orchestrator.start_phishing_email_basic_assessment(
                    _build_phishing_email_request(args, payload)
                )
            else:
                result = orchestrator.start_watchguard_log_investigation(
                    _build_watchguard_request(args, payload)
                )
            result_payload = result.to_dict()
            completion_response = orchestrator.complete_run(
                run_id=result.run["run_id"],
                requested_by="cai_orchestrator_cli",
                reason=f"One-shot CLI command '{args.command}' finished.",
            )
            result_payload["run"] = completion_response["run"]
            if "case" in completion_response:
                result_payload["case"] = completion_response["case"]
        finally:
            orchestrator.close()
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

    print(json.dumps(result_payload, indent=2, sort_keys=True))
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


def _run_ddos_investigate_command(args: argparse.Namespace) -> int:
    """Handle the run-ddos-investigate CLI command (hybrid pipeline)."""
    import asyncio

    from cai_orchestrator.ddos_agents import run_ddos_investigation

    settings = load_cai_integration_settings()
    api_base_url = args.api_base_url or settings.platform_api_base_url
    model = getattr(args, "model", None) or settings.cai_model
    try:
        result = asyncio.run(
            run_ddos_investigation(
                workspace_id=args.workspace_id,
                platform_api_base_url=api_base_url,
                model=model,
            )
        )
    except MissingCaiDependencyError as exc:
        _print_error({"error": {"type": "missing_cai_dependency", "message": str(exc)}})
        return 1
    except ValueError as exc:
        _print_error({"error": {"type": "pipeline_setup_failed", "message": str(exc)}})
        return 1
    except Exception as exc:  # noqa: BLE001
        from cai_orchestrator.errors import PlatformApiRequestError, PlatformApiUnavailableError

        if isinstance(exc, PlatformApiUnavailableError):
            _print_error({"error": {"type": "platform_api_unavailable", "message": str(exc)}})
        elif isinstance(exc, PlatformApiRequestError):
            _print_error({"error": {"type": "platform_api_request_failed", "message": str(exc)}})
        else:
            raise
        return 1

    print(result)
    return 0


def _run_blueteam_investigate_command(args: argparse.Namespace) -> int:
    """Handle the run-blueteam-investigate CLI command (hybrid pipeline)."""
    import asyncio

    from cai_orchestrator.blueteam_agents import run_blueteam_investigation

    settings = load_cai_integration_settings()
    api_base_url = args.api_base_url or settings.platform_api_base_url
    model = getattr(args, "model", None) or settings.cai_model
    try:
        result = asyncio.run(
            run_blueteam_investigation(
                workspace_id=args.workspace_id,
                client_id=args.client_id,
                platform_api_base_url=api_base_url,
                model=model,
            )
        )
    except MissingCaiDependencyError as exc:
        _print_error({"error": {"type": "missing_cai_dependency", "message": str(exc)}})
        return 1
    except ValueError as exc:
        _print_error({"error": {"type": "pipeline_setup_failed", "message": str(exc)}})
        return 1
    except Exception as exc:  # noqa: BLE001
        from cai_orchestrator.errors import PlatformApiRequestError, PlatformApiUnavailableError

        if isinstance(exc, PlatformApiUnavailableError):
            _print_error({"error": {"type": "platform_api_unavailable", "message": str(exc)}})
        elif isinstance(exc, PlatformApiRequestError):
            _print_error({"error": {"type": "platform_api_request_failed", "message": str(exc)}})
        else:
            raise
        return 1

    if hasattr(result, "model_dump"):
        print(json.dumps(result.model_dump(), indent=2, sort_keys=True))
    else:
        print(result)
    return 0


def _run_log_monitor_command(args: argparse.Namespace) -> int:
    """Handle the run-log-monitor CLI command (S3 polling loop)."""
    import asyncio
    import os
    import time

    from cai_orchestrator.log_monitor import (
        LogMonitorConfigError,
        LogMonitorSettings,
        poll_new_log_files,
    )

    settings = load_cai_integration_settings()
    api_base_url = args.api_base_url or settings.platform_api_base_url
    model = getattr(args, "model", None) or settings.cai_model

    # Build settings from CLI args, falling back to env vars
    if args.s3_bucket:
        os.environ["LOG_MONITOR_S3_BUCKET"] = args.s3_bucket
    if args.s3_prefix:
        os.environ["LOG_MONITOR_S3_PREFIX"] = args.s3_prefix
    os.environ["LOG_MONITOR_SOURCE_TYPE"] = args.source_type
    if args.interval:
        os.environ["LOG_MONITOR_POLL_INTERVAL"] = str(args.interval)

    try:
        from cai_orchestrator.log_monitor import load_log_monitor_settings
        monitor_settings = load_log_monitor_settings()
    except LogMonitorConfigError as exc:
        _print_error({"error": {"type": "log_monitor_config_error", "message": str(exc)}})
        return 1

    run_once = getattr(args, "once", False)

    while True:
        try:
            new_files = poll_new_log_files(monitor_settings)
        except Exception as exc:
            _print_error({"error": {"type": "poll_failed", "message": str(exc)}})
            if run_once:
                return 1
            time.sleep(monitor_settings.poll_interval)
            continue

        if not new_files:
            print(json.dumps({"status": "no_new_files"}))
        else:
            for log_ref in new_files:
                print(json.dumps({
                    "status": "skipped",
                    "s3_uri": log_ref.s3_uri,
                    "reason": (
                        "run-log-monitor requires workspace-based WatchGuard logs. "
                        "Use run-blueteam-investigate --workspace-id instead."
                    ),
                }))

        if run_once:
            return 0
        time.sleep(monitor_settings.poll_interval)


def _run_phishing_investigate_command(args: argparse.Namespace) -> int:
    """Handle the run-phishing-investigate CLI command."""
    from dataclasses import replace as dc_replace

    from cai_orchestrator.cai_terminal import PHISHING_INVESTIGATOR_AGENT_TYPE

    settings = load_cai_integration_settings()
    settings = dc_replace(
        settings,
        platform_api_base_url=args.api_base_url or settings.platform_api_base_url,
        cai_agent_type=PHISHING_INVESTIGATOR_AGENT_TYPE,
        cai_model=args.model or settings.cai_model,
    )

    # Determine the prompt
    if args.run_id and args.input_artifact_id:
        prompt = (
            f"Investigate run_id={args.run_id}, input_artifact_id={args.input_artifact_id}."
        )
    elif args.eml_file:
        # Parse the .eml file, submit to platform-api, then investigate
        try:
            with open(args.eml_file, "rb") as f:
                raw_eml = f.read()
        except FileNotFoundError:
            _print_error({"error": {"type": "eml_file_not_found", "message": f"file not found: {args.eml_file}"}})
            return 1

        api_base_url = args.api_base_url or get_platform_api_base_url()
        try:
            orchestrator = create_orchestrator_app(platform_api_base_url=api_base_url)
            try:
                from cai_orchestrator.flows import run_phishing_monitor_single_email
                result = run_phishing_monitor_single_email(
                    orchestrator.platform_api_client,
                    client_id=args.client_id,
                    raw_eml=raw_eml,
                    title="Phishing investigation (CLI)",
                    summary="Automated phishing investigation from run-phishing-investigate CLI.",
                )
            finally:
                orchestrator.close()
        except Exception as exc:
            _print_error({"error": {"type": "submission_failed", "message": str(exc)}})
            return 1

        run_id = result.run.get("run_id", "")
        artifact_id = result.input_artifact.get("artifact_id", "")
        prompt = f"Investigate run_id={run_id}, input_artifact_id={artifact_id}."
    else:
        _print_error({
            "error": {
                "type": "missing_arguments",
                "message": "Provide --eml-file or both --run-id and --input-artifact-id.",
            }
        })
        return 1

    try:
        return run_cai_terminal(settings=settings, prompt=prompt)
    except MissingCaiDependencyError as exc:
        _print_error({"error": {"type": "missing_cai_dependency", "message": str(exc)}})
        return 1
    except ValueError as exc:
        _print_error({"error": {"type": "invalid_cai_configuration", "message": str(exc)}})
        return 1


def _run_phishing_monitor_command(args: argparse.Namespace) -> int:
    """Handle the run-phishing-monitor CLI command."""
    import time

    from cai_orchestrator.email_bridge import EmlExtractionError, extract_eml_attachment
    from cai_orchestrator.imap_monitor import ImapMonitorConfigError, load_imap_monitor_settings, poll_unseen_messages

    try:
        settings = load_imap_monitor_settings()
    except ImapMonitorConfigError as exc:
        _print_error({"error": {"type": "imap_config_error", "message": str(exc)}})
        return 1

    api_base_url = args.api_base_url or get_platform_api_base_url()
    title_prefix = args.title_prefix or "Phishing email"
    once = args.once
    dry_run = args.dry_run
    cai_investigate = getattr(args, "cai_investigate", False)
    cai_model = getattr(args, "model", None)

    def _process_once() -> int:
        try:
            raw_messages = poll_unseen_messages(settings)
        except Exception as exc:
            _print_error({"error": {"type": "imap_poll_error", "message": str(exc)}})
            return 1

        if not raw_messages:
            print(json.dumps({"status": "no_unseen_messages"}, indent=2))
            return 0

        results = []
        for i, raw_container in enumerate(raw_messages):
            try:
                raw_eml = extract_eml_attachment(raw_container)
            except EmlExtractionError as exc:
                results.append({"status": "skipped", "reason": str(exc), "index": i})
                continue

            if dry_run:
                from cai_orchestrator.email_bridge import eml_bytes_to_structured_email_v2_payload
                payload = eml_bytes_to_structured_email_v2_payload(raw_eml)
                results.append({"status": "dry_run", "index": i, "payload_preview": {k: v for k, v in payload.items() if k not in ("html_body", "all_headers")}})
                continue

            try:
                orchestrator = create_orchestrator_app(platform_api_base_url=api_base_url)
                try:
                    result = run_phishing_monitor_single_email(
                        orchestrator.platform_api_client,
                        client_id=args.client_id,
                        raw_eml=raw_eml,
                        title=f"{title_prefix} #{i + 1}",
                        summary="Phishing email from IMAP monitor — automated analysis.",
                    )
                    completed_case: dict[str, Any] | None = None
                    completed_run: dict[str, Any] | None = None
                    if not cai_investigate:
                        completion_response = orchestrator.complete_run(
                            run_id=result.run.get("run_id", ""),
                            requested_by="phishing_monitor",
                            reason="Single email phishing monitor processing finished.",
                        )
                        completed_case = completion_response.get("case")
                        completed_run = completion_response.get("run")
                finally:
                    orchestrator.close()
                entry: dict = {"status": "processed", "index": i, **result.to_dict()}
                if completed_case is not None:
                    entry["case"] = completed_case
                if completed_run is not None:
                    entry["run"] = completed_run
                results.append(entry)
            except Exception as exc:
                results.append({"status": "error", "index": i, "message": str(exc)})
                continue

            # Launch CAI multi-agent investigator if requested
            if cai_investigate:
                run_id = result.run.get("run_id", "")
                artifact_id = result.input_artifact.get("artifact_id", "")
                if run_id and artifact_id:
                    print(json.dumps({"status": "launching_cai_investigator", "run_id": run_id, "artifact_id": artifact_id}, indent=2))
                    try:
                        from dataclasses import replace as dc_replace
                        from cai_orchestrator.cai_terminal import PHISHING_INVESTIGATOR_AGENT_TYPE, run_cai_terminal
                        cai_settings = load_cai_integration_settings()
                        cai_settings = dc_replace(
                            cai_settings,
                            platform_api_base_url=api_base_url,
                            cai_agent_type=PHISHING_INVESTIGATOR_AGENT_TYPE,
                            cai_model=cai_model or cai_settings.cai_model,
                        )
                        prompt = f"Investigate run_id={run_id}, input_artifact_id={artifact_id}."
                        run_cai_terminal(settings=cai_settings, prompt=prompt, group_id=run_id)
                    except Exception as exc:
                        results[-1]["cai_investigation_error"] = str(exc)

        print(json.dumps({"processed": len(results), "results": results}, indent=2, sort_keys=True))
        return 0

    if once:
        return _process_once()

    # Continuous polling loop
    import logging as _logging
    _monitor_log = _logging.getLogger(__name__)
    print(json.dumps({"status": "starting_monitor", "poll_interval": settings.poll_interval, "mailbox": settings.mailbox}))
    while True:
        try:
            _process_once()
        except Exception as _loop_exc:
            _monitor_log.error("phishing monitor loop error (will retry): %s", _loop_exc)
        time.sleep(settings.poll_interval)


def _run_report_collect_command(args: argparse.Namespace) -> int:
    """Fetch artifact payloads from platform-api and save case-XXXX-report.json."""
    from cai_orchestrator.report.collect import collect_report_data

    api_base_url = args.api_base_url or get_platform_api_base_url()
    try:
        out_path = collect_report_data(
            case_id=args.case_id,
            platform_api_base_url=api_base_url,
        )
    except FileNotFoundError as exc:
        _print_error({"error": {"type": "case_not_found", "message": str(exc)}})
        return 1
    except Exception as exc:  # noqa: BLE001
        from cai_orchestrator.errors import PlatformApiRequestError, PlatformApiUnavailableError

        if isinstance(exc, PlatformApiUnavailableError):
            error_type = "platform_api_unavailable"
        elif isinstance(exc, PlatformApiRequestError):
            error_type = "platform_api_request_failed"
        else:
            raise
        _print_error({"error": {"type": error_type, "message": str(exc)}})
        return 1

    print(json.dumps({"status": "ok", "output": str(out_path)}, indent=2))
    return 0


def _run_report_generate_command(args: argparse.Namespace) -> int:
    """Render case-XXXX-report.json to an HTML or PDF file.

    With --cai, a CAI agent generates the narrative sections before rendering.
    Without --cai, the report is fully deterministic (no LLM, same as before).
    """
    import asyncio
    from pathlib import Path

    from cai_orchestrator.report.generate import generate_report

    narrative = None
    if getattr(args, "cai", False):
        try:
            from cai_orchestrator.report.narrative import generate_report_narrative

            settings = load_cai_integration_settings()
            model = getattr(args, "model", None) or settings.cai_model

            # Read the collected JSON to pass to the narrative agent
            import json as _json
            report_json_path = Path(".egs_cases") / f"{args.case_id}-report.json"
            if not report_json_path.exists():
                _print_error({"error": {"type": "report_data_not_found",
                                        "message": f"Run 'report-collect' first: {report_json_path}"}})
                return 1
            case_data = _json.loads(report_json_path.read_text(encoding="utf-8"))
            narrative = asyncio.run(generate_report_narrative(case_data, model=model))
        except MissingCaiDependencyError as exc:
            _print_error({"error": {"type": "missing_cai_dependency", "message": str(exc)}})
            return 1

    fmt = args.format
    output_path = Path(args.output) if args.output else None
    try:
        out_path = generate_report(
            case_id=args.case_id,
            client_name=args.client,
            informante=args.informante,
            crm_case=args.crm_case,
            output_path=output_path,
            fmt=fmt,
            narrative=narrative,
        )
    except FileNotFoundError as exc:
        _print_error({"error": {"type": "report_data_not_found", "message": str(exc)}})
        return 1
    except RuntimeError as exc:
        _print_error({"error": {"type": "report_generation_failed", "message": str(exc)}})
        return 1

    print(json.dumps({"status": "ok", "output": str(out_path)}, indent=2))
    return 0


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
    phishing_monitor = subparsers.add_parser(
        "run-phishing-monitor",
        help="Poll IMAP mailbox for forwarded phishing emails and run the full assessment pipeline.",
    )
    phishing_monitor.add_argument(
        "--client-id",
        required=True,
        help="EGS client identifier for multi-tenant isolation.",
    )
    phishing_monitor.add_argument(
        "--title-prefix",
        default="Phishing email",
        help="Prefix for auto-generated case titles (e.g. 'Suspicious email').",
    )
    phishing_monitor.add_argument(
        "--api-base-url",
        default=None,
        help="Override the platform-api base URL. Defaults to PLATFORM_API_BASE_URL or http://127.0.0.1:8000.",
    )
    phishing_monitor.add_argument(
        "--once",
        action="store_true",
        default=False,
        help="Poll once and exit instead of running continuously.",
    )
    phishing_monitor.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Parse emails and print payloads without submitting to platform-api.",
    )
    phishing_monitor.add_argument(
        "--cai-investigate",
        action="store_true",
        default=False,
        help="After processing each email, launch the CAI multi-agent phishing investigator automatically. Requires the cai extra.",
    )
    phishing_monitor.add_argument(
        "--model",
        default=None,
        help="Override the CAI model for investigation (e.g. bedrock/...). Defaults to CAI_MODEL env var.",
    )
    phishing_investigate = subparsers.add_parser(
        "run-phishing-investigate",
        help="Investigate one phishing email using the multi-agent CAI pipeline. Requires the cai extra.",
    )
    phishing_investigate.add_argument(
        "--client-id",
        required=True,
        help="EGS client identifier for multi-tenant isolation.",
    )
    phishing_investigate.add_argument(
        "--eml-file",
        default=None,
        help="Path to a raw .eml file to parse, submit to platform-api, and investigate.",
    )
    phishing_investigate.add_argument(
        "--run-id",
        default=None,
        help="Existing run_id (use with --input-artifact-id if the run was already submitted).",
    )
    phishing_investigate.add_argument(
        "--input-artifact-id",
        default=None,
        help="Input artifact_id for an existing run.",
    )
    phishing_investigate.add_argument(
        "--api-base-url",
        default=None,
        help="Override the platform-api base URL.",
    )
    phishing_investigate.add_argument(
        "--model",
        default=None,
        help="Override CAI_MODEL for this investigation.",
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
        subparser.add_argument("--client-id", required=True, help="EGS client identifier for multi-tenant isolation.")
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
        help="Override CAI_AGENT_TYPE. Defaults to egs-analist; the legacy platform_investigation_agent alias is still accepted.",
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

    ddos_investigate = subparsers.add_parser(
        "run-ddos-investigate",
        help="Run the hybrid DDoS investigation pipeline (requires CAI extra + platform-api running).",
    )
    ddos_investigate.add_argument(
        "--workspace-id",
        required=True,
        help="WatchGuard workspace ID to investigate (must have a recent ZIP upload in S3).",
    )
    ddos_investigate.add_argument(
        "--model",
        default=None,
        help="Override CAI_MODEL for this investigation (e.g. bedrock/...).",
    )
    ddos_investigate.add_argument(
        "--api-base-url",
        default=None,
        help="Override the platform-api base URL. Defaults to PLATFORM_API_BASE_URL or http://127.0.0.1:8000.",
    )

    blueteam_investigate = subparsers.add_parser(
        "run-blueteam-investigate",
        help="Run the hybrid blue team investigation pipeline over a staged WatchGuard workspace (requires CAI extra + platform-api running).",
    )
    blueteam_investigate.add_argument(
        "--workspace-id",
        required=True,
        help="WatchGuard workspace ID (e.g. logs-ejemplo-ddos). The workspace must be uploaded to S3 first.",
    )
    blueteam_investigate.add_argument(
        "--client-id",
        default="egs",
        help="Client identifier for the platform case (default: egs).",
    )
    blueteam_investigate.add_argument(
        "--model",
        default=None,
        help="Override CAI_MODEL for this investigation (e.g. bedrock/...).",
    )
    blueteam_investigate.add_argument(
        "--api-base-url",
        default=None,
        help="Override the platform-api base URL. Defaults to PLATFORM_API_BASE_URL or http://127.0.0.1:8000.",
    )

    log_monitor = subparsers.add_parser(
        "run-log-monitor",
        help="Poll S3 for new log files and run the blue team pipeline on each (requires CAI extra + platform-api running).",
    )
    log_monitor.add_argument(
        "--source-type",
        required=True,
        choices=["windows_events", "linux_auth", "dns_logs", "firewall_csv", "web_proxy"],
        help="Log source type for all files under the monitored prefix.",
    )
    log_monitor.add_argument(
        "--s3-bucket",
        default=None,
        help="S3 bucket to monitor. Defaults to LOG_MONITOR_S3_BUCKET env var.",
    )
    log_monitor.add_argument(
        "--s3-prefix",
        default=None,
        help="S3 key prefix to monitor (e.g. logs/prod/). Defaults to LOG_MONITOR_S3_PREFIX env var.",
    )
    log_monitor.add_argument(
        "--client-id",
        default="egs",
        help="Client identifier for platform cases (default: egs).",
    )
    log_monitor.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Poll interval in seconds (default: 60 or LOG_MONITOR_POLL_INTERVAL env var).",
    )
    log_monitor.add_argument(
        "--once",
        action="store_true",
        help="Run a single poll cycle and exit instead of looping indefinitely.",
    )
    log_monitor.add_argument(
        "--model",
        default=None,
        help="Override CAI_MODEL for investigations (e.g. bedrock/...).",
    )
    log_monitor.add_argument(
        "--api-base-url",
        default=None,
        help="Override the platform-api base URL. Defaults to PLATFORM_API_BASE_URL or http://127.0.0.1:8000.",
    )

    report_collect = subparsers.add_parser(
        "report-collect",
        help="Collect artifact payloads for a DDoS case report (requires platform-api running).",
    )
    report_collect.add_argument("case_id", help="Case ID, e.g. case-0009e49b2476")
    report_collect.add_argument(
        "--api-base-url",
        default=None,
        help="Override the platform-api base URL. Defaults to PLATFORM_API_BASE_URL or http://127.0.0.1:8000.",
    )

    report_generate = subparsers.add_parser(
        "report-generate",
        help="Generate a PDF report from a collected DDoS case (offline, no platform-api needed).",
    )
    report_generate.add_argument("case_id", help="Case ID, e.g. case-0009e49b2476")
    report_generate.add_argument("--client", required=True, help="Client display name (e.g. 'Productos Fernández').")
    report_generate.add_argument("--informante", required=True, help="Name of the person requesting the report.")
    report_generate.add_argument("--crm-case", required=True, help="CRM/ticket reference (e.g. 'LL-IR-PFALIMENTOS-2024-001').")
    report_generate.add_argument("--format", default="html", choices=["html", "pdf"], help="Output format (default: html).")
    report_generate.add_argument("--output", default=None, help="Output file path. Defaults to .egs_cases/<case_id>-report.{format}.")
    report_generate.add_argument("--cai", action="store_true", default=False, help="Use CAI agent to generate narrative sections in the report.")
    report_generate.add_argument("--model", default=None, help="Model override for the CAI narrative agent (e.g. 'bedrock/...').")

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
        client_id=args.client_id,
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
        client_id=args.client_id,
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
        client_id=args.client_id,
        title=args.title,
        summary=args.summary,
        payload=payload,
    )
