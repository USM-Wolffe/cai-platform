"""Minimal CAI terminal integration over the platform-api boundary."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from cai_orchestrator.cai_tools import PlatformApiToolService
from cai_orchestrator.client import PlatformApiClient, SyncHttpSession
from cai_orchestrator.config import (
    DEFAULT_CAI_AGENT_TYPE,
    CaiIntegrationSettings,
    load_cai_integration_settings,
)
from cai_orchestrator.errors import MissingCaiDependencyError


def build_platform_investigation_agent(
    *,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> Any:
    """Build the minimal CAI agent that operates only through platform-api tools."""
    try:
        from cai.sdk.agents import Agent, function_tool
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use the CAI terminal integration."
        ) from exc

    client = PlatformApiClient(base_url=platform_api_base_url, session=session)
    service = PlatformApiToolService(platform_api_client=client)

    @function_tool
    def health() -> dict[str, Any]:
        return service.health()

    @function_tool
    def create_case(workflow_type: str, title: str, summary: str) -> dict[str, Any]:
        return service.create_case(workflow_type=workflow_type, title=title, summary=summary)

    @function_tool
    def attach_input_artifact(
        case_id: str,
        payload_path: str,
        format: str = "json",
        summary: str = "CAI terminal payload attachment",
    ) -> dict[str, Any]:
        return service.attach_input_artifact(
            case_id=case_id,
            payload_path=payload_path,
            format=format,
            summary=summary,
        )

    @function_tool
    def create_run(
        case_id: str,
        backend_id: str,
        input_artifact_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        return service.create_run(
            case_id=case_id,
            backend_id=backend_id,
            input_artifact_ids=input_artifact_ids,
        )

    @function_tool
    def execute_watchguard_normalize(
        run_id: str,
        requested_by: str = "cai_terminal",
    ) -> dict[str, Any]:
        return service.execute_watchguard_normalize(
            run_id=run_id,
            requested_by=requested_by,
        )

    @function_tool
    def execute_watchguard_filter_denied(
        run_id: str,
        requested_by: str = "cai_terminal",
    ) -> dict[str, Any]:
        return service.execute_watchguard_filter_denied(
            run_id=run_id,
            requested_by=requested_by,
        )

    @function_tool
    def execute_watchguard_analytics_basic(
        run_id: str,
        requested_by: str = "cai_terminal",
    ) -> dict[str, Any]:
        return service.execute_watchguard_analytics_basic(
            run_id=run_id,
            requested_by=requested_by,
        )

    @function_tool
    def execute_watchguard_top_talkers_basic(
        run_id: str,
        requested_by: str = "cai_terminal",
    ) -> dict[str, Any]:
        return service.execute_watchguard_top_talkers_basic(
            run_id=run_id,
            requested_by=requested_by,
        )

    @function_tool
    def execute_phishing_email_basic_assessment(
        run_id: str,
        requested_by: str = "cai_terminal",
    ) -> dict[str, Any]:
        return service.execute_phishing_email_basic_assessment(
            run_id=run_id,
            requested_by=requested_by,
        )

    @function_tool
    def execute_watchguard_guarded_custom_query(
        run_id: str,
        query: dict[str, Any],
        reason: str,
        approval_reason: str,
        approver_kind: str = "human_operator",
        approver_ref: str | None = None,
        requested_by: str = "cai_terminal",
    ) -> dict[str, Any]:
        return service.execute_watchguard_guarded_custom_query(
            run_id=run_id,
            query=query,
            reason=reason,
            approval_reason=approval_reason,
            approver_kind=approver_kind,
            approver_ref=approver_ref,
            requested_by=requested_by,
        )

    @function_tool
    def get_case(case_id: str) -> dict[str, Any]:
        return service.get_case(case_id=case_id)

    @function_tool
    def get_run(run_id: str) -> dict[str, Any]:
        return service.get_run(run_id=run_id)

    @function_tool
    def get_run_status(run_id: str) -> dict[str, Any]:
        return service.get_run_status(run_id=run_id)

    @function_tool
    def list_run_artifacts(run_id: str) -> dict[str, Any]:
        return service.list_run_artifacts(run_id=run_id)

    @function_tool
    def read_artifact_content(artifact_id: str) -> dict[str, Any]:
        return service.read_artifact_content(artifact_id=artifact_id)

    return Agent(
        name="platform_investigation_agent",
        description="Thin CAI-facing agent over the deterministic platform-api boundary.",
        instructions=(
            "You operate only through platform-api tools. Do not assume direct backend access, "
            "local backend state, or any legacy local service topology. "
            "When the operator provides a local payload path, use attach_input_artifact with that path. "
            "Use get_case and get_run to inspect deterministic state after actions."
        ),
        tools=[
            health,
            create_case,
            attach_input_artifact,
            create_run,
            execute_watchguard_normalize,
            execute_watchguard_filter_denied,
            execute_watchguard_analytics_basic,
            execute_watchguard_top_talkers_basic,
            execute_phishing_email_basic_assessment,
            execute_watchguard_guarded_custom_query,
            get_case,
            get_run,
            get_run_status,
            list_run_artifacts,
            read_artifact_content,
        ],
        tool_use_behavior="stop_on_first_tool",
        model=model,
    )


def build_agent_from_settings(
    settings: CaiIntegrationSettings,
    *,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> Any:
    """Build the configured CAI agent from the minimal supported agent set."""
    _validate_supported_agent_type(settings.cai_agent_type)
    return build_platform_investigation_agent(
        platform_api_base_url=settings.platform_api_base_url,
        session=session,
        model=model or settings.cai_model,
    )


async def run_cai_terminal_session(
    *,
    settings: CaiIntegrationSettings | None = None,
    prompt: str | None = None,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> int:
    """Run a tiny CAI terminal session against the new platform-api boundary."""
    resolved = settings or load_cai_integration_settings()
    _validate_supported_agent_type(resolved.cai_agent_type)

    try:
        from cai.sdk.agents import Runner, set_tracing_disabled
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to run the CAI terminal session."
        ) from exc

    agent = build_agent_from_settings(resolved, session=session, model=model)
    set_tracing_disabled(True)

    if prompt is not None:
        result = await Runner.run(agent, input=prompt)
        print(_format_final_output(result.final_output))
        return 0

    print("CAI platform terminal over platform-api. Type /exit to quit.")
    conversation_input: str | list[dict[str, Any]] = ""
    while True:
        try:
            user_input = input("cai-platform> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not user_input:
            continue
        if user_input in {"/exit", "/quit", "exit", "quit"}:
            return 0

        run_input: str | list[dict[str, Any]]
        if conversation_input:
            run_input = conversation_input + [{"role": "user", "content": user_input}]
        else:
            run_input = user_input

        result = await Runner.run(agent, input=run_input)
        print(_format_final_output(result.final_output))
        conversation_input = result.to_input_list()


def run_cai_terminal(
    *,
    settings: CaiIntegrationSettings | None = None,
    prompt: str | None = None,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> int:
    """Sync wrapper for the minimal CAI terminal loop."""
    return asyncio.run(
        run_cai_terminal_session(
            settings=settings,
            prompt=prompt,
            session=session,
            model=model,
        )
    )


def _format_final_output(output: Any) -> str:
    if isinstance(output, (dict, list)):
        return json.dumps(output, indent=2, sort_keys=True)
    return str(output)


def _validate_supported_agent_type(agent_type: str) -> None:
    if agent_type != DEFAULT_CAI_AGENT_TYPE:
        raise ValueError(
            f"unsupported CAI_AGENT_TYPE '{agent_type}'; only '{DEFAULT_CAI_AGENT_TYPE}' is supported in cai-platform-v2"
        )
