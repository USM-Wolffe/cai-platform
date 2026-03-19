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


def _resolve_model(model: str | None) -> Any:
    """Return an OpenAIChatCompletionsModel instance for LiteLLM models (e.g. bedrock/...).
    Returns the plain string for standard OpenAI model names so CAI handles them normally."""
    if model and "/" in model:
        try:
            import openai
            from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
            client = openai.AsyncOpenAI(api_key="dummy")
            return OpenAIChatCompletionsModel(model=model, openai_client=client)
        except ImportError:
            pass
    return model


def build_egs_analist_agent(
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

    @function_tool(strict_mode=False)
    def health() -> dict[str, Any]:
        """Check that platform-api is reachable and healthy. Call this first if unsure whether the service is up."""
        return service.health()

    @function_tool(strict_mode=False)
    def create_case(
        client_id: str,
        workflow_type: str,
        title: str,
        summary: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new investigation case. Returns a case_id needed for subsequent steps.
        client_id identifies the EGS client this case belongs to (required for multi-tenant isolation).
        workflow_type must be one of the platform-supported types (e.g. 'log_investigation', 'phishing_assessment').
        Always the first step of any investigation flow."""
        return service.create_case(
            client_id=client_id,
            workflow_type=workflow_type,
            title=title,
            summary=summary,
            metadata=metadata,
        )

    @function_tool(strict_mode=False)
    def attach_input_artifact(
        case_id: str,
        payload_path: str,
        format: str = "json",
        summary: str = "CAI terminal payload attachment",
    ) -> dict[str, Any]:
        """Attach a local JSON payload file to a case as an input artifact. Returns an artifact_id.
        Use this when the operator provides a local file path containing the raw input data (e.g. WatchGuard CSV exported as JSON, phishing email metadata).
        Do NOT use this for S3-stored workspace ZIPs — use attach_workspace_s3_zip_reference instead."""
        return service.attach_input_artifact(
            case_id=case_id,
            payload_path=payload_path,
            format=format,
            summary=summary,
        )

    @function_tool(strict_mode=False)
    def attach_workspace_s3_zip_reference(
        case_id: str,
        workspace: str,
        s3_uri: str,
        upload_prefix: str | None = None,
        summary: str = "Workspace S3 ZIP reference",
    ) -> dict[str, Any]:
        """Attach a WatchGuard workspace ZIP stored in S3 as an input artifact reference. Returns an artifact_id.
        Use this when the operator provides an S3 URI pointing to a workspace ZIP (not a local file).
        After attaching, call execute_watchguard_workspace_zip_ingestion to materialize deterministic artifacts from the ZIP."""
        return service.attach_workspace_s3_zip_reference(
            case_id=case_id,
            workspace=workspace,
            s3_uri=s3_uri,
            upload_prefix=upload_prefix,
            summary=summary,
        )

    @function_tool(strict_mode=False)
    def create_run(
        case_id: str,
        backend_id: str,
        input_artifact_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a run for a case against a specific backend. Returns a run_id needed for observation calls.
        backend_id identifies which backend will process the data (e.g. 'watchguard_logs', 'phishing_email').
        Pass the artifact_ids from the attach step as input_artifact_ids.
        Always call this after attaching input artifacts and before executing any observation."""
        return service.create_run(
            case_id=case_id,
            backend_id=backend_id,
            input_artifact_ids=input_artifact_ids,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_normalize(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Normalize and summarize a WatchGuard log payload. Produces structured normalized records and a summary artifact.
        Use this as the baseline WatchGuard observation — it parses raw traffic/event/alarm logs into a structured format.
        Returns observation_result and output artifacts that can be read with read_artifact_content."""
        return service.execute_watchguard_normalize(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_workspace_zip_ingestion(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Download and ingest a WatchGuard workspace ZIP from S3, materializing its contents as artifacts.
        Call this after attach_workspace_s3_zip_reference to process the remote ZIP file.
        After ingestion, the resulting artifacts can be used as inputs for normalize, filter, or analytics observations."""
        return service.execute_watchguard_workspace_zip_ingestion(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_filter_denied(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Filter a WatchGuard log to denied traffic events only. Returns an artifact with only the denied-action records.
        Useful when the operator wants to focus on blocked connections, policy denials, or security events."""
        return service.execute_watchguard_filter_denied(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_analytics_basic(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Run a basic analytics bundle on a WatchGuard log. Produces aggregate statistics: traffic counts, action distribution, protocol breakdown, top policies.
        Use this to get a high-level overview of traffic patterns before drilling down."""
        return service.execute_watchguard_analytics_basic(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_top_talkers_basic(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Identify the top source/destination IP pairs by traffic volume in a WatchGuard log.
        Use this to surface the most active or suspicious communication endpoints in the dataset."""
        return service.execute_watchguard_top_talkers_basic(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_phishing_email_basic_assessment(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Run a basic phishing email assessment on an email metadata payload.
        Use this when the operator provides a phishing email artifact for triage or analysis."""
        return service.execute_phishing_email_basic_assessment(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def find_latest_workspace_upload(workspace_id: str) -> dict[str, Any]:
        """Find the most recent raw.zip upload for a WatchGuard workspace in S3.
        Returns found=True plus upload_id and s3_uri if an upload exists, or found=False otherwise.
        Call this before staging a workspace to get the S3 URI of the latest ZIP."""
        return service.find_latest_workspace_upload(workspace_id=workspace_id)

    @function_tool(strict_mode=False)
    def execute_watchguard_stage_workspace_zip(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Stage a WatchGuard workspace ZIP from S3: downloads the ZIP, extracts TARs into individual CSVs, and uploads them to S3 staging/.
        Input artifact must have source='workspace_s3_zip' with an s3_uri pointing to the raw.zip.
        Returns a staging manifest artifact with staging_prefix, upload_id, families, file counts, and date range.
        This is the first step of the S3-based large-scale log analysis pipeline — always call this before duckdb analytics."""
        return service.execute_watchguard_stage_workspace_zip(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_duckdb_workspace_analytics(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Run DuckDB analytics over a staged WatchGuard workspace in S3. Reads CSVs directly from S3 via httpfs.
        Input artifact must be the staging manifest artifact produced by execute_watchguard_stage_workspace_zip.
        Returns aggregated analytics: top source/dest IPs, action counts, protocol breakdown, deny count, time range, alarm type counts.
        Use this immediately after staging to get a high-level picture before drilling down with queries."""
        return service.execute_watchguard_duckdb_workspace_analytics(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_duckdb_workspace_query(
        run_id: str,
        family: str,
        filters: list[dict[str, Any]],
        limit: int = 50,
        reason: str = "investigation drill-down",
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Run a guarded DuckDB filter query over staged WatchGuard CSVs in S3. Returns up to `limit` matching rows (max 500).
        Input artifact must be the staging manifest artifact from execute_watchguard_stage_workspace_zip.
        family: 'traffic', 'alarm', or 'event'.
        filters: list of {field, op, value} — allowed fields per family:
          traffic: src_ip, dst_ip, action, protocol, policy, src_port, dst_port
          alarm: alarm_type, src_ip, timestamp
          event: type, timestamp
        ops: '=', '!=', 'like', 'in', '>', '<', '>=', '<='.
        Use this to drill into specific IPs, actions, alarm types, or time windows after reviewing analytics."""
        return service.execute_watchguard_duckdb_workspace_query(
            run_id=run_id,
            family=family,
            filters=filters,
            limit=limit,
            reason=reason,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_guarded_custom_query(
        run_id: str,
        query: dict[str, Any],
        reason: str,
        approval_reason: str,
        approver_kind: str = "human_operator",
        approver_ref: str | None = None,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute a custom guarded query on WatchGuard log rows with explicit operator approval.
        Use this only when the operator explicitly authorizes a filtered row-level query (e.g. filtering by src_ip, dst_ip, action, protocol, policy).
        Requires reason (why the query is needed) and approval_reason (explicit authorization statement from the operator).
        query must be a dict with 'filters' (list of {field, op, value}) and optionally 'limit' and 'sort_by'."""
        return service.execute_watchguard_guarded_custom_query(
            run_id=run_id,
            query=query,
            reason=reason,
            approval_reason=approval_reason,
            approver_kind=approver_kind,
            approver_ref=approver_ref,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def get_case(case_id: str) -> dict[str, Any]:
        """Retrieve full case details including status, artifact refs, and metadata."""
        return service.get_case(case_id=case_id)

    @function_tool(strict_mode=False)
    def get_run(run_id: str) -> dict[str, Any]:
        """Retrieve full run details including input/output artifact refs and observation results."""
        return service.get_run(run_id=run_id)

    @function_tool(strict_mode=False)
    def get_run_status(run_id: str) -> dict[str, Any]:
        """Get the current status and observation result summary for a run. Use this to check if a run completed successfully."""
        return service.get_run_status(run_id=run_id)

    @function_tool(strict_mode=False)
    def list_run_artifacts(run_id: str) -> dict[str, Any]:
        """List all input and output artifacts bound to a run. Use this to discover artifact_ids before calling read_artifact_content."""
        return service.list_run_artifacts(run_id=run_id)

    @function_tool(strict_mode=False)
    def read_artifact_content(artifact_id: str) -> dict[str, Any]:
        """Read the stored content of an artifact. Use this to inspect the actual output of an observation (normalized records, analytics, filtered rows, etc.)."""
        return service.read_artifact_content(artifact_id=artifact_id)

    # Build the phishing investigator pipeline so egs-analist can hand off to it
    from cai_orchestrator.phishing_agents import build_phishing_investigator_agent
    phishing_triage = build_phishing_investigator_agent(
        platform_api_base_url=platform_api_base_url,
        session=session,
        model=model,
    )

    return Agent(
        name="egs-analist",
        description="Thin CAI-facing investigation agent over the deterministic platform-api boundary.",
        instructions=(
            "You operate only through platform-api tools. Do not assume direct backend access, "
            "local backend state, or any legacy local service topology.\n\n"
            "## WatchGuard S3 workspace investigation (large-scale logs — PREFERRED PATH)\n"
            "Use this flow when the operator provides a workspace_id or when analyzing SharePoint-sourced WatchGuard ZIPs:\n"
            "1. find_latest_workspace_upload(workspace_id) → get s3_uri of the latest raw.zip\n"
            "2. create_case(workflow_type='log_investigation', ...)\n"
            "3. attach_workspace_s3_zip_reference(case_id, workspace=workspace_id, s3_uri=...) → artifact_id\n"
            "4. create_run(case_id, backend_id='watchguard_logs', input_artifact_ids=[artifact_id]) → run_id\n"
            "5. execute_watchguard_stage_workspace_zip(run_id) → staging manifest artifact (artifact_id_staging)\n"
            "6. execute_watchguard_duckdb_workspace_analytics(run_id, input_artifact_id=artifact_id_staging) → analytics artifact\n"
            "7. read_artifact_content(artifact_id) on the analytics artifact to understand the traffic picture\n"
            "8. execute_watchguard_duckdb_workspace_query(run_id, family, filters, limit, input_artifact_id=artifact_id_staging) to drill into specific IPs/actions/alarms\n"
            "IMPORTANT: always pass input_artifact_id=<staging_manifest_artifact_id> to steps 6 and 8 — "
            "they read the staging prefix from that artifact, not from the run's original input.\n\n"
            "## WatchGuard log investigation (legacy/local path)\n"
            "Use attach_input_artifact (for local files), create_run with backend_id='watchguard_logs', "
            "then execute_watchguard_normalize, execute_watchguard_analytics_basic, etc.\n\n"
            "## Phishing email investigation\n"
            "When the operator asks to investigate a phishing or suspicious email, follow EXACTLY these steps:\n"
            "1. create_case — MUST use workflow_type='defensive_analysis' (not 'phishing_assessment' or any other value)\n"
            "2. attach_input_artifact with the payload path (JSON file)\n"
            "3. create_run — MUST use backend_id='phishing_email'\n"
            "4. Hand off to phishing-triage with the message: 'Investigate run_id=<run_id>, input_artifact_id=<artifact_id>.'\n"
            "Do NOT call execute_phishing_email_basic_assessment yourself — phishing-triage handles that.\n"
            "The phishing-triage agent will run the full multi-agent pipeline automatically.\n\n"
            "Use list_run_artifacts, read_artifact_content, get_case, and get_run to inspect state after actions."
        ),
        tools=[
            health,
            create_case,
            attach_input_artifact,
            attach_workspace_s3_zip_reference,
            create_run,
            find_latest_workspace_upload,
            execute_watchguard_stage_workspace_zip,
            execute_watchguard_duckdb_workspace_analytics,
            execute_watchguard_duckdb_workspace_query,
            execute_watchguard_workspace_zip_ingestion,
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
        handoffs=[phishing_triage],
        model=_resolve_model(model),
    )


def build_platform_investigation_agent(
    *,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> Any:
    """Compatibility wrapper kept while the visible agent name is `egs-analist`."""
    return build_egs_analist_agent(
        platform_api_base_url=platform_api_base_url,
        session=session,
        model=model,
    )


PHISHING_INVESTIGATOR_AGENT_TYPE = "phishing_investigator"


def build_agent_from_settings(
    settings: CaiIntegrationSettings,
    *,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> Any:
    """Build the configured CAI agent from the minimal supported agent set."""
    _validate_supported_agent_type(settings.cai_agent_type)
    if settings.cai_agent_type == PHISHING_INVESTIGATOR_AGENT_TYPE:
        from cai_orchestrator.phishing_agents import build_phishing_investigator_agent
        return build_phishing_investigator_agent(
            platform_api_base_url=settings.platform_api_base_url,
            session=session,
            model=model or settings.cai_model,
        )
    return build_egs_analist_agent(
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
        from cai.sdk.agents import Runner, set_default_openai_api, set_tracing_disabled
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to run the CAI terminal session."
        ) from exc

    # Use LiteLLM-backed chat completions when the model is not a plain OpenAI model
    # (e.g. bedrock/..., anthropic/..., ollama/...). The Responses API only works with OpenAI.
    effective_model = model or (resolved.cai_model if resolved else None)
    if effective_model and "/" in effective_model:
        set_default_openai_api("chat_completions")

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
    supported = {DEFAULT_CAI_AGENT_TYPE, "platform_investigation_agent", PHISHING_INVESTIGATOR_AGENT_TYPE}
    if agent_type not in supported:
        supported_list = ", ".join(f"'{t}'" for t in sorted(supported))
        raise ValueError(
            f"unsupported CAI_AGENT_TYPE '{agent_type}'; supported values are {supported_list}"
        )
