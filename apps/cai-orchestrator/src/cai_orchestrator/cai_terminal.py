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
    Returns the plain string for standard OpenAI model names so CAI handles them normally.

    For non-Claude Bedrock models (e.g. Nova Pro), CAI's _fetch_response does not have a
    'bedrock' provider branch, so tool_choice='auto' is passed through to LiteLLM which
    raises UnsupportedParamsError causing an infinite retry loop. We fix this by setting
    litellm.drop_params=True for those models before delegating to litellm.acompletion.
    """
    if model and "/" in model:
        try:
            import litellm
            import openai
            from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

            # For non-Claude Bedrock models (Nova Pro, Titan, etc.), set drop_params so
            # litellm silently ignores unsupported params like tool_choice instead of raising.
            model_lower = model.lower()
            if "bedrock/" in model_lower and "claude" not in model_lower:
                litellm.drop_params = True

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
        from cai.tools.misc.reasoning import think
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use the CAI terminal integration."
        ) from exc

    # ── Inline case-state management tools ────────────────────────────────────
    # Replaces cai.tools.workspace.egs_case_tools (not available in public releases).
    # The agent passes case_state_json between calls as a serialized JSON blob.
    _STAGES = ["identification", "analysis", "containment", "eradication", "recovery", "lessons_learned"]

    @function_tool(strict_mode=False)
    def initialize_case(title: str, summary: str) -> dict[str, Any]:
        """Initialize a new investigation case state. Returns case_state_json to pass to subsequent tools."""
        state = {"title": title, "summary": summary, "stage": _STAGES[0],
                 "hypotheses": [], "evidence": [], "findings": [], "decisions": []}
        return {"case_state_json": json.dumps(state), "updated_case_state": json.dumps(state)}

    @function_tool(strict_mode=False)
    def record_case_hypothesis(case_state_json: str, hypothesis: str, confidence: float = 0.5) -> dict[str, Any]:
        """Record a working hypothesis. Returns updated_case_state."""
        state = json.loads(case_state_json)
        state.setdefault("hypotheses", []).append({"text": hypothesis, "confidence": confidence})
        return {"updated_case_state": json.dumps(state), "case_state_json": json.dumps(state)}

    @function_tool(strict_mode=False)
    def record_case_evidence(case_state_json: str, evidence: str, source: str = "") -> dict[str, Any]:
        """Record a piece of evidence. Returns updated_case_state."""
        state = json.loads(case_state_json)
        state.setdefault("evidence", []).append({"text": evidence, "source": source})
        return {"updated_case_state": json.dumps(state), "case_state_json": json.dumps(state)}

    @function_tool(strict_mode=False)
    def record_case_finding(case_state_json: str, finding: str, severity: str = "medium", confidence: float = 0.7) -> dict[str, Any]:
        """Record a confirmed finding. severity: 'critical'|'high'|'medium'|'low'. Returns updated_case_state."""
        state = json.loads(case_state_json)
        state.setdefault("findings", []).append({"text": finding, "severity": severity, "confidence": confidence})
        return {"updated_case_state": json.dumps(state), "case_state_json": json.dumps(state)}

    @function_tool(strict_mode=False)
    def record_case_decision(case_state_json: str, decision: str, category: str = "containment", rationale: str = "", alternatives: list[str] | None = None) -> dict[str, Any]:
        """Record a response decision. Returns updated_case_state."""
        state = json.loads(case_state_json)
        state.setdefault("decisions", []).append({
            "decision": decision, "category": category,
            "rationale": rationale, "alternatives": alternatives or [],
        })
        return {"updated_case_state": json.dumps(state), "case_state_json": json.dumps(state)}

    @function_tool(strict_mode=False)
    def advance_case_stage(case_state_json: str) -> dict[str, Any]:
        """Advance the investigation to the next NIST stage. Returns updated_case_state."""
        state = json.loads(case_state_json)
        current = state.get("stage", _STAGES[0])
        idx = _STAGES.index(current) if current in _STAGES else 0
        state["stage"] = _STAGES[min(idx + 1, len(_STAGES) - 1)]
        return {"updated_case_state": json.dumps(state), "case_state_json": json.dumps(state), "new_stage": state["stage"]}

    @function_tool(strict_mode=False)
    def build_final_case_output(case_state_json: str) -> dict[str, Any]:
        """Build the final structured case report from accumulated state. Call as last step."""
        state = json.loads(case_state_json)
        return {"report": state, "case_state_json": case_state_json}

    @function_tool(strict_mode=False)
    def save_case_state(case_state_json: str, case_id: str = "") -> dict[str, Any]:
        """Persist case state (no-op stub — state lives in conversation context). Returns confirmation."""
        return {"saved": True, "case_id": case_id, "case_state_json": case_state_json}

    @function_tool(strict_mode=False)
    def load_case_state(case_id: str = "") -> dict[str, Any]:
        """Load case state by ID (stub — returns empty state when no prior state exists)."""
        return {"case_state_json": json.dumps({"stage": _STAGES[0], "hypotheses": [], "evidence": [], "findings": [], "decisions": []}), "case_id": case_id}

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
    def execute_watchguard_ddos_temporal_analysis(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Analyze DDoS attack temporal patterns over a staged WatchGuard workspace.
        Returns daily event counts with percentage variation and identifies the peak attack day.
        Input artifact must be the staging manifest from execute_watchguard_stage_workspace_zip.
        Use this first in a DDoS investigation to understand the attack timeline."""
        return service.execute_watchguard_ddos_temporal_analysis(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_top_destinations(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Identify the top destination IPs targeted in a DDoS attack from a staged WatchGuard workspace.
        Returns the top N destination IPs ranked by event count with associated policy and action breakdown.
        Input artifact must be the staging manifest from execute_watchguard_stage_workspace_zip.
        Use this to identify which internal assets were most targeted."""
        return service.execute_watchguard_ddos_top_destinations(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_top_sources(
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Identify the top source IPs and /16 network segments generating DDoS traffic.
        Returns individual top source IPs and their /16 subnet groupings with event counts.
        Input artifact must be the staging manifest from execute_watchguard_stage_workspace_zip.
        Use this to identify attack origin infrastructure and botnet segments."""
        return service.execute_watchguard_ddos_top_sources(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_segment_analysis(
        run_id: str,
        segment: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Profile all traffic from a specific /16 network segment in a DDoS investigation.
        segment: the /16 prefix, e.g. '185.220' for the 185.220.0.0/16 range.
        Returns all IPs in the segment, event counts, targeted destinations, ports, and policies hit.
        Input artifact must be the staging manifest from execute_watchguard_stage_workspace_zip.
        Use this after execute_watchguard_ddos_top_sources to drill into a suspicious /16."""
        return service.execute_watchguard_ddos_segment_analysis(
            run_id=run_id,
            segment=segment,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_ip_profile(
        run_id: str,
        ip: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Build a full forensic profile for a single source IP in a DDoS investigation.
        ip: the exact source IP address to profile, e.g. '185.220.101.47'.
        Returns total events, targeted destinations, destination ports, policies hit, actions taken, and activity timeline by hour.
        Input artifact must be the staging manifest from execute_watchguard_stage_workspace_zip.
        Use this to build NIST evidence for a specific attacker IP."""
        return service.execute_watchguard_ddos_ip_profile(
            run_id=run_id,
            ip=ip,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_hourly_distribution(
        run_id: str,
        date: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Analyze the hourly distribution of DDoS events for a specific date.
        date: the date to analyze in YYYY-MM-DD format, e.g. '2023-10-25'.
        Returns event counts per hour (0-23) and flags business-hours concentration patterns.
        Input artifact must be the staging manifest from execute_watchguard_stage_workspace_zip.
        Use this on the peak day identified by execute_watchguard_ddos_temporal_analysis."""
        return service.execute_watchguard_ddos_hourly_distribution(
            run_id=run_id,
            date=date,
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

    # Build optional sub-agent handoffs — degrade gracefully if private CAI modules are absent
    handoffs = []
    try:
        from cai_orchestrator.phishing_agents import build_phishing_investigator_agent
        handoffs.append(build_phishing_investigator_agent(
            platform_api_base_url=platform_api_base_url, session=session, model=model,
        ))
    except Exception:
        pass

    try:
        from cai_orchestrator.ddos_agents import build_ddos_investigator_agent
        handoffs.append(build_ddos_investigator_agent(
            platform_api_base_url=platform_api_base_url, session=session, model=model,
        ))
    except Exception:
        pass

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
            "## DDoS investigation (S3 workspace path)\n"
            "Use this flow when the operator asks to investigate a DDoS attack or analyze denied/flooded traffic:\n"
            "1-5. Follow the S3 workspace steps above to get a staging manifest artifact.\n"
            "6. execute_watchguard_ddos_temporal_analysis(run_id, input_artifact_id=staging_id) → daily event counts, peak day\n"
            "7. execute_watchguard_ddos_top_sources(run_id, input_artifact_id=staging_id) → top attacker IPs and /16 segments\n"
            "8. execute_watchguard_ddos_top_destinations(run_id, input_artifact_id=staging_id) → top targeted assets\n"
            "9. execute_watchguard_ddos_segment_analysis(run_id, segment='<x.y>', input_artifact_id=staging_id) → drill into suspicious /16\n"
            "10. execute_watchguard_ddos_ip_profile(run_id, ip='<ip>', input_artifact_id=staging_id) → full profile per attacker IP\n"
            "11. execute_watchguard_ddos_hourly_distribution(run_id, date='YYYY-MM-DD', input_artifact_id=staging_id) → hourly pattern on peak day\n"
            "Read each artifact with read_artifact_content to get the structured JSON results before proceeding to the next step.\n\n"
            "## DDoS investigation — NIST case tracking (ALWAYS use this alongside DDoS tools)\n"
            "Every DDoS investigation MUST track state using the case tools. Follow this protocol:\n\n"
            "**START:** Call initialize_case(title=<incident_title>, summary=<1-line_description>, "
            "run_id=<staging_manifest_artifact_id>, observed_signals=['ddos', 'traffic flood', ...]) "
            "→ save the returned case_state_json and note the case_id. "
            "The DDoS strategy (ddos_nist_v1) is selected automatically.\n\n"
            "**THINK BEFORE ACTING:** Use think(thought=...) before deciding which tool to call next, "
            "which IP to drill into, or whether to advance a stage. This is mandatory for Haiku.\n\n"
            "**CRITICAL — case_state_json rule:** Every egs_case_tools call returns `updated_case_state`. "
            "You MUST pass this EXACT string verbatim as `case_state_json` in the NEXT call. "
            "NEVER construct, summarize, or reconstruct it — copy it exactly. "
            "If you get error 'case_state_json is incomplete', call load_case_state(case_id) to recover, "
            "then retry.\n\n"
            "**EVIDENCE RECORDING:** After every DDoS tool call + read_artifact_content, call "
            "record_case_evidence(case_state_json=<updated_case_state_from_previous_state_tool>, "
            "summary=<key_finding_1_sentence>, source=<tool_name>, artifact_refs=[<artifact_id>]). "
            "Use updated_case_state from the most recent initialize_case/record_case_*/advance_case_stage call.\n\n"
            "**STAGE FLOW — pass updated_case_state between every state tool call:**\n"
            "Stage 1 intake_and_scope (NIST Detection & Analysis — scope):\n"
            "  → temporal_analysis + top_sources + top_destinations → record_case_evidence for each "
            "→ advance_case_stage → save_case_state\n"
            "Stage 2 traffic_characterization (NIST Detection & Analysis — characterization):\n"
            "  → segment_analysis (top /16) + ip_profile (top IPs) + hourly_distribution (peak day) "
            "→ record_case_evidence → record_case_finding(severity='high'|'medium', confidence=0.0-1.0) "
            "→ advance_case_stage → save_case_state\n"
            "Stage 3 containment_or_monitoring_decision (NIST Containment, Eradication & Recovery):\n"
            "  → think about the evidence → record_case_decision(category='containment', "
            "summary=<recommendation>, rationale=<why>, selected_option='block'|'monitor'|'investigate_further', "
            "alternatives=[...]) → advance_case_stage → save_case_state\n"
            "Stage 4 findings_consolidation (NIST Lessons Learned):\n"
            "  → build_final_case_output(case_state_json=...) → this JSON IS the report data for LaTeX\n\n"
            "**CONTEXT RECOVERY:** If the session is interrupted, call load_case_state(case_id=<id>) "
            "to resume from where you left off. The case_id is in the initialize_case response.\n\n"
            "**NIST STAGE IDs:** intake_and_scope, traffic_characterization, "
            "containment_or_monitoring_decision, mitre_enrichment_optional (skip unless asked), "
            "findings_consolidation.\n\n"
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
            "## DDoS multi-agent pipeline\n"
            "When the operator asks to investigate a DDoS attack with a workspace_id:\n"
            "Hand off to ddos-orchestrator with the message: 'Investigate DDoS workspace_id=<id> client_id=<client_or_unknown>'\n"
            "The ddos-orchestrator will handle staging, case setup, and the full NIST pipeline automatically.\n"
            "Only use the individual DDoS tools (execute_watchguard_ddos_*) for quick ad-hoc queries outside the pipeline.\n\n"
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
            execute_watchguard_ddos_temporal_analysis,
            execute_watchguard_ddos_top_destinations,
            execute_watchguard_ddos_top_sources,
            execute_watchguard_ddos_segment_analysis,
            execute_watchguard_ddos_ip_profile,
            execute_watchguard_ddos_hourly_distribution,
            execute_watchguard_workspace_zip_ingestion,
            execute_watchguard_normalize,
            execute_watchguard_filter_denied,
            execute_watchguard_analytics_basic,
            execute_watchguard_top_talkers_basic,
            execute_phishing_email_basic_assessment,
            execute_watchguard_guarded_custom_query,
            # CAI case state management (NIST tracking + context persistence)
            think,
            initialize_case,
            record_case_hypothesis,
            record_case_evidence,
            record_case_finding,
            record_case_decision,
            advance_case_stage,
            build_final_case_output,
            save_case_state,
            load_case_state,
            get_case,
            get_run,
            get_run_status,
            list_run_artifacts,
            read_artifact_content,
        ],
        handoffs=handoffs,
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
DDOS_INVESTIGATOR_AGENT_TYPE = "ddos_investigator"


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
    if settings.cai_agent_type == DDOS_INVESTIGATOR_AGENT_TYPE:
        from cai_orchestrator.ddos_agents import build_ddos_investigator_agent
        return build_ddos_investigator_agent(
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
    supported = {DEFAULT_CAI_AGENT_TYPE, "platform_investigation_agent", PHISHING_INVESTIGATOR_AGENT_TYPE, DDOS_INVESTIGATOR_AGENT_TYPE}
    if agent_type not in supported:
        supported_list = ", ".join(f"'{t}'" for t in sorted(supported))
        raise ValueError(
            f"unsupported CAI_AGENT_TYPE '{agent_type}'; supported values are {supported_list}"
        )
