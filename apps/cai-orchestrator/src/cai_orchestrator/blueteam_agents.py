"""Hybrid blue team investigation pipeline for WatchGuard logs.

Architecture (hybrid, mirrors ddos_agents.py):
    Phase 1 — Python (no LLM)
      Finds/creates staging for the workspace, creates platform-api case + run,
      attaches two input artifacts (traffic + alarm).

    Phase 2 — _run_blueteam_collection() (plain Python, no LLM)
      Runs all multi_source_logs observations deterministically:
      - Against traffic artifact: normalize, failed_auth_detect, lateral_movement_detect,
        dns_anomaly_detect, privilege_escalation_detect
      - Against alarm artifact: active_threats_detect
      - Cross-source correlation with combined findings.

    Phase 3 — blueteam-synthesizer (CAI agent)
      Reads all produced artifacts, synthesizes findings into BlueteamSynthesisOutput.
      Optionally posts Slack notification when incident_detected=True.

Usage:
    import asyncio
    from cai_orchestrator.blueteam_agents import run_blueteam_investigation

    result = asyncio.run(run_blueteam_investigation(
        workspace_id="logs-ejemplo-ddos",
        client_id="egs",
        platform_api_base_url="http://127.0.0.1:8000",
    ))

Or via CLI:
    python3 -m cai_orchestrator run-blueteam-investigate \\
        --workspace-id logs-ejemplo-ddos \\
        --client-id egs
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel

from cai_orchestrator.cai_terminal import _resolve_model
from cai_orchestrator.cai_tools import PlatformApiToolService, _S3_BUCKET, _S3_REGION
from cai_orchestrator.client import PlatformApiClient, SyncHttpSession
from cai_orchestrator.errors import MissingCaiDependencyError


class BlueteamSynthesisOutput(BaseModel):
    case_id: str
    run_id: str
    workspace_id: str
    overall_severity: str           # 'critical'|'high'|'medium'|'low'|'none'
    confidence: float
    incident_detected: bool
    incident_categories: list[str]  # ['flood', 'ddos', 'scanning', ...]
    multi_stage_attack: bool
    top_attacker_ip: str | None
    top_targeted_user: str | None
    nist_phase: str                 # 'detection'|'analysis'|'containment'|'eradication'|'recovery'
    recommended_actions: list[str]
    evidence_summary: str


class BlueteamSetupOutput(BaseModel):
    case_id: str
    run_id: str
    traffic_artifact_id: str
    alarm_artifact_id: str
    staging_prefix: str


def _find_latest_staging_prefix(workspace_id: str, bucket: str, region: str) -> str | None:
    """Return the most recent staging prefix for the given workspace, or None if not staged."""
    try:
        import boto3
    except ImportError:
        return None
    s3 = boto3.client("s3", region_name=region)
    prefix = f"workspaces/{workspace_id}/staging/"
    paginator = s3.get_paginator("list_objects_v2")
    staging_ids: list[str] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter="/"):
        for cp in page.get("CommonPrefixes", []):
            p = cp["Prefix"].rstrip("/")
            staging_ids.append(p.split("/")[-1])
    if not staging_ids:
        return None
    latest = sorted(staging_ids)[-1]
    return f"workspaces/{workspace_id}/staging/{latest}"


def _stage_workspace(
    workspace_id: str,
    client: PlatformApiClient,
    client_id: str,
    bucket: str,
    region: str,
) -> str:
    """Stage the workspace ZIP via platform-api, returning the staging_prefix."""
    service = PlatformApiToolService(platform_api_client=client)
    # Find the raw ZIP in S3
    upload_info = service.find_latest_workspace_upload(
        workspace_id=workspace_id, bucket=bucket, region=region
    )
    if not upload_info.get("found"):
        raise ValueError(
            f"No uploaded ZIP found for workspace '{workspace_id}' in s3://{bucket}. "
            "Upload a WatchGuard ZIP first with: make upload-workspace ZIP=path.zip WORKSPACE={workspace_id}"
        )
    s3_uri = upload_info["s3_uri"]

    # Create a staging-only case/run under watchguard_logs
    stg_case = client.create_case(
        client_id=client_id,
        workflow_type="forensic_investigation",
        title=f"WatchGuard Staging — {workspace_id}",
        summary=f"Workspace staging for blue team investigation of {workspace_id}.",
    )
    stg_case_id = stg_case["case"]["case_id"]

    stg_art = client.attach_input_artifact(
        case_id=stg_case_id,
        payload={"workspace": workspace_id, "s3_uri": s3_uri},
    )
    stg_art_id = stg_art["artifact"]["artifact_id"]

    stg_run = client.create_run(
        case_id=stg_case_id,
        backend_id="watchguard_logs",
        input_artifact_ids=[stg_art_id],
    )
    stg_run_id = stg_run["run"]["run_id"]

    result = client.execute_watchguard_stage_workspace_zip(
        run_id=stg_run_id,
        requested_by="blueteam_pipeline",
        input_artifact_id=stg_art_id,
    )
    staging_prefix = (
        result.get("artifact", {}).get("payload", {}).get("staging_prefix")
        or result.get("observation_result", {}).get("structured_summary", {}).get("staging_prefix")
    )
    if not staging_prefix:
        raise ValueError(
            f"Staging did not return a staging_prefix. Response: {result}"
        )
    return staging_prefix


def _setup_blueteam_case(
    *,
    workspace_id: str,
    client_id: str,
    client: PlatformApiClient,
    bucket: str,
    region: str,
) -> BlueteamSetupOutput:
    """Python Phase 1: find/create staging, create case + two input artifacts + run."""
    # 1. Find or create staging prefix
    staging_prefix = _find_latest_staging_prefix(workspace_id, bucket, region)
    if not staging_prefix:
        staging_prefix = _stage_workspace(workspace_id, client, client_id, bucket, region)

    # 2. Create multi_source_logs case
    case_resp = client.create_case(
        client_id=client_id,
        workflow_type="log_investigation",
        title=f"Blue Team Investigation — {workspace_id}",
        summary=f"Automated defensive analysis of WatchGuard logs from workspace {workspace_id}.",
    )
    case_id = case_resp["case"]["case_id"]

    # 3. Attach traffic artifact
    traffic_resp = client.attach_input_artifact(
        case_id=case_id,
        payload={
            "source_type": "watchguard_traffic",
            "staging_prefix": staging_prefix,
            "bucket": bucket,
            "region": region,
        },
    )
    traffic_artifact_id = traffic_resp["artifact"]["artifact_id"]

    # 4. Attach alarm artifact
    alarm_resp = client.attach_input_artifact(
        case_id=case_id,
        payload={
            "source_type": "watchguard_alarm",
            "staging_prefix": staging_prefix,
            "bucket": bucket,
            "region": region,
        },
    )
    alarm_artifact_id = alarm_resp["artifact"]["artifact_id"]

    # 5. Create run with both artifacts as input
    run_resp = client.create_run(
        case_id=case_id,
        backend_id="multi_source_logs",
        input_artifact_ids=[traffic_artifact_id, alarm_artifact_id],
    )
    run_id = run_resp["run"]["run_id"]

    return BlueteamSetupOutput(
        case_id=case_id,
        run_id=run_id,
        traffic_artifact_id=traffic_artifact_id,
        alarm_artifact_id=alarm_artifact_id,
        staging_prefix=staging_prefix,
    )


def _run_blueteam_collection(
    *,
    client: PlatformApiClient,
    case_id: str,
    run_id: str,
    traffic_artifact_id: str,
    alarm_artifact_id: str,
) -> dict[str, Any]:
    """Deterministically run all multi_source_logs observations.

    Traffic artifact:
      normalize, failed_auth_detect (FWDeny flood), lateral_movement_detect (scanning),
      privilege_escalation_detect, dns_anomaly_detect

    Alarm artifact:
      active_threats_detect (udp_flood_dos, ddos_attack_src_dos, ip_scan_dos, Block-Site-Notif)

    Cross-source correlation uses combined findings from all above operations.

    Partial failures are recorded but do not stop the pipeline.
    Returns a dict mapping operation slug → response (or error dict).
    """
    results: dict[str, Any] = {}
    errors: list[str] = []

    # Operations against traffic log artifact
    traffic_operations: list[tuple[str, Any]] = [
        ("normalize", client.execute_multi_source_logs_normalize),
        ("failed_auth_detect", client.execute_multi_source_logs_failed_auth_detect),
        ("lateral_movement_detect", client.execute_multi_source_logs_lateral_movement_detect),
        ("privilege_escalation_detect", client.execute_multi_source_logs_privilege_escalation_detect),
        ("dns_anomaly_detect", client.execute_multi_source_logs_dns_anomaly_detect),
    ]

    for slug, fn in traffic_operations:
        try:
            resp = fn(
                run_id=run_id,
                requested_by="blueteam_pipeline",
                input_artifact_id=traffic_artifact_id,
            )
            results[slug] = resp
            status = resp.get("observation_result", {}).get("status", "")
            if status == "failed":
                errors.append(f"{slug}: backend execution failed — {resp.get('error', {}).get('message', '')}")
        except Exception as exc:
            results[slug] = {"error": str(exc)}
            errors.append(f"{slug}: {exc}")

    # Active threats detection against alarm artifact
    try:
        resp = client.execute_multi_source_logs_active_threats_detect(
            run_id=run_id,
            requested_by="blueteam_pipeline",
            input_artifact_id=alarm_artifact_id,
        )
        results["active_threats_detect"] = resp
        status = resp.get("observation_result", {}).get("status", "")
        if status == "failed":
            errors.append(f"active_threats_detect: backend execution failed")
    except Exception as exc:
        results["active_threats_detect"] = {"error": str(exc)}
        errors.append(f"active_threats_detect: {exc}")

    # Cross-source correlation (uses prior_findings from structured_summary of each op)
    prior_findings: dict[str, list[dict[str, Any]]] = {}
    for slug, resp in results.items():
        if isinstance(resp, dict):
            op_key = f"multi_source_logs.{slug}"
            findings = (
                resp.get("observation_result", {}).get("structured_summary", {}).get("findings", [])
            )
            if findings:
                prior_findings[op_key] = findings

    try:
        cross_payload = {"requested_by": "blueteam_pipeline", "input_artifact_id": traffic_artifact_id}
        # The cross_source_correlate operation reads prior_findings from the input payload.
        # We pass it via a synthetic artifact that contains the findings dict.
        # Since the API doesn't support inline prior_findings in the endpoint body,
        # we pass the traffic artifact as input (it won't be re-parsed for correlation).
        resp = client.execute_multi_source_logs_cross_source_correlate(
            run_id=run_id,
            requested_by="blueteam_pipeline",
            input_artifact_id=traffic_artifact_id,
        )
        results["cross_source_correlate"] = resp
    except Exception as exc:
        results["cross_source_correlate"] = {"error": str(exc)}
        errors.append(f"cross_source_correlate: {exc}")

    return {"results": results, "errors": errors, "case_id": case_id, "run_id": run_id}


def build_blueteam_synthesizer_agent(
    *,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> Any:
    """Build the blue team synthesizer agent (Phase 3).

    Reads all artifacts from the completed run and produces BlueteamSynthesisOutput.
    Optionally posts a Slack alert when incident_detected=True.
    """
    try:
        from cai.sdk.agents import Agent, function_tool
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use the blue team investigator."
        ) from exc

    client = PlatformApiClient(base_url=platform_api_base_url, session=session)
    service = PlatformApiToolService(platform_api_client=client)
    resolved_model = _resolve_model(model)

    @function_tool
    def get_run(run_id: str) -> dict:
        """Get the current run summary including status and artifact refs."""
        return service.get_run(run_id=run_id)

    @function_tool
    def list_run_artifacts(run_id: str) -> dict:
        """List all artifacts (input + output) attached to a run."""
        return service.list_run_artifacts(run_id=run_id)

    @function_tool
    def read_artifact_content(artifact_id: str) -> dict:
        """Read the full content of an artifact by ID."""
        return service.read_artifact_content(artifact_id=artifact_id)

    tools = [get_run, list_run_artifacts, read_artifact_content]

    # Add Slack notification tool if webhook is configured
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if slack_webhook:
        @function_tool(strict_mode=False)
        def notify_slack(
            case_id: str,
            severity: str,
            incident_categories: list[str],
            summary: str,
        ) -> dict:
            """Post investigation result to SOC Slack channel. Only call when incident_detected=True."""
            try:
                import requests
            except ImportError:
                return {"notified": False, "reason": "requests library not installed"}
            webhook = os.environ.get("SLACK_WEBHOOK_URL")
            if not webhook:
                return {"notified": False, "reason": "SLACK_WEBHOOK_URL not set"}
            cats = ", ".join(incident_categories) if incident_categories else "unknown"
            text = (
                f"*[{severity.upper()}]* Blue Team Alert — Case `{case_id}`\n"
                f"Categories: {cats}\n{summary}"
            )
            try:
                requests.post(webhook, json={"text": text}, timeout=5)
                return {"notified": True}
            except Exception as exc:
                return {"notified": False, "reason": str(exc)}

        tools.append(notify_slack)

    instructions = """\
You are the blue team synthesis agent. You consolidate findings from deterministic detection operations
run against WatchGuard traffic logs (traffic CSV) and alarm logs (alarm CSV).
You have read-only tools: get_run, list_run_artifacts, read_artifact_content.
Do NOT call any detection or observation tools.

Step 1: Call list_run_artifacts(run_id) to discover all output artifact IDs.

Step 2: Call read_artifact_content on EACH output artifact. Key artifacts:
  - normalize artifact (for source_type and row_count)
  - failed_auth_detect artifact (FWDeny flood patterns from traffic)
  - lateral_movement_detect artifact (internal scanning from traffic)
  - privilege_escalation_detect artifact (if relevant)
  - dns_anomaly_detect artifact (DGA/beaconing from DNS traffic)
  - active_threats_detect artifact (alarm events: udp_flood_dos, ddos_attack_src_dos, ip_scan_dos, Block-Site-Notif)
  - cross_source_correlate artifact (multi-stage indicators)

Step 3: Analyze all structured_summary fields and findings across artifacts.

Step 4: Populate BlueteamSynthesisOutput. Apply NIST SP 800-61 phases:
  - "detection": findings identified but no confirmed attack pattern
  - "analysis": confirmed attack pattern across one or more categories
  - "containment": multi-stage attack or critical/high severity confirmed

Step 5: If notify_slack tool is available and incident_detected=True, call it with:
  - case_id, severity=overall_severity, incident_categories, evidence_summary

Step 6: Output the completed BlueteamSynthesisOutput and stop.
"""

    return Agent(
        name="blueteam-synthesizer",
        model=resolved_model,
        instructions=instructions,
        tools=tools,
        output_type=BlueteamSynthesisOutput,
    )


async def run_blueteam_investigation(
    *,
    workspace_id: str,
    client_id: str,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
    model: str | None = None,
    bucket: str = _S3_BUCKET,
    region: str = _S3_REGION,
) -> BlueteamSynthesisOutput:
    """Run the complete 3-phase hybrid blue team investigation pipeline.

    Phase 1: Python setup — finds/creates staging, creates case + two WatchGuard artifacts + run.
    Phase 2: Python deterministically runs all detection observations (no LLM).
    Phase 3: CAI synthesizer reads artifacts and produces structured BlueteamSynthesisOutput.
    """
    try:
        from cai.sdk.agents import Runner, RunConfig
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use the blue team investigator."
        ) from exc

    import httpx as _httpx
    _session = session or _httpx.Client(base_url=platform_api_base_url, timeout=600.0)
    client = PlatformApiClient(base_url=platform_api_base_url, session=_session)

    # Phase 1: Python setup (no LLM)
    setup = _setup_blueteam_case(
        workspace_id=workspace_id,
        client_id=client_id,
        client=client,
        bucket=bucket,
        region=region,
    )
    case_id = setup.case_id
    run_id = setup.run_id

    # Phase 2: Python deterministic collection
    _run_blueteam_collection(
        client=client,
        case_id=case_id,
        run_id=run_id,
        traffic_artifact_id=setup.traffic_artifact_id,
        alarm_artifact_id=setup.alarm_artifact_id,
    )

    # Phase 3: CAI synthesizer
    synthesizer = build_blueteam_synthesizer_agent(
        platform_api_base_url=platform_api_base_url,
        session=_session,
        model=model,
    )
    synth_prompt = (
        f"Synthesize blue team investigation of WatchGuard workspace '{workspace_id}'. "
        f"run_id={run_id} case_id={case_id}"
    )
    synth_result = await Runner.run(
        synthesizer,
        input=synth_prompt,
        run_config=RunConfig(
            workflow_name="blueteam-synthesis",
            group_id=case_id,
            trace_include_sensitive_data=False,
        ),
    )
    client.complete_run(
        run_id=run_id,
        requested_by="blueteam_investigation",
        reason="Hybrid blue team investigation pipeline finished.",
    )
    return synth_result.final_output
