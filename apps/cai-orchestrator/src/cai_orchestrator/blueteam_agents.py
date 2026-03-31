"""Hybrid blue team investigation pipeline: CAI agents for setup/synthesis, Python for data collection.

Architecture (hybrid, mirrors ddos_agents.py):
    Phase 1 — blueteam-orchestrator (CAI agent)
      Creates platform-api case + run, attaches input artifact.
      Outputs: SETUP_COMPLETE case_id=<id> run_id=<id> input_artifact_id=<id>

    Phase 2 — _run_blueteam_collection() (plain Python, no LLM)
      Calls all 6 multi_source_logs observations deterministically via HTTP client.
      Continues on partial failures (records errors but does not stop).

    Phase 3 — blueteam-synthesizer (CAI agent)
      Reads all produced artifacts, synthesizes findings into BlueteamSynthesisOutput.
      Optional: posts Slack notification when incident_detected=True.

Usage:
    import asyncio
    from cai_orchestrator.blueteam_agents import run_blueteam_investigation

    result = asyncio.run(run_blueteam_investigation(
        s3_uri="s3://my-bucket/logs/auth.log",
        source_type="linux_auth",
        client_id="acme",
        platform_api_base_url="http://127.0.0.1:8000",
    ))

Or via CLI:
    python3 -m cai_orchestrator run-blueteam-investigate \\
        --s3-uri s3://my-bucket/logs/auth.log \\
        --source-type linux_auth \\
        --client-id acme
"""

from __future__ import annotations

import os
import re
from typing import Any

from pydantic import BaseModel

from cai_orchestrator.cai_terminal import _resolve_model
from cai_orchestrator.cai_tools import PlatformApiToolService
from cai_orchestrator.client import PlatformApiClient, SyncHttpSession
from cai_orchestrator.errors import MissingCaiDependencyError


class BlueteamSynthesisOutput(BaseModel):
    case_id: str
    run_id: str
    source_type: str
    overall_severity: str           # 'critical'|'high'|'medium'|'low'|'none'
    confidence: float
    incident_detected: bool
    incident_categories: list[str]  # ['brute_force', 'lateral_movement', ...]
    multi_stage_attack: bool
    top_attacker_ip: str | None
    top_targeted_user: str | None
    nist_phase: str                 # 'detection'|'analysis'|'containment'|'eradication'|'recovery'
    recommended_actions: list[str]
    evidence_summary: str


def _parse_blueteam_setup_complete(text: str) -> tuple[str, str, str]:
    """Extract (case_id, run_id, input_artifact_id) from the orchestrator's SETUP_COMPLETE line."""
    match = re.search(
        r"SETUP_COMPLETE\s+case_id=(\S+)\s+run_id=(\S+)\s+input_artifact_id=(\S+)",
        text,
    )
    if not match:
        raise ValueError(
            f"Orchestrator did not output a SETUP_COMPLETE line.\nFull output:\n{text}"
        )
    return match.group(1), match.group(2), match.group(3)


def _run_blueteam_collection(
    *,
    client: PlatformApiClient,
    case_id: str,
    run_id: str,
    input_artifact_id: str,
) -> dict[str, Any]:
    """Deterministically run all 6 multi_source_logs observations.

    Partial failures are recorded but do not stop the pipeline.
    Returns a dict mapping operation slug → response (or error dict).
    """
    results: dict[str, Any] = {}
    errors: list[str] = []

    operations = [
        ("normalize", client.execute_multi_source_logs_normalize),
        ("failed_auth_detect", client.execute_multi_source_logs_failed_auth_detect),
        ("lateral_movement_detect", client.execute_multi_source_logs_lateral_movement_detect),
        ("privilege_escalation_detect", client.execute_multi_source_logs_privilege_escalation_detect),
        ("dns_anomaly_detect", client.execute_multi_source_logs_dns_anomaly_detect),
        ("cross_source_correlate", client.execute_multi_source_logs_cross_source_correlate),
    ]

    for slug, fn in operations:
        try:
            resp = fn(
                run_id=run_id,
                requested_by="blueteam_pipeline",
                input_artifact_id=input_artifact_id,
            )
            results[slug] = resp
            status = resp.get("observation_result", {}).get("status", "")
            if status == "failed":
                errors.append(f"{slug}: backend execution failed — {resp.get('error', {}).get('message', '')}")
        except Exception as exc:
            results[slug] = {"error": str(exc)}
            errors.append(f"{slug}: {exc}")

    return {"results": results, "errors": errors, "case_id": case_id, "run_id": run_id}


def build_blueteam_orchestrator_agent(
    *,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> Any:
    """Build the blue team setup agent (Phase 1).

    Creates the platform-api case, attaches the input artifact, and creates the run.
    Outputs a SETUP_COMPLETE sentinel line so the pipeline can extract IDs.
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
    def create_case(client_id: str, workflow_type: str, title: str, summary: str) -> dict:
        """Create a new investigation case via platform-api."""
        return service.create_case(
            client_id=client_id,
            workflow_type=workflow_type,
            title=title,
            summary=summary,
        )

    @function_tool
    def attach_input_artifact(case_id: str, payload: dict) -> dict:
        """Attach a JSON input artifact to a case. payload must include source_type and s3_uri."""
        return service.attach_input_artifact(
            case_id=case_id,
            payload=payload,
        )

    @function_tool
    def create_run(case_id: str, backend_id: str, input_artifact_ids: list[str]) -> dict:
        """Create a backend run for the case."""
        return service.create_run(
            case_id=case_id,
            backend_id=backend_id,
            input_artifact_ids=input_artifact_ids,
        )

    @function_tool
    def list_run_artifacts(run_id: str) -> dict:
        """List artifacts attached to a run."""
        return service.list_run_artifacts(run_id=run_id)

    instructions = """\
You are the blue team investigation setup agent. You work exclusively through platform-api tools.
You do NOT analyze logs. You prepare the investigation case.

Step 1: Call create_case with:
  - client_id from the operator prompt
  - workflow_type = "log_investigation"
  - title = "Multi-Source Log Investigation — {source_type}" (fill in actual source_type)
  - summary = "Automated defensive analysis of {source_type} logs from {s3_uri}" (fill in actual values)

Step 2: Call attach_input_artifact with:
  - case_id from Step 1
  - payload = {"source_type": "<source_type>", "s3_uri": "<s3_uri>"}

Step 3: Call create_run with:
  - case_id from Step 1
  - backend_id = "multi_source_logs"
  - input_artifact_ids = [artifact_id from Step 2]

Step 4: Output EXACTLY this line and stop (no other text):
SETUP_COMPLETE case_id=<case_id> run_id=<run_id> input_artifact_id=<artifact_id>
"""

    return Agent(
        name="blueteam-orchestrator",
        model=resolved_model,
        instructions=instructions,
        tools=[create_case, attach_input_artifact, create_run, list_run_artifacts],
    )


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
You are the blue team synthesis agent. You consolidate findings from deterministic detection operations.
You have read-only tools: get_run, list_run_artifacts, read_artifact_content.
Do NOT call any detection or observation tools.

Step 1: Call list_run_artifacts(run_id) to discover all output artifact IDs.

Step 2: Call read_artifact_content on EACH output artifact in this order:
  - normalize artifact (for source_type and row_count)
  - failed_auth_detect artifact
  - lateral_movement_detect artifact
  - privilege_escalation_detect artifact
  - dns_anomaly_detect artifact
  - cross_source_correlate artifact (if present)

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
    s3_uri: str,
    source_type: str,
    client_id: str,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> BlueteamSynthesisOutput:
    """Run the complete 3-phase hybrid blue team investigation pipeline.

    Phase 1: CAI orchestrator creates case + run (setup)
    Phase 2: Python deterministically runs all 6 detection observations
    Phase 3: CAI synthesizer reads artifacts and produces structured output
    """
    try:
        from cai.sdk.agents import Runner, RunConfig
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use the blue team investigator."
        ) from exc

    client = PlatformApiClient(base_url=platform_api_base_url, session=session)

    # Phase 1: CAI orchestrator setup
    orchestrator = build_blueteam_orchestrator_agent(
        platform_api_base_url=platform_api_base_url,
        session=session,
        model=model,
    )
    prompt = (
        f"Investigate {source_type} logs from {s3_uri}. client_id={client_id}"
    )
    group_id = s3_uri.split("/")[-1].split(".")[0]  # use filename stem as group ID
    orch_result = await Runner.run(
        orchestrator,
        input=prompt,
        run_config=RunConfig(
            workflow_name="blueteam-setup",
            group_id=group_id,
            trace_include_sensitive_data=False,
        ),
    )
    case_id, run_id, input_artifact_id = _parse_blueteam_setup_complete(
        orch_result.final_output or ""
    )

    # Phase 2: Python deterministic collection
    _run_blueteam_collection(
        client=client,
        case_id=case_id,
        run_id=run_id,
        input_artifact_id=input_artifact_id,
    )

    # Phase 3: CAI synthesizer
    synthesizer = build_blueteam_synthesizer_agent(
        platform_api_base_url=platform_api_base_url,
        session=session,
        model=model,
    )
    synth_prompt = (
        f"Synthesize blue team investigation. "
        f"run_id={run_id} case_id={case_id} source_type={source_type}"
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
    return synth_result.final_output
