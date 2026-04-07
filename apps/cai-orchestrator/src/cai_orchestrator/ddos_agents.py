"""Hybrid DDoS investigation pipeline: CAI agents for setup/synthesis, Python for data collection.

Architecture (hybrid):
    Phase 1 — ddos-orchestrator (CAI agent)
      Creates platform-api case + run, stages the workspace ZIP, initialises CaseState.
      Outputs: SETUP_COMPLETE nist_case_id=... run_id=... staging_artifact_id=...

    Phase 2 — _run_ddos_collection() (plain Python, no LLM)
      Calls all 7 DDoS observations deterministically via HTTP client.
      Records all evidence + forensic finding directly via CaseOrchestrator.
      Observations: temporal_analysis, top_sources, top_destinations, protocol_breakdown,
                    segment_analysis, ip_profile, hourly_distribution.

    Phase 3 — ddos-synthesizer (CAI agent)
      Loads the case, evaluates evidence and finding, records containment decision.
      Calls case_build_final_output → returns complete NIST SP 800-61 JSON.

Usage:
    import asyncio
    from cai_orchestrator.ddos_agents import run_ddos_investigation

    result = asyncio.run(run_ddos_investigation(
        workspace_id="logs-ejemplo-ddos",
        platform_api_base_url="http://127.0.0.1:8000",
        model="bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
    ))

Or via CLI:
    python3 -m cai_orchestrator run-ddos-investigate --workspace-id logs-ejemplo-ddos
"""

from __future__ import annotations

import json as _json
import re
from typing import Any

from pydantic import BaseModel

from cai_orchestrator.cai_terminal import _resolve_model
from cai_orchestrator.cai_tools import PlatformApiToolService
from cai_orchestrator.client import PlatformApiClient, SyncHttpSession
from cai_orchestrator.errors import MissingCaiDependencyError


class DDoSSynthesisOutput(BaseModel):
    nist_case_id: str
    incident_type: str          # 'volumetric_ddos'|'application_ddos'|'mixed'
    severity: str               # 'critical'|'high'|'medium'|'low'
    confidence: float
    peak_date: str
    top_source_ip: str
    dominant_protocol: str
    containment_decision: str   # 'block'|'monitor'|'investigate_further'
    containment_rationale: str
    nist_stage_reached: str
    evidence_summary: str
    exploratory_queries_performed: int = 0
    exploratory_findings: str = ""


class DDoSSetupOutput(BaseModel):
    nist_case_id: str
    run_id: str
    staging_artifact_id: str


def _parse_synthesis_output(text: str, fallback_case_id: str) -> DDoSSynthesisOutput:
    """Parse the synthesizer's JSON block output into a DDoSSynthesisOutput."""
    import json as _j, re as _re
    match = _re.search(r"```json\s*(\{.*?\})\s*```", text, _re.DOTALL)
    if match:
        try:
            data = _j.loads(match.group(1))
            data.setdefault("nist_case_id", fallback_case_id)
            data.setdefault("exploratory_queries_performed", 0)
            data.setdefault("exploratory_findings", "")
            return DDoSSynthesisOutput(**data)
        except Exception:
            pass
    # Fallback: try to parse any JSON object in the output
    match = _re.search(r"\{[^{}]*\"nist_case_id\"[^{}]*\}", text, _re.DOTALL)
    if match:
        try:
            data = _j.loads(match.group(0))
            data.setdefault("nist_case_id", fallback_case_id)
            data.setdefault("exploratory_queries_performed", 0)
            data.setdefault("exploratory_findings", "")
            return DDoSSynthesisOutput(**data)
        except Exception:
            pass
    raise ValueError(f"Could not parse DDoSSynthesisOutput from synthesizer output:\n{text}")


def _parse_setup_output(text: str) -> DDoSSetupOutput:
    """Parse the orchestrator's SETUP_COMPLETE text block into a DDoSSetupOutput."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        for key in ("nist_case_id", "run_id", "staging_artifact_id"):
            if line.startswith(f"{key}="):
                fields[key] = line.split("=", 1)[1].strip()
    missing = [k for k in ("nist_case_id", "run_id", "staging_artifact_id") if k not in fields]
    if missing:
        raise ValueError(
            f"Setup orchestrator output missing fields {missing}. Full output:\n{text}"
        )
    return DDoSSetupOutput(**fields)


def _run_ddos_collection(
    *,
    client: PlatformApiClient,
    nist_case_id: str,
    run_id: str,
    staging_artifact_id: str,
) -> dict:
    """Deterministically run all 7 DDoS observations and record evidence in the NIST case.

    Calls platform-api directly via the HTTP client — no LLM involved.
    Returns a structured summary dict for the synthesizer.
    """
    try:
        from cai.egs_orchestration.models.incident import SeverityLevel
        from cai.egs_orchestration.services.case_orchestrator import CaseOrchestrator
        from cai.tools.workspace.case_state_store import get_default_case_state_store
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use DDoS investigation."
        ) from exc

    orch = CaseOrchestrator()
    store = get_default_case_state_store()

    def _aid(r: dict) -> str:
        """Extract artifact_id from an observation response."""
        return r["artifacts"][0]["artifact_id"]

    def _ss(r: dict) -> dict:
        """Extract structured_summary from an observation response."""
        return r.get("observation_result", {}).get("structured_summary", {})

    state = store.load(nist_case_id)
    if state is None:
        raise ValueError(f"NIST case {nist_case_id} not found in case store")

    # 1. Temporal analysis
    r = client.execute_watchguard_ddos_temporal_analysis(
        run_id=run_id, requested_by="ddos_pipeline", input_artifact_id=staging_artifact_id
    )
    temporal_artifact_id = _aid(r)
    ss = _ss(r)
    peak_date: str = ss.get("peak_day") or ""
    total_events: int = ss.get("total_events", 0)
    state = orch.record_evidence(
        state,
        summary=f"Temporal analysis: peak day {peak_date}, {total_events:,} total events.",
        source="ddos_temporal_analysis",
        artifact_refs=[temporal_artifact_id],
    )
    store.save(state)

    # 2. Top sources
    r = client.execute_watchguard_ddos_top_sources(
        run_id=run_id, requested_by="ddos_pipeline", input_artifact_id=staging_artifact_id
    )
    sources_artifact_id = _aid(r)
    ss = _ss(r)
    # dominant_segment comes as "172.50.0.0/16" → extract "172.50" for segment_analysis
    raw_segment: str = ss.get("dominant_segment", "")
    top_segment = ".".join(raw_segment.split(".")[:2]) if raw_segment else "unknown"
    top_ip: str = ss.get("top_source", "unknown")
    state = orch.record_evidence(
        state,
        summary=f"Top sources: dominant segment {raw_segment}, top source IP {top_ip}.",
        source="ddos_top_sources",
        artifact_refs=[sources_artifact_id],
    )
    store.save(state)

    # 3. Top destinations
    r = client.execute_watchguard_ddos_top_destinations(
        run_id=run_id, requested_by="ddos_pipeline", input_artifact_id=staging_artifact_id
    )
    destinations_artifact_id = _aid(r)
    ss = _ss(r)
    state = orch.record_evidence(
        state,
        summary=f"Top destinations: top target {ss.get('top_destination')} ({ss.get('top_destination_pct', 0):.1f}%).",
        source="ddos_top_destinations",
        artifact_refs=[destinations_artifact_id],
    )
    store.save(state)

    # 4. Protocol breakdown
    r = client.execute_watchguard_ddos_protocol_breakdown(
        run_id=run_id, requested_by="ddos_pipeline", input_artifact_id=staging_artifact_id
    )
    protocol_artifact_id = _aid(r)
    ss = _ss(r)
    top_protocol: str = ss.get("top_protocol", "")
    tp_upper = top_protocol.upper()
    signals: list[str] = []
    if "ICMP" in tp_upper:
        signals.append("icmp flood")
    elif "UDP" in tp_upper:
        signals.append("udp flood")
    elif "TCP" in tp_upper or "HTTPS" in tp_upper or "HTTP" in tp_upper:
        signals.append("tcp flood")
    existing_signals = set(state.incident.observed_signals or [])
    state.incident.observed_signals = sorted(existing_signals | set(signals))
    state = orch.record_evidence(
        state,
        summary=(
            f"Protocol breakdown: top protocol {top_protocol} "
            f"({ss.get('top_protocol_pct', 0):.1f}%), {ss.get('protocol_count', 0)} protocols total."
        ),
        source="ddos_protocol_breakdown",
        artifact_refs=[protocol_artifact_id],
    )
    state = orch.advance_stage(
        state, note="Traffic characterization complete (temporal + sources + destinations + protocol)."
    )
    store.save(state)

    # 5. Segment analysis (top /16 segment)
    r = client.execute_watchguard_ddos_segment_analysis(
        run_id=run_id,
        segment=top_segment,
        requested_by="ddos_pipeline",
        input_artifact_id=staging_artifact_id,
    )
    segment_artifact_id = _aid(r)
    ss = _ss(r)
    state = orch.record_evidence(
        state,
        summary=(
            f"Segment {top_segment}: {ss.get('total_events', 0):,} events "
            f"({ss.get('allow_events', 0):,} allow / {ss.get('deny_events', 0):,} deny)."
        ),
        source="ddos_segment_analysis",
        artifact_refs=[segment_artifact_id],
    )
    store.save(state)

    # 6. IP profile (top source IP)
    r = client.execute_watchguard_ddos_ip_profile(
        run_id=run_id,
        ip=top_ip,
        requested_by="ddos_pipeline",
        input_artifact_id=staging_artifact_id,
    )
    ip_artifact_id = _aid(r)
    ss = _ss(r)
    state = orch.record_evidence(
        state,
        summary=(
            f"IP {top_ip}: {ss.get('total_events', 0):,} events "
            f"({ss.get('allow_events', 0):,} allow / {ss.get('deny_events', 0):,} deny)."
        ),
        source="ddos_ip_profile",
        artifact_refs=[ip_artifact_id],
    )
    store.save(state)

    # 7. Hourly distribution on peak day
    r = client.execute_watchguard_ddos_hourly_distribution(
        run_id=run_id,
        date=peak_date,
        requested_by="ddos_pipeline",
        input_artifact_id=staging_artifact_id,
    )
    hourly_artifact_id = _aid(r)
    ss = _ss(r)
    state = orch.record_evidence(
        state,
        summary=(
            f"Hourly distribution on {peak_date}: peak at hour {ss.get('peak_hour')}, "
            f"{ss.get('total_events', 0):,} events."
        ),
        source="ddos_hourly_distribution",
        artifact_refs=[hourly_artifact_id],
    )

    # Forensic finding
    state = orch.record_finding(
        state,
        title="Volumetric DDoS Attack",
        summary=(
            f"Confirmed volumetric DDoS attack: {total_events:,} total events. "
            f"Primary attack source segment: {raw_segment}. Top source IP: {top_ip}. "
            f"Peak activity on {peak_date}. Dominant protocol: {top_protocol}."
        ),
        severity=SeverityLevel("high"),
        confidence=0.85,
    )
    state = orch.advance_stage(
        state, note="Threat assessment complete (segment + IP + hourly analysis)."
    )
    store.save(state)

    return {
        "peak_date": peak_date,
        "total_events": total_events,
        "top_segment": raw_segment,
        "top_ip": top_ip,
        "top_protocol": top_protocol,
        "artifact_ids": {
            "temporal": temporal_artifact_id,
            "top_sources": sources_artifact_id,
            "top_destinations": destinations_artifact_id,
            "protocol_breakdown": protocol_artifact_id,
            "segment_analysis": segment_artifact_id,
            "ip_profile": ip_artifact_id,
            "hourly_distribution": hourly_artifact_id,
        },
    }


def build_ddos_investigator_agent(
    *,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
    model: str | None = None,
    _return_synthesizer: bool = False,
) -> Any:
    """Build the DDoS orchestrator agent (setup-only, hybrid pipeline entry point).

    When _return_synthesizer=True, returns (orchestrator, synthesizer) tuple.
    Used internally by run_ddos_investigation.
    """
    try:
        from cai.egs_orchestration.models.incident import IncidentInput, SeverityLevel
        from cai.egs_orchestration.services.case_orchestrator import CaseOrchestrator
        from cai.sdk.agents import Agent, function_tool
        from cai.tools.misc.reasoning import think
        from cai.tools.workspace.case_state_store import get_default_case_state_store
        from cai.tools.workspace.egs_case_tools import (
            initialize_case,
            load_case_state,
        )
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use the DDoS investigator."
        ) from exc

    client = PlatformApiClient(base_url=platform_api_base_url, session=session)
    service = PlatformApiToolService(platform_api_client=client)

    _orch = CaseOrchestrator()

    def _get_store():
        return get_default_case_state_store()

    # ── exploration budget (synthesizer active-investigation tools) ─────────
    # The synthesizer may call up to _EXPLORATION_BUDGET exploratory tool calls
    # to close gaps in the pre-collected evidence. The counter is closure-local
    # so each investigation run has its own fresh budget.
    _exploration_counter = {"count": 0}
    _EXPLORATION_BUDGET = 7

    def _check_exploration_budget(tool_name: str) -> dict[str, Any] | None:
        """Return a blocking error dict if the budget is exhausted, else increment and return None."""
        if _exploration_counter["count"] >= _EXPLORATION_BUDGET:
            return {
                "error": "exploration_budget_exhausted",
                "message": (
                    f"Exploration budget of {_EXPLORATION_BUDGET} queries already used. "
                    f"Tool {tool_name} refused. Proceed to STEP 3 (record decision) immediately."
                ),
                "queries_used": _exploration_counter["count"],
            }
        _exploration_counter["count"] += 1
        return None

    # ── staging info store/retrieve tools ─────────────────────────────────
    # Orchestrator saves staging IDs into the NIST case metadata before
    # handing off; downstream agents retrieve them with get_staging_info.

    @function_tool
    def save_staging_info(
        nist_case_id: str,
        staging_artifact_id: str,
        platform_run_id: str,
    ) -> str:
        """Persist staging IDs into the NIST case so downstream agents can retrieve them.
        Call this BEFORE handing off to ddos-processor."""
        state = _get_store().load(nist_case_id)
        if state is None:
            return _json.dumps({"error": f"NIST case {nist_case_id} not found in store."})
        state.metadata["staging_artifact_id"] = staging_artifact_id
        state.metadata["platform_run_id"] = platform_run_id
        _get_store().save(state)
        return _json.dumps({
            "ok": True,
            "nist_case_id": nist_case_id,
            "staging_artifact_id": staging_artifact_id,
            "platform_run_id": platform_run_id,
        })

    @function_tool
    def get_staging_info(nist_case_id: str) -> str:
        """Retrieve staging_artifact_id and platform_run_id for a NIST case.
        Call this at the VERY START of ddos-processor and ddos-ip-profiler."""
        state = _get_store().load(nist_case_id)
        if state is None:
            return _json.dumps({"error": f"NIST case {nist_case_id} not found in store."})
        return _json.dumps({
            "nist_case_id": nist_case_id,
            "staging_artifact_id": state.metadata.get("staging_artifact_id"),
            "platform_run_id": state.metadata.get("platform_run_id", state.data_runner_run_id),
        })

    @function_tool(strict_mode=False)
    def initialize_case_and_save_staging(
        title: str,
        summary: str,
        staging_artifact_id: str,
        platform_run_id: str,
        workspace: str | None = None,
        run_id: str | None = None,
        raw_text: str | None = None,
        labels: list[str] | None = None,
        observed_signals: list[str] | None = None,
        impacted_assets: list[str] | None = None,
    ) -> str:
        """Create a NIST case state AND atomically save staging IDs so downstream agents
        can retrieve them with get_staging_info. Combines initialize_case + save_staging_info
        into one call. Returns case state JSON with the 'case_id' field."""
        incident = IncidentInput(
            title=title,
            summary=summary,
            workspace=workspace,
            run_id=run_id,
            raw_text=raw_text,
            labels=labels or [],
            observed_signals=observed_signals or [],
            impacted_assets=impacted_assets or [],
        )
        state = _orch.open_case(incident)
        state.metadata["staging_artifact_id"] = staging_artifact_id
        state.metadata["platform_run_id"] = platform_run_id
        _get_store().save(state)
        return _json.dumps(state.model_dump(mode="json"), indent=2)

    @function_tool
    def get_workspace_staging_details(nist_case_id: str) -> str:
        """Alias for get_staging_info. Retrieve staging_artifact_id and platform_run_id."""
        state = _get_store().load(nist_case_id)
        if state is None:
            return _json.dumps({"error": f"NIST case {nist_case_id} not found in store."})
        return _json.dumps({
            "nist_case_id": nist_case_id,
            "staging_artifact_id": state.metadata.get("staging_artifact_id"),
            "platform_run_id": state.metadata.get("platform_run_id", state.data_runner_run_id),
        })

    # ── case-id-based wrapper tools (no case_state_json threading needed) ───
    # All case mutations accept case_id only — state is loaded from/saved to
    # the store automatically. Agents never need to pass large JSON blobs.

    @function_tool
    def case_record_evidence(
        case_id: str,
        summary: str,
        source: str,
        confidence: float = 0.7,
        artifact_id: str | None = None,
    ) -> str:
        """Add evidence to an existing case. Pass case_id only — no case_state_json needed."""
        state = _get_store().load(case_id)
        if state is None:
            return _json.dumps({"error": f"Case {case_id} not found in store."})
        state = _orch.record_evidence(
            state,
            summary,
            source=source,
            confidence=confidence,
            artifact_refs=[artifact_id] if artifact_id else None,
        )
        _get_store().save(state)
        return _json.dumps({"ok": True, "case_id": case_id, "evidence_count": len(state.evidence_items)})

    @function_tool
    def case_record_finding(
        case_id: str,
        title: str,
        summary: str,
        severity: str,
        confidence: float = 0.8,
    ) -> str:
        """Add a forensic finding to an existing case. severity: 'high'|'medium'|'low'."""
        state = _get_store().load(case_id)
        if state is None:
            return _json.dumps({"error": f"Case {case_id} not found in store."})
        state = _orch.record_finding(
            state,
            title=title,
            summary=summary,
            severity=SeverityLevel(severity),
            confidence=confidence,
        )
        _get_store().save(state)
        return _json.dumps({"ok": True, "case_id": case_id, "finding_count": len(state.findings)})  # noqa: E501

    @function_tool
    def case_record_decision(
        case_id: str,
        category: str,
        summary: str,
        rationale: str,
        selected_option: str,
        alternatives: list[str] | None = None,
    ) -> str:
        """Add a containment/response decision to an existing case."""
        state = _get_store().load(case_id)
        if state is None:
            return _json.dumps({"error": f"Case {case_id} not found in store."})
        state = _orch.record_decision(
            state,
            category=category,
            summary=summary,
            rationale=rationale,
            selected_option=selected_option,
            alternatives=alternatives,
        )
        _get_store().save(state)
        return _json.dumps({"ok": True, "case_id": case_id})

    @function_tool
    def case_add_observed_signals(case_id: str, signals: list[str]) -> str:
        """Append new observed signals to an existing case (avoids duplicates).
        Call after protocol_breakdown to enrich with protocol-specific signals."""
        state = _get_store().load(case_id)
        if state is None:
            return _json.dumps({"error": f"Case {case_id} not found in store."})
        existing = set(state.incident.observed_signals or [])
        for sig in signals:
            existing.add(sig)
        state.incident.observed_signals = sorted(existing)
        _get_store().save(state)
        return _json.dumps({"ok": True, "case_id": case_id, "observed_signals": state.incident.observed_signals})

    @function_tool
    def case_advance_stage(case_id: str, note: str | None = None) -> str:
        """Advance the case to the next NIST IR stage."""
        state = _get_store().load(case_id)
        if state is None:
            return _json.dumps({"error": f"Case {case_id} not found in store."})
        state = _orch.advance_stage(state, note=note)
        _get_store().save(state)
        return _json.dumps({"ok": True, "case_id": case_id, "new_stage": state.current_stage_id})

    @function_tool
    def case_build_final_output(case_id: str) -> str:
        """Build the final NIST structured case output. Call this last to produce the report JSON."""
        state = _get_store().load(case_id)
        if state is None:
            return _json.dumps({"error": f"Case {case_id} not found in store."})
        output = _orch.build_final_output(state)
        if hasattr(output, "model_dump"):
            return _json.dumps(output.model_dump(mode="json"), indent=2)
        return _json.dumps(output, indent=2)

    # ── shared read tools ───────────────────────────────────────────────────

    @function_tool(strict_mode=False)
    def read_artifact_content(artifact_id: str) -> dict[str, Any]:
        """Read the stored content of an artifact by its artifact_id."""
        return service.read_artifact_content(artifact_id=artifact_id)

    @function_tool(strict_mode=False)
    def list_run_artifacts(run_id: str) -> dict[str, Any]:
        """List all artifacts attached to a run. Use to discover artifact_ids."""
        return service.list_run_artifacts(run_id=run_id)

    # ── orchestrator-only tools ─────────────────────────────────────────────

    @function_tool(strict_mode=False)
    def find_latest_workspace_upload(workspace_id: str) -> dict[str, Any]:
        """Find the most recent raw.zip upload for a WatchGuard workspace in S3.
        Returns found=True plus upload_id and s3_uri if an upload exists."""
        return service.find_latest_workspace_upload(workspace_id=workspace_id)

    @function_tool(strict_mode=False)
    def create_case(
        client_id: str,
        workflow_type: str,
        title: str,
        summary: str,
    ) -> dict[str, Any]:
        """Create a new investigation case. Returns case_id."""
        return service.create_case(
            client_id=client_id,
            workflow_type=workflow_type,
            title=title,
            summary=summary,
        )

    @function_tool(strict_mode=False)
    def attach_workspace_s3_zip_reference(
        case_id: str,
        workspace: str,
        s3_uri: str,
    ) -> dict[str, Any]:
        """Attach a WatchGuard workspace ZIP stored in S3 as an input artifact. Returns artifact_id."""
        return service.attach_workspace_s3_zip_reference(
            case_id=case_id,
            workspace=workspace,
            s3_uri=s3_uri,
        )

    @function_tool(strict_mode=False)
    def create_run(
        case_id: str,
        backend_id: str,
        input_artifact_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a run for a case against a backend. Returns run_id."""
        return service.create_run(
            case_id=case_id,
            backend_id=backend_id,
            input_artifact_ids=input_artifact_ids,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_stage_workspace_zip(
        run_id: str,
        requested_by: str = "ddos_orchestrator",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Stage a WatchGuard workspace ZIP from S3. Returns the staging manifest artifact_id.
        This artifact_id must be passed as input_artifact_id to all DDoS observation tools."""
        return service.execute_watchguard_stage_workspace_zip(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    # ── pipeline tools ──────────────────────────────────────────────────────

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_temporal_analysis(
        run_id: str,
        requested_by: str = "ddos_pipeline",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Analyze daily event counts. Returns peak_day, events_per_day, pct_variation.
        Always pass input_artifact_id=<staging_manifest_artifact_id>."""
        return service.execute_watchguard_ddos_temporal_analysis(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_top_sources(
        run_id: str,
        requested_by: str = "ddos_pipeline",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Identify top source IPs and /16 segments by event count.
        Always pass input_artifact_id=<staging_manifest_artifact_id>."""
        return service.execute_watchguard_ddos_top_sources(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_top_destinations(
        run_id: str,
        requested_by: str = "ddos_pipeline",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Identify top destination IPs targeted in the attack.
        Always pass input_artifact_id=<staging_manifest_artifact_id>."""
        return service.execute_watchguard_ddos_top_destinations(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    # ── profiler tools ──────────────────────────────────────────────────────

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_segment_analysis(
        run_id: str,
        segment: str,
        requested_by: str = "ddos_profiler",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Profile all traffic from a /16 segment. segment='x.y' (e.g. '185.220').
        Always pass input_artifact_id=<staging_manifest_artifact_id>."""
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
        requested_by: str = "ddos_profiler",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Build a full forensic profile for a single source IP.
        Always pass input_artifact_id=<staging_manifest_artifact_id>."""
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
        requested_by: str = "ddos_profiler",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Analyze hourly event distribution for a specific date (YYYY-MM-DD).
        Always pass input_artifact_id=<staging_manifest_artifact_id>."""
        return service.execute_watchguard_ddos_hourly_distribution(
            run_id=run_id,
            date=date,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_ddos_protocol_breakdown(
        run_id: str,
        requested_by: str = "ddos_pipeline",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Analyze protocol distribution across all traffic (TCP/UDP/ICMP/etc).
        Always pass input_artifact_id=<staging_manifest_artifact_id>."""
        return service.execute_watchguard_ddos_protocol_breakdown(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    # ── synthesizer exploration tools (budget-limited) ──────────────────────
    # These are budget-gated wrappers used by the synthesizer during its
    # active-investigation phase. Each call counts toward _EXPLORATION_BUDGET.
    # All 7 DDoS observation tools are available, plus DuckDB analytics and
    # custom filter. Non-parameterizable tools (temporal, sources, destinations,
    # protocol) are useful when the synthesizer needs the full structured_summary
    # rather than the one-line evidence string stored in the case state.

    @function_tool(strict_mode=False)
    def explore_ddos_temporal_analysis(
        run_id: str,
        input_artifact_id: str,
    ) -> dict[str, Any]:
        """Re-run temporal analysis to get the full structured_summary (events_per_day,
        peak_day, pct_variation, total_events). Use when the case state summary is not
        detailed enough to answer a specific temporal question.
        BUDGET: Counts toward the 7-query exploration budget."""
        blocked = _check_exploration_budget("explore_ddos_temporal_analysis")
        if blocked is not None:
            return blocked
        return service.execute_watchguard_ddos_temporal_analysis(
            run_id=run_id,
            requested_by="ddos_synthesizer",
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def explore_ddos_top_sources(
        run_id: str,
        input_artifact_id: str,
    ) -> dict[str, Any]:
        """Re-run top-sources analysis to get the full ranked list of source IPs and
        /16 segments (top_sources, top_segments, dominant_segment, top_source).
        Use when you need to examine IPs beyond the #1 attacker noted in the summary.
        BUDGET: Counts toward the 7-query exploration budget."""
        blocked = _check_exploration_budget("explore_ddos_top_sources")
        if blocked is not None:
            return blocked
        return service.execute_watchguard_ddos_top_sources(
            run_id=run_id,
            requested_by="ddos_synthesizer",
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def explore_ddos_top_destinations(
        run_id: str,
        input_artifact_id: str,
    ) -> dict[str, Any]:
        """Re-run top-destinations analysis to get the full ranked list of targeted IPs
        (top_destinations, top_destination, top_destination_pct).
        Use when you need to understand which internal assets were targeted most.
        BUDGET: Counts toward the 7-query exploration budget."""
        blocked = _check_exploration_budget("explore_ddos_top_destinations")
        if blocked is not None:
            return blocked
        return service.execute_watchguard_ddos_top_destinations(
            run_id=run_id,
            requested_by="ddos_synthesizer",
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def explore_ddos_protocol_breakdown(
        run_id: str,
        input_artifact_id: str,
    ) -> dict[str, Any]:
        """Re-run protocol breakdown to get the full distribution (protocol_distribution,
        top_protocol, top_protocol_pct, protocol_count).
        Use when you need the full protocol mix, not just the dominant one.
        BUDGET: Counts toward the 7-query exploration budget."""
        blocked = _check_exploration_budget("explore_ddos_protocol_breakdown")
        if blocked is not None:
            return blocked
        return service.execute_watchguard_ddos_protocol_breakdown(
            run_id=run_id,
            requested_by="ddos_synthesizer",
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def explore_ddos_ip_profile(
        run_id: str,
        ip: str,
        input_artifact_id: str,
    ) -> dict[str, Any]:
        """Profile a specific source IP across the entire workspace. Use to investigate
        any IP beyond the one auto-analyzed in Phase 2.
        BUDGET: Counts toward the 7-query exploration budget."""
        blocked = _check_exploration_budget("explore_ddos_ip_profile")
        if blocked is not None:
            return blocked
        return service.execute_watchguard_ddos_ip_profile(
            run_id=run_id,
            ip=ip,
            requested_by="ddos_synthesizer",
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def explore_ddos_segment_analysis(
        run_id: str,
        segment: str,
        input_artifact_id: str,
    ) -> dict[str, Any]:
        """Profile all traffic from a /16 segment (format 'x.y'). Use for any segment
        beyond the dominant one auto-analyzed in Phase 2.
        BUDGET: Counts toward the 7-query exploration budget."""
        blocked = _check_exploration_budget("explore_ddos_segment_analysis")
        if blocked is not None:
            return blocked
        return service.execute_watchguard_ddos_segment_analysis(
            run_id=run_id,
            segment=segment,
            requested_by="ddos_synthesizer",
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def explore_ddos_hourly_distribution(
        run_id: str,
        date: str,
        input_artifact_id: str,
    ) -> dict[str, Any]:
        """Analyze hourly event distribution on a specific date (YYYY-MM-DD). Use to
        profile any day beyond the peak auto-analyzed in Phase 2.
        BUDGET: Counts toward the 7-query exploration budget."""
        blocked = _check_exploration_budget("explore_ddos_hourly_distribution")
        if blocked is not None:
            return blocked
        return service.execute_watchguard_ddos_hourly_distribution(
            run_id=run_id,
            date=date,
            requested_by="ddos_synthesizer",
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_duckdb_workspace_analytics_tool(
        run_id: str,
        input_artifact_id: str,
    ) -> dict[str, Any]:
        """Run the full pre-defined DuckDB analytics pack (top N IPs, protocol breakdown,
        date range, family counts) in one call. Useful to cross-check totals or see
        aggregate statistics the DDoS observations didn't surface.
        Pass the staging manifest artifact_id as input_artifact_id.
        BUDGET: Counts toward the 7-query exploration budget."""
        blocked = _check_exploration_budget("execute_watchguard_duckdb_workspace_analytics_tool")
        if blocked is not None:
            return blocked
        return service.execute_watchguard_duckdb_workspace_analytics(
            run_id=run_id,
            requested_by="ddos_synthesizer",
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def execute_watchguard_duckdb_custom_filter(
        run_id: str,
        input_artifact_id: str,
        family: str,
        filters: list[dict[str, Any]],
        reason: str,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Run a guarded custom DuckDB filter over the staged workspace. Use this when
        the pre-computed observations don't answer your question.

        Args:
          family: 'traffic' | 'alarm' | 'event'
          filters: list of {field, op, value} where op is 'eq' or 'in'.
                   Allowed fields for 'traffic': src_ip, dst_ip, action, protocol, policy,
                                                 src_port, dst_port
                   Allowed fields for 'alarm':   alarm_type, src_ip, timestamp
                   Allowed fields for 'event':   type, timestamp
          reason: short natural-language justification (goes into the audit trail).
          limit: max rows to return (1..500).

        Returns the matching rows plus matched_row_count and truncated flag.

        BUDGET: Counts toward the 7-query exploration budget. You may call exploration
        tools AT MOST 7 times per investigation."""
        blocked = _check_exploration_budget("execute_watchguard_duckdb_custom_filter")
        if blocked is not None:
            return blocked
        return service.execute_watchguard_duckdb_workspace_query(
            run_id=run_id,
            family=family,
            filters=filters,
            limit=limit,
            reason=reason,
            requested_by="ddos_synthesizer",
            input_artifact_id=input_artifact_id,
        )

    @function_tool(strict_mode=False)
    def complete_run_tool(run_id: str, reason: str) -> dict[str, Any]:
        """Mark the platform-api run as COMPLETED. Call this EXACTLY ONCE as the very
        last action, AFTER case_build_final_output. Do not call complete_run_tool more
        than once per investigation."""
        return client.complete_run(
            run_id=run_id,
            requested_by="ddos_synthesizer",
            reason=reason,
        )

    # ── build agents ─────────────────────────────────────────────────────────
    # Hybrid pipeline: only orchestrator (setup) + synthesizer (decision) are CAI agents.
    # Data collection (7 DDoS observations) is handled by _run_ddos_collection() in Python.

    synthesizer = Agent(
        name="ddos-synthesizer",
        description=(
            "Active investigator that reviews DDoS findings, queries the data for gaps, "
            "records the containment decision, and closes the run."
        ),
        instructions=(
            "You are the DDoS synthesizer. You investigate actively: the pre-collected\n"
            "evidence is a starting point, not the end. Do NOT ask the user anything.\n\n"

            "## Input parsing (STEP 0)\n"
            "The user message contains lines of the form 'key=value'. Extract these literal\n"
            "values and use them in every subsequent tool call:\n"
            "  - nist_case_id\n"
            "  - run_id\n"
            "  - staging_artifact_id\n"
            "  - summary (a JSON object — parse it mentally to see what was already collected)\n\n"

            "## STEP 1 — Read the case and identify gaps\n"
            "Call load_case_state(case_id=<nist_case_id>) to review evidence and findings.\n"
            "Then, think explicitly about what questions the evidence does NOT answer yet.\n"
            "Examples of real gaps (not every investigation will have them):\n"
            "  - 'Does top_source_ip hit the same dst_port across all 7 artifacts, or multiple?'\n"
            "  - 'Is there a second /16 segment with comparable volume to the top segment?'\n"
            "  - 'Were any ALLOW actions from the top source, or is it 100% DENY?'\n"
            "  - 'Is the top destination a known internal server or external-facing?'\n"
            "If the existing evidence is already conclusive, skip directly to STEP 3.\n\n"

            "## STEP 2 — Targeted queries (BUDGET: max 7 calls across ALL exploration tools)\n"
            "You MAY call ANY of the following tools, at most 7 times TOTAL combined.\n"
            "Choose based on what gap you identified in STEP 1. Each call needs a clear reason.\n\n"
            "Full DDoS observation suite (all 7 observations available):\n"
            "  - explore_ddos_temporal_analysis(run_id, input_artifact_id=<staging_artifact_id>)\n"
            "      → full events_per_day breakdown, useful when the summary only shows peak_day\n"
            "  - explore_ddos_top_sources(run_id, input_artifact_id=<staging_artifact_id>)\n"
            "      → full ranked list of source IPs and /16 segments, not just the #1 attacker\n"
            "  - explore_ddos_top_destinations(run_id, input_artifact_id=<staging_artifact_id>)\n"
            "      → full ranked list of targeted internal IPs\n"
            "  - explore_ddos_protocol_breakdown(run_id, input_artifact_id=<staging_artifact_id>)\n"
            "      → full protocol distribution, not just the dominant protocol\n"
            "  - explore_ddos_ip_profile(run_id, ip=<ip>, input_artifact_id=<staging_artifact_id>)\n"
            "      → forensic profile for any specific IP (repeat for multiple IPs)\n"
            "  - explore_ddos_segment_analysis(run_id, segment='x.y', input_artifact_id=<staging_artifact_id>)\n"
            "      → full traffic profile for any /16 segment\n"
            "  - explore_ddos_hourly_distribution(run_id, date='YYYY-MM-DD', input_artifact_id=<staging_artifact_id>)\n"
            "      → hourly breakdown for any specific date\n\n"
            "DuckDB direct access (for questions the observations can't answer):\n"
            "  - execute_watchguard_duckdb_workspace_analytics_tool(run_id, input_artifact_id=<staging_artifact_id>)\n"
            "      → aggregate stats pack in one call\n"
            "  - execute_watchguard_duckdb_custom_filter(run_id, input_artifact_id=<staging_artifact_id>,\n"
            "      family='traffic', filters=[{'field':'src_ip','op':'eq','value':'<ip>'},\n"
            "                                  {'field':'action','op':'eq','value':'allow'}],\n"
            "      reason='<why>', limit=100)\n"
            "      → filter raw rows by field/value; fields: src_ip, dst_ip, action, protocol,\n"
            "        policy, src_port, dst_port (traffic); alarm_type, src_ip (alarm); type (event)\n\n"
            "RULES for STEP 2:\n"
            "  1. Hard cap: 7 tool calls in total across all exploration tools.\n"
            "  2. Every call must answer a specific gap you named in STEP 1.\n"
            "  3. If a query returns zero rows or the same data, do NOT retry — move on.\n"
            "  4. If after 5 queries you still have no clarity, stop and decide with what you have.\n"
            "  5. If STEP 1 is already conclusive, skip STEP 2 entirely.\n\n"

            "## STEP 3 — Record the containment decision\n"
            "case_record_decision(\n"
            "  case_id=<nist_case_id>,\n"
            "  category='containment',\n"
            "  summary=<one-sentence recommendation>,\n"
            "  rationale=<why — cite BOTH pre-collected evidence AND any queries from STEP 2>,\n"
            "  selected_option='block'|'monitor'|'investigate_further',\n"
            "  alternatives=[<the other two options>]\n"
            ")\n\n"

            "## STEP 4 — Advance NIST stage and build final output\n"
            "case_advance_stage(case_id=<nist_case_id>)\n"
            "case_build_final_output(case_id=<nist_case_id>)\n\n"

            "## STEP 5 — Mark the run as completed\n"
            "complete_run_tool(run_id=<run_id>,\n"
            "  reason='Synthesizer completed DDoS investigation with N exploratory queries')\n"
            "Call this EXACTLY ONCE. Never call it twice.\n\n"

            "## Final output — after ALL 5 steps, output ONLY this JSON block:\n"
            "```json\n"
            '{"nist_case_id":"<case_id>","incident_type":"volumetric_ddos|application_ddos|mixed",'
            '"severity":"critical|high|medium|low","confidence":<0.0-1.0>,'
            '"peak_date":"<YYYY-MM-DD>","top_source_ip":"<ip>","dominant_protocol":"<proto>",'
            '"containment_decision":"block|monitor|investigate_further",'
            '"containment_rationale":"<why>","nist_stage_reached":"<stage>",'
            '"evidence_summary":"<1-2 sentences>",'
            '"exploratory_queries_performed":<count 0..7>,'
            '"exploratory_findings":"<one sentence summarizing what the extra queries revealed, or empty if none>"}\n'
            "```\n\n"
            "Do NOT hand off. Do NOT loop. Do NOT re-run STEP 2 after STEP 3."
        ),
        tools=[
            # Case management (free — no budget)
            think,
            load_case_state,
            get_staging_info,
            list_run_artifacts,
            read_artifact_content,
            case_record_decision,
            case_advance_stage,
            case_build_final_output,
            complete_run_tool,
            # Active investigation — all 7 DDoS observations (budget-gated)
            explore_ddos_temporal_analysis,
            explore_ddos_top_sources,
            explore_ddos_top_destinations,
            explore_ddos_protocol_breakdown,
            explore_ddos_ip_profile,
            explore_ddos_segment_analysis,
            explore_ddos_hourly_distribution,
            # DuckDB direct access (budget-gated)
            execute_watchguard_duckdb_workspace_analytics_tool,
            execute_watchguard_duckdb_custom_filter,
        ],
        handoffs=[],
        model=_resolve_model(model),
    )

    orchestrator = Agent(
        name="ddos-orchestrator",
        description=(
            "Entry point for DDoS investigations. Sets up the platform-api case and run, "
            "stages the workspace ZIP, initialises the NIST CaseState, and dispatches to the ddos-processor."
        ),
        instructions=(
            "You are the DDoS investigation orchestrator. Given a workspace_id (or an S3 URI), "
            "set up the investigation by calling tools in sequence.\n\n"
            "## Tool steps — call in this exact order:\n\n"
            "STEP 1: find_latest_workspace_upload(workspace_id=<id>) → note s3_uri.\n"
            "  (If the user provided an s3_uri directly, skip this step.)\n\n"
            "STEP 2: create_case(client_id='unknown', workflow_type='log_investigation',\n"
            "  title='DDoS Investigation — <workspace_id>', summary=<1_line>) → note case_id.\n\n"
            "STEP 3: attach_workspace_s3_zip_reference(case_id=<step2_case_id>,\n"
            "  workspace=<workspace_id>, s3_uri=<step1_s3_uri>) → note artifact_id.\n\n"
            "STEP 4: create_run(case_id=<step2_case_id>, backend_id='watchguard_logs',\n"
            "  input_artifact_ids=[<step3_artifact_id>]) → note run_id.\n\n"
            "STEP 5: execute_watchguard_stage_workspace_zip(run_id=<step4_run_id>)\n"
            "  → note staging_artifact_id from the artifact_id field in the response.\n"
            "  If this fails, call it once more with the same run_id before giving up.\n\n"
            "STEP 6: initialize_case_and_save_staging(\n"
            "  title='DDoS Investigation — <workspace_id>',\n"
            "  summary=<same_1_line>,\n"
            "  run_id=<step4_run_id>,\n"
            "  staging_artifact_id=<staging_artifact_id from step 5>,\n"
            "  platform_run_id=<run_id from step 4>,\n"
            "  observed_signals=['volumetric ddos', 'traffic flood']\n"
            "  ) → note the case_id from this response (this is the NIST case_id).\n\n"
            "## Final output — after ALL 6 steps are done, output ONLY this block:\n"
            "SETUP_COMPLETE\n"
            "nist_case_id=<case_id from step 6>\n"
            "run_id=<run_id from step 4>\n"
            "staging_artifact_id=<artifact_id from step 5>\n\n"
            "Do NOT run DDoS observation tools. Do NOT record evidence. Setup only."
        ),
        tools=[
            think,
            find_latest_workspace_upload,
            create_case,
            attach_workspace_s3_zip_reference,
            create_run,
            execute_watchguard_stage_workspace_zip,
            list_run_artifacts,
            read_artifact_content,
            initialize_case_and_save_staging,
        ],
        handoffs=[],
        model=_resolve_model(model),
    )

    if _return_synthesizer:
        return orchestrator, synthesizer
    return orchestrator


async def run_ddos_investigation(
    *,
    workspace_id: str,
    platform_api_base_url: str,
    model: str | None = None,
    session: SyncHttpSession | None = None,
    existing_case_id: str | None = None,
    existing_run_id: str | None = None,
    existing_staging_artifact_id: str | None = None,
) -> str:
    """Full hybrid DDoS pipeline: orchestrator setup → Python collection → synthesizer.

    Phase 1 (CAI): orchestrator sets up platform-api case/run/staging, outputs SETUP_COMPLETE.
    Phase 2 (Python): _run_ddos_collection runs all 7 observations deterministically.
    Phase 3 (CAI): synthesizer reads the case, records containment decision, builds final output.

    If existing_case_id, existing_run_id, and existing_staging_artifact_id are all
    provided, Phase 1 is skipped and the pipeline resumes from Phase 2 using those IDs.
    This allows the UI to hand off a case it already staged to the AI pipeline.

    Returns the synthesizer's final output (NIST case JSON as string).
    """
    try:
        from cai.sdk.agents import Runner
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use DDoS investigation."
        ) from exc

    import httpx as _httpx
    # Staging a large workspace ZIP can take 10+ minutes — use a long timeout.
    _session = session or _httpx.Client(base_url=platform_api_base_url, timeout=900.0)
    client = PlatformApiClient(base_url=platform_api_base_url, session=_session)
    try:
        orchestrator, synthesizer = build_ddos_investigator_agent(
            platform_api_base_url=platform_api_base_url,
            session=_session,
            model=model,
            _return_synthesizer=True,
        )

        from cai.sdk.agents import RunConfig

        # Phase 1: Setup (skip if caller already has case/run/staging from the UI)
        if existing_case_id and existing_run_id and existing_staging_artifact_id:
            nist_case_id = existing_case_id
            run_id = existing_run_id
            staging_artifact_id = existing_staging_artifact_id
        else:
            orch_result = await Runner.run(
                orchestrator,
                input=f"Investigate DDoS workspace_id={workspace_id}",
                run_config=RunConfig(
                    workflow_name="ddos-investigation",
                    group_id=workspace_id,
                    trace_include_sensitive_data=False,
                ),
            )
            setup = _parse_setup_output(orch_result.final_output)
            nist_case_id = setup.nist_case_id
            run_id = setup.run_id
            staging_artifact_id = setup.staging_artifact_id

        # Phase 2: Deterministic collection (no LLM)
        summary = _run_ddos_collection(
            client=client,
            nist_case_id=nist_case_id,
            run_id=run_id,
            staging_artifact_id=staging_artifact_id,
        )

        # Phase 3: Synthesis (active investigation — may run up to 5 exploratory
        # queries, then records decision and closes the run itself).
        synth_input = (
            f"nist_case_id={nist_case_id}\n"
            f"run_id={run_id}\n"
            f"staging_artifact_id={staging_artifact_id}\n"
            f"summary={_json.dumps(summary)}"
        )
        synth_result = await Runner.run(
            synthesizer,
            input=synth_input,
            run_config=RunConfig(
                workflow_name="ddos-synthesis",
                group_id=nist_case_id,
                trace_include_sensitive_data=False,
            ),
        )

        # Defensive: if the agent forgot to call complete_run_tool, close the run
        # ourselves and log a warning. complete_run is idempotent in platform-core.
        # get_run_status returns {"run": {"status": ...}, ...} — status is nested.
        try:
            run_status = client.get_run_status(run_id=run_id)
            if run_status.get("run", {}).get("status") != "completed":
                import logging
                logging.getLogger(__name__).warning(
                    "ddos-synthesizer did not call complete_run_tool; closing run %s defensively.",
                    run_id,
                )
                client.complete_run(
                    run_id=run_id,
                    requested_by="ddos_investigation_fallback",
                    reason="Synthesizer did not close run; closed by orchestrator fallback.",
                )
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(
                "Failed to verify/fallback-close run %s: %s", run_id, exc
            )

        result = _parse_synthesis_output(synth_result.final_output, nist_case_id)

        # Persist exploratory investigation metadata AND close out remaining NIST
        # stages so the case reaches findings_consolidation / READY_FOR_REPORT.
        # The synthesizer advances one stage (containment_or_monitoring_decision →
        # mitre_enrichment_optional); we advance the rest deterministically here.
        try:
            from cai.egs_orchestration.services.case_orchestrator import CaseOrchestrator as _CO
            from cai.tools.workspace.case_state_store import get_default_case_state_store as _gds
            _store = _gds()
            _state = _store.load(nist_case_id)
            if _state is not None:
                _state.metadata["exploratory_queries_performed"] = result.exploratory_queries_performed
                _state.metadata["exploratory_findings"] = result.exploratory_findings
                _orch2 = _CO()
                _TERMINAL = {"findings_consolidation", None}
                # Advance through any remaining stages until terminal.
                _iters = 0
                while _state.current_stage_id not in _TERMINAL and _iters < 5:
                    _note = (
                        "MITRE enrichment skipped — automated pipeline."
                        if _state.current_stage_id == "mitre_enrichment_optional"
                        else "Closed by orchestrator post-synthesis."
                    )
                    _state = _orch2.advance_stage(_state, note=_note)
                    _iters += 1
                # Advance findings_consolidation itself to mark strategy complete.
                if _state.current_stage_id == "findings_consolidation":
                    _state = _orch2.advance_stage(
                        _state, note="Findings consolidation complete — DDoS pipeline finished."
                    )
                _store.save(_state)

                # Persist full NIST case state as a platform-api artifact so the UI
                # can generate complete reports without access to .egs_cases/.
                try:
                    client.attach_input_artifact(
                        case_id=nist_case_id,
                        payload=_state.model_dump(mode="json"),
                        format="json",
                        summary="NIST case state snapshot (decisiones + evidencia + etapas)",
                        metadata={"subtype": "watchguard.nist_case_snapshot"},
                    )
                except Exception as _snap_exc:
                    import logging
                    logging.getLogger(__name__).warning(
                        "Could not persist NIST snapshot artifact for case %s: %s",
                        nist_case_id, _snap_exc,
                    )
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "Could not close NIST stages for case %s: %s", nist_case_id, exc
            )

        return result
    finally:
        if session is None:
            client.close()
