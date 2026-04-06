"""CAI-driven narrative generation for investigation reports.

The agent reads structured investigation facts (already collected by report-collect)
and writes the 5 narrative sections. All factual data (numbers, IPs, tables) comes
from the deterministic template — the agent only writes interpretation and context.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    pass


class ReportNarrative(BaseModel):
    executive_summary: str = Field(max_length=800)
    """2-3 sentences in plain language for a non-technical reader."""

    incident_context: str = Field(max_length=1200)
    """What was happening in the network: traffic context, attack vectors observed."""

    technical_analysis: str = Field(max_length=1500)
    """Interpretation of the quantitative findings: what the peak means,
    why the dominant protocol is significant, what the top attacker IP profile implies."""

    impact_assessment: str = Field(max_length=1000)
    """Real or potential impact for the client: availability, data, reputation."""

    recommendations: str = Field(max_length=1500)
    """Concrete, prioritized action steps. Reference specific IPs, segments,
    or protocols from the investigation data."""


def build_report_narrative_agent(model: str | None = None) -> Any:
    """Build the CAI agent that generates the narrative sections of the report.

    The agent receives structured JSON facts (not the full raw case data) and
    fills ReportNarrative via output_type. No tools — pure reasoning from provided data.
    """
    try:
        from cai.sdk.agents import Agent
        from cai_orchestrator.cai_terminal import _resolve_model
    except ImportError as exc:
        from cai_orchestrator.errors import MissingCaiDependencyError
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use CAI report generation."
        ) from exc

    instructions = """\
You are a cybersecurity incident report writer producing content for a professional PDF report.
You receive structured JSON data extracted from a completed security investigation.
Your job is to write clear, accurate narrative sections based strictly on that data.

CRITICAL RULES:
- Do NOT invent numbers, IP addresses, dates, protocols, or any factual claims not present
  in the provided data. Every numerical claim must cite a value from the input.
- Write in the same language as the client_name field (use Spanish if the name is Spanish).
- Populate ALL five fields. Do not leave any field empty or with placeholder text.
- Respect the character limit per field.
- executive_summary must be understandable by a non-technical manager — avoid jargon.
- recommendations must be actionable and specific: reference actual IPs, segments,
  or protocols from the data when available.
- Do not speculate about attacker identity or motive beyond what the evidence supports.
"""

    return Agent(
        name="report-narrative-writer",
        model=_resolve_model(model),
        instructions=instructions,
        tools=[],
        output_type=ReportNarrative,
    )


async def generate_report_narrative(
    case_data: dict[str, Any],
    model: str | None = None,
) -> ReportNarrative:
    """Generate narrative sections for the report from the collected case data.

    Reads only the factual fields needed for narrative — does not pass raw tables.
    Uses RunConfig with trace_include_sensitive_data=False (case data may include
    client IPs and finding details).
    """
    try:
        from cai.sdk.agents import Runner, RunConfig
        from cai_orchestrator.errors import MissingCaiDependencyError
    except ImportError as exc:
        from cai_orchestrator.errors import MissingCaiDependencyError
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use CAI report generation."
        ) from exc

    agent = build_report_narrative_agent(model=model)
    facts = _extract_narrative_facts(case_data)
    prompt = f"Write the report narrative sections based on this investigation data:\n\n{facts}"

    result = await Runner.run(
        agent,
        input=prompt,
        run_config=RunConfig(
            workflow_name="report-narrative",
            group_id=case_data.get("case_id", "unknown"),
            trace_include_sensitive_data=False,
        ),
    )
    return result.final_output


def _extract_narrative_facts(case_data: dict[str, Any]) -> str:
    """Extract only the fields needed for narrative generation.

    Uses _build_context (which knows how to read artifact_payloads) to get the
    already-extracted values, then filters to a concise subset for the agent prompt.
    Excludes raw tables (top_sources, by_hour) to keep the prompt focused.
    """
    from cai_orchestrator.report.generate import _build_context

    ctx = _build_context(case_data, client_name="", informante="", crm_case="")

    stage_progress = ctx.get("stage_progress", [])
    last_stage = stage_progress[-1].get("label") if stage_progress else None

    top_segments = ctx.get("top_segments", [])
    top_segment = top_segments[0] if top_segments else None

    protocols = ctx.get("protocols", [])
    top_protocol = protocols[0] if protocols else None

    facts: dict[str, Any] = {
        "case_id": ctx.get("case_id"),
        "severity": ctx.get("severity"),
        "period": f"{ctx.get('date_from')} → {ctx.get('date_to')}",
        "total_events": ctx.get("total_events"),
        "peak_day": ctx.get("peak_day"),
        "peak_events": ctx.get("peak_events"),
        "incident_type": ctx.get("strategy"),
        "top_source_segment": top_segment,
        "top_protocol": top_protocol,
        "top_attacker_ip": ctx.get("ip_prof_ip"),
        "attacker_event_count": ctx.get("ip_prof_total"),
        "observed_signals": ctx.get("observed_signals", []),
        "finding_title": ctx.get("finding_title"),
        "finding_summary": ctx.get("finding_summary"),
        "finding_confidence_pct": ctx.get("finding_confidence"),
        "containment_decision": ctx.get("decision_option"),
        "containment_rationale": ctx.get("decision_rationale"),
        "containment_alternatives": ctx.get("decision_alternatives", []),
        "nist_stage_reached": last_stage,
    }
    # Remove None and placeholder "–" values to keep the prompt clean
    facts = {k: v for k, v in facts.items() if v is not None and v != "–"}
    return json.dumps(facts, indent=2, ensure_ascii=False)
