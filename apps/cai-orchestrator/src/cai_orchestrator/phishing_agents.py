"""Multi-agent phishing investigator pipeline using CAI handoffs.

Architecture:
    phishing-triage  (entry point)
      Runs basic_assessment, reads the output artifact, delegates to specialists.
      handoffs → url-specialist, header-specialist, attachment-specialist, synthesis

    phishing-url-specialist
      Reads URL-related artifacts and provides a focused URL threat assessment.
      handoffs → synthesis

    phishing-header-specialist
      Runs header_analysis and reads the resulting artifact.
      handoffs → synthesis

    phishing-attachment-specialist
      Reads attachment evidence from existing artifacts.
      handoffs → synthesis

    phishing-synthesis  (terminal node — no handoffs)
      Consolidates all specialist findings into a structured verdict JSON.

Usage:
    agent = build_phishing_investigator_agent(
        platform_api_base_url="http://127.0.0.1:8000",
        model="claude-sonnet-4-6",
    )
    result = await Runner.run(agent, input="Investigate run_id=... input_artifact_id=...")
"""

from __future__ import annotations

from typing import Any

from cai_orchestrator.cai_terminal import _resolve_model
from cai_orchestrator.cai_tools import PlatformApiToolService
from cai_orchestrator.client import PlatformApiClient, SyncHttpSession
from cai_orchestrator.errors import MissingCaiDependencyError


def build_phishing_investigator_agent(
    *,
    platform_api_base_url: str,
    session: SyncHttpSession | None = None,
    model: str | None = None,
) -> Any:
    """Build the phishing investigator multi-agent pipeline."""
    try:
        from cai.sdk.agents import Agent, function_tool
    except ImportError as exc:
        raise MissingCaiDependencyError(
            "CAI is not installed. Install the optional 'cai' extra to use the phishing investigator."
        ) from exc

    client = PlatformApiClient(base_url=platform_api_base_url, session=session)
    service = PlatformApiToolService(platform_api_client=client)

    # ── shared read-only tools ──────────────────────────────────────────────

    @function_tool(strict_mode=False)
    def list_run_artifacts(run_id: str) -> dict[str, Any]:
        """List all input and output artifacts for a run. Use this to discover artifact_ids."""
        return service.list_run_artifacts(run_id=run_id)

    @function_tool(strict_mode=False)
    def read_artifact_content(artifact_id: str) -> dict[str, Any]:
        """Read the stored content of one artifact. Use to inspect risk scores, triggered rules, URLs, etc."""
        return service.read_artifact_content(artifact_id=artifact_id)

    @function_tool(strict_mode=False)
    def get_run(run_id: str) -> dict[str, Any]:
        """Get full run details including observation results and artifact refs."""
        return service.get_run(run_id=run_id)

    # ── triage-specific tools ───────────────────────────────────────────────

    @function_tool(strict_mode=False)
    def execute_phishing_email_basic_assessment(
        run_id: str,
        requested_by: str = "phishing_investigator",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute the deterministic phishing basic assessment. Always the first step in triage.
        Returns risk_level, risk_score, triggered_rules, suspicious_urls."""
        return service.execute_phishing_email_basic_assessment(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    # ── header-specialist tools ─────────────────────────────────────────────

    @function_tool(strict_mode=False)
    def execute_phishing_email_header_analysis(
        run_id: str,
        requested_by: str = "phishing_investigator",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute the header_analysis observation. Requires a structured_email_v2 input artifact.
        Checks SPF/DKIM/DMARC failures, short Received chains, IP-literal origins, and chain loops."""
        return service.execute_phishing_email_header_analysis(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    # ── synthesis agent (terminal — no handoffs) ────────────────────────────

    synthesis = Agent(
        name="phishing-synthesis",
        description="Consolidates all specialist findings into a final phishing verdict.",
        instructions=(
            "You are the final synthesis agent in a phishing investigation pipeline. "
            "You receive handoffs from specialist agents after they have completed their analyses. "
            "You have NO handoffs — you are the terminal node.\n\n"
            "Your workflow:\n"
            "1. Call list_run_artifacts to discover all artifacts for the run.\n"
            "2. Call read_artifact_content on each output artifact (basic_assessment, "
            "   header_analysis if present, etc.) to gather all evidence.\n"
            "3. Produce a single structured JSON verdict with exactly these fields:\n"
            "   overall_verdict: 'phishing' | 'likely_phishing' | 'suspicious' | 'benign'\n"
            "   risk_level: 'high' | 'medium' | 'low' | 'none'\n"
            "   confidence: 'high' | 'medium' | 'low'\n"
            "   triggered_rules: list of rule_ids that fired across all analyses\n"
            "   authentication_summary: dict with spf/dkim/dmarc values (or null if not analyzed)\n"
            "   url_summary: dict with suspicious_url_count and sample reasons\n"
            "   attachment_summary: dict with suspicious_attachment_count and mime_mismatch flag\n"
            "   recommended_action: 'delete' | 'quarantine' | 'escalate' | 'no_action'\n"
            "   evidence_summary: one-paragraph human-readable summary of findings\n\n"
            "Respond with ONLY the JSON verdict object — no preamble, no markdown fences, "
            "no explanation. Just the raw JSON."
        ),
        tools=[list_run_artifacts, read_artifact_content, get_run],
        handoffs=[],
        model=_resolve_model(model),
    )

    # ── specialist agents ────────────────────────────────────────────────────

    url_specialist = Agent(
        name="phishing-url-specialist",
        description="Performs focused URL threat analysis on phishing artifacts.",
        instructions=(
            "You are the URL specialist in a phishing investigation. "
            "You have exactly two tools: list_run_artifacts and read_artifact_content. "
            "Do NOT attempt to call any other tool.\n\n"
            "Your workflow (strictly follow these steps in order):\n"
            "1. Call list_run_artifacts to find the basic_assessment artifact.\n"
            "2. Call read_artifact_content on that artifact to read suspicious_urls.\n"
            "3. For each suspicious URL, analyze: scheme (data: URIs, non-https), "
            "   IP literals, URL shorteners, punycode homoglyphs, "
            "   high percent-encoding, null bytes (%00), suspicious path/query terms.\n"
            "4. After completing your analysis, you MUST immediately hand off to "
            "   phishing-synthesis. This is mandatory — do not output text and stop, "
            "   do not call any more tools. Transfer control to phishing-synthesis."
        ),
        tools=[list_run_artifacts, read_artifact_content],
        handoffs=[synthesis],
        model=_resolve_model(model),
    )

    header_specialist = Agent(
        name="phishing-header-specialist",
        description="Analyzes email authentication headers for phishing indicators.",
        instructions=(
            "You are the header analysis specialist in a phishing investigation. "
            "You have three tools: execute_phishing_email_header_analysis, "
            "list_run_artifacts, and read_artifact_content. "
            "Do NOT attempt to call any other tool.\n\n"
            "Your workflow (strictly follow these steps in order):\n"
            "1. Call list_run_artifacts to discover the run_id and input artifact_id.\n"
            "2. Call execute_phishing_email_header_analysis.\n"
            "3. Call read_artifact_content on the resulting header_analysis artifact.\n"
            "4. Analyze: SPF/DKIM/DMARC failures (critical signals), short Received chain "
            "   (fewer than 2 hops is suspicious), first-hop IP literal, routing loops.\n"
            "5. After completing your analysis, you MUST immediately hand off to "
            "   phishing-synthesis. This is mandatory — do not output text and stop."
            "If header_analysis fails (e.g. input is not structured_email_v2), note that "
            "header data was unavailable, then STILL hand off to phishing-synthesis."
        ),
        tools=[execute_phishing_email_header_analysis, list_run_artifacts, read_artifact_content],
        handoffs=[synthesis],
        model=_resolve_model(model),
    )

    attachment_specialist = Agent(
        name="phishing-attachment-specialist",
        description="Evaluates attachment evidence from phishing assessment artifacts.",
        instructions=(
            "You are the attachment specialist in a phishing investigation. "
            "You have exactly two tools: list_run_artifacts and read_artifact_content. "
            "Do NOT attempt to call any other tool.\n\n"
            "Your workflow (strictly follow these steps in order):\n"
            "1. Call list_run_artifacts to find the basic_assessment artifact.\n"
            "2. Call read_artifact_content and examine 'suspicious_attachment_extension' rule "
            "   and the 'attachments' field. Look for:\n"
            "   - MIME mismatch (e.g. invoice.pdf served as application/zip)\n"
            "   - Dangerous extensions (.exe, .scr, .js, .lnk, .docm, .xlsm)\n"
            "   - Zip-wrapped executable patterns\n"
            "3. After completing your analysis, you MUST immediately hand off to "
            "   phishing-synthesis. This is mandatory — do not output text and stop."
        ),
        tools=[list_run_artifacts, read_artifact_content],
        handoffs=[synthesis],
        model=_resolve_model(model),
    )

    # ── triage (entry point) ─────────────────────────────────────────────────

    triage = Agent(
        name="phishing-triage",
        description="Entry point of the phishing investigator — runs basic assessment and delegates to specialists.",
        instructions=(
            "You are the triage agent for the phishing investigation pipeline.\n\n"
            "You ONLY work with existing runs — you do NOT create cases, artifacts, or runs. "
            "You receive a run_id and input_artifact_id from the operator or from egs-analist via handoff.\n\n"
            "Step 1: Call execute_phishing_email_basic_assessment using the run_id and "
            "input_artifact_id provided in the prompt.\n\n"
            "Step 2: Call read_artifact_content on the output artifact from basic_assessment "
            "to understand what signals fired.\n\n"
            "Step 3: Hand off to exactly ONE specialist based on the highest-priority signal:\n"
            "  - If suspicious_urls fired → hand off to phishing-url-specialist\n"
            "  - Else if the input is structured_email_v2 → hand off to phishing-header-specialist\n"
            "  - Else if suspicious_attachment_extension fired → hand off to phishing-attachment-specialist\n"
            "  - Else (no significant signals) → hand off to phishing-synthesis\n\n"
            "IMPORTANT: After you hand off to a specialist, your work is done. "
            "The specialist will hand off to phishing-synthesis automatically. "
            "You must NOT hand off to multiple specialists or to phishing-synthesis yourself "
            "(unless there were no signals at all). Hand off to exactly ONE agent and stop."
        ),
        tools=[
            execute_phishing_email_basic_assessment,
            list_run_artifacts,
            read_artifact_content,
            get_run,
        ],
        handoffs=[url_specialist, header_specialist, attachment_specialist, synthesis],
        model=_resolve_model(model),
    )

    return triage
