"""Generate a PDF incident-response report from a collected case-XXXX-report.json.

This module is fully deterministic and offline — no platform-api, no LLM required.
Same input JSON + same template = same PDF, always.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cai_orchestrator.report.narrative import ReportNarrative

_CASES_DIR = Path(".egs_cases")
_HERE = Path(__file__).parent

_STRATEGY_LABELS: dict[str, str] = {
    "ddos_nist_v1": "Análisis DDoS — NIST SP 800-61",
    "phishing_email_v1": "Análisis de Phishing — NIST SP 800-61",
    "blueteam_investigation_v1": "Investigación Blue Team — NIST SP 800-61",
}


def _find_artifact_payload(
    case_data: dict[str, Any],
    source: str,
) -> dict[str, Any]:
    """Return the first artifact payload whose evidence source matches `source`."""
    payloads: dict[str, Any] = case_data.get("artifact_payloads", {})
    for evidence in case_data.get("evidence_items", []):
        if evidence.get("source") == source:
            for artifact_id in evidence.get("artifact_refs", []):
                if artifact_id in payloads:
                    raw = payloads[artifact_id]
                    # Unwrap nested {"metadata": {...}} structure from platform-api artifact
                    if isinstance(raw, dict) and "metadata" in raw and isinstance(raw["metadata"], dict):
                        return raw["metadata"]
                    return raw if isinstance(raw, dict) else {}
    return {}


def _fmt_date(iso_str: str | None) -> str:
    if not iso_str:
        return "–"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y")
    except (ValueError, AttributeError):
        return iso_str or "–"


def _fmt_datetime(iso_str: str | None) -> str:
    if not iso_str:
        return "–"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M UTC")
    except (ValueError, AttributeError):
        return iso_str or "–"


def _stage_duration(stage: dict[str, Any]) -> str:
    start = stage.get("started_at")
    end = stage.get("completed_at")
    if not start or not end:
        return "–"
    try:
        t0 = datetime.fromisoformat(start.replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(end.replace("Z", "+00:00"))
        delta = t1 - t0
        minutes = int(delta.total_seconds() / 60)
        if minutes < 60:
            return f"{minutes} min"
        hours = minutes // 60
        mins = minutes % 60
        return f"{hours}h {mins}min"
    except (ValueError, AttributeError):
        return "–"


def _enrich_bars(rows: list[dict], key: str) -> list[dict]:
    """Add bar_pct (0–100) to each row for proportional bar chart rendering."""
    max_val = max((r.get(key, 0) for r in rows), default=1) or 1
    return [{**r, "bar_pct": round(r.get(key, 0) / max_val * 100)} for r in rows]


def _cai_pipeline_duration(stage_progress: list[dict]) -> str:
    """Compute total wall-clock time from first stage start to last stage completion."""
    starts = [s.get("started_at") for s in stage_progress if s.get("started_at")]
    ends = [s.get("completed_at") for s in stage_progress if s.get("completed_at")]
    if not starts or not ends:
        return "–"
    try:
        t0 = min(datetime.fromisoformat(s.replace("Z", "+00:00")) for s in starts)
        t1 = max(datetime.fromisoformat(e.replace("Z", "+00:00")) for e in ends)
        total = int((t1 - t0).total_seconds())
        mins, secs = divmod(total, 60)
        return f"{mins} min {secs} seg" if mins else f"{secs} seg"
    except (ValueError, AttributeError):
        return "–"


def _is_private_ip(ip: str) -> bool:
    """True if the IP is an RFC-1918 private or loopback address."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _run_data_quality_checks(case_data: dict[str, Any]) -> list[dict[str, str]]:
    """Run generic heuristic quality checks on collected artifact payloads.

    Returns a list of warning dicts: [{"severity": "warning"|"info", "code": str, "message": str}]
    Checks do NOT block report generation — they surface information for the analyst.
    The checks are pipeline-agnostic: they look for artifact sources by name and
    gracefully skip checks when the relevant artifacts are not present.
    """
    warnings: list[dict[str, str]] = []

    # ── Check 1: Private IP dominance ────────────────────────────────────────
    # Works for DDoS (ddos_top_sources) and blue team (multi_source_logs_normalize)
    sources_payload = _find_artifact_payload(case_data, "ddos_top_sources")
    if not sources_payload:
        sources_payload = _find_artifact_payload(case_data, "multi_source_logs_normalize")
    if sources_payload:
        top_ips = sources_payload.get("sources", [])[:10]
        if top_ips:
            private_count = sum(1 for s in top_ips if _is_private_ip(s.get("src_ip", "")))
            pct = private_count / len(top_ips) * 100
            if pct >= 60:
                warnings.append({
                    "severity": "warning",
                    "code": "PRIVATE_IP_DOMINANCE",
                    "message": (
                        f"{private_count} de las {len(top_ips)} IPs de origen principales "
                        f"son direcciones privadas RFC-1918 ({pct:.0f}%). "
                        "Esto puede indicar tráfico interno, un entorno NAT, "
                        "o logs de red interna en lugar de un ataque externo real. "
                        "Verificar la fuente de los logs antes de aplicar medidas de bloqueo."
                    ),
                })

    # ── Check 2: Analysis window very short (< 1 hour) ──────────────────────
    temporal = _find_artifact_payload(case_data, "ddos_temporal_analysis")
    if temporal:
        date_range = temporal.get("date_range", {})
        if isinstance(date_range, dict) and date_range.get("from") and date_range.get("to"):
            try:
                t0 = datetime.fromisoformat(date_range["from"])
                t1 = datetime.fromisoformat(date_range["to"])
                if (t1 - t0).total_seconds() < 3600:
                    warnings.append({
                        "severity": "info",
                        "code": "SHORT_ANALYSIS_WINDOW",
                        "message": (
                            "El período analizado es menor a 1 hora. "
                            "Los patrones detectados pueden no ser representativos del comportamiento general de la red."
                        ),
                    })
            except (ValueError, TypeError):
                pass

        # ── Check 3: Zero events ─────────────────────────────────────────────
        total_events = temporal.get("total_events", 0)
        if total_events == 0:
            warnings.append({
                "severity": "warning",
                "code": "NO_EVENTS",
                "message": (
                    "No se detectaron eventos en el período analizado. "
                    "Verificar que el archivo de logs sea válido y no esté vacío."
                ),
            })

    return warnings


def _compute_case_status(stage_progress: list[dict], run_status: str | None) -> dict[str, str]:
    """Determine if the case is closed or still in review."""
    closed_terminal_stages = {"findings_consolidation", "containment_or_monitoring_decision"}
    last_stage = stage_progress[-1] if stage_progress else {}
    case_is_closed = (
        last_stage.get("status") == "completed"
        and last_stage.get("stage_id") in closed_terminal_stages
    ) or run_status == "completed"
    return {
        "case_status": "Cerrado" if case_is_closed else "En revisión",
        "case_status_css": "completed" if case_is_closed else "in-progress",
    }


def _compute_data_quality(case_data: dict[str, Any]) -> dict[str, Any]:
    """Run data quality checks and return template-ready context keys."""
    dq_warnings = _run_data_quality_checks(case_data)
    return {
        "data_quality_warnings": dq_warnings,
        "has_data_quality_warnings": bool(dq_warnings),
    }


def _build_context(
    case_data: dict[str, Any],
    client_name: str,
    informante: str,
    crm_case: str,
) -> dict[str, Any]:
    """Extract all template variables from case_data and CLI params."""

    # ── Core case fields ───────────────────────────────────────────────────
    case_id = case_data.get("case_id", "")
    incident = case_data.get("incident", {})
    classification = case_data.get("classification", {})
    findings = case_data.get("findings", [])
    decisions = case_data.get("decisions", [])
    stage_progress = case_data.get("stage_progress", [])
    timeline = case_data.get("timeline", [])

    finding = findings[0] if findings else {}
    decision = decisions[0] if decisions else {}

    # ── Artifact payloads ─────────────────────────────────────────────────
    temporal = _find_artifact_payload(case_data, "ddos_temporal_analysis")
    sources = _find_artifact_payload(case_data, "ddos_top_sources")
    destinations = _find_artifact_payload(case_data, "ddos_top_destinations")
    protocol = _find_artifact_payload(case_data, "ddos_protocol_breakdown")
    hourly = _find_artifact_payload(case_data, "ddos_hourly_distribution")
    segment_analysis = _find_artifact_payload(case_data, "ddos_segment_analysis")
    ip_profile_data = _find_artifact_payload(case_data, "ddos_ip_profile")

    # ── Computed values ───────────────────────────────────────────────────
    date_range = temporal.get("date_range", {})
    date_from = _fmt_date(date_range.get("from") if isinstance(date_range, dict) else None)
    date_to = _fmt_date(date_range.get("to") if isinstance(date_range, dict) else None)
    total_events = temporal.get("total_events", 0)

    created_at = incident.get("created_at", case_data.get("incident", {}).get("created_at"))
    report_date = _fmt_date(created_at)

    # ── Logo as base64 data URI ──────────────────────────────────────────
    # Search order: CWD (Docker WORKDIR /app), repo-root heuristic (editable dev install)
    repo_root = Path(__file__).parent.parent.parent.parent.parent.parent
    logo_b64 = ""
    for base_dir in (Path.cwd(), repo_root):
        png_path = base_dir / "logo_egs.png"
        svg_path = base_dir / "logo_egs.svg"
        if png_path.exists():
            logo_b64 = "data:image/png;base64," + base64.b64encode(png_path.read_bytes()).decode("ascii")
            break
        if svg_path.exists():
            logo_b64 = "data:image/svg+xml;base64," + base64.b64encode(svg_path.read_bytes()).decode("ascii")
            break

    # Stage label mapping
    stage_labels = {
        "intake_and_scope": "3.2.1 Alcance del Incidente",
        "traffic_characterization": "3.2.2 Caracterización del Tráfico",
        "containment_or_monitoring_decision": "3.3 Contención",
        "mitre_enrichment_optional": "Enriquecimiento MITRE (opcional)",
        "findings_consolidation": "3.4 Lecciones Aprendidas",
    }

    return {
        # CLI params
        "client_name": client_name,
        "informante": informante,
        "crm_case": crm_case,
        "report_date": report_date,
        "generation_date": datetime.now(tz=timezone.utc).strftime("%d/%m/%Y %H:%M UTC"),

        # Case metadata
        "case_id": case_id,
        "workspace": incident.get("workspace", "–"),
        "observed_signals": incident.get("observed_signals", []),
        "severity": case_data.get("severity", "–"),
        "classification_rationale": classification.get("rationale", "–"),
        "classification_confidence": round(classification.get("confidence", 0) * 100),
        "strategy": _STRATEGY_LABELS.get(
            case_data.get("current_strategy_id", ""),
            case_data.get("current_strategy_id", "–"),
        ),

        # Temporal
        "date_from": date_from,
        "date_to": date_to,
        "total_events": f"{total_events:,}",
        "peak_day": temporal.get("peak_day", "–"),
        "peak_events": f"{temporal.get('peak_events', 0):,}",
        "by_day": temporal.get("by_day", []),

        # Sources
        "top_sources": sources.get("sources", [])[:10],
        "top_segments": sources.get("segments", [])[:5],

        # Destinations
        "top_destinations": destinations.get("destinations", [])[:10],

        # Protocol breakdown
        "protocols": protocol.get("protocols", []),

        # Hourly — enrich each row with bar_pct for visual bar chart
        "hourly_peak_hour": hourly.get("peak_hour"),
        "hourly_pattern": hourly.get("pattern", "–"),
        "hourly_peak_events": f"{hourly.get('peak_events', 0):,}",
        "hourly_date": hourly.get("date", "–"),
        "by_hour": _enrich_bars(hourly.get("by_hour", []), key="events"),

        # Segment analysis (top /16 from ip-profiler)
        "seg_segment": segment_analysis.get("segment", "–"),
        "seg_total_events": f"{segment_analysis.get('total_events', 0):,}",
        "seg_allow_events": f"{segment_analysis.get('allow_events', 0):,}",
        "seg_deny_events": f"{segment_analysis.get('deny_events', 0):,}",
        "seg_top_dst_ports": segment_analysis.get("top_dst_ports", [])[:8],
        "seg_top_policies": segment_analysis.get("top_policies", [])[:8],
        # seg_has_data only if the artifact actually contains a "segment" key
        "seg_has_data": bool(segment_analysis.get("segment")),

        # IP profile (top attacker from ip-profiler)
        "ip_prof_ip": ip_profile_data.get("ip", "–"),
        "ip_prof_total": f"{ip_profile_data.get('total_events', 0):,}",
        "ip_prof_allow": f"{ip_profile_data.get('allow_events', 0):,}",
        "ip_prof_deny": f"{ip_profile_data.get('deny_events', 0):,}",
        "ip_prof_first_seen": _fmt_datetime(ip_profile_data.get("first_seen")),
        "ip_prof_last_seen": _fmt_datetime(ip_profile_data.get("last_seen")),
        "ip_prof_top_ports": ip_profile_data.get("top_dst_ports", [])[:8],
        "ip_prof_top_policies": ip_profile_data.get("top_policies", [])[:5],
        # ip_prof_has_data only if the artifact actually contains an "ip" key
        "ip_prof_has_data": bool(ip_profile_data.get("ip")),

        # Finding
        "finding_title": finding.get("title", "–"),
        "finding_summary": finding.get("summary", "–"),
        "finding_severity": finding.get("severity", "–"),
        "finding_confidence": round((finding.get("confidence", 0)) * 100),
        "finding_created": _fmt_datetime(finding.get("created_at")),

        # Decision
        "decision_summary": decision.get("summary", "–"),
        "decision_rationale": decision.get("rationale", "–"),
        "decision_option": decision.get("selected_option", "–"),
        "decision_alternatives": decision.get("alternatives", []),

        # Recommended actions (from case data, used in section 3.4)
        "recommended_actions": case_data.get("recommended_actions", []),
        "has_recommended_actions": bool(case_data.get("recommended_actions")),

        # Case status derived from stage progress and run_status
        **_compute_case_status(stage_progress, case_data.get("run_status")),

        # Data quality warnings (heuristic checks on artifact payloads)
        **_compute_data_quality(case_data),

        # Stages
        "stage_progress": [
            {
                **s,
                "label": stage_labels.get(s.get("stage_id", ""), s.get("stage_id", "–")),
                "started_fmt": _fmt_datetime(s.get("started_at")),
                "completed_fmt": _fmt_datetime(s.get("completed_at")),
                "duration": _stage_duration(s),
            }
            for s in stage_progress
        ],

        # CAI pipeline metadata
        "cai_pipeline_duration": _cai_pipeline_duration(stage_progress),
        "cai_stages_completed": len([s for s in stage_progress if s.get("status") == "completed"]),
        "cai_evidence_count": len(case_data.get("evidence_items", [])),
        "cai_agents": ["ddos-orchestrator", "ddos-processor", "ddos-ip-profiler", "ddos-synthesizer"],

        # Active investigation (synthesizer exploratory queries)
        "exploratory_queries_performed": case_data.get("metadata", {}).get("exploratory_queries_performed", 0),
        "exploratory_findings": case_data.get("metadata", {}).get("exploratory_findings", ""),
        "has_exploratory_findings": bool(case_data.get("metadata", {}).get("exploratory_findings")),

        # Timeline (last 10 entries for display)
        "timeline": [
            {**e, "created_fmt": _fmt_datetime(e.get("created_at"))}
            for e in timeline[-10:]
        ],

        # Logo
        "logo_b64": logo_b64,

        # Report title (used in @page header via CSS string-set)
        "report_title": f"LL-IR-{client_name.upper().replace(' ', '_')[:20]}",
    }


def _inject_narrative(context: dict[str, Any], narrative: ReportNarrative | None) -> None:
    """Inject optional CAI narrative sections into the template context.

    When narrative is None all cai_* variables are set to empty strings and
    cai_narrative_enabled is False — the template renders exactly as before.
    """
    if narrative is not None:
        context["cai_narrative_enabled"] = True
        context["cai_executive_summary"] = narrative.executive_summary
        context["cai_incident_context"] = narrative.incident_context
        context["cai_technical_analysis"] = narrative.technical_analysis
        context["cai_impact_assessment"] = narrative.impact_assessment
        context["cai_recommendations"] = narrative.recommendations
    else:
        context["cai_narrative_enabled"] = False
        context["cai_executive_summary"] = ""
        context["cai_incident_context"] = ""
        context["cai_technical_analysis"] = ""
        context["cai_impact_assessment"] = ""
        context["cai_recommendations"] = ""


def generate_report_from_context(
    case_data: dict[str, Any],
    client_name: str,
    informante: str,
    crm_case: str,
    fmt: str = "html",
    narrative: ReportNarrative | None = None,
) -> bytes:
    """Render a report from an in-memory case_data dict. Returns file bytes.

    Same as generate_report() but accepts the case_data dict directly instead
    of reading from disk. Useful for Streamlit where no local filesystem is needed.

    Args:
        case_data: Dict with same structure as case-XXXX-report.json
        client_name: Client display name for the cover page
        informante: Name of the person who requested the report
        crm_case: CRM/ticket reference number
        fmt: "html" (default) or "pdf"

    Returns:
        File bytes (UTF-8 HTML or binary PDF)
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:
        raise RuntimeError(
            "jinja2 is required. Install with: pip install jinja2"
        ) from exc

    context = _build_context(case_data, client_name, informante, crm_case)
    context["css"] = (_HERE / "styles.css").read_text(encoding="utf-8")
    _inject_narrative(context, narrative)

    env = Environment(
        loader=FileSystemLoader(str(_HERE)),
        autoescape=select_autoescape(["html"]),
    )
    html_content = env.get_template("template.html").render(**context)

    if fmt == "pdf":
        try:
            from weasyprint import HTML as WeasyHTML
        except ImportError as exc:
            raise RuntimeError(
                "weasyprint is required for PDF output. "
                "Install with: pip install weasyprint"
            ) from exc
        import io
        buf = io.BytesIO()
        WeasyHTML(string=html_content, base_url=str(_HERE)).write_pdf(buf)
        return buf.getvalue()
    else:
        return html_content.encode("utf-8")


def generate_report(
    case_id: str,
    client_name: str,
    informante: str,
    crm_case: str,
    output_path: Path | None = None,
    fmt: str = "html",
    narrative: ReportNarrative | None = None,
) -> Path:
    """Render the case into an HTML or PDF report.

    Args:
        case_id: The case ID, e.g. "case-0009e49b2476"
        client_name: Client display name for the cover page
        informante: Name of the person who requested the report
        crm_case: CRM/ticket reference number
        output_path: Override output path. Defaults to .egs_cases/<case_id>-report.{fmt}
        fmt: Output format — "html" (default) or "pdf"

    Returns:
        Path to the generated file
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:
        raise RuntimeError(
            "jinja2 is required. Install with: pip install jinja2"
        ) from exc

    report_json_path = _CASES_DIR / f"{case_id}-report.json"
    if not report_json_path.exists():
        raise FileNotFoundError(
            f"Report data not found: {report_json_path}\n"
            "Run 'report-collect' first while platform-api is running."
        )

    case_data = json.loads(report_json_path.read_text(encoding="utf-8"))
    context = _build_context(case_data, client_name, informante, crm_case)
    context["css"] = (_HERE / "styles.css").read_text(encoding="utf-8")
    _inject_narrative(context, narrative)

    env = Environment(
        loader=FileSystemLoader(str(_HERE)),
        autoescape=select_autoescape(["html"]),
    )
    html_content = env.get_template("template.html").render(**context)

    if output_path is None:
        output_path = _CASES_DIR / f"{case_id}-report.{fmt}"

    if fmt == "pdf":
        try:
            from weasyprint import HTML as WeasyHTML
        except ImportError as exc:
            raise RuntimeError(
                "weasyprint is required for PDF output. "
                "Install with: pip install weasyprint"
            ) from exc
        WeasyHTML(string=html_content, base_url=str(_HERE)).write_pdf(str(output_path))
    else:
        output_path.write_text(html_content, encoding="utf-8")

    return output_path
