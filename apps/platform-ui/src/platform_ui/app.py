"""Streamlit UI for cai-platform — wraps the cai-orchestrator layer."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import time
from typing import Any

import boto3
import pandas as pd
import streamlit as st

from cai_orchestrator.client import PlatformApiClient
from cai_orchestrator.email_bridge import (
    EmlExtractionError,
    eml_bytes_to_structured_email_v2_payload,
    extract_eml_attachment,
)
from cai_orchestrator.errors import (
    OrchestrationFlowError,
    PlatformApiRequestError,
    PlatformApiUnavailableError,
)
from cai_orchestrator.flows import (
    PHISHING_EMAIL_BACKEND_ID,
    PHISHING_EMAIL_WORKFLOW_TYPE,
    WATCHGUARD_BACKEND_ID,
    WATCHGUARD_WORKFLOW_TYPE,
    PhishingEmailAssessmentRequest,
    run_phishing_email_basic_assessment,
    run_phishing_monitor_single_email,
)
from cai_orchestrator.imap_monitor import (
    ImapMonitorConfigError,
    ImapMonitorSettings,
    poll_unseen_messages,
)

# CAI availability — mirrors cai_terminal.py convention.
#
# cai.util registers a SIGINT handler at module import time via signal.signal().
# Streamlit runs user scripts in a non-main thread, which makes signal.signal()
# raise ValueError. We temporarily patch it to a no-op so the import succeeds,
# then restore the original. The handler simply won't be registered in this
# thread (Streamlit manages its own signals from the main thread).
import signal as _signal_module

_orig_signal_fn = _signal_module.signal


def _noop_on_thread_signal(signum: int, handler: Any) -> Any:
    try:
        return _orig_signal_fn(signum, handler)
    except ValueError:
        return None


_signal_module.signal = _noop_on_thread_signal  # type: ignore[assignment]
try:
    from cai_orchestrator.cai_terminal import build_egs_analist_agent
    from cai_orchestrator.phishing_agents import build_phishing_investigator_agent
    from cai.sdk.agents import Runner, set_tracing_disabled  # type: ignore[import]

    set_tracing_disabled(True)  # suppress OpenAI tracing 401 errors (sk-placeholder)
    _CAI_AVAILABLE = True
except ImportError:
    _CAI_AVAILABLE = False
finally:
    _signal_module.signal = _orig_signal_fn  # type: ignore[assignment]

# Suppress litellm logging noise from ResponseAPIUsage version mismatch
import logging as _logging
_logging.getLogger("LiteLLM").setLevel(_logging.CRITICAL)

# ── Constants (env defaults, all overridable from sidebar) ──────────────────

_DEFAULT_API_URL = os.getenv("PLATFORM_API_BASE_URL", "http://127.0.0.1:8000")
_DEFAULT_MODEL = os.getenv("CAI_MODEL") or ""
_DEFAULT_BUCKET = os.getenv("WATCHGUARD_S3_BUCKET", "egslatam-cai-dev")
_DEFAULT_REGION = os.getenv("WATCHGUARD_S3_REGION", "us-east-2")
_DEFAULT_CLIENT_ID = os.getenv("CLIENT_ID", "default")


# ── Helpers ──────────────────────────────────────────────────────────────────


def make_client(settings: dict[str, Any]) -> PlatformApiClient:
    return PlatformApiClient(base_url=settings["api_url"])


def make_boto3_s3(settings: dict[str, Any]):
    kwargs: dict[str, Any] = {"region_name": settings["aws_region"]}
    if settings.get("aws_key") and settings.get("aws_secret"):
        kwargs["aws_access_key_id"] = settings["aws_key"]
        kwargs["aws_secret_access_key"] = settings["aws_secret"]
    return boto3.client("s3", **kwargs)


def upload_zip_to_s3(
    s3_client: Any,
    zip_bytes: bytes,
    workspace_id: str,
    bucket: str,
) -> str:
    """Upload zip bytes to S3 using the standard key convention.

    Key: workspaces/{workspace_id}/input/uploads/{upload_id}/raw.zip
    Returns the s3:// URI.
    """
    upload_id = time.strftime("%Y%m%d_%H%M%S")
    key = f"workspaces/{workspace_id}/input/uploads/{upload_id}/raw.zip"
    s3_client.put_object(Bucket=bucket, Key=key, Body=zip_bytes)
    return f"s3://{bucket}/{key}"


def run_cai_agent(agent: Any, input_: Any) -> Any:
    """Run async CAI Runner.run() safely from Streamlit's sync context.

    Uses a ThreadPoolExecutor so asyncio.run() gets a fresh event loop
    in a separate OS thread — no conflict with Streamlit's own event loop.
    """

    def _in_thread() -> Any:
        return asyncio.run(Runner.run(agent, input=input_))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(_in_thread).result()


def _extract_first_output_artifact_id(resp: dict[str, Any]) -> str | None:
    """Pull the first output artifact_id from an execute_* response."""
    for artifact in resp.get("output_artifacts", []):
        if aid := artifact.get("artifact_id"):
            return aid
    obs = resp.get("observation_result", {})
    refs = obs.get("output_artifact_refs", []) or obs.get("output_artifact_ids", [])
    if refs:
        item = refs[0]
        return item.get("artifact_id") or item if isinstance(item, str) else None
    return None


def _parse_cai_verdict(final_output: Any) -> dict[str, Any] | None:
    if isinstance(final_output, dict):
        return final_output
    if isinstance(final_output, str):
        # Try direct JSON parse first
        try:
            return json.loads(final_output)
        except json.JSONDecodeError:
            pass
        # Extract JSON object from strings like "Final Synthesis: {...}"
        start = final_output.find("{")
        end = final_output.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(final_output[start : end + 1])
            except json.JSONDecodeError:
                pass
        return {"evidence_summary": final_output}
    return None


def _format_cai_output(output: Any) -> str:
    if isinstance(output, (dict, list)):
        return json.dumps(output, indent=2, ensure_ascii=False)
    return str(output)


def _build_cai_chat_input(
    user_input: str,
    raw_history: list | None,
    run_id: str,
    staging_artifact_id: str,
) -> Any:
    """Build CAI runner input for a chat turn.

    First turn: inject context string so the agent knows which run/artifact to use.
    Subsequent turns: prepend accumulated to_input_list() result + new user message.
    """
    if raw_history is None:
        return (
            f"You are helping investigate a WatchGuard log workspace. "
            f"The run_id is {run_id!r} and the staging manifest artifact_id is "
            f"{staging_artifact_id!r}. Always pass input_artifact_id={staging_artifact_id!r} "
            f"to duckdb analytics and query tools. User question: {user_input}"
        )
    return raw_history + [{"role": "user", "content": user_input}]


# ── Sidebar ───────────────────────────────────────────────────────────────────


def render_sidebar() -> dict[str, Any]:
    with st.sidebar:
        st.title("Settings")

        if not _CAI_AVAILABLE:
            st.warning(
                "CAI not installed. Chat and multi-agent features are disabled. "
                "Run `make install-ui-cai` to enable them."
            )

        st.subheader("Platform")
        api_url = st.text_input("Platform API URL", value=_DEFAULT_API_URL, key="s_api_url")
        client_id = st.text_input("Client ID", value=_DEFAULT_CLIENT_ID, key="s_client_id")

        st.subheader("CAI Model")
        model = st.text_input(
            "Model string",
            value=_DEFAULT_MODEL,
            placeholder="bedrock/us.anthropic.claude-sonnet-4-6",
            key="s_model",
        )

        st.subheader("AWS")
        aws_key = st.text_input(
            "Access Key ID",
            type="password",
            value=os.getenv("AWS_ACCESS_KEY_ID", ""),
            key="s_aws_key",
        )
        aws_secret = st.text_input(
            "Secret Access Key",
            type="password",
            value=os.getenv("AWS_SECRET_ACCESS_KEY", ""),
            key="s_aws_secret",
        )
        aws_region = st.text_input("Region", value=_DEFAULT_REGION, key="s_aws_region")
        s3_bucket = st.text_input("S3 Bucket", value=_DEFAULT_BUCKET, key="s_s3_bucket")

    return {
        "api_url": api_url.strip() or _DEFAULT_API_URL,
        "client_id": client_id.strip() or "default",
        "model": model.strip() or None,
        "aws_key": aws_key.strip() or None,
        "aws_secret": aws_secret.strip() or None,
        "aws_region": aws_region.strip() or _DEFAULT_REGION,
        "s3_bucket": s3_bucket.strip() or _DEFAULT_BUCKET,
    }


# ── Tab 1: WatchGuard S3 Investigation ───────────────────────────────────────


def render_watchguard_tab(settings: dict[str, Any]) -> None:
    st.header("WatchGuard S3 Investigation")
    st.caption(
        "Sube el ZIP de SharePoint, describe qué quieres investigar y el pipeline "
        "hará el resto: sube a S3, extrae los logs, corre analytics con DuckDB y "
        "deja el chat disponible para preguntas de seguimiento."
    )

    uploaded_file = st.file_uploader(
        "ZIP de SharePoint", type=["zip"], key="wg_zip"
    )

    default_workspace = ""
    if uploaded_file:
        default_workspace = uploaded_file.name.removesuffix(".zip")

    workspace_id = st.text_input(
        "Workspace ID",
        value=default_workspace,
        help="Auto-detectado del nombre del archivo. Edítalo si es necesario.",
        key="wg_workspace",
    )
    question = st.text_area(
        "¿Qué quieres investigar?",
        value="Top IPs con más denials, tipos de alarmas y rango de fechas del dataset.",
        key="wg_question",
    )

    if st.button("Investigar", key="wg_run", disabled=not (uploaded_file and workspace_id)):
        _run_watchguard_investigation(settings, uploaded_file, workspace_id, question)

    if st.session_state.get("wg_run_id"):
        _render_analytics_cached(settings)
        st.divider()
        _render_watchguard_chat(settings)


def _run_watchguard_investigation(
    settings: dict[str, Any],
    uploaded_file: Any,
    workspace_id: str,
    question: str,
) -> None:
    zip_bytes = uploaded_file.read()

    with st.status("Ejecutando pipeline WatchGuard S3...", expanded=True) as status:
        try:
            # Step 1 — Upload ZIP to S3
            status.update(label="Subiendo ZIP a S3...")
            s3 = make_boto3_s3(settings)
            s3_uri = upload_zip_to_s3(s3, zip_bytes, workspace_id, settings["s3_bucket"])
            st.write(f"Subido: `{s3_uri}`")

            # Step 2 — Create case
            status.update(label="Creando caso de investigación...")
            client = make_client(settings)
            case_resp = client.create_case(
                client_id=settings["client_id"],
                workflow_type=WATCHGUARD_WORKFLOW_TYPE,
                title=f"WatchGuard — {workspace_id}",
                summary=question,
            )
            case_id = case_resp["case"]["case_id"]
            st.write(f"Caso: `{case_id}`")

            # Step 3 — Attach S3 ZIP artifact reference
            status.update(label="Adjuntando referencia S3...")
            art_resp = client.attach_input_artifact(
                case_id=case_id,
                payload={
                    "source": "workspace_s3_zip",
                    "workspace": workspace_id,
                    "s3_uri": s3_uri,
                },
                format="json",
                summary="Workspace S3 ZIP reference from platform-ui",
            )
            artifact_id = art_resp["artifact"]["artifact_id"]

            # Step 4 — Create run
            status.update(label="Creando run...")
            run_resp = client.create_run(
                case_id=case_id,
                backend_id=WATCHGUARD_BACKEND_ID,
                input_artifact_ids=[artifact_id],
            )
            run_id = run_resp["run"]["run_id"]
            st.write(f"Run: `{run_id}`")

            # Step 5 — Stage workspace ZIP (extract TARs → individual CSVs → S3)
            status.update(label="Staging: extrayendo TARs y subiendo CSVs a S3...")
            staging_resp = client.execute_watchguard_stage_workspace_zip(
                run_id=run_id,
                requested_by="platform_ui",
                input_artifact_id=artifact_id,
            )
            staging_artifact_id = _extract_first_output_artifact_id(staging_resp)
            if not staging_artifact_id:
                raise ValueError(f"No se encontró staging artifact en: {staging_resp}")
            st.write(f"Staging manifest: `{staging_artifact_id}`")

            # Step 6 — DuckDB workspace analytics
            status.update(label="Corriendo analytics con DuckDB...")
            analytics_resp = client.execute_watchguard_duckdb_workspace_analytics(
                run_id=run_id,
                requested_by="platform_ui",
                input_artifact_id=staging_artifact_id,
            )
            analytics_artifact_id = _extract_first_output_artifact_id(analytics_resp)
            if not analytics_artifact_id:
                raise ValueError(f"No se encontró analytics artifact en: {analytics_resp}")

            # Step 7 — Read analytics artifact content
            status.update(label="Leyendo resultados...")
            content_resp = client.read_artifact_content(artifact_id=analytics_artifact_id)
            content = content_resp.get("content", content_resp)

            # Persist in session state
            st.session_state["wg_run_id"] = run_id
            st.session_state["wg_staging_artifact_id"] = staging_artifact_id
            st.session_state["wg_analytics_content"] = content
            st.session_state["wg_chat_history"] = []
            st.session_state["wg_chat_raw_history"] = None

            status.update(label="Pipeline completado.", state="complete")

        except (PlatformApiUnavailableError, PlatformApiRequestError, OrchestrationFlowError) as exc:
            status.update(label=f"Error: {exc}", state="error")
            st.error(str(exc))
            return
        except Exception as exc:
            status.update(label=f"Error inesperado: {exc}", state="error")
            st.error(str(exc))
            return


def _render_analytics_cached(settings: dict[str, Any]) -> None:
    content = st.session_state.get("wg_analytics_content")
    if content:
        _render_analytics_results(content)


def _render_analytics_results(content: dict[str, Any]) -> None:
    st.subheader("Resultados de Analytics")

    # Top-level scalar metrics
    deny_count = content.get("deny_count", 0)
    time_range = content.get("time_range") or {}
    t_min = time_range.get("min", "—")
    t_max = time_range.get("max", "—")

    col1, col2, col3 = st.columns(3)
    col1.metric("Deny Count", deny_count)
    col2.metric("Fecha inicio", t_min)
    col3.metric("Fecha fin", t_max)

    # Table helpers
    def _show_table(key: str, label: str) -> None:
        rows = content.get(key)
        if rows:
            with st.expander(label, expanded=True):
                st.dataframe(pd.DataFrame(rows), use_container_width=True)

    _show_table("top_src_ips", "Top Source IPs")
    _show_table("top_dst_ips", "Top Destination IPs")
    _show_table("action_counts", "Distribución de Acciones")
    _show_table("protocol_breakdown", "Protocolos")
    _show_table("alarm_type_counts", "Tipos de Alarma")


def _render_watchguard_chat(settings: dict[str, Any]) -> None:
    st.subheader("Preguntas de seguimiento")

    if not _CAI_AVAILABLE:
        st.info(
            "Instala `cai-platform-ui[cai]` (ejecuta `make install-ui-cai`) "
            "para habilitar el chat con el agente."
        )
        return

    for msg in st.session_state.get("wg_chat_history", []):
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    user_input = st.chat_input(
        "Pregunta sobre la investigación...", key="wg_chat_input"
    )
    if user_input:
        _handle_watchguard_chat_turn(settings, user_input)


def _handle_watchguard_chat_turn(settings: dict[str, Any], user_input: str) -> None:
    run_id = st.session_state["wg_run_id"]
    staging_artifact_id = st.session_state["wg_staging_artifact_id"]
    raw_history = st.session_state.get("wg_chat_raw_history")

    st.session_state["wg_chat_history"].append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.write(user_input)

    cai_input = _build_cai_chat_input(user_input, raw_history, run_id, staging_artifact_id)

    agent = build_egs_analist_agent(
        platform_api_base_url=settings["api_url"],
        model=settings["model"],
    )

    with st.chat_message("assistant"):
        with st.spinner("El agente está pensando..."):
            try:
                result = run_cai_agent(agent, cai_input)
            except Exception as exc:
                st.error(f"Error del agente CAI: {exc}")
                return

        response_text = _format_cai_output(result.final_output)
        st.write(response_text)

    st.session_state["wg_chat_history"].append(
        {"role": "assistant", "content": response_text}
    )
    st.session_state["wg_chat_raw_history"] = result.to_input_list()


# ── Tab 2: Phishing Investigation ────────────────────────────────────────────


def render_phishing_tab(settings: dict[str, Any]) -> None:
    st.header("Phishing Email Investigation")
    st.caption(
        "Sube un archivo .eml o pega el payload JSON del email sospechoso. "
        "El pipeline corre el basic assessment y, opcionalmente, el pipeline "
        "multi-agente de CAI para producir un veredicto completo."
    )

    input_mode = st.radio(
        "Modo de entrada",
        ["Subir archivo .eml", "Pegar payload JSON"],
        horizontal=True,
        key="ph_input_mode",
    )

    payload: dict[str, Any] | None = None

    if input_mode == "Subir archivo .eml":
        eml_file = st.file_uploader("Archivo .eml", type=["eml"], key="ph_eml")
        if eml_file:
            raw_eml = eml_file.read()
            try:
                payload = eml_bytes_to_structured_email_v2_payload(raw_eml)
                st.success("EML parseado correctamente.")
                with st.expander("Preview del payload"):
                    preview = {
                        k: v
                        for k, v in payload.items()
                        if k not in ("html_body", "all_headers", "text_body")
                    }
                    st.json(preview)
            except Exception as exc:
                st.error(f"No se pudo parsear el .eml: {exc}")

    else:
        json_text = st.text_area(
            "Payload JSON del email",
            height=200,
            key="ph_json",
            placeholder=json.dumps(
                {
                    "subject": "Urgent action required",
                    "sender": {"email": "attacker@example.com", "display_name": "Security"},
                    "reply_to": None,
                    "urls": ["http://198.51.100.7/login?verify=1"],
                    "text": "Click here immediately to avoid suspension.",
                    "attachments": [],
                },
                indent=2,
            ),
        )
        if json_text.strip():
            try:
                parsed = json.loads(json_text)
                if not isinstance(parsed, dict):
                    st.error("El payload debe ser un objeto JSON.")
                else:
                    payload = parsed
            except json.JSONDecodeError as exc:
                st.error(f"JSON inválido: {exc}")

    title = st.text_input("Título del caso", value="Phishing email investigation", key="ph_title")
    summary = st.text_area(
        "Resumen",
        value="Investigación automática de phishing vía platform-ui.",
        key="ph_summary",
    )

    run_cai_pipeline = st.checkbox(
        "Correr pipeline multi-agente CAI (veredicto completo)",
        value=_CAI_AVAILABLE,
        disabled=not _CAI_AVAILABLE,
        key="ph_run_cai",
        help="Requiere `cai-platform-ui[cai]` instalado." if not _CAI_AVAILABLE else "",
    )

    if st.button("Investigar", key="ph_run", disabled=payload is None):
        _run_phishing_investigation(settings, payload, title, summary, run_cai_pipeline)


def _run_phishing_investigation(
    settings: dict[str, Any],
    payload: dict[str, Any],
    title: str,
    summary: str,
    run_cai: bool,
) -> None:
    with st.status("Ejecutando investigación phishing...", expanded=True) as status:
        try:
            client = make_client(settings)
            request = PhishingEmailAssessmentRequest(
                client_id=settings["client_id"],
                title=title,
                summary=summary,
                payload=payload,
            )

            status.update(label="Corriendo basic assessment...")
            result = run_phishing_email_basic_assessment(client, request)
            run_id = result.run.get("run_id") or result.run.get("run", {}).get("run_id")
            artifact_id = (
                result.input_artifact.get("artifact_id")
                or result.input_artifact.get("artifact", {}).get("artifact_id")
            )

            # Read basic assessment output artifact
            artifacts_resp = client.list_run_artifacts(run_id=run_id)
            basic_content: dict[str, Any] = {}
            output_arts = artifacts_resp.get("output_artifacts", [])
            if output_arts:
                basic_art_id = output_arts[0].get("artifact_id")
                if basic_art_id:
                    raw = client.read_artifact_content(artifact_id=basic_art_id)
                    basic_content = raw.get("content", raw)

            verdict_data: dict[str, Any] | None = None
            if run_cai and _CAI_AVAILABLE:
                status.update(label="Corriendo pipeline multi-agente CAI...")
                agent = build_phishing_investigator_agent(
                    platform_api_base_url=settings["api_url"],
                    model=settings["model"],
                )
                cai_result = run_cai_agent(
                    agent,
                    f"Investigate run_id={run_id!r}, input_artifact_id={artifact_id!r}.",
                )
                verdict_data = _parse_cai_verdict(cai_result.final_output)

            status.update(label="Investigación completada.", state="complete")

        except (PlatformApiUnavailableError, PlatformApiRequestError, OrchestrationFlowError) as exc:
            status.update(label=f"Error: {exc}", state="error")
            st.error(str(exc))
            return
        except Exception as exc:
            status.update(label=f"Error inesperado: {exc}", state="error")
            st.error(str(exc))
            return

    _render_phishing_verdict(basic_content, verdict_data)


def _render_phishing_verdict(
    basic_content: dict[str, Any],
    verdict_data: dict[str, Any] | None,
) -> None:
    st.subheader("Resultados del Assessment")

    risk_level = basic_content.get("risk_level", "unknown")
    risk_score = basic_content.get("risk_score", 0)
    triggered_rules = basic_content.get("triggered_rules", [])

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Level", risk_level.upper())
    col2.metric("Risk Score", risk_score)
    col3.metric("Reglas activadas", len(triggered_rules))

    if triggered_rules:
        with st.expander("Reglas activadas"):
            for rule in triggered_rules:
                rule_id = rule.get("rule_id") or rule.get("id") or "?"
                message = rule.get("message") or rule.get("description") or ""
                st.markdown(f"- **{rule_id}**: {message}")

    if basic_content.get("url_signals"):
        with st.expander("Señales de URLs"):
            st.json(basic_content["url_signals"])

    if basic_content.get("attachment_signals"):
        with st.expander("Señales de Adjuntos"):
            st.json(basic_content["attachment_signals"])

    if verdict_data:
        st.subheader("Veredicto CAI Multi-Agente")
        if verdict_data.get("overall_verdict"):
            cols = st.columns(3)
            cols[0].metric("Veredicto", verdict_data.get("overall_verdict", "—"))
            cols[1].metric("Confianza", verdict_data.get("confidence", "—"))
            cols[2].metric("Acción recomendada", verdict_data.get("recommended_action", "—"))
            evidence = verdict_data.get("evidence_summary", "")
            if evidence:
                st.markdown(f"**Resumen de evidencia:** {evidence}")
            with st.expander("Veredicto completo (JSON)"):
                st.json(verdict_data)
        else:
            # Agent produced text analysis but no structured JSON verdict
            st.info("El agente completó el análisis pero no produjo un veredicto JSON estructurado.")
            evidence = verdict_data.get("evidence_summary", "")
            if evidence:
                st.markdown(evidence)


def _eml_to_assessment_payload(raw_eml: bytes) -> dict[str, Any]:
    """Parse raw EML bytes into a structured_email_v2 payload with fallbacks applied.

    Returns the full v2 dict so that header_analysis (which requires
    input_shape='structured_email_v2') has access to all_headers/received_chain,
    while basic_assessment still works because normalize_phishing_email_payload
    only reads the v1-compatible REQUIRED_FIELDS and ignores extras.

    Fallbacks applied:
    - text: plain text → HTML-stripped → subject placeholder (never empty)
    - subject: must be non-empty
    - attachments: filter entries with empty filenames (forwarded message/rfc822 parts)
    """
    import re as _re
    v2 = eml_bytes_to_structured_email_v2_payload(raw_eml)

    # text: plain text body, or HTML-stripped fallback, or subject placeholder
    text: str = v2.get("text") or ""
    if not text.strip():
        html = v2.get("html_body") or ""
        text = _re.sub(r"<[^>]+>", " ", html)
        text = _re.sub(r"\s+", " ", text).strip()
    if not text.strip():
        text = f"[No text content] Subject: {v2.get('subject') or 'Unknown'}"

    # subject: must be non-empty
    subject = (v2.get("subject") or "").strip() or "(no subject)"

    # Filter out attachments with empty filenames (e.g. message/rfc822 forwarded chains)
    attachments = [
        a for a in v2.get("attachments", [])
        if isinstance(a, dict) and a.get("filename", "").strip()
    ]

    # Sanitize sender.email — some From headers (e.g. automated system notifications) are
    # malformed and contain no parseable email address (e.g. `"Display Name (via System"`
    # without a closing angle-bracket address). Try to find an email anywhere in the sender
    # dict values; fall back to a synthetic placeholder so the backend doesn't reject it.
    sender = dict(v2.get("sender") or {})
    sender_email = (sender.get("email") or "").strip()
    if "@" not in sender_email:
        found = None
        for val in sender.values():
            if isinstance(val, str):
                m = _re.search(r"[\w.+%-]+@[\w.-]+\.[a-zA-Z]{2,}", val)
                if m:
                    found = m.group(0).lower()
                    break
        sender["email"] = found or "unknown@unknown.local"
        sender.setdefault("domain", sender["email"].split("@")[-1])

    # Return full v2 payload with fallbacks applied — keeps all_headers, received_chain, etc.
    return {**v2, "subject": subject, "sender": sender, "text": text, "attachments": attachments}


# ── Tab 3: IMAP Email Monitor ────────────────────────────────────────────────


def render_imap_tab(settings: dict[str, Any]) -> None:
    st.header("Monitor de Email (IMAP)")
    st.caption(
        "Revisa los correos no leídos del buzón configurado y corre el pipeline "
        "de phishing automáticamente sobre cada uno. Equivalente a "
        "`run-phishing-monitor --once` desde el CLI."
    )

    # IMAP settings (read from env by default, override in UI)
    with st.expander("Configuración IMAP", expanded=not os.getenv("IMAP_HOST")):
        col1, col2 = st.columns([3, 1])
        imap_host = col1.text_input(
            "Host", value=os.getenv("IMAP_HOST", "imap.gmail.com"), key="imap_host"
        )
        imap_port = col2.number_input(
            "Puerto", value=int(os.getenv("IMAP_PORT", "993")), key="imap_port"
        )
        imap_user = st.text_input(
            "Usuario (email)", value=os.getenv("IMAP_USERNAME", ""), key="imap_user"
        )
        imap_pass = st.text_input(
            "Contraseña de aplicación",
            type="password",
            value=os.getenv("IMAP_PASSWORD", ""),
            key="imap_pass",
            help="Para Gmail: genera una App Password en myaccount.google.com/apppasswords",
        )
        imap_mailbox = st.text_input(
            "Buzón", value=os.getenv("IMAP_MAILBOX", "INBOX"), key="imap_mailbox"
        )
        imap_mark_seen = st.checkbox(
            "Marcar como leído después de procesar",
            value=os.getenv("IMAP_MARK_SEEN", "true").lower() not in ("false", "0", "no"),
            key="imap_mark_seen",
        )
        run_cai_pipeline = st.checkbox(
            "Correr pipeline multi-agente CAI en cada email",
            value=_CAI_AVAILABLE,
            disabled=not _CAI_AVAILABLE,
            key="imap_run_cai",
        )

    imap_ready = bool(imap_host and imap_user and imap_pass)

    if st.button(
        "Revisar correos nuevos",
        key="imap_run",
        disabled=not imap_ready,
        help="Requiere host, usuario y contraseña configurados." if not imap_ready else "",
    ):
        _run_imap_monitor(
            settings=settings,
            imap_host=str(imap_host),
            imap_port=int(imap_port),
            imap_user=imap_user,
            imap_pass=imap_pass,
            imap_mailbox=imap_mailbox,
            mark_seen=imap_mark_seen,
            run_cai=run_cai_pipeline,
        )


def _run_imap_monitor(
    *,
    settings: dict[str, Any],
    imap_host: str,
    imap_port: int,
    imap_user: str,
    imap_pass: str,
    imap_mailbox: str,
    mark_seen: bool,
    run_cai: bool,
) -> None:
    imap_settings = ImapMonitorSettings(
        imap_host=imap_host,
        imap_port=imap_port,
        username=imap_user,
        password=imap_pass,
        mailbox=imap_mailbox,
        mark_seen=mark_seen,
    )

    with st.status("Conectando al buzón...", expanded=True) as status:
        try:
            status.update(label="Buscando correos no leídos...")
            raw_emails = poll_unseen_messages(imap_settings)
        except Exception as exc:
            status.update(label=f"Error de conexión IMAP: {exc}", state="error")
            st.error(str(exc))
            return

        if not raw_emails:
            status.update(label="No hay correos nuevos.", state="complete")
            st.info("No se encontraron mensajes no leídos en el buzón.")
            return

        status.update(label=f"Encontrados {len(raw_emails)} correo(s). Procesando...")
        client = make_client(settings)
        results = []

        for i, raw_eml in enumerate(raw_emails, start=1):
            status.update(label=f"Procesando email {i}/{len(raw_emails)}...")
            try:
                # The CAI mailbox receives forwarding container emails from employees.
                # The actual suspicious email is attached inside as message/rfc822 or .eml.
                # Try to extract it; fall back to the raw bytes if not a forwarding container.
                try:
                    inner_eml = extract_eml_attachment(raw_eml)
                except EmlExtractionError:
                    inner_eml = raw_eml  # email was submitted directly, not forwarded
                payload = _eml_to_assessment_payload(inner_eml)
                request = PhishingEmailAssessmentRequest(
                    client_id=settings["client_id"],
                    title=f"Email monitor — {payload.get('subject', 'mensaje ' + str(i))}",
                    summary="Investigación automática vía IMAP monitor desde platform-ui.",
                    payload=payload,
                )
                flow_result = run_phishing_email_basic_assessment(client, request)
                # Wrap into a compatible structure for rendering
                run_id = (
                    flow_result.run.get("run", {}).get("run_id")
                    or flow_result.run.get("run_id")
                )
                artifact_id = (
                    flow_result.input_artifact.get("artifact", {}).get("artifact_id")
                    or flow_result.input_artifact.get("artifact_id")
                )
                artifacts_resp = client.list_run_artifacts(run_id=run_id)
                output_arts = artifacts_resp.get("output_artifacts", [])
                basic_content: dict[str, Any] = {}
                if output_arts:
                    raw_content = client.read_artifact_content(
                        artifact_id=output_arts[0]["artifact_id"]
                    )
                    basic_content = raw_content.get("content", raw_content)

                verdict_data: dict[str, Any] | None = None
                if run_cai and _CAI_AVAILABLE:
                    agent = build_phishing_investigator_agent(
                        platform_api_base_url=settings["api_url"],
                        model=settings["model"],
                    )
                    cai_result = run_cai_agent(
                        agent,
                        f"Investigate run_id={run_id!r}, input_artifact_id={artifact_id!r}.",
                    )
                    verdict_data = _parse_cai_verdict(cai_result.final_output)

                results.append((basic_content, verdict_data, payload))
            except Exception as exc:
                import traceback
                st.warning(f"Error procesando email {i}: {exc}")
                with st.expander(f"Detalle del error (email {i})"):
                    st.code(traceback.format_exc())
                    # Show API error payload if available
                    if hasattr(exc, "details") and exc.details:
                        st.write("**details:**"); st.json(exc.details)
                    cause = getattr(exc, "__cause__", None)
                    if cause and hasattr(cause, "payload"):
                        st.write("**API response payload:**"); st.json(cause.payload)
                    # Show parsed payload for debugging
                    try:
                        try:
                            _dbg_inner = extract_eml_attachment(raw_eml)
                        except EmlExtractionError:
                            _dbg_inner = raw_eml
                        dbg_payload = _eml_to_assessment_payload(_dbg_inner)
                        st.write("**Payload parseado:**")
                        st.json({k: v for k, v in dbg_payload.items() if k not in ("text",)})
                        st.write(f"**text (primeros 200 chars):** {dbg_payload.get('text', '')[:200]!r}")
                    except Exception as pe:
                        st.write(f"Error parseando EML: {pe}")

        status.update(
            label=f"Procesados {len(results)}/{len(raw_emails)} correos.",
            state="complete",
        )

    # Render results per email
    for i, (basic_content, verdict_data, payload) in enumerate(results, start=1):
        subject = payload.get("subject") or f"Email {i}"
        sender_info = payload.get("sender") or {}
        sender = sender_info.get("email") if isinstance(sender_info, dict) else str(sender_info)
        risk_level = basic_content.get("risk_level", "unknown")

        with st.expander(f"Email {i} — {subject} ({risk_level.upper()})", expanded=True):
            col1, col2, col3 = st.columns(3)
            col1.metric("Remitente", sender or "—")
            col2.metric("Risk Level", risk_level.upper())
            col3.metric("Risk Score", basic_content.get("risk_score", 0))

            triggered = basic_content.get("triggered_rules", [])
            if triggered:
                st.markdown("**Reglas activadas:**")
                for rule in triggered:
                    rule_id = rule.get("rule_id") or "?"
                    msg = rule.get("message") or ""
                    st.markdown(f"- **{rule_id}**: {msg}")

            if verdict_data:
                st.markdown("---")
                if verdict_data.get("overall_verdict"):
                    vcols = st.columns(3)
                    vcols[0].metric("Veredicto CAI", verdict_data.get("overall_verdict", "—"))
                    vcols[1].metric("Confianza", verdict_data.get("confidence", "—"))
                    vcols[2].metric("Acción", verdict_data.get("recommended_action", "—"))
                if verdict_data.get("evidence_summary"):
                    st.caption(verdict_data["evidence_summary"])


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    st.set_page_config(
        page_title="CAI Platform UI",
        page_icon=":shield:",
        layout="wide",
    )
    st.title("CAI Platform")

    settings = render_sidebar()

    tab_wg, tab_ph, tab_imap = st.tabs(
        ["WatchGuard S3 Investigation", "Phishing Investigation", "Monitor de Email"]
    )

    with tab_wg:
        render_watchguard_tab(settings)

    with tab_ph:
        render_phishing_tab(settings)

    with tab_imap:
        render_imap_tab(settings)


if __name__ == "__main__":
    main()
