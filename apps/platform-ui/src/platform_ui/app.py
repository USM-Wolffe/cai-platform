"""Streamlit UI for cai-platform — wraps the cai-orchestrator layer."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import threading
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
    from cai_orchestrator.ddos_agents import run_ddos_investigation as _run_ddos_investigation_pipeline
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

try:
    from cai_orchestrator.report.generate import generate_report_from_context as _generate_report_from_context
    _REPORT_AVAILABLE = True
except ImportError:
    _REPORT_AVAILABLE = False

# ── Constants (env defaults, all overridable from sidebar) ──────────────────

_DEFAULT_API_URL = os.getenv("PLATFORM_API_BASE_URL", "http://127.0.0.1:8000")
_DEFAULT_MODEL = os.getenv("CAI_MODEL") or ""
_DEFAULT_BUCKET = os.getenv("WATCHGUARD_S3_BUCKET", "egslatam-cai-dev")
_DEFAULT_REGION = os.getenv("WATCHGUARD_S3_REGION", "us-east-2")
_DEFAULT_CLIENT_ID = os.getenv("CLIENT_ID", "default")


# ── Helpers ──────────────────────────────────────────────────────────────────


def make_client(settings: dict[str, Any], timeout: float = 900.0) -> PlatformApiClient:
    return PlatformApiClient(base_url=settings["api_url"], timeout=timeout)


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
    progress_callback: Any | None = None,
) -> str:
    """Upload zip bytes to S3 using multipart upload.

    Splits the file into 50 MB parts so large ZIPs (1-2 GB) never load fully
    into memory and the caller receives byte-level progress updates.

    Key: workspaces/{workspace_id}/input/uploads/{upload_id}/raw.zip
    Returns the s3:// URI.
    progress_callback(bytes_uploaded: int, total_bytes: int) — called after each part.
    """
    import io
    import math

    PART_SIZE = 50 * 1024 * 1024  # 50 MB per part
    upload_id = time.strftime("%Y%m%d_%H%M%S")
    key = f"workspaces/{workspace_id}/input/uploads/{upload_id}/raw.zip"
    total = len(zip_bytes)

    # Small files: single-part upload is simpler
    if total <= PART_SIZE:
        s3_client.put_object(Bucket=bucket, Key=key, Body=zip_bytes)
        if progress_callback:
            progress_callback(total, total)
        return f"s3://{bucket}/{key}"

    # Multipart upload
    mpu = s3_client.create_multipart_upload(Bucket=bucket, Key=key)
    mpu_id = mpu["UploadId"]
    parts = []
    stream = io.BytesIO(zip_bytes)
    part_number = 1
    uploaded = 0

    try:
        while True:
            chunk = stream.read(PART_SIZE)
            if not chunk:
                break
            resp = s3_client.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=mpu_id,
                PartNumber=part_number,
                Body=chunk,
            )
            parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})
            uploaded += len(chunk)
            if progress_callback:
                progress_callback(uploaded, total)
            part_number += 1

        s3_client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=mpu_id,
            MultipartUpload={"Parts": parts},
        )
    except Exception:
        s3_client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=mpu_id)
        raise

    return f"s3://{bucket}/{key}"


def find_latest_s3_uri_for_workspace(
    s3_client: Any, bucket: str, workspace_id: str
) -> str | None:
    """Return the s3:// URI of the most recent raw.zip upload for a workspace.

    Scans workspaces/{workspace_id}/input/uploads/*/raw.zip and returns the
    latest key (upload IDs are timestamp strings, so lexicographic sort works).
    Returns None if no uploads exist.
    """
    prefix = f"workspaces/{workspace_id}/input/uploads/"
    resp = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix)
    keys = [
        obj["Key"]
        for obj in resp.get("Contents", [])
        if obj["Key"].endswith("/raw.zip")
    ]
    if not keys:
        return None
    keys.sort()
    return f"s3://{bucket}/{keys[-1]}"


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
    # Top-level "artifacts" list (full objects with artifact_id key)
    for artifact in resp.get("artifacts", []) + resp.get("output_artifacts", []):
        if aid := artifact.get("artifact_id"):
            return aid
    # observation_result.output_artifact_refs: EntityRef objects {entity_type, id}
    obs = resp.get("observation_result", {})
    refs = obs.get("output_artifact_refs", []) or obs.get("output_artifact_ids", [])
    if refs:
        item = refs[0]
        if isinstance(item, str):
            return item
        return item.get("artifact_id") or item.get("id")
    return None


# DDoS artifact subtype → wg_ddos_results key mapping
_DDOS_SUBTYPE_MAP: dict[str, str] = {
    "watchguard.ddos_temporal_analysis": "temporal",
    "watchguard.ddos_top_destinations": "destinations",
    "watchguard.ddos_top_sources": "sources",
    "watchguard.ddos_protocol_breakdown": "protocols",
    "watchguard.ddos_hourly_distribution": "hourly",
    "watchguard.ddos_segment_analysis": "segment",
    "watchguard.ddos_ip_profile": "ip_profile",
}


def _find_existing_staging(settings: dict[str, Any], workspace_id: str) -> dict[str, Any] | None:
    """Return the most recent staging manifest for this workspace across all cases, or None.

    Also extracts analytics content and DDoS results directly from artifact metadata,
    so restoration requires zero additional API calls.
    """
    try:
        client = make_client(settings)
        resp = client.list_cases(client_id=settings["client_id"])
        cases = resp.get("cases", [])
    except Exception:
        return None

    wg_title = f"WatchGuard — {workspace_id}"
    matching = [
        c for c in cases
        if c.get("case", {}).get("workflow_type") == WATCHGUARD_WORKFLOW_TYPE
        and c.get("case", {}).get("title") == wg_title
    ]
    if not matching:
        return None

    matching.sort(key=lambda c: c.get("case", {}).get("created_at", ""), reverse=True)

    for case_data in matching:
        artifacts = case_data.get("artifacts", [])
        staging_art = next(
            (a for a in artifacts if a.get("subtype") == "watchguard.workspace_staging_manifest"),
            None,
        )
        if not staging_art:
            continue
        run_id = (staging_art.get("produced_by_run_ref") or {}).get("id")
        if not run_id:
            continue

        analytics_art = next(
            (a for a in artifacts if a.get("subtype") == "watchguard.duckdb_workspace_analytics"),
            None,
        )

        # Collect DDoS results from artifact metadata (no extra API calls needed)
        ddos_results: dict[str, Any] = {}
        for subtype, key in _DDOS_SUBTYPE_MAP.items():
            art = next((a for a in artifacts if a.get("subtype") == subtype), None)
            if art and art.get("metadata"):
                ddos_results[key] = art["metadata"]

        return {
            "case_id": case_data.get("case", {}).get("case_id"),
            "run_id": run_id,
            "workspace_id": workspace_id,
            "staging_artifact_id": staging_art.get("artifact_id"),
            "analytics_content": analytics_art.get("metadata") if analytics_art else None,
            "ddos_results": ddos_results or None,
            "created_at": case_data.get("case", {}).get("created_at", ""),
        }
    return None


def _restore_investigation_state(
    settings: dict[str, Any],
    run_id: str,
    staging_artifact_id: str,
    analytics_content: dict[str, Any] | None,
    ddos_results: dict[str, Any] | None = None,
    case_id: str | None = None,
    workspace_id: str | None = None,
) -> None:
    """Restore session state from an existing run + staging artifact. Zero API calls."""
    st.session_state["wg_run_id"] = run_id
    st.session_state["wg_staging_artifact_id"] = staging_artifact_id
    st.session_state.setdefault("wg_chat_history", [])
    st.session_state.setdefault("wg_chat_raw_history", None)
    if analytics_content:
        st.session_state["wg_analytics_content"] = analytics_content
    if ddos_results:
        st.session_state["wg_ddos_results"] = ddos_results
    else:
        st.session_state.pop("wg_ddos_results", None)
    if case_id:
        st.session_state["wg_case_id"] = case_id
    if workspace_id:
        st.session_state["wg_workspace_id"] = workspace_id


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


# ── AbuseIPDB integration ─────────────────────────────────────────────────────


def _query_abuseipdb(ip: str, api_key: str) -> dict[str, Any]:
    """Query AbuseIPDB v2 /check endpoint. Result cached in session state."""
    cache_key = f"_abuseipdb_{ip}"
    if cache_key in st.session_state:
        return st.session_state[cache_key]
    try:
        import httpx as _httpx
        resp = _httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10.0,
        )
        data = resp.json().get("data", {})
    except Exception as exc:
        data = {"error": str(exc)}
    st.session_state[cache_key] = data
    return data


def _render_abuseipdb_data(data: dict[str, Any], ip: str) -> None:
    if data.get("error"):
        st.error(f"AbuseIPDB error: {data['error']}")
        return
    score = data.get("abuseConfidenceScore", 0)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Abuse Score", f"{score}%")
    col2.metric("Reportes totales", data.get("totalReports", 0))
    col3.metric("País", data.get("countryCode", "—"))
    col4.metric("ISP", (data.get("isp") or "—")[:25])
    info_parts = []
    if data.get("usageType"):
        info_parts.append(f"Uso: {data['usageType']}")
    if data.get("lastReportedAt"):
        info_parts.append(f"Último reporte: {data['lastReportedAt'][:10]}")
    if info_parts:
        st.caption("  |  ".join(info_parts))
    st.markdown(f"[Ver perfil completo en AbuseIPDB →](https://www.abuseipdb.com/check/{ip})")


# ── Report export helpers ─────────────────────────────────────────────────────


def _build_report_case_data(
    case_id: str,
    workspace_id: str,
    ddos_results: dict[str, Any],
    created_at: str | None = None,
    nist_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a case_data dict compatible with generate_report_from_context().

    If nist_snapshot is provided (the full NIST case state stored as a platform-api
    artifact), it is used as the primary source for decisions/findings/stage_progress.
    ddos_results still provides artifact_payloads so observation tables render.
    """
    source_map = {
        "temporal": "ddos_temporal_analysis",
        "sources": "ddos_top_sources",
        "destinations": "ddos_top_destinations",
        "protocols": "ddos_protocol_breakdown",
        "hourly": "ddos_hourly_distribution",
        "segment": "ddos_segment_analysis",
        "ip_profile": "ddos_ip_profile",
    }
    artifact_payloads: dict[str, Any] = {}
    for key, source in source_map.items():
        if data := ddos_results.get(key):
            artifact_payloads[f"report-{key}"] = data

    if nist_snapshot:
        # Full NIST state available — use it as the base, override artifact_payloads.
        # The snapshot already has evidence_items with real artifact_ids; add fake-id
        # payloads so the report's observation sections can render from ddos_results too.
        case_data = dict(nist_snapshot)
        # Merge artifact_payloads from ddos_results (fake IDs) alongside any real ones.
        existing_payloads = case_data.get("artifact_payloads", {})
        case_data["artifact_payloads"] = {**existing_payloads, **artifact_payloads}
        # Ensure top-level keys expected by the report generator.
        case_data.setdefault("case_id", case_id)
        case_data.setdefault("current_strategy_id", "ddos_nist_v1")
        if case_data.get("incident") and not case_data["incident"].get("created_at"):
            case_data["incident"]["created_at"] = created_at or ""
        return case_data

    # Fallback: observations-only (no AI decisions/findings).
    evidence_items = []
    for key, source in source_map.items():
        if ddos_results.get(key):
            evidence_items.append({"source": source, "artifact_refs": [f"report-{key}"]})

    return {
        "case_id": case_id,
        "incident": {
            "workspace": workspace_id,
            "observed_signals": [],
            "created_at": created_at or "",
        },
        "classification": {},
        "findings": [],
        "decisions": [],
        "stage_progress": [],
        "timeline": [],
        "severity": "—",
        "current_strategy_id": "ddos_nist_v1",
        "evidence_items": evidence_items,
        "artifact_payloads": artifact_payloads,
    }


# ── DDoS pipeline background launcher ────────────────────────────────────────


def _launch_ddos_pipeline_bg(
    settings: dict[str, Any],
    workspace_id: str,
    case_id: str,
    run_id: str,
    staging_artifact_id: str,
    status_key: str,
    result_key: str,
) -> None:
    """Run the full DDoS AI pipeline (Phase 2 + 3) in a background thread.

    Writes to st.session_state[status_key] ('running'|'done'|'error') and
    st.session_state[result_key] (result dict or error string).
    Designed to be launched via threading.Thread so Streamlit can continue rendering.
    """
    if not _CAI_AVAILABLE:
        st.session_state[status_key] = "error"
        st.session_state[result_key] = "CAI not available in this environment."
        return
    st.session_state[status_key] = "running"
    try:
        result = asyncio.run(
            _run_ddos_investigation_pipeline(
                workspace_id=workspace_id,
                platform_api_base_url=settings["platform_api_base_url"],
                existing_case_id=case_id,
                existing_run_id=run_id,
                existing_staging_artifact_id=staging_artifact_id,
            )
        )
        st.session_state[result_key] = result.model_dump() if hasattr(result, "model_dump") else str(result)
        st.session_state[status_key] = "done"
    except Exception as exc:
        st.session_state[result_key] = str(exc)
        st.session_state[status_key] = "error"


# ── Phishing dashboard data ───────────────────────────────────────────────────


def _load_phishing_dashboard_data(settings: dict[str, Any]) -> list[dict[str, Any]]:
    """Return all phishing cases with assessment metadata extracted."""
    client = make_client(settings)
    try:
        resp = client.list_cases(client_id=settings["client_id"])
    finally:
        client.close()
    cases = resp.get("cases", [])
    rows = []
    for c in cases:
        case = c.get("case", {})
        if case.get("workflow_type") != PHISHING_EMAIL_WORKFLOW_TYPE:
            continue
        artifacts = c.get("artifacts", [])
        # Assessment artifact: any ANALYSIS_OUTPUT whose metadata has risk_level
        meta: dict[str, Any] = {}
        for a in artifacts:
            m = a.get("metadata") or {}
            if isinstance(m, dict) and "risk_level" in m:
                meta = m
                break
        sender_raw = meta.get("sender") or {}
        sender_email = sender_raw.get("email", "—") if isinstance(sender_raw, dict) else str(sender_raw)
        rows.append({
            "case_id": case.get("case_id", ""),
            "title": case.get("title", "—"),
            "created_at": case.get("created_at", ""),
            "risk_level": meta.get("risk_level", "unknown"),
            "risk_score": meta.get("risk_score", 0),
            "triggered_rules": meta.get("triggered_rules", []),
            "sender": sender_email,
            "subject": meta.get("subject", "—"),
        })
    return sorted(rows, key=lambda r: r["created_at"], reverse=True)


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

        st.subheader("Integraciones (opcional)")
        abuseipdb_key = st.text_input(
            "AbuseIPDB API Key",
            type="password",
            value=os.getenv("ABUSEIPDB_API_KEY", ""),
            key="s_abuseipdb_key",
            help="Para enriquecimiento de reputación IP. Regístrate gratis en abuseipdb.com",
        )

    return {
        "api_url": api_url.strip() or _DEFAULT_API_URL,
        "client_id": client_id.strip() or "default",
        "model": model.strip() or None,
        "aws_key": aws_key.strip() or None,
        "aws_secret": aws_secret.strip() or None,
        "aws_region": aws_region.strip() or _DEFAULT_REGION,
        "s3_bucket": s3_bucket.strip() or _DEFAULT_BUCKET,
        "abuseipdb_key": abuseipdb_key.strip() or None,
    }


# ── Tab 1: WatchGuard S3 Investigation ───────────────────────────────────────


def _render_direct_upload_component(settings: dict[str, Any]) -> None:
    """Render a browser-side upload component that PUTs directly to S3 via presigned URL.

    The file never passes through the ECS container — bytes go browser → S3 directly.
    After upload, shows the workspace_id for the user to confirm via a Streamlit button.
    """
    api_url = settings["api_url"].rstrip("/")

    component_html = f"""
<style>
  #uploader {{ font-family: sans-serif; padding: 4px 0; }}
  #ws-input {{ width: 100%; padding: 6px 8px; border: 1px solid #ccc; border-radius: 4px;
               font-size: 14px; box-sizing: border-box; margin-bottom: 8px; }}
  #file-input {{ margin-bottom: 8px; font-size: 13px; }}
  #upload-btn {{ background: #e63946; color: white; border: none; padding: 8px 20px;
                 border-radius: 4px; cursor: pointer; font-size: 14px; }}
  #upload-btn:disabled {{ background: #ccc; cursor: not-allowed; }}
  #progress-wrap {{ margin-top: 10px; display: none; }}
  #progress-bar {{ width: 100%; height: 10px; border-radius: 5px; accent-color: #e63946; }}
  #status-msg {{ font-size: 13px; color: #555; margin-top: 4px; }}
  #result-box {{ display: none; margin-top: 10px; padding: 8px 12px; background: #f0fdf4;
                 border: 1px solid #86efac; border-radius: 4px; font-size: 13px; }}
  #result-ws {{ font-weight: bold; font-family: monospace; }}
</style>
<div id="uploader">
  <input id="ws-input" placeholder="Workspace ID (dejar vacío para auto-generar desde nombre del archivo)" />
  <input id="file-input" type="file" accept=".zip" />
  <br/>
  <button id="upload-btn" onclick="startUpload()" disabled>Subir a S3</button>
  <div id="progress-wrap">
    <progress id="progress-bar" value="0" max="100"></progress>
    <div id="status-msg">Preparando...</div>
  </div>
  <div id="result-box">
    ✓ Subido. Workspace ID: <span id="result-ws"></span><br/>
    <small>Ingresá ese ID en "Iniciar investigación" (sección 2) para continuar.</small>
  </div>
</div>
<script>
document.getElementById('file-input').addEventListener('change', function() {{
  document.getElementById('upload-btn').disabled = !this.files.length;
  document.getElementById('result-box').style.display = 'none';
}});

async function startUpload() {{
  const fileInput = document.getElementById('file-input');
  const file = fileInput.files[0];
  if (!file) return;

  const wsRaw = document.getElementById('ws-input').value.trim();
  const workspaceId = wsRaw || file.name.replace(/\\.zip$/i, '');

  document.getElementById('upload-btn').disabled = true;
  document.getElementById('progress-wrap').style.display = 'block';
  document.getElementById('result-box').style.display = 'none';
  document.getElementById('status-msg').textContent = 'Obteniendo URL firmada...';

  try {{
    // 1. Get presigned URL from platform-api
    const resp = await fetch(`{api_url}/s3/presigned-upload-url?workspace_id=${{encodeURIComponent(workspaceId)}}`, {{
      method: 'POST'
    }});
    if (!resp.ok) throw new Error(`API error ${{resp.status}}: ${{await resp.text()}}`);
    const data = await resp.json();

    // 2. PUT directly to S3
    document.getElementById('status-msg').textContent = 'Subiendo a S3...';
    await new Promise((resolve, reject) => {{
      const xhr = new XMLHttpRequest();
      xhr.upload.addEventListener('progress', (e) => {{
        if (e.lengthComputable) {{
          const pct = Math.round((e.loaded / e.total) * 100);
          const mbDone = (e.loaded / 1048576).toFixed(0);
          const mbTotal = (e.total / 1048576).toFixed(0);
          document.getElementById('progress-bar').value = pct;
          document.getElementById('status-msg').textContent = `S3: ${{mbDone}} / ${{mbTotal}} MB (${{pct}}%)`;
        }}
      }});
      xhr.addEventListener('load', () => {{
        if (xhr.status >= 200 && xhr.status < 300) resolve();
        else reject(new Error(`S3 PUT failed: ${{xhr.status}}`));
      }});
      xhr.addEventListener('error', () => reject(new Error('Network error')));
      xhr.open('PUT', data.presigned_url);
      xhr.setRequestHeader('Content-Type', 'application/zip');
      xhr.send(file);
    }});

    document.getElementById('progress-bar').value = 100;
    document.getElementById('status-msg').textContent = 'Completado.';
    document.getElementById('result-ws').textContent = workspaceId;
    document.getElementById('result-box').style.display = 'block';
    document.getElementById('upload-btn').disabled = false;

  }} catch(err) {{
    document.getElementById('status-msg').textContent = 'Error: ' + err.message;
    document.getElementById('status-msg').style.color = 'red';
    document.getElementById('upload-btn').disabled = false;
  }}
}}
</script>
"""
    import streamlit.components.v1 as components
    components.html(component_html, height=200)


def render_watchguard_tab(settings: dict[str, Any]) -> None:
    st.header("WatchGuard S3 Investigation")
    st.caption(
        "Sube los ZIPs a S3 cuando quieras y luego inicia la investigación cuando estés listo."
    )

    # ── Section 1: Upload ─────────────────────────────────────────────────────
    st.subheader("1. Subir ZIPs a S3")
    _render_direct_upload_component(settings)
    st.caption("Cuando termine el upload, el workspace ID aparece en el componente. Úsalo en la sección 2.")

    uploaded_workspaces: list[dict] = st.session_state.get("wg_uploaded_workspaces", [])

    st.divider()

    # ── Section 2: Investigate ────────────────────────────────────────────────
    st.subheader("2. Iniciar investigación")

    workspace_options = [w["workspace_id"] for w in uploaded_workspaces]
    s3_uri_ready: str | None = None

    if workspace_options:
        ws_source = st.radio(
            "Workspace a investigar",
            ["Seleccionar de subidos en esta sesión", "Ingresar manualmente"],
            horizontal=True,
            key="wg_ws_source",
        )
        if ws_source == "Seleccionar de subidos en esta sesión":
            selected_ws = st.selectbox("Workspace", workspace_options, key="wg_ws_select")
            workspace_id = selected_ws or ""
            s3_uri_ready = next(
                (w["s3_uri"] for w in uploaded_workspaces if w["workspace_id"] == selected_ws),
                None,
            )
        else:
            workspace_id = st.text_input(
                "Workspace ID",
                help="ID de un workspace previamente subido a S3.",
                key="wg_workspace_manual",
            )
    else:
        workspace_id = st.text_input(
            "Workspace ID",
            help="Sube un ZIP primero, o ingresa el ID de un workspace ya existente en S3.",
            key="wg_workspace_manual",
        )

    question = st.text_area(
        "¿Qué quieres investigar?",
        value="Top IPs con más denials, tipos de alarmas y rango de fechas del dataset.",
        key="wg_question",
    )

    # ── Prior investigation check ─────────────────────────────────────────────
    if workspace_id:
        # Auto-check once per workspace change; cache result in session_state
        if st.session_state.get("_wg_prior_checked_for") != workspace_id:
            with st.spinner("Verificando investigaciones previas..."):
                st.session_state["_wg_prior"] = _find_existing_staging(settings, workspace_id)
                st.session_state["_wg_prior_checked_for"] = workspace_id

        prior = st.session_state.get("_wg_prior")
        if prior:
            created_short = prior["created_at"][:10] if prior.get("created_at") else "—"
            st.info(
                f"Investigación previa encontrada — **{created_short}** | "
                f"Run: `{prior['run_id'][:20]}...`"
            )
            col_ret, col_new, _ = st.columns([1, 1, 2])
            if col_ret.button("↩ Retomar investigación", key="wg_retomar"):
                with st.spinner("Restaurando estado..."):
                    _restore_investigation_state(
                        settings,
                        prior["run_id"],
                        prior["staging_artifact_id"],
                        prior.get("analytics_content"),
                        prior.get("ddos_results"),
                        case_id=prior.get("case_id"),
                        workspace_id=prior.get("workspace_id", workspace_id),
                    )
                st.rerun()
            nueva_label = "⊕ Nueva investigación"
        else:
            nueva_label = "Investigar"
    else:
        nueva_label = "Investigar"

    if st.button(nueva_label, key="wg_run", disabled=not workspace_id):
        resolved_uri = s3_uri_ready
        if not resolved_uri:
            # Try to find the latest upload for this workspace in S3
            with st.spinner(f"Buscando último upload de '{workspace_id}' en S3..."):
                try:
                    s3 = make_boto3_s3(settings)
                    resolved_uri = find_latest_s3_uri_for_workspace(
                        s3, settings["s3_bucket"], workspace_id
                    )
                except Exception as exc:
                    st.error(f"Error consultando S3: {exc}")
                    resolved_uri = None
            if not resolved_uri:
                st.error(
                    f"No se encontró ningún upload para el workspace '{workspace_id}' en S3. "
                    "Sube el ZIP primero."
                )
        if resolved_uri:
            # Clear prior cache so after this run the new investigation is found
            st.session_state.pop("_wg_prior_checked_for", None)
            _run_watchguard_investigation(settings, resolved_uri, workspace_id, question)

    if st.session_state.get("wg_run_id"):
        _render_analytics_cached(settings)
        st.divider()
        _render_ddos_suite(settings)
        st.divider()
        _render_query_builder(settings)
        st.divider()
        _render_watchguard_chat(settings)


def _run_watchguard_investigation(
    settings: dict[str, Any],
    s3_uri: str,
    workspace_id: str,
    question: str,
) -> None:
    with st.status("Ejecutando pipeline WatchGuard S3...", expanded=True) as status:
        try:
            st.write(f"Workspace: `{workspace_id}`")
            st.write(f"S3 URI: `{s3_uri}`")

            # Step 1 — Create case
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

            # Step 2 — Attach S3 ZIP artifact reference
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

            # Step 3 — Create run
            status.update(label="Creando run...")
            run_resp = client.create_run(
                case_id=case_id,
                backend_id=WATCHGUARD_BACKEND_ID,
                input_artifact_ids=[artifact_id],
            )
            run_id = run_resp["run"]["run_id"]
            st.write(f"Run: `{run_id}`")

            # Step 4 — Stage workspace ZIP (extract TARs → individual CSVs → S3)
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

            # Step 5 — DuckDB workspace analytics
            status.update(label="Corriendo analytics con DuckDB...")
            analytics_resp = client.execute_watchguard_duckdb_workspace_analytics(
                run_id=run_id,
                requested_by="platform_ui",
                input_artifact_id=staging_artifact_id,
            )
            analytics_artifact_id = _extract_first_output_artifact_id(analytics_resp)
            if not analytics_artifact_id:
                raise ValueError(f"No se encontró analytics artifact en: {analytics_resp}")

            # Step 6 — Read analytics artifact content
            status.update(label="Leyendo resultados...")
            content_resp = client.read_artifact_content(artifact_id=analytics_artifact_id)
            content = content_resp.get("content", content_resp)

            # Persist in session state
            st.session_state["wg_run_id"] = run_id
            st.session_state["wg_staging_artifact_id"] = staging_artifact_id
            st.session_state["wg_analytics_content"] = content
            st.session_state["wg_case_id"] = case_id
            st.session_state["wg_workspace_id"] = workspace_id
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

    # Analytics payload nests data under family keys: traffic / alarm / event
    traffic = content.get("traffic") or content  # fallback for legacy flat format
    alarm = content.get("alarm") or {}

    deny_count = traffic.get("deny_count", 0)
    time_range = traffic.get("time_range") or {}
    t_min = time_range.get("min", "—")
    t_max = time_range.get("max", "—")
    total_rows = traffic.get("total_rows", 0)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total eventos", f"{total_rows:,}" if total_rows else "—")
    col2.metric("Deny Count", deny_count)
    col3.metric("Fecha inicio", str(t_min)[:10] if t_min and t_min != "—" else "—")
    col4.metric("Fecha fin", str(t_max)[:10] if t_max and t_max != "—" else "—")

    def _show_table(src: dict[str, Any], key: str, label: str) -> None:
        rows = src.get(key)
        if rows:
            with st.expander(label, expanded=True):
                st.dataframe(pd.DataFrame(rows) if isinstance(rows, list) else pd.DataFrame([rows]), use_container_width=True)

    _show_table(traffic, "top_src_ips", "Top Source IPs")
    _show_table(traffic, "top_dst_ips", "Top Destination IPs")
    _show_table(traffic, "protocol_breakdown", "Protocolos")
    _show_table(alarm, "alarm_type_counts", "Tipos de Alarma")


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


# ── DDoS Suite ───────────────────────────────────────────────────────────────


def _run_ddos_observations(
    settings: dict[str, Any], run_id: str, staging_artifact_id: str
) -> None:
    """Run all 7 DDoS observations sequentially and store results in session state."""
    client = make_client(settings)
    results: dict[str, Any] = {}

    def _obs_content(resp: dict[str, Any]) -> dict[str, Any]:
        art_id = _extract_first_output_artifact_id(resp)
        if not art_id:
            return {}
        raw = client.read_artifact_content(artifact_id=art_id)
        return raw.get("content", raw)

    with st.status("Ejecutando análisis DDoS...", expanded=True) as status:
        try:
            status.update(label="Análisis temporal (eventos por día)...")
            resp = client.execute_watchguard_ddos_temporal_analysis(
                run_id=run_id, requested_by="platform_ui", input_artifact_id=staging_artifact_id
            )
            results["temporal"] = _obs_content(resp)
            st.write(f"Temporal: {results['temporal'].get('total_events', 0)} eventos totales")

            status.update(label="Top destinos (IPs más atacadas)...")
            resp = client.execute_watchguard_ddos_top_destinations(
                run_id=run_id, requested_by="platform_ui", input_artifact_id=staging_artifact_id
            )
            results["destinations"] = _obs_content(resp)

            status.update(label="Top fuentes (IPs atacantes)...")
            resp = client.execute_watchguard_ddos_top_sources(
                run_id=run_id, requested_by="platform_ui", input_artifact_id=staging_artifact_id
            )
            results["sources"] = _obs_content(resp)

            status.update(label="Distribución de protocolos...")
            resp = client.execute_watchguard_ddos_protocol_breakdown(
                run_id=run_id, requested_by="platform_ui", input_artifact_id=staging_artifact_id
            )
            results["protocols"] = _obs_content(resp)

            peak_day = results["temporal"].get("peak_day")
            if peak_day:
                status.update(label=f"Distribución horaria del día pico ({peak_day})...")
                resp = client.execute_watchguard_ddos_hourly_distribution(
                    run_id=run_id, requested_by="platform_ui",
                    input_artifact_id=staging_artifact_id, date=peak_day,
                )
                results["hourly"] = _obs_content(resp)

            top_segment = None
            segments = results["sources"].get("segments", [])
            if segments:
                top_segment = segments[0].get("segment")
            if top_segment:
                status.update(label=f"Análisis de segmento dominante ({top_segment})...")
                resp = client.execute_watchguard_ddos_segment_analysis(
                    run_id=run_id, requested_by="platform_ui",
                    input_artifact_id=staging_artifact_id, segment=top_segment,
                )
                results["segment"] = _obs_content(resp)

            top_src_ip = None
            sources = results["sources"].get("sources", [])
            if sources:
                top_src_ip = sources[0].get("src_ip")
            if top_src_ip:
                status.update(label=f"Perfil del atacante principal ({top_src_ip})...")
                resp = client.execute_watchguard_ddos_ip_profile(
                    run_id=run_id, requested_by="platform_ui",
                    input_artifact_id=staging_artifact_id, ip=top_src_ip,
                )
                results["ip_profile"] = _obs_content(resp)

            st.session_state["wg_ddos_results"] = results
            status.update(label="Análisis DDoS completado.", state="complete")

        except Exception as exc:
            status.update(label=f"Error en análisis DDoS: {exc}", state="error")
            st.error(str(exc))


def _render_ddos_suite(settings: dict[str, Any]) -> None:
    st.subheader("Análisis DDoS")
    run_id = st.session_state.get("wg_run_id")
    staging_artifact_id = st.session_state.get("wg_staging_artifact_id")
    if not (run_id and staging_artifact_id):
        return

    ddos = st.session_state.get("wg_ddos_results")

    if not ddos:
        st.caption("Corre el análisis DDoS especializado sobre los logs del workspace.")

        # ── Lanzar pipeline CAI completo (Phase 2 + 3) ───────────────────────
        pipeline_status = st.session_state.get("wg_pipeline_status")
        if _CAI_AVAILABLE:
            if pipeline_status == "running":
                st.info("Pipeline CAI en ejecución — las 3 fases están corriendo en segundo plano. Actualizá la página para ver el resultado.")
            elif pipeline_status == "done":
                st.success("Pipeline CAI completado. Los resultados están en el tab **Case History**.")
                if st.button("Limpiar y ver análisis rápido", key="wg_pipeline_done_clear"):
                    st.session_state.pop("wg_pipeline_status", None)
                    st.session_state.pop("wg_pipeline_result", None)
                    st.rerun()
            elif pipeline_status == "error":
                st.error(f"Pipeline CAI falló: {st.session_state.get('wg_pipeline_result', 'Error desconocido')}")
                if st.button("Reintentar", key="wg_pipeline_retry"):
                    st.session_state.pop("wg_pipeline_status", None)
                    st.rerun()
            else:
                case_id = st.session_state.get("wg_case_id")
                ws_id = st.session_state.get("wg_workspace_id", "workspace")
                if case_id and st.button(
                    "Lanzar análisis CAI completo (Phase 1→2→3)",
                    key="wg_launch_full_pipeline",
                    type="primary",
                    help="Corre las 3 fases del pipeline: orquestador CAI → recolección → síntesis. Más lento pero produce decisión de contención y cierra el caso.",
                ):
                    t = threading.Thread(
                        target=_launch_ddos_pipeline_bg,
                        args=(settings, ws_id, case_id, run_id, staging_artifact_id,
                              "wg_pipeline_status", "wg_pipeline_result"),
                        daemon=True,
                    )
                    t.start()
                    st.rerun()
            st.divider()

        if st.button("Iniciar Análisis DDoS rápido", key="wg_ddos_run"):
            _run_ddos_observations(settings, run_id, staging_artifact_id)
            st.rerun()
        return

    # ── Temporal ──────────────────────────────────────────────────────────────
    temporal = ddos.get("temporal", {})
    by_day = temporal.get("by_day", [])
    if by_day:
        with st.expander("Eventos por día", expanded=True):
            col1, col2, col3 = st.columns(3)
            col1.metric("Total eventos", temporal.get("total_events", 0))
            col2.metric("Día pico", temporal.get("peak_day", "—"))
            col3.metric("Eventos en pico", temporal.get("peak_events", 0))
            df_temporal = pd.DataFrame(by_day).rename(columns={"date": "Fecha", "events": "Eventos"})
            if "Fecha" in df_temporal.columns:
                df_temporal = df_temporal.set_index("Fecha")
            st.line_chart(df_temporal[["Eventos"]])

    # ── Top Destinations ──────────────────────────────────────────────────────
    destinations = ddos.get("destinations", {}).get("destinations", [])
    if destinations:
        with st.expander("IPs más atacadas (destinos)", expanded=True):
            df_dst = pd.DataFrame(destinations).rename(
                columns={"dst_ip": "IP Destino", "count": "Eventos", "pct": "% del total", "rank": "Rank"}
            )
            st.dataframe(df_dst, use_container_width=True, hide_index=True)
            if "Eventos" in df_dst.columns and "IP Destino" in df_dst.columns:
                st.bar_chart(df_dst.set_index("IP Destino")[["Eventos"]].head(10))

    # ── Top Sources ───────────────────────────────────────────────────────────
    sources_data = ddos.get("sources", {})
    sources = sources_data.get("sources", [])
    segments = sources_data.get("segments", [])
    if sources:
        with st.expander("IPs atacantes (fuentes)", expanded=True):
            col_s, col_seg = st.columns(2)
            with col_s:
                st.caption("Top IPs fuente")
                df_src = pd.DataFrame(sources).rename(
                    columns={"src_ip": "IP Fuente", "count": "Eventos", "pct": "%", "rank": "Rank"}
                )
                st.dataframe(df_src, use_container_width=True, hide_index=True)
            with col_seg:
                if segments:
                    st.caption("Segmentos /16 dominantes")
                    df_seg = pd.DataFrame(segments).rename(
                        columns={"segment": "Segmento", "count": "Eventos", "pct": "%", "rank": "Rank"}
                    )
                    st.dataframe(df_seg, use_container_width=True, hide_index=True)

    # ── Protocol Breakdown ────────────────────────────────────────────────────
    protocols = ddos.get("protocols", {}).get("protocols", [])
    if protocols:
        with st.expander("Distribución de protocolos"):
            df_proto = pd.DataFrame(protocols).rename(
                columns={"protocol": "Protocolo", "count": "Eventos", "pct": "%", "rank": "Rank"}
            )
            st.dataframe(df_proto, use_container_width=True, hide_index=True)
            if "Eventos" in df_proto.columns and "Protocolo" in df_proto.columns:
                st.bar_chart(df_proto.set_index("Protocolo")[["Eventos"]])

    # ── Hourly Distribution ───────────────────────────────────────────────────
    hourly = ddos.get("hourly", {})
    by_hour = hourly.get("by_hour", [])
    if by_hour:
        with st.expander(f"Distribución horaria — {hourly.get('date', '')}"):
            col1, col2 = st.columns(2)
            col1.metric("Hora pico", hourly.get("peak_hour", "—"))
            col2.metric("Eventos en hora pico", hourly.get("peak_events", 0))
            df_hour = pd.DataFrame(by_hour).rename(columns={"hour": "Hora", "events": "Eventos"})
            if "Hora" in df_hour.columns:
                df_hour = df_hour.set_index("Hora")
            st.bar_chart(df_hour[["Eventos"]])

    # ── Segment Analysis ──────────────────────────────────────────────────────
    segment = ddos.get("segment", {})
    if segment:
        with st.expander(f"Análisis de segmento — {segment.get('segment', '')}"):
            c1, c2, c3 = st.columns(3)
            c1.metric("Total eventos", segment.get("total_events", 0))
            c2.metric("Allow", segment.get("allow_events", 0))
            c3.metric("Deny", segment.get("deny_events", 0))
            if segment.get("top_dst_ips"):
                st.caption("IPs destino más afectadas en el segmento")
                st.dataframe(pd.DataFrame(segment["top_dst_ips"]), use_container_width=True, hide_index=True)
            if segment.get("top_dst_ports"):
                st.caption("Puertos destino")
                st.dataframe(pd.DataFrame(segment["top_dst_ports"]), use_container_width=True, hide_index=True)

    # ── IP Profile ────────────────────────────────────────────────────────────
    ip_profile = ddos.get("ip_profile", {})
    if ip_profile:
        with st.expander(f"Perfil IP atacante — {ip_profile.get('ip', '')}"):
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total eventos", ip_profile.get("total_events", 0))
            c2.metric("Allow", ip_profile.get("allow_events", 0))
            c3.metric("Deny", ip_profile.get("deny_events", 0))
            c4.metric("Activo desde", ip_profile.get("first_seen", "—"))
            if ip_profile.get("top_dst_ips"):
                st.caption("IPs destino más atacadas por este IP")
                st.dataframe(pd.DataFrame(ip_profile["top_dst_ips"]), use_container_width=True, hide_index=True)

            # ── AbuseIPDB enrichment ───────────────────────────────────────
            ip_addr = ip_profile.get("ip", "")
            abuseipdb_key = settings.get("abuseipdb_key")
            if ip_addr and abuseipdb_key:
                cached = st.session_state.get(f"_abuseipdb_{ip_addr}")
                if cached is None:
                    if st.button("Enriquecer con AbuseIPDB", key="wg_abuseipdb_query"):
                        with st.spinner("Consultando AbuseIPDB..."):
                            _query_abuseipdb(ip_addr, abuseipdb_key)
                        st.rerun()
                else:
                    st.markdown("---")
                    _render_abuseipdb_data(cached, ip_addr)
            elif ip_addr:
                st.caption(
                    "Configura la AbuseIPDB API Key en el sidebar para ver reputación de este IP."
                )

    # ── Export Report ─────────────────────────────────────────────────────────
    if _REPORT_AVAILABLE:
        with st.expander("Exportar Informe"):
            col_cn, col_inf, col_crm = st.columns(3)
            client_name = col_cn.text_input("Cliente", value="", key="rpt_client_name")
            informante = col_inf.text_input("Informante", value="", key="rpt_informante")
            crm_case = col_crm.text_input("Caso CRM / Ticket", value="", key="rpt_crm_case")
            fmt = st.radio("Formato", ["HTML", "PDF"], horizontal=True, key="rpt_fmt")

            if st.button("Generar informe", key="rpt_generate"):
                if not ddos:
                    st.warning("No hay resultados DDoS para exportar. Corre el análisis primero.")
                else:
                    try:
                        with st.spinner("Generando informe..."):
                            case_data_for_report = _build_report_case_data(
                                case_id=st.session_state.get("wg_case_id", "unknown"),
                                workspace_id=st.session_state.get("wg_workspace_id", "workspace"),
                                ddos_results=ddos,
                            )
                            report_bytes = _generate_report_from_context(
                                case_data_for_report,
                                client_name=client_name or "—",
                                informante=informante or "—",
                                crm_case=crm_case or "—",
                                fmt=fmt.lower(),
                            )
                        ext = fmt.lower()
                        st.session_state["rpt_bytes"] = (report_bytes, ext, fmt)
                    except Exception as exc:
                        st.error(f"Error generando informe: {exc}")

            rpt_result = st.session_state.get("rpt_bytes")
            if rpt_result:
                report_bytes, ext, fmt_label = rpt_result
                ws_id = st.session_state.get("wg_workspace_id", "workspace")
                mime = "text/html" if ext == "html" else "application/pdf"
                st.download_button(
                    f"Descargar {fmt_label}",
                    data=report_bytes,
                    file_name=f"informe-ddos-{ws_id[:30]}.{ext}",
                    mime=mime,
                    key="rpt_download",
                )

    if st.button("Re-ejecutar análisis DDoS", key="wg_ddos_rerun"):
        del st.session_state["wg_ddos_results"]
        st.rerun()


# ── Query Builder ─────────────────────────────────────────────────────────────


def _render_query_builder(settings: dict[str, Any]) -> None:
    st.subheader("Consultas personalizadas")
    run_id = st.session_state.get("wg_run_id")
    staging_artifact_id = st.session_state.get("wg_staging_artifact_id")
    if not (run_id and staging_artifact_id):
        return

    mode = st.radio(
        "Tipo de consulta",
        ["Filtro simple", "SQL avanzado (DuckDB)"],
        horizontal=True,
        key="qb_mode",
    )

    if mode == "Filtro simple":
        _render_simple_filter(settings, run_id, staging_artifact_id)
    else:
        _render_duckdb_query(settings, run_id, staging_artifact_id)

    query_result = st.session_state.get("wg_query_result")
    if query_result:
        st.caption(f"Resultados de la consulta ({query_result.get('row_count', 0)} filas)")
        rows = query_result.get("rows", [])
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info("La consulta no devolvió resultados.")


def _render_simple_filter(
    settings: dict[str, Any], run_id: str, staging_artifact_id: str
) -> None:
    FIELDS = ["src_ip", "dst_ip", "action", "protocol", "policy"]
    OPS = ["eq", "in"]
    ACTION_VALS = ["allow", "deny", "drop", "reject"]

    col1, col2, col3 = st.columns([2, 1, 3])
    with col1:
        field = st.selectbox("Campo", FIELDS, key="qb_field")
    with col2:
        op = st.selectbox("Operador", OPS, key="qb_op")
    with col3:
        if field == "action":
            if op == "in":
                value_raw = st.multiselect("Valores", ACTION_VALS, default=["deny"], key="qb_value_multi")
                value = value_raw
            else:
                value = st.selectbox("Valor", ACTION_VALS, key="qb_value_action")
        else:
            raw = st.text_input(
                "Valor (para 'in', separa con comas)" if op == "in" else "Valor",
                key="qb_value_text",
            )
            value = [v.strip() for v in raw.split(",")] if op == "in" and raw else raw

    limit = st.slider("Límite de resultados", min_value=1, max_value=50, value=20, key="qb_limit")
    reason = st.text_input("Razón de la consulta", value="Investigación vía platform-ui", key="qb_reason")

    if st.button("Ejecutar filtro", key="qb_run_filter"):
        if not value:
            st.warning("Ingresa un valor para el filtro.")
            return
        client = make_client(settings)
        query = {"filters": [{"field": field, "op": op, "value": value}], "limit": limit}
        try:
            with st.spinner("Ejecutando consulta..."):
                resp = client.execute_watchguard_guarded_custom_query(
                    run_id=run_id,
                    input_artifact_id=staging_artifact_id,
                    query=query,
                    reason=reason,
                    approval={
                        "status": "approved",
                        "reason": "Aprobado por el analista vía platform-ui",
                        "approver_kind": "platform_ui_analyst",
                        "approver_ref": None,
                    },
                    requested_by="platform_ui",
                )
            summary = resp.get("query_summary", {})
            rows = summary.get("rows", []) or []
            st.session_state["wg_query_result"] = {
                "rows": rows,
                "row_count": summary.get("row_count", len(rows)),
            }
            st.rerun()
        except Exception as exc:
            st.error(f"Error en la consulta: {exc}")


def _render_duckdb_query(
    settings: dict[str, Any], run_id: str, staging_artifact_id: str
) -> None:
    FAMILIES = ["traffic", "alarm", "event"]
    family = st.selectbox("Familia de logs", FAMILIES, key="qb_family")

    st.caption(
        "Filtros opcionales — campo + operador + valor. "
        "Campos disponibles en **traffic**: src_ip, dst_ip, action, protocol, policy, src_port, dst_port. "
        "En **alarm**: alarm_type, src_ip. En **event**: type."
    )

    n_filters = st.number_input("Número de filtros", min_value=0, max_value=5, value=0, step=1, key="qb_n_filters")
    filters: list[dict[str, Any]] = []
    for i in range(int(n_filters)):
        c1, c2, c3 = st.columns([2, 1, 3])
        f_field = c1.text_input("Campo", key=f"qb_df_field_{i}")
        f_op = c2.selectbox("Op", ["eq", "in", "gt", "lt", "gte", "lte"], key=f"qb_df_op_{i}")
        f_val_raw = c3.text_input("Valor (comas para 'in')", key=f"qb_df_val_{i}")
        if f_field and f_val_raw:
            f_val = [v.strip() for v in f_val_raw.split(",")] if f_op == "in" else f_val_raw
            filters.append({"field": f_field, "op": f_op, "value": f_val})

    limit = st.slider("Límite de resultados", min_value=1, max_value=500, value=50, key="qb_sql_limit")
    reason = st.text_input("Razón", value="Consulta DuckDB vía platform-ui", key="qb_sql_reason")

    if st.button("Ejecutar consulta DuckDB", key="qb_run_sql"):
        client = make_client(settings)
        try:
            with st.spinner("Ejecutando consulta DuckDB en S3..."):
                resp = client.execute_watchguard_duckdb_workspace_query(
                    run_id=run_id,
                    input_artifact_id=staging_artifact_id,
                    family=family,
                    filters=filters,
                    limit=limit,
                    reason=reason,
                    requested_by="platform_ui",
                )
            summary = resp.get("query_summary", {})
            rows = summary.get("rows", []) or []
            st.session_state["wg_query_result"] = {
                "rows": rows,
                "row_count": summary.get("row_count", len(rows)),
            }
            st.rerun()
        except Exception as exc:
            st.error(f"Error en la consulta DuckDB: {exc}")


# ── Tab: Workspace Browser ────────────────────────────────────────────────────


def _list_s3_workspaces(s3_client: Any, bucket: str) -> list[dict[str, Any]]:
    """List all workspaces in S3 with upload and staging status."""
    resp = s3_client.list_objects_v2(Bucket=bucket, Prefix="workspaces/", Delimiter="/")
    workspaces = []
    for prefix_entry in resp.get("CommonPrefixes", []):
        ws_prefix = prefix_entry["Prefix"]  # e.g. "workspaces/logs-ejemplo-ddos/"
        ws_id = ws_prefix.rstrip("/").split("/")[-1]

        # Find latest upload
        uploads_resp = s3_client.list_objects_v2(
            Bucket=bucket, Prefix=f"{ws_prefix}input/uploads/", Delimiter="/"
        )
        upload_ids = [
            p["Prefix"].rstrip("/").split("/")[-1]
            for p in uploads_resp.get("CommonPrefixes", [])
        ]
        upload_ids.sort()
        last_upload_id = upload_ids[-1] if upload_ids else None
        last_upload_s3_uri = (
            f"s3://{bucket}/{ws_prefix}input/uploads/{last_upload_id}/raw.zip"
            if last_upload_id
            else None
        )

        # Check staging
        staging_resp = s3_client.list_objects_v2(
            Bucket=bucket, Prefix=f"{ws_prefix}staging/", Delimiter="/"
        )
        has_staging = len(staging_resp.get("CommonPrefixes", [])) > 0

        workspaces.append({
            "workspace_id": ws_id,
            "upload_count": len(upload_ids),
            "last_upload_id": last_upload_id,
            "last_upload_s3_uri": last_upload_s3_uri,
            "has_staging": has_staging,
        })
    return workspaces


def render_workspace_browser_tab(settings: dict[str, Any]) -> None:
    st.header("Workspace Browser")
    st.caption(
        f"Workspaces disponibles en S3 — bucket: `{settings['s3_bucket']}`"
    )

    col_btn, col_info = st.columns([1, 4])
    if col_btn.button("Actualizar lista", key="wb_refresh"):
        st.session_state.pop("wb_workspaces", None)

    if "wb_workspaces" not in st.session_state:
        with st.spinner("Consultando S3..."):
            try:
                s3 = make_boto3_s3(settings)
                st.session_state["wb_workspaces"] = _list_s3_workspaces(s3, settings["s3_bucket"])
            except Exception as exc:
                st.error(f"Error consultando S3: {exc}")
                return

    workspaces: list[dict] = st.session_state.get("wb_workspaces", [])
    if not workspaces:
        st.info("No se encontraron workspaces en S3.")
        return

    table_rows = [
        {
            "Workspace ID": w["workspace_id"],
            "Uploads": w["upload_count"],
            "Último upload": w["last_upload_id"] or "—",
            "Staging": "✓" if w["has_staging"] else "—",
            "S3 URI (último)": w["last_upload_s3_uri"] or "—",
        }
        for w in workspaces
    ]
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Seleccionar workspace para investigar")

    ws_options = [w["workspace_id"] for w in workspaces if w["last_upload_s3_uri"]]
    if not ws_options:
        st.warning("Ningún workspace tiene uploads disponibles.")
        return

    selected = st.selectbox("Workspace", ws_options, key="wb_selected")
    selected_ws = next((w for w in workspaces if w["workspace_id"] == selected), None)

    if selected_ws:
        st.write(f"Último upload: `{selected_ws['last_upload_s3_uri']}`")
        st.write(f"Staging completado: {'Sí' if selected_ws['has_staging'] else 'No'}")

    if st.button("Agregar a sesión e investigar", key="wb_investigate", disabled=not selected_ws):
        ws = selected_ws
        if "wg_uploaded_workspaces" not in st.session_state:
            st.session_state["wg_uploaded_workspaces"] = []

        entry = {
            "workspace_id": ws["workspace_id"],
            "s3_uri": ws["last_upload_s3_uri"],
            "filename": f"{ws['workspace_id']}.zip",
            "size_mb": 0.0,
            "uploaded_at": ws["last_upload_id"] or "—",
        }
        existing = [
            w for w in st.session_state["wg_uploaded_workspaces"]
            if w["workspace_id"] == ws["workspace_id"]
        ]
        if existing:
            existing[0].update(entry)
        else:
            st.session_state["wg_uploaded_workspaces"].append(entry)
        # Store message and rerun so WatchGuard tab (rendered before this tab)
        # picks up the updated wg_uploaded_workspaces on the next pass.
        st.session_state["wb_pending_success"] = (
            f"Workspace `{ws['workspace_id']}` agregado. "
            "Ve al tab **WatchGuard S3 Investigation** → Sección 2 para iniciar la investigación."
        )
        st.rerun()

    if msg := st.session_state.pop("wb_pending_success", None):
        st.success(msg)


# ── Tab: Case History ─────────────────────────────────────────────────────────


def render_case_history_tab(settings: dict[str, Any]) -> None:
    st.header("Historial de Casos")
    st.caption(f"Casos del cliente `{settings['client_id']}`")

    col_btn, _ = st.columns([1, 4])
    if col_btn.button("Actualizar", key="ch_refresh"):
        st.session_state.pop("ch_cases", None)

    if "ch_cases" not in st.session_state:
        with st.spinner("Cargando casos..."):
            try:
                client = make_client(settings)
                resp = client.list_cases(client_id=settings["client_id"])
                st.session_state["ch_cases"] = resp.get("cases", [])
            except Exception as exc:
                st.error(f"Error cargando historial: {exc}")
                return

    cases: list[dict] = st.session_state.get("ch_cases", [])
    if not cases:
        st.info("No hay casos para este cliente.")
        return

    # Sort: newest first (case_id is a UUID, use created_at if available)
    cases_sorted = sorted(
        cases,
        key=lambda c: c.get("case", {}).get("created_at", ""),
        reverse=True,
    )

    table_rows = []
    for c in cases_sorted:
        case = c.get("case", {})
        artifacts = c.get("artifacts", [])
        table_rows.append({
            "Case ID": case.get("case_id", "")[:8] + "...",
            "Título": case.get("title", "—"),
            "Workflow": case.get("workflow_type", "—"),
            "Estado": case.get("status", "—"),
            "Artefactos": len(artifacts),
            "Creado": case.get("created_at", "—"),
            "_case_id": case.get("case_id", ""),
        })

    df = pd.DataFrame(table_rows)
    st.dataframe(
        df.drop(columns=["_case_id"]),
        use_container_width=True,
        hide_index=True,
    )

    st.divider()
    st.subheader("Detalle del caso")

    case_ids = [row["_case_id"] for row in table_rows]
    case_labels = [f"{row['Título']} [{row['_case_id'][:8]}]" for row in table_rows]
    selected_label = st.selectbox("Seleccionar caso", case_labels, key="ch_selected_case")

    if selected_label:
        idx = case_labels.index(selected_label)
        selected_case_id = case_ids[idx]
        selected = next(
            (c for c in cases_sorted if c.get("case", {}).get("case_id") == selected_case_id),
            None,
        )

        if selected:
            case = selected.get("case", {})
            artifacts = selected.get("artifacts", [])

            col1, col2, col3 = st.columns(3)
            col1.metric("Workflow", case.get("workflow_type", "—"))
            col2.metric("Estado", case.get("status", "—"))
            col3.metric("Artefactos", len(artifacts))

            st.markdown(f"**Resumen:** {case.get('summary', '—')}")
            st.caption(f"Case ID: `{case.get('case_id')}`  |  Creado: {case.get('created_at', '—')}")

            # ── Continuar investigación ───────────────────────────────────────
            if case.get("workflow_type") == WATCHGUARD_WORKFLOW_TYPE:
                staging_art = next(
                    (a for a in artifacts if a.get("subtype") == "watchguard.workspace_staging_manifest"),
                    None,
                )
                if staging_art:
                    run_id = (staging_art.get("produced_by_run_ref") or {}).get("id")
                    staging_artifact_id = staging_art.get("artifact_id")
                    analytics_art = next(
                        (a for a in artifacts if a.get("subtype") == "watchguard.duckdb_workspace_analytics"),
                        None,
                    )
                    analytics_content = analytics_art.get("metadata") if analytics_art else None
                    ddos_results: dict[str, Any] = {}
                    for subtype, key in _DDOS_SUBTYPE_MAP.items():
                        art = next((a for a in artifacts if a.get("subtype") == subtype), None)
                        if art and art.get("metadata"):
                            ddos_results[key] = art["metadata"]
                    if run_id and staging_artifact_id:
                        if st.button(
                            "↩ Continuar investigación en WatchGuard",
                            key=f"ch_continue_{selected_case_id}",
                            type="primary",
                        ):
                            title_str = case.get("title", "")
                            ws_from_title = (
                                title_str.removeprefix("WatchGuard — ")
                                if title_str.startswith("WatchGuard — ")
                                else "unknown"
                            )
                            with st.spinner("Restaurando estado de investigación..."):
                                _restore_investigation_state(
                                    settings, run_id, staging_artifact_id,
                                    analytics_content, ddos_results or None,
                                    case_id=case.get("case_id"),
                                    workspace_id=ws_from_title,
                                )
                            st.session_state["ch_pending_navigate"] = (
                                f"Investigación restaurada — ve al tab **WatchGuard S3 Investigation**."
                            )
                            st.rerun()

                    # ── Exportar Informe ──────────────────────────────────────
                    if _REPORT_AVAILABLE and ddos_results:
                        with st.expander("Exportar Informe DDoS"):
                            col_cn, col_inf, col_crm = st.columns(3)
                            client_name = col_cn.text_input(
                                "Cliente", value="", key=f"ch_rpt_client_{selected_case_id}"
                            )
                            informante = col_inf.text_input(
                                "Informante", value="", key=f"ch_rpt_informante_{selected_case_id}"
                            )
                            crm_case = col_crm.text_input(
                                "Caso CRM / Ticket", value="", key=f"ch_rpt_crm_{selected_case_id}"
                            )
                            fmt = st.radio(
                                "Formato", ["HTML", "PDF"], horizontal=True,
                                key=f"ch_rpt_fmt_{selected_case_id}",
                            )
                            if st.button(
                                "Generar informe", key=f"ch_rpt_generate_{selected_case_id}"
                            ):
                                try:
                                    with st.spinner("Generando informe..."):
                                        title_str = case.get("title", "")
                                        ws_from_title = (
                                            title_str.removeprefix("WatchGuard — ")
                                            if title_str.startswith("WatchGuard — ")
                                            else selected_case_id[:8]
                                        )
                                        # Try to load full NIST state snapshot (richer report).
                                        nist_snapshot = None
                                        snapshot_art = next(
                                            (a for a in artifacts
                                             if a.get("metadata", {}).get("subtype")
                                             == "watchguard.nist_case_snapshot"),
                                            None,
                                        )
                                        if snapshot_art:
                                            try:
                                                _snap_client = make_client(settings)
                                                _raw = _snap_client.read_artifact_content(
                                                    artifact_id=snapshot_art["artifact_id"]
                                                )
                                                _snap_client.close()
                                                nist_snapshot = _raw.get("content", _raw)
                                            except Exception:
                                                pass  # fall back to observations-only
                                        case_data_for_report = _build_report_case_data(
                                            case_id=selected_case_id,
                                            workspace_id=ws_from_title,
                                            ddos_results=ddos_results,
                                            created_at=case.get("created_at"),
                                            nist_snapshot=nist_snapshot,
                                        )
                                        report_bytes = _generate_report_from_context(
                                            case_data_for_report,
                                            client_name=client_name or "—",
                                            informante=informante or "—",
                                            crm_case=crm_case or "—",
                                            fmt=fmt.lower(),
                                        )
                                    st.session_state[f"ch_rpt_{selected_case_id}"] = (
                                        report_bytes, fmt.lower(), fmt, ws_from_title
                                    )
                                except Exception as exc:
                                    st.error(f"Error generando informe: {exc}")

                            rpt = st.session_state.get(f"ch_rpt_{selected_case_id}")
                            if rpt:
                                report_bytes, ext, fmt_label, ws_id = rpt
                                mime = "text/html" if ext == "html" else "application/pdf"
                                st.download_button(
                                    f"Descargar {fmt_label}",
                                    data=report_bytes,
                                    file_name=f"informe-ddos-{ws_id[:30]}.{ext}",
                                    mime=mime,
                                    key=f"ch_rpt_download_{selected_case_id}",
                                )

            if msg := st.session_state.pop("ch_pending_navigate", None):
                st.success(msg)

            if artifacts:
                with st.expander("Artefactos del caso"):
                    for art in artifacts:
                        art_id = art.get("artifact_id", "?")
                        art_kind = art.get("kind", "?")
                        art_summary = art.get("summary", "")
                        st.markdown(f"- **{art_kind}** `{art_id[:12]}...` — {art_summary}")

                        if st.button(f"Ver contenido", key=f"ch_art_{art_id}"):
                            try:
                                client = make_client(settings)
                                content_resp = client.read_artifact_content(artifact_id=art_id)
                                content = content_resp.get("content", content_resp)
                                with st.expander(f"Contenido de {art_id[:12]}...", expanded=True):
                                    st.json(content)
                            except Exception as exc:
                                st.error(f"Error leyendo artefacto: {exc}")


# ── Phishing Dashboard ────────────────────────────────────────────────────────


def _render_phishing_dashboard(settings: dict[str, Any]) -> None:
    st.subheader("Dashboard de Casos Phishing")

    col_btn, _ = st.columns([1, 4])
    if col_btn.button("Actualizar dashboard", key="ph_dash_refresh"):
        st.session_state.pop("ph_dash_data", None)

    if "ph_dash_data" not in st.session_state:
        with st.spinner("Cargando casos..."):
            try:
                st.session_state["ph_dash_data"] = _load_phishing_dashboard_data(settings)
            except Exception as exc:
                st.error(f"Error cargando dashboard: {exc}")
                return

    rows: list[dict] = st.session_state.get("ph_dash_data", [])
    if not rows:
        st.info("No hay casos phishing analizados aún.")
        st.divider()
        return

    total = len(rows)
    risk_counts: dict[str, int] = {}
    rule_counter: dict[str, int] = {}
    for r in rows:
        level = (r["risk_level"] or "unknown").lower()
        risk_counts[level] = risk_counts.get(level, 0) + 1
        for rule in r.get("triggered_rules", []):
            rule_id = rule.get("rule_id") or rule.get("id") or "?"
            rule_counter[rule_id] = rule_counter.get(rule_id, 0) + 1

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total analizados", total)
    col2.metric("Alto riesgo", risk_counts.get("high", 0))
    col3.metric("Riesgo medio", risk_counts.get("medium", 0))
    col4.metric("Bajo riesgo", risk_counts.get("low", 0))

    col_a, col_b = st.columns(2)
    with col_a:
        risk_df_data = [
            {"Nivel": k.capitalize(), "Casos": v}
            for k, v in sorted(risk_counts.items(), key=lambda x: x[1], reverse=True)
            if v > 0
        ]
        if risk_df_data:
            st.caption("Distribución de riesgo")
            st.bar_chart(pd.DataFrame(risk_df_data).set_index("Nivel"))

    with col_b:
        if rule_counter:
            top_rules = sorted(rule_counter.items(), key=lambda x: x[1], reverse=True)[:10]
            df_rules = pd.DataFrame(top_rules, columns=["Regla", "Activaciones"])
            st.caption("Reglas más frecuentes")
            st.dataframe(df_rules.set_index("Regla"), use_container_width=True)

    with st.expander("Lista de casos", expanded=False):
        df_cases = pd.DataFrame([
            {
                "Fecha": r["created_at"][:10] if r.get("created_at") else "—",
                "Asunto": (r.get("subject") or "—")[:60],
                "Remitente": r.get("sender", "—"),
                "Riesgo": (r["risk_level"] or "unknown").upper(),
                "Score": r["risk_score"],
                "Reglas": len(r.get("triggered_rules", [])),
            }
            for r in rows
        ])
        st.dataframe(df_cases, use_container_width=True, hide_index=True)

    st.divider()


# ── Tab 2: Phishing Investigation ────────────────────────────────────────────


def render_phishing_tab(settings: dict[str, Any]) -> None:
    st.header("Phishing Email Investigation")
    st.caption(
        "Sube un archivo .eml o pega el payload JSON del email sospechoso. "
        "El pipeline corre el basic assessment y, opcionalmente, el pipeline "
        "multi-agente de CAI para producir un veredicto completo."
    )

    _render_phishing_dashboard(settings)

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


# ── Tab: CAI Terminal ─────────────────────────────────────────────────────────


def render_cai_terminal_tab(settings: dict[str, Any]) -> None:
    st.header("Asistente CAI")
    st.caption(
        "Chat libre con el agente de análisis. Puede consultar casos, "
        "correr queries sobre workspaces activos, y responder preguntas de ciberseguridad."
    )

    if not _CAI_AVAILABLE:
        st.info(
            "Instala `cai-platform-ui[cai]` (ejecuta `make install-ui-cai`) "
            "para habilitar el asistente."
        )
        return

    # Optionally inject active WatchGuard investigation context
    wg_run_id = st.session_state.get("wg_run_id")
    wg_staging = st.session_state.get("wg_staging_artifact_id")

    use_wg_context = False
    if wg_run_id and wg_staging:
        wg_workspace = st.session_state.get("wg_workspace_id", wg_run_id[:16])
        use_wg_context = st.checkbox(
            f"Usar contexto de investigación activa (workspace: `{wg_workspace}`)",
            value=True,
            key="term_use_wg_context",
        )

    col_clear, _ = st.columns([1, 4])
    if col_clear.button("Limpiar conversación", key="term_clear"):
        st.session_state.pop("term_chat_history", None)
        st.session_state.pop("term_chat_raw_history", None)
        st.rerun()

    for msg in st.session_state.get("term_chat_history", []):
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    user_input = st.chat_input("Pregunta al asistente CAI...", key="term_chat_input")
    if user_input:
        _handle_terminal_chat_turn(
            settings,
            user_input,
            wg_run_id=wg_run_id if use_wg_context else None,
            wg_staging_artifact_id=wg_staging if use_wg_context else None,
        )


def _handle_terminal_chat_turn(
    settings: dict[str, Any],
    user_input: str,
    wg_run_id: str | None = None,
    wg_staging_artifact_id: str | None = None,
) -> None:
    if "term_chat_history" not in st.session_state:
        st.session_state["term_chat_history"] = []

    raw_history = st.session_state.get("term_chat_raw_history")

    st.session_state["term_chat_history"].append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.write(user_input)

    if raw_history is None:
        if wg_run_id and wg_staging_artifact_id:
            cai_input = (
                f"You are helping investigate a WatchGuard log workspace. "
                f"The run_id is {wg_run_id!r} and the staging manifest artifact_id is "
                f"{wg_staging_artifact_id!r}. Always pass input_artifact_id={wg_staging_artifact_id!r} "
                f"to duckdb analytics and query tools. User question: {user_input}"
            )
        else:
            cai_input = user_input
    else:
        cai_input = raw_history + [{"role": "user", "content": user_input}]

    agent = build_egs_analist_agent(
        platform_api_base_url=settings["api_url"],
        model=settings["model"],
    )

    with st.chat_message("assistant"):
        with st.spinner("El asistente está pensando..."):
            try:
                result = run_cai_agent(agent, cai_input)
            except Exception as exc:
                st.error(f"Error del agente CAI: {exc}")
                return

        response_text = _format_cai_output(result.final_output)
        st.write(response_text)

    st.session_state["term_chat_history"].append(
        {"role": "assistant", "content": response_text}
    )
    st.session_state["term_chat_raw_history"] = result.to_input_list()


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    st.set_page_config(
        page_title="CAI Platform UI",
        page_icon=":shield:",
        layout="wide",
    )
    st.title("CAI Platform")

    settings = render_sidebar()

    tab_wg, tab_ws, tab_ph, tab_imap, tab_hist, tab_term = st.tabs([
        "WatchGuard S3 Investigation",
        "Workspace Browser",
        "Phishing Investigation",
        "Monitor de Email",
        "Historial de Casos",
        "Asistente CAI",
    ])

    with tab_wg:
        render_watchguard_tab(settings)

    with tab_ws:
        render_workspace_browser_tab(settings)

    with tab_ph:
        render_phishing_tab(settings)

    with tab_imap:
        render_imap_tab(settings)

    with tab_hist:
        render_case_history_tab(settings)

    with tab_term:
        render_cai_terminal_tab(settings)


if __name__ == "__main__":
    main()
