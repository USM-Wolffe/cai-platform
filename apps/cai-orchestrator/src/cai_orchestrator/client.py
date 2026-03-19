"""Thin client for the first platform-api slice."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import httpx

from cai_orchestrator.errors import PlatformApiRequestError, PlatformApiUnavailableError


@runtime_checkable
class ResponseLike(Protocol):
    """Small response protocol used by the thin platform-api client."""

    status_code: int

    def json(self) -> Any:
        """Return the parsed JSON payload."""


@runtime_checkable
class SyncHttpSession(Protocol):
    """Small sync HTTP session protocol used by the thin platform-api client."""

    def get(self, url: str) -> ResponseLike:
        """Perform a GET request."""

    def post(self, url: str, *, json: dict[str, Any] | None = None) -> ResponseLike:
        """Perform a POST request."""

    def close(self) -> None:
        """Release any client resources."""


class PlatformApiClient:
    """Very small client for the deterministic platform-api boundary."""

    def __init__(
        self,
        *,
        base_url: str,
        session: SyncHttpSession | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not base_url.strip():
            raise ValueError("base_url must not be empty")
        self._base_url = base_url.rstrip("/")
        self._owns_session = session is None
        self._session: SyncHttpSession = session or httpx.Client(base_url=self._base_url, timeout=timeout)

    def close(self) -> None:
        """Close the owned HTTP session when one was created locally."""
        if self._owns_session:
            self._session.close()

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def create_case(
        self,
        *,
        client_id: str,
        workflow_type: str,
        title: str,
        summary: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/cases",
            json={
                "client_id": client_id,
                "workflow_type": workflow_type,
                "title": title,
                "summary": summary,
                "metadata": metadata or {},
            },
        )

    def attach_input_artifact(
        self,
        *,
        case_id: str,
        payload: dict[str, Any],
        format: str = "json",
        summary: str | None = None,
        labels: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/cases/{case_id}/artifacts/input",
            json={
                "format": format,
                "payload": payload,
                "summary": summary,
                "labels": labels or [],
                "metadata": metadata or {},
            },
        )

    def create_run(
        self,
        *,
        case_id: str,
        backend_id: str,
        input_artifact_ids: list[str] | None = None,
        scope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/runs",
            json={
                "case_id": case_id,
                "backend_id": backend_id,
                "input_artifact_ids": input_artifact_ids or [],
                "scope": scope or {},
            },
        )

    def execute_watchguard_workspace_zip_ingestion(
        self,
        *,
        run_id: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"requested_by": requested_by}
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/observations/watchguard-ingest-workspace-zip",
            json=payload,
        )

    def execute_watchguard_normalize(
        self,
        *,
        run_id: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"requested_by": requested_by}
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/observations/watchguard-normalize",
            json=payload,
        )

    def execute_watchguard_filter_denied(
        self,
        *,
        run_id: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"requested_by": requested_by}
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/observations/watchguard-filter-denied",
            json=payload,
        )

    def execute_watchguard_analytics_basic(
        self,
        *,
        run_id: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"requested_by": requested_by}
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/observations/watchguard-analytics-basic",
            json=payload,
        )

    def execute_watchguard_top_talkers_basic(
        self,
        *,
        run_id: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"requested_by": requested_by}
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/observations/watchguard-top-talkers-basic",
            json=payload,
        )

    def execute_watchguard_stage_workspace_zip(
        self,
        *,
        run_id: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"requested_by": requested_by}
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/observations/watchguard-stage-workspace-zip",
            json=payload,
        )

    def execute_watchguard_duckdb_workspace_analytics(
        self,
        *,
        run_id: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"requested_by": requested_by}
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/observations/watchguard-duckdb-workspace-analytics",
            json=payload,
        )

    def execute_watchguard_duckdb_workspace_query(
        self,
        *,
        run_id: str,
        family: str,
        filters: list[dict[str, Any]],
        limit: int,
        reason: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "requested_by": requested_by,
            "family": family,
            "filters": filters,
            "limit": limit,
            "reason": reason,
        }
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/queries/watchguard-duckdb-workspace-query",
            json=payload,
        )

    def execute_phishing_email_basic_assessment(
        self,
        *,
        run_id: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"requested_by": requested_by}
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/observations/phishing-email-basic-assessment",
            json=payload,
        )

    def execute_phishing_email_header_analysis(
        self,
        *,
        run_id: str,
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"requested_by": requested_by}
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/observations/phishing-email-header-analysis",
            json=payload,
        )

    def execute_watchguard_guarded_custom_query(
        self,
        *,
        run_id: str,
        query: dict[str, Any],
        reason: str,
        approval: dict[str, Any],
        requested_by: str,
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "requested_by": requested_by,
            "query": query,
            "reason": reason,
            "approval": approval,
        }
        if input_artifact_id is not None:
            payload["input_artifact_id"] = input_artifact_id
        return self._request(
            "POST",
            f"/runs/{run_id}/queries/watchguard-guarded-filtered-rows",
            json=payload,
        )

    def get_case(self, *, case_id: str) -> dict[str, Any]:
        return self._request("GET", f"/cases/{case_id}")

    def get_run(self, *, run_id: str) -> dict[str, Any]:
        return self._request("GET", f"/runs/{run_id}")

    def get_run_status(self, *, run_id: str) -> dict[str, Any]:
        return self._request("GET", f"/runs/{run_id}/status")

    def list_run_artifacts(self, *, run_id: str) -> dict[str, Any]:
        return self._request("GET", f"/runs/{run_id}/artifacts")

    def read_artifact_content(self, *, artifact_id: str) -> dict[str, Any]:
        return self._request("GET", f"/artifacts/{artifact_id}/content")

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            if method == "GET":
                response = self._session.get(path)
            elif method == "POST":
                response = self._session.post(path, json=json)
            else:
                raise ValueError(f"unsupported method '{method}'")
        except httpx.HTTPError as exc:
            raise PlatformApiUnavailableError(f"platform-api request failed for {method} {path}") from exc

        payload = response.json()
        if response.status_code >= 400:
            raise PlatformApiRequestError(
                method=method,
                path=path,
                status_code=response.status_code,
                payload=payload,
            )
        return payload
