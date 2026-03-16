"""Thin CAI-facing tool wrappers over platform-api."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from cai_orchestrator.client import PlatformApiClient


@dataclass
class PlatformApiToolService:
    """Very small CAI-facing service that delegates every action to platform-api."""

    platform_api_client: PlatformApiClient

    def health(self) -> dict[str, Any]:
        return self.platform_api_client.health()

    def create_case(self, *, workflow_type: str, title: str, summary: str) -> dict[str, Any]:
        return self.platform_api_client.create_case(
            workflow_type=workflow_type,
            title=title,
            summary=summary,
        )

    def attach_input_artifact(
        self,
        *,
        case_id: str,
        payload_path: str,
        format: str = "json",
        summary: str | None = None,
        labels: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = load_payload_file(payload_path)
        return self.platform_api_client.attach_input_artifact(
            case_id=case_id,
            payload=payload,
            format=format,
            summary=summary,
            labels=labels,
            metadata=metadata,
        )

    def create_run(
        self,
        *,
        case_id: str,
        backend_id: str,
        input_artifact_ids: list[str] | None = None,
        scope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.create_run(
            case_id=case_id,
            backend_id=backend_id,
            input_artifact_ids=input_artifact_ids,
            scope=scope,
        )

    def execute_watchguard_normalize(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_normalize(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_filter_denied(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_filter_denied(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_analytics_basic(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_analytics_basic(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_top_talkers_basic(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_top_talkers_basic(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_phishing_email_basic_assessment(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_phishing_email_basic_assessment(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_guarded_custom_query(
        self,
        *,
        run_id: str,
        query: dict[str, Any],
        reason: str,
        approval_reason: str,
        approver_kind: str = "human_operator",
        approver_ref: str | None = None,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_guarded_custom_query(
            run_id=run_id,
            query=query,
            reason=reason,
            approval={
                "status": "approved",
                "reason": approval_reason,
                "approver_kind": approver_kind,
                "approver_ref": approver_ref,
            },
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def get_case(self, *, case_id: str) -> dict[str, Any]:
        return self.platform_api_client.get_case(case_id=case_id)

    def get_run(self, *, run_id: str) -> dict[str, Any]:
        return self.platform_api_client.get_run(run_id=run_id)

    def get_run_status(self, *, run_id: str) -> dict[str, Any]:
        return self.platform_api_client.get_run_status(run_id=run_id)

    def list_run_artifacts(self, *, run_id: str) -> dict[str, Any]:
        return self.platform_api_client.list_run_artifacts(run_id=run_id)

    def read_artifact_content(self, *, artifact_id: str) -> dict[str, Any]:
        return self.platform_api_client.read_artifact_content(artifact_id=artifact_id)


def load_payload_file(path: str) -> dict[str, Any]:
    """Load a JSON payload file for terminal-driven attach_input_artifact calls."""
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("payload JSON must be an object")
    return payload
