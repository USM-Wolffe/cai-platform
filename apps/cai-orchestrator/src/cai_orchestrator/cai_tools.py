"""Thin CAI-facing tool wrappers over platform-api."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import boto3

from cai_orchestrator.client import PlatformApiClient

_S3_BUCKET = os.environ.get("WATCHGUARD_S3_BUCKET", "egslatam-cai-dev")
_S3_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-2")


@dataclass
class PlatformApiToolService:
    """Very small CAI-facing service that delegates every action to platform-api."""

    platform_api_client: PlatformApiClient

    def health(self) -> dict[str, Any]:
        return self.platform_api_client.health()

    def create_case(
        self,
        *,
        client_id: str,
        workflow_type: str,
        title: str,
        summary: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.create_case(
            client_id=client_id,
            workflow_type=workflow_type,
            title=title,
            summary=summary,
            metadata=metadata,
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

    def attach_workspace_s3_zip_reference(
        self,
        *,
        case_id: str,
        workspace: str,
        s3_uri: str,
        upload_prefix: str | None = None,
        summary: str | None = None,
        labels: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "source": "workspace_s3_zip",
            "workspace": workspace,
            "s3_uri": s3_uri,
        }
        if upload_prefix is not None:
            payload["upload_prefix"] = upload_prefix
        return self.platform_api_client.attach_input_artifact(
            case_id=case_id,
            payload=payload,
            format="json",
            summary=summary,
            labels=labels,
            metadata=metadata,
        )

    def execute_watchguard_workspace_zip_ingestion(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_workspace_zip_ingestion(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
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

    def find_latest_workspace_upload(
        self,
        *,
        workspace_id: str,
        bucket: str = _S3_BUCKET,
        region: str = _S3_REGION,
    ) -> dict[str, Any]:
        """Return the S3 URI of the most recent raw.zip for the given workspace."""
        s3 = boto3.client("s3", region_name=region)
        prefix = f"workspaces/{workspace_id}/input/uploads/"
        paginator = s3.get_paginator("list_objects_v2")
        upload_ids: list[str] = []
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter="/"):
            for cp in page.get("CommonPrefixes", []):
                p = cp["Prefix"].rstrip("/")
                upload_ids.append(p.split("/")[-1])
        if not upload_ids:
            return {"found": False, "workspace_id": workspace_id}
        latest = sorted(upload_ids)[-1]
        s3_uri = f"s3://{bucket}/workspaces/{workspace_id}/input/uploads/{latest}/raw.zip"
        return {"found": True, "workspace_id": workspace_id, "upload_id": latest, "s3_uri": s3_uri}

    def execute_watchguard_stage_workspace_zip(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_stage_workspace_zip(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_duckdb_workspace_analytics(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_duckdb_workspace_analytics(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_ddos_temporal_analysis(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_ddos_temporal_analysis(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_ddos_top_destinations(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_ddos_top_destinations(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_ddos_top_sources(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_ddos_top_sources(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_ddos_segment_analysis(
        self,
        *,
        run_id: str,
        segment: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_ddos_segment_analysis(
            run_id=run_id,
            segment=segment,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_ddos_ip_profile(
        self,
        *,
        run_id: str,
        ip: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_ddos_ip_profile(
            run_id=run_id,
            ip=ip,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_ddos_hourly_distribution(
        self,
        *,
        run_id: str,
        date: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_ddos_hourly_distribution(
            run_id=run_id,
            date=date,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_ddos_protocol_breakdown(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_ddos_protocol_breakdown(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=input_artifact_id,
        )

    def execute_watchguard_duckdb_workspace_query(
        self,
        *,
        run_id: str,
        family: str,
        filters: list[dict[str, Any]],
        limit: int = 50,
        reason: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_watchguard_duckdb_workspace_query(
            run_id=run_id,
            family=family,
            filters=filters,
            limit=limit,
            reason=reason,
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

    def execute_phishing_email_header_analysis(
        self,
        *,
        run_id: str,
        requested_by: str = "cai_terminal",
        input_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        return self.platform_api_client.execute_phishing_email_header_analysis(
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
