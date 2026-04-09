"""S3 presigned URL generation for direct browser uploads."""

from __future__ import annotations

import os
import time

import boto3
from botocore.config import Config
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/s3", tags=["s3"])

_BUCKET = os.getenv("WATCHGUARD_S3_BUCKET", "egslatam-cai-dev")
_REGION = os.getenv("WATCHGUARD_S3_REGION", "us-east-2")
_EXPIRES = 3600  # 1 hour


def _s3_client():
    return boto3.client(
        "s3",
        region_name=_REGION,
        config=Config(signature_version="s3v4"),
    )


@router.get("/workspaces")
def list_workspaces() -> dict[str, object]:
    """List all workspace IDs that have been uploaded to S3."""
    client = _s3_client()
    paginator = client.get_paginator("list_objects_v2")
    workspace_ids: list[str] = []
    for page in paginator.paginate(Bucket=_BUCKET, Prefix="workspaces/", Delimiter="/"):
        for cp in page.get("CommonPrefixes", []):
            # cp["Prefix"] is like "workspaces/my-ws/"
            part = cp["Prefix"].rstrip("/").split("/")[-1]
            if part:
                workspace_ids.append(part)
    return {"workspaces": workspace_ids}


@router.get("/workspaces/{workspace_id}/latest-staging")
def get_latest_staging(workspace_id: str) -> dict[str, object]:
    """Return the most recent staging prefix for a workspace.

    The staging path is: workspaces/{workspace_id}/staging/{upload_id}/
    Returns the last one lexicographically (latest upload_id).
    """
    client = _s3_client()
    paginator = client.get_paginator("list_objects_v2")
    prefix = f"workspaces/{workspace_id}/staging/"
    upload_ids: list[str] = []
    for page in paginator.paginate(Bucket=_BUCKET, Prefix=prefix, Delimiter="/"):
        for cp in page.get("CommonPrefixes", []):
            part = cp["Prefix"].rstrip("/").split("/")[-1]
            if part:
                upload_ids.append(part)
    if not upload_ids:
        raise HTTPException(
            status_code=404,
            detail=f"No staging found for workspace '{workspace_id}'. Upload a ZIP first.",
        )
    latest = sorted(upload_ids)[-1]
    staging_prefix = f"workspaces/{workspace_id}/staging/{latest}"
    return {
        "workspace_id": workspace_id,
        "staging_prefix": staging_prefix,
        "upload_id": latest,
        "bucket": _BUCKET,
        "region": _REGION,
    }


@router.get("/workspaces/{workspace_id}/latest-upload")
def get_latest_upload(workspace_id: str) -> dict[str, object]:
    """Return the most recently uploaded raw ZIP for a workspace.

    The upload path is: workspaces/{workspace_id}/input/uploads/{upload_id}/raw.zip
    """
    client = _s3_client()
    paginator = client.get_paginator("list_objects_v2")
    prefix = f"workspaces/{workspace_id}/input/uploads/"
    upload_ids: list[str] = []
    for page in paginator.paginate(Bucket=_BUCKET, Prefix=prefix, Delimiter="/"):
        for cp in page.get("CommonPrefixes", []):
            part = cp["Prefix"].rstrip("/").split("/")[-1]
            if part:
                upload_ids.append(part)
    if not upload_ids:
        raise HTTPException(
            status_code=404,
            detail=f"No uploaded ZIP found for workspace '{workspace_id}'.",
        )
    latest = sorted(upload_ids)[-1]
    key = f"workspaces/{workspace_id}/input/uploads/{latest}/raw.zip"
    return {
        "workspace_id": workspace_id,
        "upload_id": latest,
        "s3_uri": f"s3://{_BUCKET}/{key}",
        "bucket": _BUCKET,
        "region": _REGION,
    }


@router.post("/presigned-upload-url")
def presigned_upload_url(
    workspace_id: str = Query(..., description="Workspace ID to upload into"),
) -> dict[str, object]:
    """Generate a presigned PUT URL so the browser can upload a ZIP directly to S3.

    The key is: workspaces/{workspace_id}/input/uploads/{upload_id}/raw.zip
    The caller should HTTP PUT the file body to the returned URL (no extra headers needed).
    """
    upload_id = time.strftime("%Y%m%d_%H%M%S")
    key = f"workspaces/{workspace_id}/input/uploads/{upload_id}/raw.zip"
    try:
        url = _s3_client().generate_presigned_url(
            "put_object",
            Params={"Bucket": _BUCKET, "Key": key, "ContentType": "application/zip"},
            ExpiresIn=_EXPIRES,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not generate presigned URL: {exc}") from exc

    return {
        "presigned_url": url,
        "workspace_id": workspace_id,
        "upload_id": upload_id,
        "s3_uri": f"s3://{_BUCKET}/{key}",
        "expires_in": _EXPIRES,
    }
