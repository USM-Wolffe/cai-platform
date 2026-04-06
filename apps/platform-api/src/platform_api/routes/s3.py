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
