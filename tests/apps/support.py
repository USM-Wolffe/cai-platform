from __future__ import annotations

from dataclasses import dataclass
import gzip
import io
import tarfile
from typing import Any
import zipfile

from fastapi.testclient import TestClient

from platform_api import create_app


def build_watchguard_traffic_csv_row(
    *,
    timestamp: str,
    action: str,
    policy: str,
    protocol: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    record_type: str = "traffic",
    question: str = "",
) -> str:
    columns = [""] * 24
    columns[0] = timestamp
    columns[5] = action
    columns[6] = policy
    columns[8] = protocol
    columns[11] = src_ip
    columns[12] = str(src_port)
    columns[13] = dst_ip
    columns[14] = str(dst_port)
    columns[22] = record_type
    columns[23] = question
    return ",".join(columns)


def build_watchguard_traffic_csv_payload(rows: list[str]) -> dict[str, Any]:
    return {
        "log_type": "traffic",
        "csv_rows": rows,
    }


def build_phishing_email_attachment(
    *,
    filename: str,
    content_type: str | None = None,
) -> dict[str, Any]:
    attachment = {"filename": filename}
    if content_type is not None:
        attachment["content_type"] = content_type
    return attachment


def build_phishing_email_payload(
    *,
    subject: str,
    sender_email: str,
    sender_display_name: str | None = None,
    reply_to_email: str | None = None,
    reply_to_display_name: str | None = None,
    urls: list[str] | None = None,
    text: str,
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    sender: dict[str, Any] = {"email": sender_email}
    if sender_display_name is not None:
        sender["display_name"] = sender_display_name

    reply_to: dict[str, Any] | None = None
    if reply_to_email is not None:
        reply_to = {"email": reply_to_email}
        if reply_to_display_name is not None:
            reply_to["display_name"] = reply_to_display_name

    return {
        "subject": subject,
        "sender": sender,
        "reply_to": reply_to,
        "urls": urls or [],
        "text": text,
        "attachments": attachments or [],
    }


def build_workspace_s3_zip_payload(
    *,
    workspace: str,
    s3_uri: str,
    upload_prefix: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": "workspace_s3_zip",
        "workspace": workspace,
        "s3_uri": s3_uri,
    }
    if upload_prefix is not None:
        payload["upload_prefix"] = upload_prefix
    return payload


def build_watchguard_workspace_zip_bytes(
    *,
    traffic_rows: list[str] | None = None,
    event_rows: list[str] | None = None,
    alarm_rows: list[str] | None = None,
) -> bytes:
    traffic_rows = traffic_rows or []
    event_rows = event_rows or []
    alarm_rows = alarm_rows or []

    event_tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=event_tar_bytes, mode="w") as archive:
        event_payload = "\n".join(event_rows).encode("utf-8")
        event_info = tarfile.TarInfo(name="event.csv")
        event_info.size = len(event_payload)
        archive.addfile(event_info, io.BytesIO(event_payload))

    alarm_payload = "\n".join(alarm_rows).encode("utf-8")
    alarm_gz_bytes = gzip.compress(alarm_payload)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w") as archive:
        archive.writestr(
            "watchguard/traffic/2025-10-22/traffic.csv",
            "\n".join(traffic_rows),
        )
        archive.writestr(
            "watchguard/event/2025-10-23/event.tar",
            event_tar_bytes.getvalue(),
        )
        archive.writestr(
            "watchguard/alarm/2025-10-22/alarm.txt.gz",
            alarm_gz_bytes,
        )
    return zip_buffer.getvalue()


def create_test_client() -> TestClient:
    return TestClient(create_app())


@dataclass
class FakeResponse:
    status_code: int
    payload: Any

    def json(self) -> Any:
        return self.payload


class QueuedSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, str, Any]] = []

    def get(self, url: str) -> FakeResponse:
        self.calls.append(("GET", url, None))
        return self._next_response()

    def post(self, url: str, *, json: dict[str, Any] | None = None) -> FakeResponse:
        self.calls.append(("POST", url, json))
        return self._next_response()

    def close(self) -> None:
        return None

    def _next_response(self) -> FakeResponse:
        if not self._responses:
            raise AssertionError("queued session ran out of fake responses")
        return self._responses.pop(0)
