from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
