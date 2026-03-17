import pytest

from platform_adapters.watchguard import (
    InvalidWatchGuardInputError,
    WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
    WATCHGUARD_SEMANTIC_RECORDS_INPUT_SHAPE,
    WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE,
    WATCHGUARD_TRAFFIC_LOG_TYPE,
    filter_denied_watchguard_batch,
    inspect_watchguard_input_artifact,
    is_denied_watchguard_action,
    normalize_watchguard_log_payload,
    parse_workspace_s3_zip_reference,
)
from platform_contracts import Artifact, ArtifactKind


def _make_watchguard_traffic_csv_row(
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


def _make_watchguard_traffic_csv_payload(rows: list[str]) -> dict[str, object]:
    return {
        "log_type": "traffic",
        "csv_rows": rows,
    }


def test_watchguard_adapter_transforms_realistic_traffic_csv_export_wrapper():
    artifact = Artifact(
        artifact_id="artifact_watchguard_input",
        kind=ArtifactKind.INPUT,
        format="json",
        storage_ref="memory://watchguard/input.json",
        content_hash="sha256:watchguard",
    )
    payload = _make_watchguard_traffic_csv_payload(
        [
            _make_watchguard_traffic_csv_row(
                timestamp="15/03/2026 00:00",
                action="ALLOW",
                policy="allow-web",
                protocol="TCP",
                src_ip="10.0.0.1",
                src_port=51514,
                dst_ip="8.8.8.8",
                dst_port=53,
                question="dns-allow",
            ),
            _make_watchguard_traffic_csv_row(
                timestamp="15/03/2026 00:01",
                action="DENY",
                policy="deny-dns",
                protocol="udp",
                src_ip="10.0.0.2",
                src_port=51515,
                dst_ip="1.1.1.1",
                dst_port=53,
                question="dns-blocked",
            ),
        ]
    )

    inspect_watchguard_input_artifact(artifact)
    normalized = normalize_watchguard_log_payload(payload)

    assert normalized.record_count == 2
    assert normalized.action_counts == {"allow": 1, "deny": 1}
    assert normalized.input_shape == WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE
    assert normalized.log_type == WATCHGUARD_TRAFFIC_LOG_TYPE
    assert normalized.records[0].timestamp == "2026-03-15T00:00:00Z"
    assert normalized.records[0].protocol == "tcp"
    assert normalized.records[0].policy == "allow-web"
    assert normalized.records[0].src_port == 51514
    assert normalized.records[0].dst_port == 53
    assert normalized.records[1].protocol == "udp"
    assert normalized.records[1].question == "dns-blocked"


def test_watchguard_adapter_preserves_semantic_records_payload_as_compatibility_path():
    normalized = normalize_watchguard_log_payload(
        {
            "records": [
                {
                    "timestamp": "2026-03-15T00:00:00Z",
                    "action": "ALLOW",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "8.8.8.8",
                    "protocol": "TCP",
                },
                {
                    "timestamp": "2026-03-15T00:01:00Z",
                    "action": "DENY",
                    "src_ip": "10.0.0.2",
                    "dst_ip": "1.1.1.1",
                },
            ]
        }
    )

    assert normalized.record_count == 2
    assert normalized.action_counts == {"allow": 1, "deny": 1}
    assert normalized.input_shape == WATCHGUARD_SEMANTIC_RECORDS_INPUT_SHAPE
    assert normalized.log_type == WATCHGUARD_TRAFFIC_LOG_TYPE
    assert normalized.records[0].protocol == "tcp"
    assert normalized.records[1].protocol == "unknown"


def test_watchguard_adapter_rejects_invalid_realistic_csv_input_shape():
    with pytest.raises(InvalidWatchGuardInputError):
        normalize_watchguard_log_payload(
            {
                "log_type": "traffic",
                "csv_rows": [
                    "15/03/2026 00:00,,,,,ALLOW,allow-web,,TCP,,,10.0.0.1,not-a-port,8.8.8.8,53"
                ],
            }
        )


def test_watchguard_adapter_filters_denied_and_blocked_actions_deterministically():
    normalized = normalize_watchguard_log_payload(
        {
            "records": [
                {
                    "timestamp": "2026-03-15T00:00:00Z",
                    "action": "DENY",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "8.8.8.8",
                },
                {
                    "timestamp": "2026-03-15T00:01:00Z",
                    "action": "blocked",
                    "src_ip": "10.0.0.2",
                    "dst_ip": "1.1.1.1",
                },
                {
                    "timestamp": "2026-03-15T00:02:00Z",
                    "action": "ALLOW",
                    "src_ip": "10.0.0.3",
                    "dst_ip": "9.9.9.9",
                },
            ]
        }
    )

    denied = filter_denied_watchguard_batch(normalized)

    assert denied.record_count == 2
    assert denied.action_counts == {"deny": 1, "blocked": 1}
    assert [record.action for record in denied.records] == ["deny", "blocked"]
    assert denied.input_shape == WATCHGUARD_SEMANTIC_RECORDS_INPUT_SHAPE
    assert denied.log_type == WATCHGUARD_TRAFFIC_LOG_TYPE
    assert is_denied_watchguard_action("DENY") is True
    assert is_denied_watchguard_action("blocked") is True
    assert is_denied_watchguard_action("allow") is False


def test_parse_workspace_s3_zip_reference_validates_and_derives_metadata():
    reference = parse_workspace_s3_zip_reference(
        {
            "source": WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
            "workspace": "acme-lab",
            "s3_uri": "s3://egslatam-cai-dev/workspaces/acme-lab/input/uploads/20260316_abc/logs.zip",
        }
    )

    assert reference.workspace == "acme-lab"
    assert reference.bucket == "egslatam-cai-dev"
    assert reference.object_key == "workspaces/acme-lab/input/uploads/20260316_abc/logs.zip"
    assert reference.upload_prefix == "workspaces/acme-lab/input/uploads/20260316_abc"


def test_parse_workspace_s3_zip_reference_rejects_wrong_workspace_prefix():
    with pytest.raises(InvalidWatchGuardInputError):
        parse_workspace_s3_zip_reference(
            {
                "source": WATCHGUARD_WORKSPACE_S3_ZIP_SOURCE_KIND,
                "workspace": "workspace-a",
                "s3_uri": "s3://egslatam-cai-dev/workspaces/workspace-b/input/uploads/20260316_abc/logs.zip",
            }
        )
