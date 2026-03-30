import json

import pytest

from platform_adapters.watchguard import WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE, WATCHGUARD_TRAFFIC_LOG_TYPE
from platform_contracts import (
    ArtifactKind,
    BackendCapabilityName,
    EntityKind,
    EntityRef,
    ObservationRequest,
    ObservationStatus,
    QueryMode,
    QueryRequest,
    WorkflowType,
)
from platform_core import UnsupportedBackendError, create_case, create_run_for_case, ensure_backend_supports_query_mode

from platform_backends.watchguard_logs import (
    WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
    WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION,
    WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
    WATCHGUARD_LOGS_BACKEND_ID,
    WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
    WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
    WATCHGUARD_WORKSPACE_ZIP_INGESTION_OPERATION,
    InvalidWatchGuardQueryError,
    execute_guarded_custom_query,
    execute_predefined_observation,
    get_watchguard_logs_backend_descriptor,
)

from .support import InMemoryCaseRepository, InMemoryRunRepository, RecordingAuditPort, make_input_artifact
from tests.apps.support import build_watchguard_workspace_zip_bytes, build_workspace_s3_zip_payload


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


class StaticBackendRegistry:
    def __init__(self) -> None:
        self._descriptor = get_watchguard_logs_backend_descriptor()

    def get_backend(self, backend_id: str):
        if backend_id == self._descriptor.backend_id:
            return self._descriptor.model_copy(deep=True)
        return None


def test_backend_descriptor_declares_capabilities_deterministically():
    descriptor = get_watchguard_logs_backend_descriptor()

    assert descriptor.backend_id == WATCHGUARD_LOGS_BACKEND_ID
    assert [capability.name for capability in descriptor.capabilities] == [
        BackendCapabilityName.CREATE_RUN,
        BackendCapabilityName.EXECUTE_PREDEFINED_QUERY,
        BackendCapabilityName.EXECUTE_CUSTOM_QUERY,
        BackendCapabilityName.GET_RUN_STATUS,
        BackendCapabilityName.LIST_RUN_ARTIFACTS,
        BackendCapabilityName.READ_ARTIFACT_CONTENT,
    ]
    assert descriptor.supported_workflow_types == [WorkflowType.LOG_INVESTIGATION]
    assert descriptor.supported_query_classes == [
        "watchguard_logs.workspace_zip_ingestion",
        "watchguard_logs.normalize_summary",
        "watchguard_logs.filter_denied_events",
        "watchguard_logs.analytics_bundle_basic",
        "watchguard_logs.top_talkers_basic",
        "watchguard_logs.guarded_filtered_rows",
        "watchguard_logs.stage_workspace_zip",
        "watchguard_logs.duckdb_workspace_analytics",
        "watchguard_logs.duckdb_workspace_query",
        "watchguard_logs.ddos_temporal_analysis",
        "watchguard_logs.ddos_top_destinations",
        "watchguard_logs.ddos_top_sources",
        "watchguard_logs.ddos_segment_analysis",
        "watchguard_logs.ddos_ip_profile",
        "watchguard_logs.ddos_hourly_distribution",
        "watchguard_logs.ddos_protocol_breakdown",
    ]
    assert [kind.value for kind in descriptor.produced_artifact_kinds] == [
        "normalized",
        "analysis_output",
        "query_result",
    ]


def test_backend_accepts_supported_query_modes():
    descriptor = get_watchguard_logs_backend_descriptor()

    ensure_backend_supports_query_mode(descriptor, QueryMode.PREDEFINED)
    ensure_backend_supports_query_mode(descriptor, QueryMode.CUSTOM_GUARDED)


def test_backend_rejects_unsupported_workflow_clearly_through_core_run_creation():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.SANDBOX_INVESTIGATION,
        title="Unsupported workflow case",
        summary="Case to confirm workflow rejection.",
    )

    with pytest.raises(UnsupportedBackendError):
        create_run_for_case(
            case_repository,
            run_repository,
            backend_registry,
            audit_port,
            case_id=case.case_id,
            backend_id=WATCHGUARD_LOGS_BACKEND_ID,
        )


def test_predefined_observation_produces_normalized_artifact_and_valid_result():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard backend case",
        summary="Case for backend slice.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload={
            "records": [
                {
                    "timestamp": "2026-03-15T00:00:00Z",
                    "action": "ALLOW",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "8.8.8.8",
                    "protocol": "TCP",
                }
            ]
        },
        observation_request=observation_request,
    )

    assert len(outcome.artifacts) == 1
    assert outcome.artifacts[0].kind.value == "normalized"
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED
    assert outcome.observation_result.output_artifact_refs[0].id == outcome.artifacts[0].artifact_id
    assert outcome.observation_result.structured_summary["record_count"] == 1


def test_workspace_zip_ingestion_produces_manifest_and_family_artifacts(monkeypatch):
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Workspace ZIP ingestion case",
        summary="Case for S3 ZIP ingestion.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_WORKSPACE_ZIP_INGESTION_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    monkeypatch.setattr(
        "platform_backends.watchguard_logs.execute._download_s3_object",
        lambda bucket, object_key: build_watchguard_workspace_zip_bytes(
            traffic_rows=[
                _make_watchguard_traffic_csv_row(
                    timestamp="2025-10-22T09:02:37",
                    action="Allow",
                    policy="DNS - OUT-00",
                    protocol="dns/udp",
                    src_ip="172.26.25.64",
                    src_port=55738,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                ),
                _make_watchguard_traffic_csv_row(
                    timestamp="2025-10-22T09:02:38",
                    action="Deny",
                    policy="Unhandled Internal Packet-00",
                    protocol="28080/tcp",
                    src_ip="172.26.25.65",
                    src_port=41864,
                    dst_ip="47.85.92.246",
                    dst_port=28080,
                ),
            ],
            event_rows=[
                "2025-10-23T09:26:52,FWStatus,ev,FW_PL1_CL_PRI,FW_XTM_PRI,loggerd,\\N,10976070,3D01-0003,Archived log file /var/log/traffic.log which reached max size",
            ],
            alarm_rows=[
                "2025-10-22T09:00:03,Notify,al,FW_PL1_CL_PRI,FW_XTM_PRI,firewall,6,\\N,39632546,3000-0155,udp_flood_dos,email,Wed Oct 22 06:00:03 2025 (-03),UDP flood attack against 8.8.8.8 from 172.26.25.56 detected.",
            ],
        ),
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=build_workspace_s3_zip_payload(
            workspace="acme-lab",
            s3_uri="s3://egslatam-cai-dev/workspaces/acme-lab/input/uploads/20260316_abc/logs.zip",
        ),
        observation_request=observation_request,
    )

    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED
    assert outcome.observation_result.structured_summary["family_counts"]["traffic"]["record_count"] == 2
    assert outcome.observation_result.structured_summary["family_counts"]["event"]["record_count"] == 1
    assert outcome.observation_result.structured_summary["family_counts"]["alarm"]["record_count"] == 1
    assert [artifact.subtype for artifact in outcome.artifacts] == [
        "watchguard.workspace_zip_manifest",
        "watchguard.workspace_zip.traffic",
        "watchguard.workspace_zip.event",
        "watchguard.workspace_zip.alarm",
    ]
    traffic_artifact = next(
        artifact for artifact in outcome.artifacts if artifact.subtype == "watchguard.workspace_zip.traffic"
    )
    assert traffic_artifact.metadata["log_type"] == "traffic"
    assert traffic_artifact.metadata["record_count"] == 2


def test_failure_paths_return_normalized_failure_semantics():
    descriptor = get_watchguard_logs_backend_descriptor()
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Failure semantics case",
        summary="Case for failure semantics.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=descriptor.backend_id,
    )

    input_artifact = make_input_artifact()
    bad_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=run.case_ref.id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=descriptor.backend_id),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind="watchguard_logs.unsupported",
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload={"records": []},
        observation_request=bad_request,
    )

    assert outcome.artifacts == []
    assert outcome.observation_result.status == ObservationStatus.FAILED
    assert "unsupported operation_kind" in outcome.observation_result.errors[0]


def test_filter_denied_events_produces_denied_only_artifact_and_valid_result():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard denied events case",
        summary="Case for denied event filtering.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_FILTER_DENIED_EVENTS_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=_make_watchguard_traffic_csv_payload(
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
                    protocol="UDP",
                    src_ip="10.0.0.2",
                    src_port=51515,
                    dst_ip="1.1.1.1",
                    dst_port=53,
                    question="dns-blocked",
                ),
                _make_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:02",
                    action="blocked",
                    policy="block-rdp",
                    protocol="TCP",
                    src_ip="10.0.0.3",
                    src_port=51516,
                    dst_ip="9.9.9.9",
                    dst_port=3389,
                    question="rdp-blocked",
                ),
            ]
        ),
        observation_request=observation_request,
    )

    assert len(outcome.artifacts) == 1
    assert outcome.artifacts[0].kind.value == "normalized"
    assert outcome.artifacts[0].subtype == "watchguard.denied_events"
    assert outcome.artifacts[0].summary == "Filtered 2 denied WatchGuard log records."
    assert outcome.artifacts[0].metadata["action_counts"] == {"deny": 1, "blocked": 1}
    assert outcome.artifacts[0].metadata["input_shape"] == WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED
    assert outcome.observation_result.structured_summary["record_count"] == 2
    assert outcome.observation_result.structured_summary["summary"] == "Filtered 2 denied WatchGuard log records."
    assert outcome.observation_result.structured_summary["input_shape"] == WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE
    assert outcome.observation_result.structured_summary["denied_record_count"] == 2


def test_realistic_watchguard_traffic_csv_payload_produces_normalized_artifact_and_metadata():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard CSV ingest case",
        summary="Case for realistic traffic CSV ingest.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_NORMALIZE_SUMMARY_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=_make_watchguard_traffic_csv_payload(
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
                    protocol="UDP",
                    src_ip="10.0.0.2",
                    src_port=51515,
                    dst_ip="1.1.1.1",
                    dst_port=53,
                    question="dns-blocked",
                ),
            ]
        ),
        observation_request=observation_request,
    )

    assert len(outcome.artifacts) == 1
    assert outcome.artifacts[0].metadata["input_shape"] == WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE
    assert outcome.artifacts[0].metadata["log_type"] == WATCHGUARD_TRAFFIC_LOG_TYPE
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED
    assert outcome.observation_result.structured_summary["record_count"] == 2
    assert outcome.observation_result.structured_summary["input_shape"] == WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE
    assert outcome.observation_result.structured_summary["log_type"] == WATCHGUARD_TRAFFIC_LOG_TYPE
    assert outcome.observation_result.provenance["input_shape"] == WATCHGUARD_TRAFFIC_CSV_INPUT_SHAPE


def test_basic_analytics_bundle_produces_analysis_output_with_deterministic_rankings():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard analytics case",
        summary="Case for basic analytics bundle.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=_make_watchguard_traffic_csv_payload(
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
                    protocol="UDP",
                    src_ip="10.0.0.2",
                    src_port=51515,
                    dst_ip="9.9.9.9",
                    dst_port=53,
                    question="dns-blocked",
                ),
                _make_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:02",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="UDP",
                    src_ip="10.0.0.1",
                    src_port=51516,
                    dst_ip="9.9.9.9",
                    dst_port=443,
                    question="https-allow",
                ),
                _make_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:03",
                    action="blocked",
                    policy="block-rdp",
                    protocol="TCP",
                    src_ip="10.0.0.2",
                    src_port=51517,
                    dst_ip="8.8.8.8",
                    dst_port=3389,
                    question="rdp-blocked",
                ),
            ]
        ),
        observation_request=observation_request,
    )

    assert len(outcome.artifacts) == 1
    artifact = outcome.artifacts[0]
    assert artifact.kind == ArtifactKind.ANALYSIS_OUTPUT
    assert artifact.subtype == "watchguard.analytics_bundle_basic"
    assert artifact.summary == "Built a basic WatchGuard analytics bundle from 4 log records."
    assert artifact.metadata["record_count"] == 4
    assert artifact.metadata["time_range"] == {
        "ts_min": "2026-03-15T00:00:00Z",
        "ts_max": "2026-03-15T00:03:00Z",
    }
    assert artifact.metadata["action_counts"] == {"allow": 2, "blocked": 1, "deny": 1}
    assert artifact.metadata["top_source_ips"] == [
        {"ip": "10.0.0.1", "count": 2},
        {"ip": "10.0.0.2", "count": 2},
    ]
    assert artifact.metadata["top_destination_ips"] == [
        {"ip": "8.8.8.8", "count": 2},
        {"ip": "9.9.9.9", "count": 2},
    ]
    assert artifact.metadata["protocol_breakdown"] == [
        {"protocol": "tcp", "count": 2},
        {"protocol": "udp", "count": 2},
    ]
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED
    assert outcome.observation_result.structured_summary["top_source_ip"] == {"ip": "10.0.0.1", "count": 2}
    assert outcome.observation_result.structured_summary["top_destination_ip"] == {"ip": "8.8.8.8", "count": 2}
    assert outcome.observation_result.structured_summary["top_protocol"] == {"protocol": "tcp", "count": 2}


def test_basic_analytics_bundle_returns_no_findings_and_empty_analysis_for_zero_records():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard zero analytics case",
        summary="Case for zero-record analytics.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload={"records": []},
        observation_request=observation_request,
    )

    assert len(outcome.artifacts) == 1
    assert outcome.artifacts[0].kind == ArtifactKind.ANALYSIS_OUTPUT
    assert outcome.artifacts[0].metadata["record_count"] == 0
    assert outcome.artifacts[0].metadata["top_source_ips"] == []
    assert outcome.artifacts[0].metadata["time_range"] == {"ts_min": None, "ts_max": None}
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED_NO_FINDINGS
    assert outcome.observation_result.structured_summary["top_source_ip"] is None
    assert outcome.observation_result.structured_summary["top_protocol"] is None


def test_basic_analytics_bundle_invalid_input_returns_normalized_failure_semantics():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard analytics invalid case",
        summary="Case for invalid analytics input.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_ANALYTICS_BUNDLE_BASIC_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=_make_watchguard_traffic_csv_payload(
            [
                "15/03/2026 00:00,,,,,ALLOW,allow-web,,TCP,,,10.0.0.1,not-a-port,8.8.8.8,53"
            ]
        ),
        observation_request=observation_request,
    )

    assert outcome.artifacts == []
    assert outcome.observation_result.status == ObservationStatus.FAILED
    assert "invalid 'src_port'" in outcome.observation_result.errors[0]


def test_top_talkers_basic_produces_deterministic_analysis_output():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard top talkers case",
        summary="Case for the top talkers slice.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=_make_watchguard_traffic_csv_payload(
            [
                _make_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:00",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="TCP",
                    src_ip="10.0.0.2",
                    src_port=51514,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    question="dns-allow",
                ),
                _make_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:01",
                    action="DENY",
                    policy="deny-dns",
                    protocol="UDP",
                    src_ip="10.0.0.1",
                    src_port=51515,
                    dst_ip="1.1.1.1",
                    dst_port=53,
                    question="dns-blocked",
                ),
                _make_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:02",
                    action="ALLOW",
                    policy="allow-web",
                    protocol="UDP",
                    src_ip="10.0.0.1",
                    src_port=51516,
                    dst_ip="9.9.9.9",
                    dst_port=443,
                    question="https-allow",
                ),
                _make_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:03",
                    action="blocked",
                    policy="block-rdp",
                    protocol="TCP",
                    src_ip="10.0.0.2",
                    src_port=51517,
                    dst_ip="1.1.1.1",
                    dst_port=3389,
                    question="rdp-blocked",
                ),
            ]
        ),
        observation_request=observation_request,
    )

    assert len(outcome.artifacts) == 1
    artifact = outcome.artifacts[0]
    assert artifact.kind == ArtifactKind.ANALYSIS_OUTPUT
    assert artifact.subtype == "watchguard.top_talkers_basic"
    assert artifact.summary == "Built a basic WatchGuard top-talkers summary from 4 log records."
    assert artifact.metadata["record_count"] == 4
    assert artifact.metadata["top_source_ips"] == [
        {"ip": "10.0.0.1", "count": 2},
        {"ip": "10.0.0.2", "count": 2},
    ]
    assert artifact.metadata["top_destination_ips"] == [
        {"ip": "1.1.1.1", "count": 2},
        {"ip": "8.8.8.8", "count": 1},
        {"ip": "9.9.9.9", "count": 1},
    ]
    assert artifact.metadata["top_source_destination_pairs"] == [
        {"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "count": 1},
        {"src_ip": "10.0.0.1", "dst_ip": "9.9.9.9", "count": 1},
        {"src_ip": "10.0.0.2", "dst_ip": "1.1.1.1", "count": 1},
        {"src_ip": "10.0.0.2", "dst_ip": "8.8.8.8", "count": 1},
    ]
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED
    assert outcome.observation_result.structured_summary["top_source_ip"] == {"ip": "10.0.0.1", "count": 2}
    assert outcome.observation_result.structured_summary["top_destination_ip"] == {"ip": "1.1.1.1", "count": 2}
    assert outcome.observation_result.structured_summary["top_pair"] == {
        "src_ip": "10.0.0.1",
        "dst_ip": "1.1.1.1",
        "count": 1,
    }


def test_top_talkers_basic_returns_no_findings_and_empty_artifact_for_zero_records():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard zero top talkers case",
        summary="Case for zero-record top talkers.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload={"records": []},
        observation_request=observation_request,
    )

    assert len(outcome.artifacts) == 1
    assert outcome.artifacts[0].kind == ArtifactKind.ANALYSIS_OUTPUT
    assert outcome.artifacts[0].metadata["record_count"] == 0
    assert outcome.artifacts[0].metadata["top_source_ips"] == []
    assert outcome.artifacts[0].metadata["top_destination_ips"] == []
    assert outcome.artifacts[0].metadata["top_source_destination_pairs"] == []
    assert outcome.observation_result.status == ObservationStatus.SUCCEEDED_NO_FINDINGS
    assert outcome.observation_result.structured_summary["top_source_ip"] is None
    assert outcome.observation_result.structured_summary["top_pair"] is None


def test_top_talkers_basic_invalid_input_returns_normalized_failure_semantics():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard top talkers invalid case",
        summary="Case for invalid top talkers input.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    observation_request = ObservationRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        operation_kind=WATCHGUARD_TOP_TALKERS_BASIC_OPERATION,
        input_artifact_refs=[EntityRef(entity_type=EntityKind.ARTIFACT, id=input_artifact.artifact_id)],
        requested_by="tester",
    )

    outcome = execute_predefined_observation(
        run=run,
        input_artifact=input_artifact,
        input_payload=_make_watchguard_traffic_csv_payload(
            [
                "15/03/2026 00:00,,,,,ALLOW,allow-web,,TCP,,,,51514,8.8.8.8,53"
            ]
        ),
        observation_request=observation_request,
    )

    assert outcome.artifacts == []
    assert outcome.observation_result.status == ObservationStatus.FAILED
    assert "invalid 'src_ip'" in outcome.observation_result.errors[0]


def test_guarded_custom_query_produces_query_result_with_deterministic_rows_and_limit():
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="WatchGuard guarded query case",
        summary="Case for the first guarded custom query slice.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    query = {
        "filters": [
            {
                "field": "src_ip",
                "op": "eq",
                "value": "10.0.0.1",
            }
        ],
        "limit": 2,
    }
    query_request = QueryRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        query_mode=QueryMode.CUSTOM_GUARDED,
        parameters={
            "query": query,
            "query_class": WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
        },
        requested_scope=WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
        reason="Investigate one source IP across normalized rows.",
        requested_by="tester",
        custom_query_text=json.dumps(query, sort_keys=True),
    )

    outcome = execute_guarded_custom_query(
        run=run,
        input_artifact=input_artifact,
        input_payload=_make_watchguard_traffic_csv_payload(
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
                    protocol="UDP",
                    src_ip="10.0.0.1",
                    src_port=51515,
                    dst_ip="1.1.1.1",
                    dst_port=53,
                    question="dns-blocked",
                ),
                _make_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:02",
                    action="ALLOW",
                    policy="allow-https",
                    protocol="TCP",
                    src_ip="10.0.0.3",
                    src_port=51516,
                    dst_ip="9.9.9.9",
                    dst_port=443,
                    question="https-allow",
                ),
                _make_watchguard_traffic_csv_row(
                    timestamp="15/03/2026 00:03",
                    action="ALLOW",
                    policy="allow-dns",
                    protocol="UDP",
                    src_ip="10.0.0.1",
                    src_port=51517,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    question="dns-allow-late",
                ),
            ]
        ),
        query_request=query_request,
    )

    assert len(outcome.artifacts) == 1
    artifact = outcome.artifacts[0]
    assert artifact.kind == ArtifactKind.QUERY_RESULT
    assert artifact.subtype == "watchguard.guarded_filtered_rows"
    assert artifact.metadata["matched_row_count"] == 3
    assert artifact.metadata["returned_row_count"] == 2
    assert artifact.metadata["truncated"] is True
    assert artifact.metadata["rows"] == [
        {
            "timestamp": "2026-03-15T00:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "action": "allow",
            "protocol": "tcp",
            "policy": "allow-web",
            "src_port": 51514,
            "dst_port": 53,
            "question": "dns-allow",
            "record_type": "traffic",
        },
        {
            "timestamp": "2026-03-15T00:01:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "1.1.1.1",
            "action": "deny",
            "protocol": "udp",
            "policy": "deny-dns",
            "src_port": 51515,
            "dst_port": 53,
            "question": "dns-blocked",
            "record_type": "traffic",
        },
    ]
    assert outcome.query_summary == {
        "query_class": WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
        "record_count": 3,
        "returned_row_count": 2,
        "limit": 2,
        "truncated": True,
        "top_row": artifact.metadata["rows"][0],
        "summary": "Returned 2 WatchGuard rows for the guarded custom query (matched 3, limit 2).",
    }


@pytest.mark.parametrize(
    ("query", "error_message"),
    [
        (
            {
                "filters": [{"field": "dst_port", "op": "eq", "value": "53"}],
                "limit": 5,
            },
            "field 'dst_port' is not allowed",
        ),
        (
            {
                "filters": [{"field": "src_ip", "op": "contains", "value": "10.0.0.1"}],
                "limit": 5,
            },
            "op 'contains' is not allowed",
        ),
        (
            {
                "filters": [{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}],
                "limit": 51,
            },
            "limit must be <= 50",
        ),
    ],
)
def test_guarded_custom_query_rejects_unsafe_query_shapes(query, error_message):
    case_repository = InMemoryCaseRepository()
    run_repository = InMemoryRunRepository()
    audit_port = RecordingAuditPort()
    backend_registry = StaticBackendRegistry()
    input_artifact = make_input_artifact()

    case = create_case(
        case_repository,
        client_id="test-client",
        workflow_type=WorkflowType.LOG_INVESTIGATION,
        title="Unsafe guarded query case",
        summary="Case for invalid guarded query validation.",
    )
    run = create_run_for_case(
        case_repository,
        run_repository,
        backend_registry,
        audit_port,
        case_id=case.case_id,
        backend_id=WATCHGUARD_LOGS_BACKEND_ID,
    )
    query_request = QueryRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=WATCHGUARD_LOGS_BACKEND_ID),
        run_ref=EntityRef(entity_type=EntityKind.RUN, id=run.run_id),
        query_mode=QueryMode.CUSTOM_GUARDED,
        parameters={
            "query": query,
            "query_class": WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
        },
        requested_scope=WATCHGUARD_GUARDED_FILTERED_ROWS_QUERY_CLASS,
        reason="Unsafe custom query validation.",
        requested_by="tester",
        custom_query_text=json.dumps(query, sort_keys=True),
    )

    with pytest.raises(InvalidWatchGuardQueryError, match=error_message):
        execute_guarded_custom_query(
            run=run,
            input_artifact=input_artifact,
            input_payload=_make_watchguard_traffic_csv_payload(
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
                    )
                ]
            ),
            query_request=query_request,
        )
