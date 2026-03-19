"""The first narrow orchestration flow over platform-api."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from cai_orchestrator.client import PlatformApiClient
from cai_orchestrator.errors import (
    InvalidOperatorInputError,
    OrchestrationFlowError,
    PlatformApiRequestError,
    PlatformApiUnavailableError,
)

WATCHGUARD_BACKEND_ID = "watchguard_logs"
WATCHGUARD_WORKFLOW_TYPE = "log_investigation"
PHISHING_EMAIL_BACKEND_ID = "phishing_email"
PHISHING_EMAIL_WORKFLOW_TYPE = "defensive_analysis"


@dataclass(frozen=True)
class WatchGuardInvestigationRequest:
    """Operator input for the first WatchGuard orchestration slice."""

    client_id: str
    title: str
    summary: str
    payload: dict[str, Any]
    requested_by: str = "cai_orchestrator"


@dataclass(frozen=True)
class WatchGuardGuardedQueryRequest:
    """Operator input for the first guarded WatchGuard custom-query slice."""

    client_id: str
    title: str
    summary: str
    payload: dict[str, Any]
    query: dict[str, Any]
    reason: str
    approval_reason: str
    approver_kind: str = "human_operator"
    approver_ref: str | None = None
    requested_by: str = "cai_orchestrator"


@dataclass(frozen=True)
class WatchGuardInvestigationResult:
    """Structured result returned to the operator after the first slice completes."""

    case: dict[str, Any]
    input_artifact: dict[str, Any]
    run: dict[str, Any]
    execution: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Return the result as a plain dictionary for CAI tools or other callers."""
        return asdict(self)


@dataclass(frozen=True)
class PhishingEmailAssessmentRequest:
    """Operator input for the phishing email assessment slice."""

    client_id: str
    title: str
    summary: str
    payload: dict[str, Any]
    requested_by: str = "cai_orchestrator"


@dataclass(frozen=True)
class PhishingEmailAssessmentResult:
    """Structured result returned to the operator after the phishing slice completes."""

    case: dict[str, Any]
    input_artifact: dict[str, Any]
    run: dict[str, Any]
    execution: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Return the result as a plain dictionary for CAI tools or other callers."""
        return asdict(self)


def run_watchguard_log_investigation(
    client: PlatformApiClient,
    request: WatchGuardInvestigationRequest,
) -> WatchGuardInvestigationResult:
    """Execute the first narrow WatchGuard flow through platform-api."""
    return _run_watchguard_operation(
        client,
        request,
        execute_phase="execute_observation",
        execute_operation=lambda run_id: client.execute_watchguard_normalize(
            run_id=run_id,
            requested_by=request.requested_by,
        ),
    )


def run_watchguard_filter_denied_events(
    client: PlatformApiClient,
    request: WatchGuardInvestigationRequest,
) -> WatchGuardInvestigationResult:
    """Execute the denied-event WatchGuard flow through platform-api."""
    return _run_watchguard_operation(
        client,
        request,
        execute_phase="execute_denied_filter_observation",
        execute_operation=lambda run_id: client.execute_watchguard_filter_denied(
            run_id=run_id,
            requested_by=request.requested_by,
        ),
    )


def run_watchguard_analytics_bundle_basic(
    client: PlatformApiClient,
    request: WatchGuardInvestigationRequest,
) -> WatchGuardInvestigationResult:
    """Execute the basic analytics WatchGuard flow through platform-api."""
    return _run_watchguard_operation(
        client,
        request,
        execute_phase="execute_analytics_bundle_basic_observation",
        execute_operation=lambda run_id: client.execute_watchguard_analytics_basic(
            run_id=run_id,
            requested_by=request.requested_by,
        ),
    )


def run_watchguard_top_talkers_basic(
    client: PlatformApiClient,
    request: WatchGuardInvestigationRequest,
) -> WatchGuardInvestigationResult:
    """Execute the basic top-talkers WatchGuard flow through platform-api."""
    return _run_watchguard_operation(
        client,
        request,
        execute_phase="execute_top_talkers_basic_observation",
        execute_operation=lambda run_id: client.execute_watchguard_top_talkers_basic(
            run_id=run_id,
            requested_by=request.requested_by,
        ),
    )


def run_watchguard_guarded_custom_query(
    client: PlatformApiClient,
    request: WatchGuardGuardedQueryRequest,
) -> WatchGuardInvestigationResult:
    """Execute the first guarded custom WatchGuard query flow through platform-api."""
    _validate_guarded_query_request(request)

    case_response = _run_phase(
        phase="create_case",
        operation=lambda: client.create_case(
            client_id=request.client_id,
            workflow_type=WATCHGUARD_WORKFLOW_TYPE,
            title=request.title,
            summary=request.summary,
        ),
    )
    case_id = case_response["case"]["case_id"]

    artifact_response = _run_phase(
        phase="attach_input_artifact",
        operation=lambda: client.attach_input_artifact(
            case_id=case_id,
            payload=request.payload,
            format="json",
            summary="WatchGuard investigation input payload",
        ),
    )
    artifact_id = artifact_response["artifact"]["artifact_id"]

    run_response = _run_phase(
        phase="create_run",
        operation=lambda: client.create_run(
            case_id=case_id,
            backend_id=WATCHGUARD_BACKEND_ID,
            input_artifact_ids=[artifact_id],
        ),
    )
    run_id = run_response["run"]["run_id"]

    execution_response = _run_phase(
        phase="execute_guarded_custom_query",
        operation=lambda: client.execute_watchguard_guarded_custom_query(
            run_id=run_id,
            query=request.query,
            reason=request.reason,
            approval={
                "status": "approved",
                "reason": request.approval_reason,
                "approver_kind": request.approver_kind,
                "approver_ref": request.approver_ref,
            },
            requested_by=request.requested_by,
            input_artifact_id=artifact_id,
        ),
    )
    final_run = execution_response.get("run", run_response["run"])

    return WatchGuardInvestigationResult(
        case=case_response["case"],
        input_artifact=artifact_response["artifact"],
        run=final_run,
        execution=execution_response,
    )


def run_phishing_email_basic_assessment(
    client: PlatformApiClient,
    request: PhishingEmailAssessmentRequest,
) -> PhishingEmailAssessmentResult:
    """Execute the phishing email basic assessment through platform-api."""
    _validate_phishing_email_request(request)

    case_response = _run_phase(
        phase="create_case",
        operation=lambda: client.create_case(
            client_id=request.client_id,
            workflow_type=PHISHING_EMAIL_WORKFLOW_TYPE,
            title=request.title,
            summary=request.summary,
        ),
    )
    case_id = case_response["case"]["case_id"]

    artifact_response = _run_phase(
        phase="attach_input_artifact",
        operation=lambda: client.attach_input_artifact(
            case_id=case_id,
            payload=request.payload,
            format="json",
            summary="Phishing email assessment input payload",
        ),
    )
    artifact_id = artifact_response["artifact"]["artifact_id"]

    run_response = _run_phase(
        phase="create_run",
        operation=lambda: client.create_run(
            case_id=case_id,
            backend_id=PHISHING_EMAIL_BACKEND_ID,
            input_artifact_ids=[artifact_id],
        ),
    )
    run_id = run_response["run"]["run_id"]

    execution_response = _run_phase(
        phase="execute_phishing_email_basic_assessment",
        operation=lambda: client.execute_phishing_email_basic_assessment(
            run_id=run_id,
            requested_by=request.requested_by,
            input_artifact_id=artifact_id,
        ),
    )
    final_run = execution_response.get("run", run_response["run"])

    return PhishingEmailAssessmentResult(
        case=case_response["case"],
        input_artifact=artifact_response["artifact"],
        run=final_run,
        execution=execution_response,
    )


@dataclass(frozen=True)
class PhishingMonitorEmailResult:
    """Structured result returned after processing one monitored phishing email."""

    case: dict[str, Any]
    input_artifact: dict[str, Any]
    run: dict[str, Any]
    basic_assessment: dict[str, Any]
    header_analysis: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the result as a plain dictionary for CAI tools or other callers."""
        return asdict(self)


def run_phishing_monitor_single_email(
    client: PlatformApiClient,
    *,
    client_id: str,
    raw_eml: bytes,
    title: str,
    summary: str,
    requested_by: str = "cai_orchestrator",
) -> PhishingMonitorEmailResult:
    """Parse one raw .eml and run it through the full phishing assessment pipeline.

    Executes:
    1. create_case (defensive_analysis)
    2. attach_input_artifact (structured_email_v2 payload)
    3. create_run (phishing_email backend)
    4. execute phishing-email-basic-assessment
    5. execute phishing-email-header-analysis (requires structured_email_v2 input)
    """
    from cai_orchestrator.email_bridge import eml_bytes_to_structured_email_v2_payload

    payload = eml_bytes_to_structured_email_v2_payload(raw_eml)

    case_response = _run_phase(
        phase="create_case",
        operation=lambda: client.create_case(
            client_id=client_id,
            workflow_type=PHISHING_EMAIL_WORKFLOW_TYPE,
            title=title,
            summary=summary,
        ),
    )
    case_id = case_response["case"]["case_id"]

    artifact_response = _run_phase(
        phase="attach_input_artifact",
        operation=lambda: client.attach_input_artifact(
            case_id=case_id,
            payload=payload,
            format="json",
            summary="Phishing email (structured_email_v2) from IMAP monitor",
        ),
    )
    artifact_id = artifact_response["artifact"]["artifact_id"]

    run_response = _run_phase(
        phase="create_run",
        operation=lambda: client.create_run(
            case_id=case_id,
            backend_id=PHISHING_EMAIL_BACKEND_ID,
            input_artifact_ids=[artifact_id],
        ),
    )
    run_id = run_response["run"]["run_id"]

    basic_assessment_response = _run_phase(
        phase="execute_phishing_email_basic_assessment",
        operation=lambda: client.execute_phishing_email_basic_assessment(
            run_id=run_id,
            requested_by=requested_by,
            input_artifact_id=artifact_id,
        ),
    )

    header_analysis_response: dict[str, Any] | None = None
    try:
        header_analysis_response = _run_phase(
            phase="execute_phishing_email_header_analysis",
            operation=lambda: client.execute_phishing_email_header_analysis(
                run_id=run_id,
                requested_by=requested_by,
                input_artifact_id=artifact_id,
            ),
        )
    except OrchestrationFlowError:
        pass  # header_analysis is best-effort for non-v2 inputs

    final_run = header_analysis_response.get("run", basic_assessment_response.get("run", run_response["run"])) if header_analysis_response else basic_assessment_response.get("run", run_response["run"])

    return PhishingMonitorEmailResult(
        case=case_response["case"],
        input_artifact=artifact_response["artifact"],
        run=final_run,
        basic_assessment=basic_assessment_response,
        header_analysis=header_analysis_response,
    )


def _run_watchguard_operation(
    client: PlatformApiClient,
    request: WatchGuardInvestigationRequest,
    *,
    execute_phase: str,
    execute_operation,
) -> WatchGuardInvestigationResult:
    """Execute one narrow WatchGuard predefined operation through platform-api."""
    _validate_request(request)

    case_response = _run_phase(
        phase="create_case",
        operation=lambda: client.create_case(
            client_id=request.client_id,
            workflow_type=WATCHGUARD_WORKFLOW_TYPE,
            title=request.title,
            summary=request.summary,
        ),
    )
    case_id = case_response["case"]["case_id"]

    artifact_response = _run_phase(
        phase="attach_input_artifact",
        operation=lambda: client.attach_input_artifact(
            case_id=case_id,
            payload=request.payload,
            format="json",
            summary="WatchGuard investigation input payload",
        ),
    )
    artifact_id = artifact_response["artifact"]["artifact_id"]

    run_response = _run_phase(
        phase="create_run",
        operation=lambda: client.create_run(
            case_id=case_id,
            backend_id=WATCHGUARD_BACKEND_ID,
            input_artifact_ids=[artifact_id],
        ),
    )
    run_id = run_response["run"]["run_id"]

    execution_response = _run_phase(phase=execute_phase, operation=lambda: execute_operation(run_id))
    final_run = execution_response.get("run", run_response["run"])

    return WatchGuardInvestigationResult(
        case=case_response["case"],
        input_artifact=artifact_response["artifact"],
        run=final_run,
        execution=execution_response,
    )


def _validate_request(request: WatchGuardInvestigationRequest) -> None:
    if not request.title.strip():
        raise InvalidOperatorInputError("title must not be empty")
    if not request.summary.strip():
        raise InvalidOperatorInputError("summary must not be empty")
    if not isinstance(request.payload, dict):
        raise InvalidOperatorInputError("payload must be a mapping")


def _validate_guarded_query_request(request: WatchGuardGuardedQueryRequest) -> None:
    _validate_request(
        WatchGuardInvestigationRequest(
            client_id=request.client_id,
            title=request.title,
            summary=request.summary,
            payload=request.payload,
            requested_by=request.requested_by,
        )
    )
    if not request.reason.strip():
        raise InvalidOperatorInputError("reason must not be empty")
    if not request.approval_reason.strip():
        raise InvalidOperatorInputError("approval_reason must not be empty")
    if not request.approver_kind.strip():
        raise InvalidOperatorInputError("approver_kind must not be empty")
    if not isinstance(request.query, dict):
        raise InvalidOperatorInputError("query must be a mapping")


def _validate_phishing_email_request(request: PhishingEmailAssessmentRequest) -> None:
    if not request.title.strip():
        raise InvalidOperatorInputError("title must not be empty")
    if not request.summary.strip():
        raise InvalidOperatorInputError("summary must not be empty")
    if not isinstance(request.payload, dict):
        raise InvalidOperatorInputError("payload must be a mapping")


def _run_phase(*, phase: str, operation) -> dict[str, Any]:
    try:
        return operation()
    except PlatformApiRequestError as exc:
        raise OrchestrationFlowError(
            phase=phase,
            message=f"{phase} failed through platform-api",
            status_code=exc.status_code,
            details=exc.payload,
        ) from exc
    except PlatformApiUnavailableError as exc:
        raise OrchestrationFlowError(
            phase=phase,
            message=f"{phase} could not reach platform-api",
        ) from exc
