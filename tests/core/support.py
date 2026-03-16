from __future__ import annotations

from platform_contracts import (
    ApprovalDecision,
    ApprovalScopeKind,
    ApprovalStatus,
    Artifact,
    ArtifactKind,
    BackendCapability,
    BackendCapabilityName,
    BackendDescriptor,
    Case,
    DecisionRecord,
    EntityKind,
    EntityRef,
    QueryDefinition,
    QueryMode,
    QueryRequest,
    QueryResultContract,
    RiskClass,
    Run,
    TimelineEvent,
    WorkflowType,
)


class InMemoryCaseRepository:
    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}

    def get_case(self, case_id: str) -> Case | None:
        case = self._cases.get(case_id)
        return None if case is None else case.model_copy(deep=True)

    def save_case(self, case: Case) -> Case:
        saved = case.model_copy(deep=True)
        self._cases[saved.case_id] = saved
        return saved.model_copy(deep=True)


class InMemoryArtifactRepository:
    def __init__(self) -> None:
        self._artifacts: dict[str, Artifact] = {}

    def add_artifact(self, artifact: Artifact) -> None:
        self._artifacts[artifact.artifact_id] = artifact.model_copy(deep=True)

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        artifact = self._artifacts.get(artifact_id)
        return None if artifact is None else artifact.model_copy(deep=True)


class InMemoryRunRepository:
    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}

    def get_run(self, run_id: str) -> Run | None:
        run = self._runs.get(run_id)
        return None if run is None else run.model_copy(deep=True)

    def save_run(self, run: Run) -> Run:
        saved = run.model_copy(deep=True)
        self._runs[saved.run_id] = saved
        return saved.model_copy(deep=True)


class InMemoryDefinitionRepository:
    def __init__(self) -> None:
        self._definitions = {}

    def add_definition(self, definition) -> None:
        self._definitions[definition.investigation_definition_id] = definition.model_copy(deep=True)

    def get_investigation_definition(self, investigation_definition_id: str):
        definition = self._definitions.get(investigation_definition_id)
        return None if definition is None else definition.model_copy(deep=True)


class InMemoryBackendRegistry:
    def __init__(self) -> None:
        self._backends: dict[str, BackendDescriptor] = {}

    def add_backend(self, backend: BackendDescriptor) -> None:
        self._backends[backend.backend_id] = backend.model_copy(deep=True)

    def get_backend(self, backend_id: str) -> BackendDescriptor | None:
        backend = self._backends.get(backend_id)
        return None if backend is None else backend.model_copy(deep=True)


class RecordingAuditPort:
    def __init__(self) -> None:
        self.timeline_events: list[tuple[str, TimelineEvent]] = []
        self.decision_records: list[tuple[str, DecisionRecord]] = []

    def append_timeline_event(self, *, case_id: str, event: TimelineEvent) -> None:
        self.timeline_events.append((case_id, event.model_copy(deep=True)))

    def append_decision_record(self, *, case_id: str, decision: DecisionRecord) -> None:
        self.decision_records.append((case_id, decision.model_copy(deep=True)))


class SimpleApprovalPolicy:
    def query_requires_approval(
        self,
        *,
        query_request: QueryRequest,
        query_definition: QueryDefinition | None,
        backend: BackendDescriptor,
    ) -> bool:
        if query_request.query_mode == QueryMode.CUSTOM_GUARDED:
            return True
        if query_definition is not None and query_definition.risk_class in {RiskClass.HIGH, RiskClass.CRITICAL}:
            return True
        return False

    def is_approval_acceptable(
        self,
        *,
        query_request: QueryRequest,
        approval_decision: ApprovalDecision | None,
        query_definition: QueryDefinition | None,
        backend: BackendDescriptor,
    ) -> bool:
        if approval_decision is None:
            return False
        return (
            approval_decision.status == ApprovalStatus.APPROVED
            and approval_decision.scope_kind == ApprovalScopeKind.QUERY_REQUEST
            and approval_decision.scope_ref.id == query_request.query_request_id
        )


def make_backend(
    *,
    backend_id: str = "backend_logs",
    workflow_types: list[WorkflowType] | None = None,
    capabilities: list[BackendCapabilityName] | None = None,
) -> BackendDescriptor:
    return BackendDescriptor(
        backend_id=backend_id,
        backend_type="generic_backend",
        supported_workflow_types=workflow_types or [WorkflowType.LOG_INVESTIGATION],
        capabilities=[
            BackendCapability(name=name)
            for name in (
                capabilities
                or [
                    BackendCapabilityName.CREATE_RUN,
                    BackendCapabilityName.EXECUTE_PREDEFINED_QUERY,
                    BackendCapabilityName.EXECUTE_CUSTOM_QUERY,
                ]
            )
        ],
        accepted_artifact_kinds=[ArtifactKind.INPUT, ArtifactKind.NORMALIZED],
        produced_artifact_kinds=[ArtifactKind.QUERY_RESULT, ArtifactKind.ANALYSIS_OUTPUT],
    )


def make_artifact(*, artifact_id: str = "artifact_input") -> Artifact:
    return Artifact(
        artifact_id=artifact_id,
        kind=ArtifactKind.INPUT,
        format="json",
        storage_ref=f"object://bucket/{artifact_id}.json",
        content_hash=f"sha256:{artifact_id}",
    )


def make_query_definition(*, risk_class: RiskClass = RiskClass.LOW) -> QueryDefinition:
    return QueryDefinition(
        query_mode=QueryMode.PREDEFINED,
        query_class="timeline_slice",
        backend_scope="generic_backend",
        result_contract=QueryResultContract(summary_type="timeline_summary"),
        risk_class=risk_class,
    )


def make_predefined_query_request(*, backend_id: str = "backend_logs", case_id: str = "case_test") -> QueryRequest:
    return QueryRequest(
        query_definition_ref=EntityRef(entity_type=EntityKind.QUERY_DEFINITION, id="querydef_test"),
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=backend_id),
        query_mode=QueryMode.PREDEFINED,
        requested_scope="default scope",
        reason="standard triage",
        requested_by="tester",
    )


def make_custom_query_request(*, backend_id: str = "backend_logs", case_id: str = "case_test") -> QueryRequest:
    return QueryRequest(
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case_id),
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=backend_id),
        query_mode=QueryMode.CUSTOM_GUARDED,
        requested_scope="guarded scope",
        reason="need deeper query",
        requested_by="tester",
        custom_query_text="filter action = allow",
    )


def make_approval_for_query(query_request: QueryRequest, *, status: ApprovalStatus = ApprovalStatus.APPROVED) -> ApprovalDecision:
    return ApprovalDecision(
        status=status,
        scope_kind=ApprovalScopeKind.QUERY_REQUEST,
        scope_ref=EntityRef(entity_type=EntityKind.QUERY_REQUEST, id=query_request.query_request_id),
        reason="approval for guarded query",
        approver_kind="human_operator",
    )
