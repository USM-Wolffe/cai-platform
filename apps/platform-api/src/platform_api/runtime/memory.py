"""In-memory runtime wiring for the first platform-api slice."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from platform_backends.phishing_email import get_phishing_email_backend_descriptor
from platform_backends.watchguard_logs import get_watchguard_logs_backend_descriptor
from platform_contracts import (
    ApprovalDecision,
    ApprovalScopeKind,
    ApprovalStatus,
    Artifact,
    ArtifactKind,
    BackendDescriptor,
    Case,
    DecisionRecord,
    EntityKind,
    EntityRef,
    InvestigationDefinition,
    ObservationRequest,
    ObservationResult,
    QueryDefinition,
    QueryMode,
    QueryRequest,
    RiskClass,
    Run,
    RunStatus,
)
from platform_contracts.common import generate_opaque_id, utc_now
from platform_core import InvalidStateError, NotFoundError


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
        self._payloads: dict[str, object] = {}
        self._content_sources: dict[str, str] = {}

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        artifact = self._artifacts.get(artifact_id)
        return None if artifact is None else artifact.model_copy(deep=True)

    def save_artifact(
        self,
        artifact: Artifact,
        *,
        payload: object | None = None,
        content_source: str | None = None,
    ) -> Artifact:
        saved = artifact.model_copy(deep=True)
        self._artifacts[saved.artifact_id] = saved
        if payload is not None:
            self._payloads[saved.artifact_id] = payload
            if content_source is not None:
                self._content_sources[saved.artifact_id] = content_source
        return saved.model_copy(deep=True)

    def get_payload(self, artifact_id: str) -> object | None:
        return self._payloads.get(artifact_id)

    def get_content_source(self, artifact_id: str) -> str | None:
        return self._content_sources.get(artifact_id)

    def get_artifacts(self, artifact_ids: list[str]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        for artifact_id in artifact_ids:
            artifact = self.get_artifact(artifact_id)
            if artifact is not None:
                artifacts.append(artifact)
        return artifacts


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


class InMemoryInvestigationDefinitionRepository:
    def get_investigation_definition(self, investigation_definition_id: str) -> InvestigationDefinition | None:
        return None


class InProcessBackendRegistry:
    def __init__(self, descriptors: list[BackendDescriptor]) -> None:
        self._descriptors = {descriptor.backend_id: descriptor.model_copy(deep=True) for descriptor in descriptors}

    def get_backend(self, backend_id: str) -> BackendDescriptor | None:
        descriptor = self._descriptors.get(backend_id)
        return None if descriptor is None else descriptor.model_copy(deep=True)

    def list_backend_ids(self) -> list[str]:
        return sorted(self._descriptors.keys())


class DevelopmentApprovalPolicy:
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
        return (
            approval_decision is not None
            and approval_decision.status == ApprovalStatus.APPROVED
            and approval_decision.scope_kind == ApprovalScopeKind.QUERY_REQUEST
            and approval_decision.scope_ref.id == query_request.query_request_id
        )


class InMemoryAuditPort:
    def __init__(self) -> None:
        self.timeline_events: list[tuple[str, object]] = []
        self.decision_records: list[tuple[str, object]] = []

    def append_timeline_event(self, *, case_id: str, event) -> None:
        self.timeline_events.append((case_id, event.model_copy(deep=True)))

    def append_decision_record(self, *, case_id: str, decision: DecisionRecord) -> None:
        self.decision_records.append((case_id, decision.model_copy(deep=True)))


@dataclass
class AppRuntime:
    """In-memory runtime bundle for the first deterministic API slice."""

    case_repository: InMemoryCaseRepository
    artifact_repository: InMemoryArtifactRepository
    run_repository: InMemoryRunRepository
    definition_repository: InMemoryInvestigationDefinitionRepository
    backend_registry: InProcessBackendRegistry
    approval_policy: DevelopmentApprovalPolicy
    audit_port: InMemoryAuditPort
    observation_requests: dict[str, ObservationRequest] = field(default_factory=dict)
    observation_results: dict[str, ObservationResult] = field(default_factory=dict)
    query_requests: dict[str, QueryRequest] = field(default_factory=dict)
    approval_decisions: dict[str, ApprovalDecision] = field(default_factory=dict)

    def create_input_artifact(
        self,
        *,
        payload: dict[str, Any],
        format: str,
        summary: str | None,
        labels: list[str],
        metadata: dict[str, Any],
    ) -> Artifact:
        serialized_payload = json.dumps(payload, sort_keys=True)
        content_hash = sha256(serialized_payload.encode("utf-8")).hexdigest()
        artifact = Artifact(
            artifact_id=generate_opaque_id("artifact"),
            kind=ArtifactKind.INPUT,
            format=format,
            storage_ref=f"memory://artifacts/{generate_opaque_id('blob')}",
            content_hash=f"sha256:{content_hash}",
            summary=summary,
            labels=labels,
            metadata=metadata,
        )
        return self.artifact_repository.save_artifact(
            artifact,
            payload=payload,
            content_source="attached_input_payload",
        )

    def save_derived_artifact(self, artifact: Artifact) -> Artifact:
        return self.artifact_repository.save_artifact(
            artifact,
            payload=artifact.metadata,
            content_source="derived_artifact_payload",
        )

    def get_case_or_raise(self, case_id: str) -> Case:
        case = self.case_repository.get_case(case_id)
        if case is None:
            raise NotFoundError(f"case '{case_id}' was not found")
        return case

    def get_run_or_raise(self, run_id: str) -> Run:
        run = self.run_repository.get_run(run_id)
        if run is None:
            raise NotFoundError(f"run '{run_id}' was not found")
        return run

    def get_case_or_raise_from_run(self, run: Run) -> Case:
        if run.case_ref is None:
            raise InvalidStateError(f"run '{run.run_id}' is not attached to a case")
        return self.get_case_or_raise(run.case_ref.id)

    def get_artifact_payload_or_raise(self, artifact_id: str) -> object:
        payload = self.artifact_repository.get_payload(artifact_id)
        if payload is None:
            raise NotFoundError(f"artifact payload '{artifact_id}' was not found")
        return payload

    def get_artifact_or_raise(self, artifact_id: str) -> Artifact:
        artifact = self.artifact_repository.get_artifact(artifact_id)
        if artifact is None:
            raise NotFoundError(f"artifact '{artifact_id}' was not found")
        return artifact

    def get_artifact_content_or_raise(self, artifact_id: str) -> tuple[Artifact, object, str]:
        artifact = self.get_artifact_or_raise(artifact_id)
        payload = self.artifact_repository.get_payload(artifact_id)
        if payload is None:
            raise InvalidStateError(
                f"artifact '{artifact_id}' has no readable stored content in the current runtime"
            )
        content_source = self.artifact_repository.get_content_source(artifact_id) or "stored_payload"
        return artifact, payload, content_source

    def get_case_artifacts(self, case: Case) -> list[Artifact]:
        return self.artifact_repository.get_artifacts([ref.id for ref in case.artifact_refs])

    def get_run_input_artifacts(self, run: Run) -> list[Artifact]:
        return self.artifact_repository.get_artifacts([ref.id for ref in run.input_artifact_refs])

    def get_run_output_artifacts(self, run: Run) -> list[Artifact]:
        return self.artifact_repository.get_artifacts([ref.id for ref in run.output_artifact_refs])

    def list_run_artifacts(self, run: Run) -> list[Artifact]:
        return [
            *self.get_run_input_artifacts(run),
            *self.get_run_output_artifacts(run),
        ]

    def record_observation_request(self, observation_request: ObservationRequest) -> None:
        self.observation_requests[observation_request.observation_id] = observation_request.model_copy(deep=True)

    def record_observation_result(self, observation_result: ObservationResult) -> None:
        self.observation_results[observation_result.observation_result_id] = observation_result.model_copy(deep=True)

    def record_query_request(self, query_request: QueryRequest) -> None:
        self.query_requests[query_request.query_request_id] = query_request.model_copy(deep=True)

    def record_approval_decision(self, approval_decision: ApprovalDecision) -> None:
        self.approval_decisions[approval_decision.approval_id] = approval_decision.model_copy(deep=True)

    def list_run_observation_results(self, run: Run) -> list[ObservationResult]:
        return [
            result.model_copy(deep=True)
            for result in self.observation_results.values()
            if result.observation_ref.id in {ref.id for ref in run.observation_refs}
        ]

    def get_observation_input_artifact(self, *, run: Run, input_artifact_id: str | None = None) -> Artifact:
        artifact_id = input_artifact_id
        if artifact_id is None:
            if not run.input_artifact_refs:
                raise InvalidStateError(f"run '{run.run_id}' has no bound input artifacts")
            artifact_id = run.input_artifact_refs[0].id

        if all(ref.id != artifact_id for ref in run.input_artifact_refs):
            raise InvalidStateError(f"artifact '{artifact_id}' is not bound to run '{run.run_id}'")

        artifact = self.artifact_repository.get_artifact(artifact_id)
        if artifact is None:
            raise NotFoundError(f"artifact '{artifact_id}' was not found")
        return artifact

    def publish_query_artifacts(self, *, case: Case, run: Run, artifacts: list[Artifact]) -> tuple[Case, Run]:
        output_refs = [EntityRef(entity_type=EntityKind.ARTIFACT, id=artifact.artifact_id) for artifact in artifacts]
        updated_run = run.model_copy(
            update={
                "status": RunStatus.RUNNING if run.status == RunStatus.CREATED else run.status,
                "output_artifact_refs": _merge_refs(run.output_artifact_refs, output_refs),
                "updated_at": utc_now(),
            }
        )
        saved_run = self.run_repository.save_run(updated_run)

        updated_case = case.model_copy(
            update={
                "artifact_refs": _merge_refs(case.artifact_refs, output_refs),
                "updated_at": utc_now(),
            }
        )
        saved_case = self.case_repository.save_case(updated_case)
        return saved_case, saved_run


def build_default_runtime() -> AppRuntime:
    return AppRuntime(
        case_repository=InMemoryCaseRepository(),
        artifact_repository=InMemoryArtifactRepository(),
        run_repository=InMemoryRunRepository(),
        definition_repository=InMemoryInvestigationDefinitionRepository(),
        backend_registry=InProcessBackendRegistry(
            [
                get_watchguard_logs_backend_descriptor(),
                get_phishing_email_backend_descriptor(),
            ]
        ),
        approval_policy=DevelopmentApprovalPolicy(),
        audit_port=InMemoryAuditPort(),
    )


def _merge_refs(existing: list[EntityRef], additions: list[EntityRef]) -> list[EntityRef]:
    merged = list(existing)
    for ref in additions:
        if not any(item.entity_type == ref.entity_type and item.id == ref.id for item in merged):
            merged.append(ref)
    return merged
