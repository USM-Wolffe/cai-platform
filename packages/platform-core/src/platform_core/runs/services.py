"""Run-level coordination services."""

from __future__ import annotations

from platform_contracts import (
    Case,
    EntityKind,
    EntityRef,
    ObservationRequest,
    ObservationResult,
    ObservationStatus,
    Run,
    RunStatus,
)
from platform_contracts.common import utc_now

from platform_core.artifacts import build_artifact_ref, get_artifact_or_raise
from platform_core.audit import append_timeline_event_to_case
from platform_core.errors import ContractViolationError, InvalidStateError, NotFoundError
from platform_core.ports import ArtifactRepository, AuditPort, BackendRegistry, CaseRepository, RunRepository
from platform_core.services import (
    ensure_backend_can_create_run,
    ensure_backend_supports_workflow,
    get_backend_or_raise,
)


def create_run_for_case(
    case_repository: CaseRepository,
    run_repository: RunRepository,
    backend_registry: BackendRegistry,
    audit_port: AuditPort,
    *,
    case_id: str,
    backend_id: str,
    scope: dict[str, object] | None = None,
    input_artifact_ids: list[str] | None = None,
    artifact_repository: ArtifactRepository | None = None,
) -> Run:
    """Create and persist a run for a case against a known backend."""
    case = case_repository.get_case(case_id)
    if case is None:
        raise NotFoundError(f"case '{case_id}' was not found")

    backend = get_backend_or_raise(backend_registry, backend_id)
    ensure_backend_can_create_run(backend)
    ensure_backend_supports_workflow(backend, case.workflow_type)

    input_artifact_refs = _resolve_input_artifact_refs(
        artifact_repository=artifact_repository,
        input_artifact_ids=input_artifact_ids or [],
    )
    run = Run(
        backend_ref=EntityRef(entity_type=EntityKind.BACKEND, id=backend.backend_id),
        case_ref=EntityRef(entity_type=EntityKind.CASE, id=case.case_id),
        scope=scope or {},
        input_artifact_refs=input_artifact_refs,
    )
    saved_run = run_repository.save_run(run)

    run_ref = EntityRef(entity_type=EntityKind.RUN, id=saved_run.run_id)
    if _contains_ref(case.run_refs, run_ref):
        return saved_run

    updated_case, event = append_timeline_event_to_case(
        case,
        kind="run_created",
        summary=f"Created run {saved_run.run_id} against backend {backend.backend_id}",
        related_refs=[
            run_ref,
            EntityRef(entity_type=EntityKind.BACKEND, id=backend.backend_id),
            *input_artifact_refs,
        ],
    )
    updated_case = updated_case.model_copy(
        update={
            "run_refs": [*case.run_refs, run_ref],
            "updated_at": utc_now(),
        }
    )
    saved_case = case_repository.save_case(updated_case)
    audit_port.append_timeline_event(case_id=saved_case.case_id, event=event)
    return saved_run


def publish_observation_result(
    case_repository: CaseRepository,
    run_repository: RunRepository,
    audit_port: AuditPort,
    *,
    observation_request: ObservationRequest,
    observation_result: ObservationResult,
) -> tuple[Case, Run]:
    """Publish one observation result back into case and run coordination state."""
    if observation_result.observation_ref.id != observation_request.observation_id:
        raise ContractViolationError("observation_result.observation_ref must reference observation_request")

    case = case_repository.get_case(observation_request.case_ref.id)
    if case is None:
        raise NotFoundError(f"case '{observation_request.case_ref.id}' was not found")

    run = run_repository.get_run(observation_request.run_ref.id)
    if run is None:
        raise NotFoundError(f"run '{observation_request.run_ref.id}' was not found")

    _validate_observation_context(case=case, run=run, observation_request=observation_request)

    output_refs = _collect_output_artifact_refs(observation_result)
    observation_ref = EntityRef(entity_type=EntityKind.OBSERVATION_REQUEST, id=observation_request.observation_id)
    updated_run = run.model_copy(
        update={
            "status": _derive_run_status(run, observation_result),
            "observation_refs": _merge_refs(run.observation_refs, [observation_ref]),
            "output_artifact_refs": _merge_refs(run.output_artifact_refs, output_refs),
            "error_summary": _derive_error_summary(run, observation_result),
            "updated_at": utc_now(),
        }
    )
    saved_run = run_repository.save_run(updated_run)

    updated_case, event = append_timeline_event_to_case(
        case,
        kind="observation_result_published",
        summary=f"Published observation result '{observation_result.status.value}' for {observation_request.operation_kind}",
        related_refs=[observation_ref, *output_refs],
    )
    updated_case = updated_case.model_copy(
        update={
            "artifact_refs": _merge_refs(case.artifact_refs, output_refs),
            "updated_at": utc_now(),
        }
    )
    saved_case = case_repository.save_case(updated_case)
    audit_port.append_timeline_event(case_id=saved_case.case_id, event=event)
    return saved_case, saved_run


def _resolve_input_artifact_refs(
    *,
    artifact_repository: ArtifactRepository | None,
    input_artifact_ids: list[str],
) -> list[EntityRef]:
    if not input_artifact_ids:
        return []
    if artifact_repository is None:
        raise ContractViolationError("artifact_repository is required when input_artifact_ids are provided")
    refs: list[EntityRef] = []
    for artifact_id in input_artifact_ids:
        artifact = get_artifact_or_raise(artifact_repository, artifact_id)
        refs.append(build_artifact_ref(artifact))
    return refs


def _validate_observation_context(*, case: Case, run: Run, observation_request: ObservationRequest) -> None:
    if run.case_ref is None or run.case_ref.id != case.case_id:
        raise ContractViolationError("run.case_ref must point to the observation request case")
    if run.run_id != observation_request.run_ref.id:
        raise ContractViolationError("observation_request.run_ref must match the target run")
    if case.case_id != observation_request.case_ref.id:
        raise ContractViolationError("observation_request.case_ref must match the target case")
    if run.backend_ref.id != observation_request.backend_ref.id:
        raise ContractViolationError("observation_request.backend_ref must match the target run backend")
    if run.status in {RunStatus.COMPLETED, RunStatus.CANCELLED}:
        raise InvalidStateError(f"run '{run.run_id}' is terminal and cannot accept observation results")


def _collect_output_artifact_refs(observation_result: ObservationResult) -> list[EntityRef]:
    refs = list(observation_result.output_artifact_refs)
    if observation_result.raw_result_ref is not None:
        refs = _merge_refs(refs, [observation_result.raw_result_ref])
    return refs


def _derive_run_status(run: Run, observation_result: ObservationResult) -> RunStatus:
    if observation_result.status == ObservationStatus.FAILED:
        return RunStatus.FAILED
    if observation_result.status == ObservationStatus.BLOCKED:
        return RunStatus.BLOCKED
    if run.status == RunStatus.CREATED:
        return RunStatus.RUNNING
    return run.status


def _derive_error_summary(run: Run, observation_result: ObservationResult) -> str | None:
    if observation_result.status == ObservationStatus.FAILED:
        return observation_result.errors[0]
    if observation_result.status in {ObservationStatus.SUCCEEDED, ObservationStatus.SUCCEEDED_NO_FINDINGS}:
        return None
    return run.error_summary


def _merge_refs(existing: list[EntityRef], additions: list[EntityRef]) -> list[EntityRef]:
    merged = list(existing)
    for ref in additions:
        if not _contains_ref(merged, ref):
            merged.append(ref)
    return merged


def _contains_ref(refs: list[EntityRef], candidate: EntityRef) -> bool:
    return any(ref.entity_type == candidate.entity_type and ref.id == candidate.id for ref in refs)
