"""Case-level core services built on the shared contracts."""

from __future__ import annotations

from platform_contracts import (
    Artifact,
    Case,
    CaseStatus,
    EntityKind,
    EntityRef,
    ExternalReference,
    WorkflowType,
)
from platform_contracts.common import utc_now

from platform_core.artifacts import build_artifact_ref, get_artifact_or_raise
from platform_core.audit import append_timeline_event_to_case
from platform_core.errors import ContractViolationError, NotFoundError
from platform_core.ports import (
    ArtifactRepository,
    AuditPort,
    CaseRepository,
    InvestigationDefinitionRepository,
)


def create_case(
    case_repository: CaseRepository,
    *,
    client_id: str,
    workflow_type: WorkflowType,
    title: str,
    summary: str,
    status: CaseStatus = CaseStatus.OPEN,
    investigation_definition_id: str | None = None,
    definition_repository: InvestigationDefinitionRepository | None = None,
    labels: list[str] | None = None,
    external_refs: list[ExternalReference] | None = None,
    metadata: dict[str, object] | None = None,
) -> Case:
    """Create and persist the smallest useful case record."""
    investigation_definition_ref = None
    current_stage_id = None

    if investigation_definition_id is not None:
        if definition_repository is None:
            raise ContractViolationError(
                "definition_repository is required when investigation_definition_id is provided"
            )
        definition = definition_repository.get_investigation_definition(investigation_definition_id)
        if definition is None:
            raise NotFoundError(f"investigation definition '{investigation_definition_id}' was not found")
        if definition.workflow_type != workflow_type:
            raise ContractViolationError(
                "case workflow_type must match the selected investigation definition workflow_type"
            )
        investigation_definition_ref = EntityRef(
            entity_type=EntityKind.INVESTIGATION_DEFINITION,
            id=definition.investigation_definition_id,
        )
        current_stage_id = definition.stages[0].stage_id

    case = Case(
        client_id=client_id,
        workflow_type=workflow_type,
        status=status,
        title=title,
        summary=summary,
        investigation_definition_ref=investigation_definition_ref,
        current_stage_id=current_stage_id,
        labels=labels or [],
        external_refs=external_refs or [],
        metadata=metadata or {},
    )
    return case_repository.save_case(case)


def attach_artifact_ref_to_case(
    case_repository: CaseRepository,
    artifact_repository: ArtifactRepository,
    audit_port: AuditPort,
    *,
    case_id: str,
    artifact_id: str,
) -> Case:
    """Attach one durable artifact reference to a case if it is not already attached."""
    case = case_repository.get_case(case_id)
    if case is None:
        raise NotFoundError(f"case '{case_id}' was not found")

    artifact = get_artifact_or_raise(artifact_repository, artifact_id)
    artifact_ref = build_artifact_ref(artifact)
    if _contains_ref(case.artifact_refs, artifact_ref):
        return case

    updated_case, event = _attach_artifact_ref(case, artifact)
    saved_case = case_repository.save_case(updated_case)
    audit_port.append_timeline_event(case_id=saved_case.case_id, event=event)
    return saved_case


def _attach_artifact_ref(case: Case, artifact: Artifact) -> tuple[Case, object]:
    artifact_ref = build_artifact_ref(artifact)
    case_with_event, event = append_timeline_event_to_case(
        case,
        kind="artifact_attached",
        summary=f"Attached artifact {artifact.artifact_id}",
        related_refs=[artifact_ref],
    )
    updated_case = case_with_event.model_copy(
        update={
            "artifact_refs": [*case.artifact_refs, artifact_ref],
            "updated_at": utc_now(),
        }
    )
    return updated_case, event


def _contains_ref(refs: list[EntityRef], candidate: EntityRef) -> bool:
    return any(ref.entity_type == candidate.entity_type and ref.id == candidate.id for ref in refs)
