"""Thin request models and response serializers for platform-api."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from platform_contracts import ApprovalDecision, ApprovalStatus, Artifact, Case, ObservationResult, QueryRequest, Run, WorkflowType


class ApiModel(BaseModel):
    """Strict thin transport model for the API layer."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CreateCaseRequest(ApiModel):
    client_id: str = Field(min_length=1)
    workflow_type: WorkflowType
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttachInputArtifactRequest(ApiModel):
    format: str = Field(default="json", min_length=1)
    payload: dict[str, Any]
    summary: str | None = None
    labels: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CreateRunRequest(ApiModel):
    case_id: str = Field(min_length=1)
    backend_id: str = Field(min_length=1)
    input_artifact_ids: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)


class ExecuteObservationRequest(ApiModel):
    requested_by: str = Field(default="platform_api", min_length=1)
    input_artifact_id: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class CompleteRunRequest(ApiModel):
    requested_by: str = Field(default="platform_api", min_length=1)
    reason: str | None = Field(default=None, min_length=1)


class ApprovalDecisionInput(ApiModel):
    status: ApprovalStatus
    reason: str = Field(min_length=1)
    approver_kind: str = Field(min_length=1)
    approver_ref: str | None = None


class ExecuteWatchGuardGuardedCustomQueryRequest(ApiModel):
    requested_by: str = Field(default="platform_api", min_length=1)
    input_artifact_id: str | None = None
    reason: str = Field(min_length=1)
    query: dict[str, Any]
    approval: ApprovalDecisionInput | None = None


class ExecuteWatchGuardDuckDBQueryRequest(ApiModel):
    requested_by: str = Field(default="platform_api", min_length=1)
    input_artifact_id: str | None = None
    reason: str = Field(min_length=1)
    family: str = Field(min_length=1, description="Log family: traffic, alarm, or event")
    filters: list[dict[str, Any]] = Field(default_factory=list, description="List of {field, op, value} filter dicts")
    limit: int = Field(default=50, ge=1, le=500)


def serialize_run_status(*, run: Run, observation_results: list[ObservationResult]) -> dict[str, Any]:
    return {
        "run": run.model_dump(mode="json"),
        "observation_results": [result.model_dump(mode="json") for result in observation_results],
        "summary": {
            "input_artifact_count": len(run.input_artifact_refs),
            "output_artifact_count": len(run.output_artifact_refs),
            "observation_result_count": len(observation_results),
        },
    }


def serialize_run_artifacts(
    *,
    run: Run,
    input_artifacts: list[Artifact],
    output_artifacts: list[Artifact],
) -> dict[str, Any]:
    return {
        "run": run.model_dump(mode="json"),
        "input_artifacts": [artifact.model_dump(mode="json") for artifact in input_artifacts],
        "output_artifacts": [artifact.model_dump(mode="json") for artifact in output_artifacts],
    }


def serialize_artifact_content(
    *,
    artifact: Artifact,
    content: object,
    content_source: str,
) -> dict[str, Any]:
    return {
        "artifact": artifact.model_dump(mode="json"),
        "content": content,
        "content_source": content_source,
    }


def serialize_custom_query_response(
    *,
    case: Case,
    run: Run,
    query_request: QueryRequest,
    approval_decision: ApprovalDecision | None,
    artifacts: list[Artifact],
    query_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "case": case.model_dump(mode="json"),
        "run": run.model_dump(mode="json"),
        "query_request": query_request.model_dump(mode="json"),
        "approval_decision": None if approval_decision is None else approval_decision.model_dump(mode="json"),
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
        "query_summary": query_summary,
    }


def serialize_case_summary(*, case: Case, artifacts: list[Artifact]) -> dict[str, Any]:
    return {
        "case": case.model_dump(mode="json"),
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
    }


def serialize_run_summary(
    *,
    run: Run,
    input_artifacts: list[Artifact],
    output_artifacts: list[Artifact],
    observation_results: list[ObservationResult],
) -> dict[str, Any]:
    return {
        "run": run.model_dump(mode="json"),
        "input_artifacts": [artifact.model_dump(mode="json") for artifact in input_artifacts],
        "output_artifacts": [artifact.model_dump(mode="json") for artifact in output_artifacts],
        "observation_results": [result.model_dump(mode="json") for result in observation_results],
    }


def serialize_execution_response(
    *,
    case: Case,
    run: Run,
    artifacts: list[Artifact],
    observation_result: ObservationResult,
) -> dict[str, Any]:
    return {
        "case": case.model_dump(mode="json"),
        "run": run.model_dump(mode="json"),
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
        "observation_result": observation_result.model_dump(mode="json"),
    }
