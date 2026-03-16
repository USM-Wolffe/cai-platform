from __future__ import annotations

from platform_contracts import Artifact, ArtifactKind, Case, Run


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


class RecordingAuditPort:
    def __init__(self) -> None:
        self.timeline_events = []

    def append_timeline_event(self, *, case_id: str, event) -> None:
        self.timeline_events.append((case_id, event.model_copy(deep=True)))

    def append_decision_record(self, *, case_id: str, decision) -> None:
        return None


def make_input_artifact(*, artifact_id: str = "artifact_input") -> Artifact:
    return Artifact(
        artifact_id=artifact_id,
        kind=ArtifactKind.INPUT,
        format="json",
        storage_ref=f"memory://watchguard/{artifact_id}.json",
        content_hash=f"sha256:{artifact_id}",
    )
