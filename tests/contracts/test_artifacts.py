from platform_contracts import Artifact, ArtifactKind


def test_artifact_minimum_valid_model_construction():
    artifact = Artifact(
        kind=ArtifactKind.NORMALIZED,
        format="parquet",
        storage_ref="object://bucket/normalized/data.parquet",
        content_hash="sha256:def456",
        summary="Normalized evidence dataset.",
    )

    assert artifact.artifact_id.startswith("artifact_")
    assert artifact.kind == ArtifactKind.NORMALIZED
    assert artifact.storage_ref.startswith("object://")

