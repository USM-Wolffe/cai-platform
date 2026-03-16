from pathlib import Path

import cai_orchestrator


def test_cai_orchestrator_has_no_vendored_cai_tree_and_no_old_repo_dependencies():
    package_root = Path(cai_orchestrator.__file__).resolve().parent
    forbidden_fragments = [
        "cai-project",
        "collector",
        "analyzer",
        "data-runner",
        "runtime/",
        "platform_core",
        "platform_backends",
        "platform_adapters",
        "platform_contracts",
    ]

    assert not (package_root / "cai").exists()
    assert not (package_root / "sdk").exists()

    for path in package_root.rglob("*.py"):
        content = path.read_text(encoding="utf-8")
        for fragment in forbidden_fragments:
            assert fragment not in content
