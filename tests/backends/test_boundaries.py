from pathlib import Path

import platform_backends


def test_platform_backends_has_no_cai_or_old_repo_dependencies():
    package_root = Path(platform_backends.__file__).resolve().parent
    forbidden_fragments = [
        "import cai",
        "from cai",
        "cai-project",
        "collector",
        "analyzer",
        "data-runner",
        "runtime/",
    ]

    for path in package_root.rglob("*.py"):
        content = path.read_text(encoding="utf-8")
        for fragment in forbidden_fragments:
            assert fragment not in content
