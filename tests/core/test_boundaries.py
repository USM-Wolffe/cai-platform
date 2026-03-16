from pathlib import Path

import platform_core


def test_platform_core_has_no_cai_imports():
    package_root = Path(platform_core.__file__).resolve().parent
    for path in package_root.rglob("*.py"):
        content = path.read_text(encoding="utf-8")
        assert "import cai" not in content
        assert "from cai" not in content
