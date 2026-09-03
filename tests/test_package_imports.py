"""Every package must import on its own, and its declared surface must resolve.

The suite imports submodules directly (`pramaan.evals.labels`), which never runs the
sibling `__init__` that closes an import cycle. So 1036 green tests coexisted with
`import pramaan.calibration` and `import pramaan.tickets` both raising ImportError --
broken for anyone using the library, invisible to the tests. These run each import in a
fresh interpreter, because import cycles are order-dependent and a shared process that
already imported the modules cannot see them.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PACKAGES = [
    "pramaan",
    "pramaan.schemas",
    "pramaan.store",
    "pramaan.ingest",
    "pramaan.policy",
    "pramaan.agent",
    "pramaan.evals",
    "pramaan.calibration",
    "pramaan.proof",
    "pramaan.validators",
    "pramaan.fix",
    "pramaan.mcp",
    "pramaan.tickets",
    "pramaan.report",
]

ROOT = Path(__file__).resolve().parent.parent


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=90,
    )


@pytest.mark.parametrize("package", PACKAGES)
def test_package_imports_in_a_fresh_interpreter(package: str) -> None:
    result = _run(f"import {package}")
    assert result.returncode == 0, (
        f"{package} failed to import on its own:\n{result.stderr.strip()}"
    )


@pytest.mark.parametrize("package", PACKAGES)
def test_every_exported_name_actually_resolves(package: str) -> None:
    """A lazy `__getattr__` that silently returns nothing is worse than a cycle."""
    result = _run(
        f"import {package} as m\n"
        "names = getattr(m, '__all__', [])\n"
        "missing = [n for n in names if not hasattr(m, n)]\n"
        "assert not missing, f'declared in __all__ but unresolvable: {missing}'\n"
    )
    assert result.returncode == 0, result.stderr.strip()
