"""Lane E — the subprocess seam every validator sits behind."""

from __future__ import annotations

import sys

from pramaan.validators.process import CommandResult, run_command, which


def test_captures_exit_code_and_streams(tmp_path):
    result = run_command(
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"],
        cwd=tmp_path,
    )
    assert result.returncode == 3
    assert "out" in result.stdout
    assert "err" in result.stderr
    assert "out" in result.output and "err" in result.output
    assert result.usable is True
    assert result.ok is False


def test_missing_executable_is_not_usable(tmp_path):
    result = run_command(["pramaan-definitely-not-installed"], cwd=tmp_path)
    assert result.started is False
    assert result.usable is False
    assert result.ok is False
    assert "FileNotFoundError" in (result.error or "")


def test_timeout_is_not_usable(tmp_path):
    """A hung process must never read as a clean exit. This is the shape of the
    silent failure in `poc.py`: a timed-out exploit is not a blocked exploit."""
    result = run_command(
        [sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout_s=0.4
    )
    assert result.timed_out is True
    assert result.usable is False
    assert result.ok is False
    assert "timed out" in result.summary()


def test_env_overrides_are_merged(tmp_path):
    result = run_command(
        [sys.executable, "-c", "import os; print(os.environ['PRAMAAN_TEST'])"],
        cwd=tmp_path,
        env={"PRAMAAN_TEST": "abc"},
    )
    assert result.stdout.strip() == "abc"
    # The rest of the environment survives, or nothing that needs PATH would run.
    assert result.ok


def test_summary_truncates_long_output():
    result = CommandResult(argv=("x",), returncode=0, stdout="y" * 2000)
    assert result.summary().endswith("...")
    assert len(result.summary()) < 500


def test_which_finds_the_interpreter():
    assert which("python3") or which("python")
    assert which("pramaan-definitely-not-installed") is None
