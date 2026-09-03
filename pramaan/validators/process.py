"""Subprocess plumbing shared by every validator in this lane.

Two properties are load-bearing.

**Nothing here raises.** A missing executable, a timeout and a non-zero exit are
all *recorded outcomes*, not exceptions. An exception escaping a validator would
be an outcome the proof bundle has no grade for, and the tempting way to handle
that upstream is `except: pass` — which is precisely how a validator that never
ran turns into a validator that "passed". `CommandResult.usable` is the single
question every caller asks before believing an exit code.

**The runner is a Protocol.** `CommandRunner` is injected everywhere, so the
whole validator lane is unit-testable against fakes with no semgrep, no PHP
toolchain and no network. The real `run_command` is exercised against genuine
temporary git repositories in the tests that need a real process.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, Sequence

__all__ = [
    "CommandResult",
    "CommandRunner",
    "run_command",
    "which",
]

DEFAULT_TIMEOUT_S = 600.0


@dataclass(frozen=True, slots=True)
class CommandResult:
    """One completed (or failed-to-complete) subprocess run."""

    argv: tuple[str, ...]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    started: bool = True
    error: str | None = None
    duration_s: float = 0.0

    @property
    def usable(self) -> bool:
        """Did the process run to completion, whatever it then exited with?

        A timeout is the case worth naming: a PoC exploit that hangs has not
        been "blocked", and a test suite that hangs is not "green". Both are
        `unavailable`, and both would read as a pass if callers only checked
        `returncode`.
        """
        return self.started and not self.timed_out and self.returncode is not None

    @property
    def ok(self) -> bool:
        return self.usable and self.returncode == 0

    @property
    def output(self) -> str:
        """stdout and stderr joined. Test runners split their summary lines
        across the two inconsistently, so parsers read both."""
        if self.stderr:
            return f"{self.stdout}\n{self.stderr}" if self.stdout else self.stderr
        return self.stdout

    @property
    def command(self) -> str:
        return " ".join(self.argv)

    def summary(self, *, limit: int = 400) -> str:
        """A short, log-safe description for a `ValidatorResult.detail`."""
        if not self.started:
            return f"{self.command}: {self.error or 'could not start'}"
        if self.timed_out:
            return f"{self.command}: timed out"
        tail = self.output.strip().replace("\n", " / ")
        if len(tail) > limit:
            tail = tail[:limit] + "..."
        return f"{self.command}: exit {self.returncode}" + (f": {tail}" if tail else "")


class CommandRunner(Protocol):
    """The seam. `run_command` satisfies it; tests pass a fake."""

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult: ...


def run_command(
    argv: Sequence[str],
    *,
    cwd: str | Path,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run `argv` in `cwd`. Never raises; never uses a shell.

    `shell=False` is not a style preference. The validators run against a tree a
    model has just written to, and building a command string from any part of
    that tree and handing it to `/bin/sh` would hand the fixer a shell it is not
    supposed to have.
    """
    args = tuple(str(a) for a in argv)
    merged = {**os.environ, **(env or {})}
    started_at = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False, by design
            args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=merged,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=args,
            stdout=_decode(exc.stdout),
            stderr=_decode(exc.stderr),
            timed_out=True,
            error=f"timed out after {timeout_s}s",
            duration_s=time.monotonic() - started_at,
        )
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
        return CommandResult(
            argv=args,
            started=False,
            error=f"{type(exc).__name__}: {exc}",
            duration_s=time.monotonic() - started_at,
        )
    return CommandResult(
        argv=args,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        duration_s=time.monotonic() - started_at,
    )


def _decode(raw: object) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def which(name: str) -> str | None:
    """Wrapped so tests can simulate a toolchain that is not installed."""
    return shutil.which(name)
