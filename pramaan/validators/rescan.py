"""`rescan_clean`: re-run the *same* Semgrep rule on the patched tree.

PCI DSS 4.0.1 req 11.3.1 / 11.4.4 want a rescan after remediation, and the proof
bundle is that evidence. The word doing the work is *same*: rescanning with a
different ruleset, or with a ruleset that failed to load, produces a clean
report for reasons that have nothing to do with the patch.

Three ways a rescan lies, all handled here as `unavailable` rather than `pass`:

  * **Semgrep is not installed** — a missing binary produces no findings.
  * **Semgrep scanned nothing** — a bad `--include`, an over-broad
    `.semgrepignore` or a wrong path yields `results: []` over zero files. This
    is checked explicitly against `paths.scanned`, because it is indistinguishable
    from a real clean result if you only read `results`.
  * **The rule never fired on the base tree either** — then a clean patched tree
    is not evidence about the patch. This is the rescan's analogue of
    `INVALID_POC`, and it is available through `base_tree`.

`config` has no default. A default would silently become the ruleset every proof
in the project was produced with, and the whole point is that it is the ruleset
the finding came from.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from pramaan.ingest.errors import IngestError
from pramaan.ingest.semgrep import parse_json
from pramaan.schemas import Finding, ValidatorResult
from pramaan.validators.process import (
    CommandResult,
    CommandRunner,
    run_command,
    which,
)

__all__ = [
    "RESCAN_TIMEOUT_S",
    "SEMGREP_BIN",
    "RescanOutcome",
    "build_semgrep_argv",
    "rescan",
    "run_semgrep",
]

VALIDATOR_NAME = "rescan_clean"
SEMGREP_BIN = "semgrep"
RESCAN_TIMEOUT_S = 900.0

# 0 = clean, 1 = findings. Everything else is Semgrep telling us it failed.
_RAN_EXIT_CODES = frozenset({0, 1})


def build_semgrep_argv(
    *,
    config: str,
    targets: Sequence[str] = (),
    semgrep_bin: str = SEMGREP_BIN,
    timeout_per_rule_s: int = 60,
) -> tuple[str, ...]:
    """`--metrics=off` and `--disable-version-check` keep the rescan offline.

    The fixer runs egress-free; a validator that phones the Semgrep registry
    mid-proof would put the network back in the loop at exactly the step whose
    reproducibility is the claim. Pass a local rule file as `config` for a fully
    offline rescan.
    """
    argv = [
        semgrep_bin,
        "scan",
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        "--config",
        config,
        "--timeout",
        str(timeout_per_rule_s),
    ]
    argv.extend(targets or ["."])
    return tuple(argv)


@dataclass(frozen=True, slots=True)
class RescanOutcome:
    """One Semgrep run, already interrogated for the ways it can lie."""

    ran: bool
    findings: tuple[Finding, ...] = ()
    scanned_files: int = 0
    detail: str = ""
    command: str = ""
    raw_errors: tuple[str, ...] = ()

    @property
    def matches(self) -> tuple[Finding, ...]:
        return self.findings


def _scanned_count(doc: Any) -> int | None:
    """`paths.scanned` is a list in every Semgrep version this targets. `None`
    means the key was absent, which is not the same as zero."""
    if not isinstance(doc, dict):
        return None
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return None
    scanned = paths.get("scanned")
    if isinstance(scanned, list):
        return len(scanned)
    return None


def _semgrep_errors(doc: Any) -> tuple[str, ...]:
    if not isinstance(doc, dict):
        return ()
    errors = doc.get("errors")
    if not isinstance(errors, list):
        return ()
    out: list[str] = []
    for err in errors:
        if isinstance(err, dict):
            out.append(str(err.get("message") or err.get("type") or err))
        else:
            out.append(str(err))
    return tuple(out)


def run_semgrep(
    tree: str | Path,
    *,
    config: str,
    rule_id: str | None = None,
    path: str | None = None,
    repo: str | None = None,
    runner: CommandRunner = run_command,
    semgrep_bin: str = SEMGREP_BIN,
    timeout_s: float = RESCAN_TIMEOUT_S,
    require_scanned_files: bool = True,
    which_fn: Callable[[str], str | None] = which,
) -> RescanOutcome:
    """Run Semgrep over `tree` and return the findings for `rule_id`.

    `ran=False` means the result carries no information about the tree, for any
    of the reasons in the module docstring.
    """
    if which_fn(semgrep_bin) is None:
        return RescanOutcome(
            ran=False, detail=f"{semgrep_bin} is not installed; rescan did not run"
        )

    targets = [path] if path else []
    argv = build_semgrep_argv(config=config, targets=targets, semgrep_bin=semgrep_bin)
    result: CommandResult = runner(argv, cwd=tree, timeout_s=timeout_s)
    command = result.command

    if not result.usable:
        return RescanOutcome(ran=False, detail=result.summary(), command=command)
    if result.returncode not in _RAN_EXIT_CODES:
        return RescanOutcome(
            ran=False,
            detail=f"semgrep exited {result.returncode}: {result.summary()}",
            command=command,
        )

    try:
        doc = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return RescanOutcome(
            ran=False, detail=f"semgrep output is not JSON: {exc}", command=command
        )

    scanned = _scanned_count(doc)
    errors = _semgrep_errors(doc)
    if require_scanned_files and scanned == 0:
        return RescanOutcome(
            ran=False,
            scanned_files=0,
            detail=(
                "semgrep scanned 0 files; a clean result here is an artefact of "
                "the target selection, not of the patch"
            ),
            command=command,
            raw_errors=errors,
        )

    try:
        findings = parse_json(result.stdout, repo=repo)
    except IngestError as exc:
        return RescanOutcome(
            ran=False,
            scanned_files=scanned or 0,
            detail=f"could not parse semgrep output: {exc}",
            command=command,
            raw_errors=errors,
        )

    if rule_id is not None:
        findings = [f for f in findings if f.rule_id == rule_id]
    if path is not None:
        wanted = path.replace("\\", "/").lstrip("./")
        findings = [f for f in findings if f.path.replace("\\", "/").lstrip("./") == wanted]

    return RescanOutcome(
        ran=True,
        findings=tuple(findings),
        scanned_files=scanned if scanned is not None else -1,
        detail="",
        command=command,
        raw_errors=errors,
    )


def rescan(
    *,
    patched_tree: str | Path,
    config: str,
    rule_id: str | None = None,
    path: str | None = None,
    repo: str | None = None,
    base_tree: str | Path | None = None,
    runner: CommandRunner = run_command,
    semgrep_bin: str = SEMGREP_BIN,
    timeout_s: float = RESCAN_TIMEOUT_S,
    which_fn: Callable[[str], str | None] = which,
) -> ValidatorResult:
    """Re-run `rule_id` on the patched tree.

    Args:
        patched_tree: the worktree the fixer edited.
        config: the ruleset the finding came from. A local path keeps the rescan
            offline and reproducible; a registry id (`p/php`) does not.
        rule_id: filter results to the rule that produced the finding. `None`
            rescans for *any* finding from the ruleset, which is stricter.
        path: restrict the scan to one file. Speeds a per-finding rescan up by
            two orders of magnitude, at the cost of not noticing a defect the
            patch moved somewhere else — so `base_tree` is worth pairing with it.
        base_tree: when given, the rule must fire here. If it does not, the
            patched tree being clean says nothing and the result is
            `unavailable`.
    """
    if base_tree is not None:
        before = run_semgrep(
            base_tree,
            config=config,
            rule_id=rule_id,
            path=path,
            repo=repo,
            runner=runner,
            semgrep_bin=semgrep_bin,
            timeout_s=timeout_s,
            which_fn=which_fn,
        )
        if not before.ran:
            return ValidatorResult(
                VALIDATOR_NAME,
                "unavailable",
                f"base-tree rescan did not run: {before.detail}",
                {"stage": "base", "command": before.command},
            )
        if not before.findings:
            return ValidatorResult(
                VALIDATOR_NAME,
                "unavailable",
                (
                    f"rule {rule_id or '<any>'} does not fire on the base tree; a "
                    "clean patched tree is not evidence about this patch"
                ),
                {"stage": "base", "base_matches": 0, "command": before.command},
            )

    after = run_semgrep(
        patched_tree,
        config=config,
        rule_id=rule_id,
        path=path,
        repo=repo,
        runner=runner,
        semgrep_bin=semgrep_bin,
        timeout_s=timeout_s,
        which_fn=which_fn,
    )
    if not after.ran:
        return ValidatorResult(
            VALIDATOR_NAME,
            "unavailable",
            after.detail,
            {"stage": "patched", "command": after.command},
        )

    evidence: dict[str, Any] = {
        "stage": "patched",
        "rule_id": rule_id,
        "config": config,
        "scanned_files": after.scanned_files,
        "match_count": len(after.findings),
        "matches": [
            {"path": f.path, "line_start": f.line_start, "rule_id": f.rule_id}
            for f in after.findings[:20]
        ],
        "semgrep_errors": list(after.raw_errors),
        "command": after.command,
    }

    if after.findings:
        where = ", ".join(f"{f.path}:{f.line_start}" for f in after.findings[:5])
        return ValidatorResult(
            VALIDATOR_NAME,
            "fail",
            f"{len(after.findings)} match(es) for {rule_id or '<any rule>'} remain: {where}",
            evidence,
        )
    return ValidatorResult(
        VALIDATOR_NAME,
        "pass",
        f"no matches for {rule_id or '<any rule>'} across {after.scanned_files} scanned file(s)",
        evidence,
    )
