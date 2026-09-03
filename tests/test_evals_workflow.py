"""The nightly workflow's contract (D14, D19).

A workflow file is configuration, and configuration drifts silently. Four
properties are load-bearing enough to assert:

  * it runs on a **schedule**, not on push (D14);
  * every measuring step is **non-blocking**, so a bad night is news rather
    than a blocked repository;
  * the **disclosure gate self-check is not** non-blocking, and runs before the
    upload — a leak is the one failure that must stop the run;
  * a **fresh run epoch** is minted and threaded into every arm (D19), because
    an epoch that misses the cache by construction is the entire mechanism that
    makes the nightly a measurement rather than a replay.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
NIGHTLY = WORKFLOWS / "evals.yml"

# The measuring arms. Each may fail without failing the run.
MEASURING_STEPS = {
    "Full eval suite (nightly tier, cache bypassed)",
    "Context-scope ablation",
    "Paired prompt-injection run (D12)",
    "Render the trust report",
    "Weekly risk summary",
}


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(NIGHTLY.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def steps(workflow) -> list[dict]:
    return workflow["jobs"]["nightly"]["steps"]


@pytest.fixture(scope="module")
def raw() -> str:
    return NIGHTLY.read_text(encoding="utf-8")


def _triggers(workflow: dict) -> dict:
    # PyYAML resolves an unquoted `on:` key to the boolean True.
    return workflow.get("on") or workflow[True]


def test_the_nightly_runs_on_a_schedule_and_never_on_push(workflow):
    triggers = _triggers(workflow)
    assert "schedule" in triggers
    assert triggers["schedule"][0]["cron"].split()[1] == "2", "runs overnight"
    assert "push" not in triggers
    assert "pull_request" not in triggers
    assert "workflow_dispatch" in triggers, "an on-demand rerun is how you debug it"


def test_every_measuring_step_is_non_blocking(steps):
    named = {s.get("name"): s for s in steps}
    for name in MEASURING_STEPS:
        assert name in named, f"{name} is missing from the nightly"
        assert named[name].get("continue-on-error") is True, name


def test_the_disclosure_gate_is_the_one_step_allowed_to_fail_the_run(steps):
    gate = next(s for s in steps if s.get("name") == "Disclosure gate self-check")
    assert gate.get("continue-on-error") is not True

    order = [s.get("name") for s in steps]
    assert order.index("Disclosure gate self-check") < order.index("Upload artifacts"), (
        "the gate must run before anything leaves the runner"
    )


def test_a_fresh_run_epoch_is_minted_and_threaded_into_every_arm(steps, raw):
    mint = next(s for s in steps if s.get("name") == "Mint a fresh run epoch (D19)")
    assert "new_run_epoch()" in mint["run"]
    assert "PRAMAAN_RUN_EPOCH" in mint["run"]

    for name in (
        "Full eval suite (nightly tier, cache bypassed)",
        "Context-scope ablation",
        "Paired prompt-injection run (D12)",
    ):
        step = next(s for s in steps if s.get("name") == name)
        assert '--run-epoch "$PRAMAAN_RUN_EPOCH"' in step["run"], name

    assert "already appears in the published verdict" in raw, (
        "reusing an epoch would replay the cache; the workflow checks for it"
    )


def test_the_nightly_never_reuses_the_ci_stratification_seed(raw):
    """The CI tier replays a cached subset. The nightly must not imitate it."""
    assert "pramaan-ci-subset-v1" not in raw


def test_the_nightly_declares_that_it_does_not_block(raw):
    assert "REPORTED, NEVER BLOCKING" in raw
    assert "required checks" in raw


def test_live_arms_degrade_without_an_api_key(steps):
    """A nightly that hard-fails on a missing secret stops being run."""
    for name in (
        "Full eval suite (nightly tier, cache bypassed)",
        "Context-scope ablation",
        "Paired prompt-injection run (D12)",
    ):
        step = next(s for s in steps if s.get("name") == name)
        assert "ANTHROPIC_API_KEY" in step["run"], name
        assert "skipping" in step["run"], name


def test_the_report_renders_even_when_every_arm_is_skipped(steps):
    step = next(s for s in steps if s.get("name") == "Render the trust report")
    assert "ANTHROPIC_API_KEY" not in step.get("env", {})
    assert "render_to_file" in step["run"], "a library fallback, so an artifact always exists"


def test_every_cli_invocation_actually_parses(raw):
    """The workflow and `pramaan/cli.py` must not drift apart silently.

    A workflow that passes a flag the CLI does not accept fails at 02:17 UTC
    with an argparse error nobody is awake to read. Every `pramaan ...` command
    line in the file is extracted and run through the real parser.
    """
    import shlex

    from pramaan.cli import build_parser

    # Join YAML line continuations, then pull out the pramaan invocations.
    joined = raw.replace("\\\n", " ")
    invocations = re.findall(r"uv run (pramaan [^\n|]+)", joined)
    assert len(invocations) == 5, f"expected five CLI calls, found {invocations}"

    base = {
        "PRAMAAN_RUN_EPOCH": "20260903T000000Z-abcd1234",
        "PRAMAAN_ARTIFACTS": "artifacts",
    }
    # `$ABLATION` is a whole optional flag group. Both of its runtime values have
    # to parse, since the ablation is the arm most likely to have been skipped.
    for ablation in ("", "--ablation artifacts/ablation.json"):
        env = {**base, "ABLATION": ablation}
        parser = build_parser()
        for line in invocations:
            expanded = re.sub(
                r"\$([A-Z_][A-Z0-9_]*)", lambda m: env.get(m.group(1), ""), line
            )
            argv = shlex.split(expanded, posix=True)[1:]
            # raises SystemExit on an unknown, missing or misspelled flag
            parser.parse_args(argv)


def test_concurrency_prevents_two_epochs_racing(workflow):
    group = workflow["concurrency"]
    assert group["group"] == "pramaan-nightly"
    assert group["cancel-in-progress"] is False


def test_the_workflow_asks_for_no_write_permission(workflow):
    assert workflow["permissions"] == {"contents": "read"}


def test_the_blocking_tier_is_untouched():
    """Lane G owns `evals.yml` and nothing else in this directory."""
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert "pytest" in ci
    assert "schedule" not in ci, "the blocking tier runs on pull requests, not nightly"
    assert sorted(p.name for p in WORKFLOWS.glob("*.yml")) == ["ci.yml", "evals.yml"]
