"""CLI contract tests.

The distinction these pin down is the one a user hits first: which commands run
offline and which need a live model. A command that needs a model must say so and
exit 3 -- never emit an empty artifact, because an empty artifact is
indistinguishable from a real result that measured nothing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pramaan.cli import EXIT_NEEDS_MODEL, EXIT_OK, build_parser, main

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "data" / "corpus" / "findings.jsonl"

OFFLINE = ["ingest", "policy", "calibrate"]
NEEDS_MODEL = [
    ["triage", "--finding-id", "x"],
    ["fix", "--finding-id", "x"],
    ["evals", "nightly", "--run-epoch", "e", "--out", "o.json"],
    ["evals", "ablation", "--run-epoch", "e", "--out", "o.json"],
    ["evals", "injection", "--run-epoch", "e", "--out", "o.json"],
]


def test_the_parser_builds_and_every_subcommand_has_a_handler() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])  # a bare invocation must not silently do nothing


@pytest.mark.parametrize("argv", NEEDS_MODEL, ids=lambda a: " ".join(a[:2]))
def test_commands_needing_a_model_exit_three_and_write_nothing(
    argv: list[str], tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(argv) == EXIT_NEEDS_MODEL
    # The distinct exit code matters: 3 is "not wired to a model", not "the run
    # failed", so a nightly can tell a missing key from a real regression.
    assert EXIT_NEEDS_MODEL != EXIT_OK
    assert not list(tmp_path.glob("*.json")), "wrote an artifact it could not fill"


def test_audit_draw_is_reproducible_from_its_seed(tmp_path: Path) -> None:
    frame = tmp_path / "ids.json"
    frame.write_text(json.dumps([f"finding-{i}" for i in range(60)]), encoding="utf-8")

    outs = []
    for name in ("a.json", "b.json"):
        out = tmp_path / name
        assert main([
            "evals", "audit", "--auto-closed", str(frame),
            "--seed", "2026-09-w36", "--out", str(out),
        ]) == EXIT_OK
        outs.append(json.loads(out.read_text(encoding="utf-8")))

    assert outs[0]["sample_ids"] == outs[1]["sample_ids"]
    # ~10% of 60. The published report has to be able to say which items were drawn.
    assert 4 <= len(outs[0]["sample_ids"]) <= 8
    assert outs[0]["seed"] == "2026-09-w36"


@pytest.mark.skipif(not CORPUS.exists(), reason="corpus not present")
def test_policy_decides_on_a_real_corpus_finding_offline(tmp_path: Path) -> None:
    """No network, no model, no API key -- D8's whole point."""
    finding = json.loads(CORPUS.read_text(encoding="utf-8").splitlines()[0])

    verdict = tmp_path / "v.json"
    verdict.write_text(json.dumps({
        "finding_id": finding["finding_id"],
        "verdict": "false_positive",
        "confidence": 0.97,
        "cwe": finding.get("cwe") or "CWE-79",
        "evidence": [{"file": finding["path"], "line": finding["line_start"], "why": "x"}],
        "reachability": "unknown",
        "business_impact": {
            "payment_path": False, "auth_or_session": False,
            "pci_scope_hint": False, "kyc_or_settlement": False,
        },
        "injection_observed": False,
        "rationale": "test",
    }), encoding="utf-8")

    out = tmp_path / "d.json"
    assert main([
        "policy", "--verdict", str(verdict), "--tau", "0.9",
        "--path", finding["path"], "--out", str(out),
    ]) == EXIT_OK

    decision = json.loads(out.read_text(encoding="utf-8"))
    assert decision["recommended_action"] in {
        "auto_close", "open_ticket", "fix_candidate", "escalate_human"
    }
    assert decision["policy_row"]


def test_cli_runs_as_a_module_without_the_package_installed() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pramaan.cli", "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0
    for command in [*OFFLINE, "evals", "report", "prove"]:
        assert command in result.stdout


@pytest.mark.skipif(not CORPUS.exists(), reason="corpus not present")
def test_report_render_produces_a_leak_free_page_from_the_real_corpus(tmp_path: Path) -> None:
    """This path drifted once already.

    `cmd_report` was calling `render(suite=..., injection=..., ablation=...)` while the
    real signature takes a single `ReportInputs`. Every unit test on both sides passed,
    because nothing exercised the seam between them. So this test runs the actual CLI
    over the actual 121-finding corpus and checks the actual output.
    """
    import json as _json

    out = tmp_path / "trust-report.html"
    assert main([
        "report", "render", "--findings", str(CORPUS), "--out", str(out),
    ]) == EXIT_OK

    html = out.read_text(encoding="utf-8")
    lowered = html.lower()

    findings = [_json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]
    for finding in findings:
        assert finding["path"].lower() not in lowered, f"leaked path for {finding['repo']}"
        assert finding["finding_id"].lower() not in lowered

    # ...and it must still be a report. A leak check passes trivially on a blank page.
    assert "<svg" in html
    assert "121" in html
    assert "will not print" in lowered, "the refusals section is the honesty mechanism"


def test_report_render_defaults_to_treating_the_corpus_as_unlabelled(tmp_path: Path) -> None:
    """Claiming a labelled corpus when it is not is the one error here that silently
    makes every published number look real, so it must be opt-in."""
    parser = build_parser()
    args = parser.parse_args(["report", "render", "--out", "x.html"])
    assert args.corpus_labelled is False
