"""Command-line entry points.

Deliberately thin. Every subcommand is a dispatcher over library functions that are
already unit-tested; the CLI's own job is argument handling, artifact writing, and
being honest about which commands can run offline.

That last part matters more than it sounds. Roughly half of this surface is pure
computation over cached verdicts -- calibration, metrics, the audit draw, the trust
report -- and runs with no API key at all. That is a design goal, not an accident:
the calibration must be reproducible from the published verdict table by someone who
has no access to the model that produced it. Commands that genuinely need a live model
say so and exit non-zero rather than emitting an empty artifact that looks like a result.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NEEDS_MODEL = 3  # distinct: "not wired to a model", not "the run failed"


def _jsonable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return _jsonable(asdict(obj))
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _write(path: str | None, payload: Any) -> None:
    text = json.dumps(_jsonable(payload), indent=2, sort_keys=True)
    if path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _load_labels(path: Path) -> dict[str, str]:
    """Accept either the labelling CSV or a plain JSON map.

    The CSV is the artifact a human actually fills in, so reading it directly avoids
    a conversion step that could silently drop or relabel rows.
    """
    if path.suffix.lower() == ".csv":
        import csv

        with path.open(encoding="utf-8") as handle:
            return {
                row["finding_id"]: row["label"].strip()
                for row in csv.DictReader(handle)
                if row.get("label", "").strip()
            }
    return json.loads(path.read_text(encoding="utf-8"))


def _needs_model(command: str, why: str) -> int:
    print(
        f"`pramaan {command}` needs a live model and is not wired to one here.\n{why}\n"
        "Nothing was written. This exits 3 rather than emitting an empty artifact, "
        "because an empty artifact is indistinguishable from a real result that "
        "measured nothing.",
        file=sys.stderr,
    )
    return EXIT_NEEDS_MODEL


# --------------------------------------------------------------------------- #
# ingest
# --------------------------------------------------------------------------- #

def cmd_ingest(args: argparse.Namespace) -> int:
    from pramaan.ingest import IngestError, dedup, parse_json, parse_sarif

    text = Path(args.input).read_text(encoding="utf-8")
    parse = parse_sarif if args.format == "sarif" else parse_json
    try:
        findings = parse(text, repo=args.repo)
    except IngestError as exc:
        print(f"ingest failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    before = len(findings)
    findings = dedup(findings)
    print(f"{before} raw -> {len(findings)} after dedup", file=sys.stderr)

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as handle:
            for finding in findings:
                handle.write(json.dumps(_jsonable(finding.to_dict()), sort_keys=True) + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        for finding in findings:
            print(json.dumps(_jsonable(finding.to_dict()), sort_keys=True))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# policy
# --------------------------------------------------------------------------- #

def cmd_policy(args: argparse.Namespace) -> int:
    """Pure. No model, no network -- the whole point of D8."""
    from pramaan.policy import decide, tag
    from pramaan.schemas import BusinessImpact, Verdict

    raw = json.loads(Path(args.verdict).read_text(encoding="utf-8"))
    verdict = Verdict.from_dict(raw)
    path_tags: BusinessImpact = tag(args.path) if args.path else BusinessImpact()
    decision = decide(verdict, path_tags, args.tau)
    _write(args.out, decision)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# calibrate
# --------------------------------------------------------------------------- #

def cmd_calibrate(args: argparse.Namespace) -> int:
    """Re-derives tau from a published verdict table. No API key required."""
    from pramaan.calibration.tau import derive, reliability_diagram
    from pramaan.evals.labels import from_attempts, one_row_per_finding
    from pramaan.store.verdict_cache import load_jsonl

    rows = list(load_jsonl(Path(args.verdicts)))
    labels = _load_labels(Path(args.labels))
    # on_missing_label="skip": an unlabelled finding is not an error, it is simply
    # outside the calibration set. Erroring would make a partially labelled corpus
    # unusable, which is the normal state of one being labelled by hand.
    items = from_attempts([r.attempt for r in rows], labels)
    scored = one_row_per_finding(items)

    result = derive(scored, k=args.k, repeats=args.repeats)
    diagram = reliability_diagram(scored)
    _write(args.out, {"tau": result, "reliability": diagram})
    return EXIT_OK


# --------------------------------------------------------------------------- #
# evals
# --------------------------------------------------------------------------- #

def cmd_evals(args: argparse.Namespace) -> int:
    if args.eval_command == "audit":
        from pramaan.evals.audit_sample import draw

        ids = json.loads(Path(args.auto_closed).read_text(encoding="utf-8"))
        _write(args.out, draw(ids, fraction=args.fraction, seed=args.seed))
        return EXIT_OK

    if args.eval_command == "nightly":
        return _needs_model(
            "evals nightly",
            "It replays every finding k times against the live model with a fresh "
            "run-epoch, which by design bypasses the verdict cache (D19).",
        )
    if args.eval_command == "ablation":
        return _needs_model(
            "evals ablation",
            "The context-scope ablation runs each finding at every context width, so "
            "there is nothing cached to read.",
        )
    if args.eval_command == "injection":
        return _needs_model(
            "evals injection",
            "The paired run (D12) needs both arms live -- and the control arm must "
            "actually be compromised, which cannot be established from a cache.",
        )
    return EXIT_ERROR


# --------------------------------------------------------------------------- #
# triage / fix / prove
# --------------------------------------------------------------------------- #

def cmd_triage(args: argparse.Namespace) -> int:
    return _needs_model(
        "triage", "It calls the model once per attempt via claude_agent_sdk."
    )


def cmd_fix(args: argparse.Namespace) -> int:
    return _needs_model(
        "fix", "The fixer runs in a sandboxed worktree against a live model."
    )


def cmd_prove(args: argparse.Namespace) -> int:
    """Deterministic: validators only, no model. Needs a patched tree to point at."""
    from pramaan.proof.bundle import run_proof

    print(
        "`pramaan prove` needs a base tree, a patched tree and a proof request; "
        "wire it through pramaan.proof.bundle.run_proof for now.",
        file=sys.stderr,
    )
    _ = run_proof
    return EXIT_ERROR


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #

def cmd_report(args: argparse.Namespace) -> int:
    from pramaan.report import trust_report

    if args.report_command == "summary":
        from pramaan.report import summary as summary_mod

        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(summary_mod.render(), encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
        return EXIT_OK

    def _load(path: str | None) -> Any:
        return json.loads(Path(path).read_text(encoding="utf-8")) if path else None

    html = trust_report.render(
        suite=_load(args.suite),
        injection=_load(args.injection),
        ablation=_load(args.ablation),
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out} ({len(html)} bytes)", file=sys.stderr)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pramaan",
        description="Evidence-gated vulnerability triage and remediation harness.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", help="Semgrep output -> normalised Findings")
    p.add_argument("--input", required=True)
    p.add_argument("--repo", required=True, help="bare repo name; it is a fingerprint term")
    p.add_argument("--format", choices=["sarif", "json"], default="json")
    p.add_argument("--out")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("triage", help="read-only triage of one finding (needs a model)")
    p.add_argument("--finding-id", required=True)
    p.add_argument("--run-epoch")
    p.add_argument("-k", type=int, default=1)
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("policy", help="act-vs-escalate decision (pure, offline)")
    p.add_argument("--verdict", required=True)
    p.add_argument("--tau", type=float, required=True)
    p.add_argument("--path", help="source path, for deterministic sensitivity tagging")
    p.add_argument("--out")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("fix", help="draft a fix in a sandboxed worktree (needs a model)")
    p.add_argument("--finding-id", required=True)
    p.set_defaults(func=cmd_fix)

    p = sub.add_parser("prove", help="run the deterministic proof validators")
    p.add_argument("--finding-id", required=True)
    p.set_defaults(func=cmd_prove)

    p = sub.add_parser("calibrate", help="re-derive tau from a verdict table (offline)")
    p.add_argument("--verdicts", required=True, help="exported verdict table (JSONL)")
    p.add_argument("--labels", required=True)
    p.add_argument("-k", type=int, default=5)
    p.add_argument("--repeats", type=int, default=10)
    p.add_argument("--out")
    p.set_defaults(func=cmd_calibrate)

    p = sub.add_parser("evals", help="the Kasauti eval suite")
    esub = p.add_subparsers(dest="eval_command", required=True)
    for name, helptext in [
        ("nightly", "full suite, fresh run-epoch (D19)"),
        ("ablation", "context-scope ablation"),
    ]:
        q = esub.add_parser(name, help=helptext)
        q.add_argument("--run-epoch", required=True)
        q.add_argument("--out", required=True)
    q = esub.add_parser("injection", help="paired injection run (D12)")
    q.add_argument("--run-epoch", required=True)
    q.add_argument("--out", required=True)
    q.add_argument(
        "--arm",
        choices=["control", "hardened", "paired"],
        default="paired",
        help="single arms exist so a control that stops being compromised is debuggable",
    )
    q = esub.add_parser("audit", help="draw the 10%% auto-close audit sample (offline)")
    q.add_argument("--auto-closed", required=True, help="JSON list of auto-closed ids")
    q.add_argument("--fraction", type=float, default=0.10)
    # A string seed, not an int: it is recorded in the report so the draw can be
    # reproduced, and a named seed ("2026-09-w36") says what it was for.
    q.add_argument("--seed", default="pramaan-audit-v1")
    q.add_argument("--out", required=True)
    p.set_defaults(func=cmd_evals)

    p = sub.add_parser("report", help="trust report and risk summary")
    rsub = p.add_subparsers(dest="report_command", required=True)
    q = rsub.add_parser("render", help="render the trust report to HTML")
    q.add_argument("--suite")
    q.add_argument("--injection")
    q.add_argument("--ablation", help="optional: renders without it if absent")
    q.add_argument("--out", required=True)
    q = rsub.add_parser("summary", help="weekly risk summary with SLA clocks")
    q.add_argument("--out", required=True)
    p.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
