"""The trust report: a self-contained HTML page, and a disclosure gate around it.

Everything else in Pramaan measures. This publishes, which makes it the one
place where a mistake becomes permanent and public — so the most important
property of this module is not what it renders but what it refuses to.

Three refusals are structural rather than editorial:

1. **No `file:line` for anything unfixed.** `render()` builds a
   `redaction.RedactionLedger` before it writes a byte, renders evidence only
   for findings the ledger marks `full`, and then runs `redaction.assert_clean`
   over its own finished output. A leaked path is a raised
   `DisclosureViolation`, not a published page. There is no flag to skip it.

2. **No number the corpus cannot support.** Every proportion arrives as a
   `stats.Rate` and goes through `_rate_html`, which prints counts and an
   interval — and, below the reporting minimum, prints the counts and says the
   rate is withheld. A zero-event rate additionally carries the rule-of-three
   upper bound, because "0/10" and "0%" are different claims and only one of
   them is true.

3. **No recomputation.** Precision, ECE, tau, pass^k and the injection ASRs are
   read off the eval lane's result objects. This module counts findings by
   repository, rule and CWE — which the disclosure policy names as publishable —
   and computes nothing else.

The page is one file: inline CSS, hand-rolled inline SVG, no script, no font
download, no CDN. It is themed for light and dark through CSS variables, and it
prints.
"""

from __future__ import annotations

import html
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pramaan.calibration.tau import ReliabilityDiagram, TauResult
from pramaan.evals.agreement import IntraRaterAgreement, ModelHumanAgreement
from pramaan.evals.injection import PairedInjectionResult
from pramaan.evals.runner import CorpusReport, SuiteResult
from pramaan.evals.stats import InsufficientData, Rate, zero_events_upper_bound
from pramaan.proof.bundle import FunnelReport, funnel_report, split_by_funnel
from pramaan.report import charts
from pramaan.report.redaction import (
    SYNTHETIC_TARGET_ALLOWLIST,
    RedactionLedger,
    assert_clean,
    build_ledger,
)
from pramaan.report.summary import RiskSummary, summarise
from pramaan.schemas import Finding, FunnelKind, ProofBundle

__all__ = [
    "ReportInputs",
    "Withholding",
    "render",
    "render_to_file",
]


# --------------------------------------------------------------------------- #
# Inputs
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class ReportInputs:
    """Everything the report draws, already measured elsewhere.

    Every field is optional. A report with nothing in it renders as a page that
    says there is nothing in it — which is the honest artifact for a run that
    produced no findings, and is a tested path rather than an accident.
    """

    findings: Sequence[Finding] = ()
    bundles: Sequence[ProofBundle] = ()
    suite: SuiteResult | None = None
    injection: PairedInjectionResult | None = None
    intra_rater: IntraRaterAgreement | None = None
    model_human: ModelHumanAgreement | None = None
    summary: RiskSummary | None = None
    funnels: Mapping[str, FunnelKind | None] | None = None
    generated_at: datetime | None = None
    commit_sha: str = ""
    model_id: str = ""
    run_epoch: str = ""
    corpus_labelled: bool = True
    title: str = "Pramaan — trust report"
    allowlist: frozenset[str] = SYNTHETIC_TARGET_ALLOWLIST


@dataclass(frozen=True, slots=True)
class Withholding:
    """One number the report declined to print, and why."""

    topic: str
    reason: str


@dataclass
class _Ctx:
    """Render-time accumulator. Not part of the public surface."""

    ledger: RedactionLedger
    withheld: list[Withholding] = field(default_factory=list)

    def refuse(self, topic: str, reason: str) -> None:
        self.withheld.append(Withholding(topic, reason))

    def clean(self, text: str) -> str:
        return _e(self.ledger.scrub(text))


# --------------------------------------------------------------------------- #
# Small HTML helpers
# --------------------------------------------------------------------------- #

def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _section(anchor: str, heading: str, *blocks: str, lede: str = "") -> str:
    intro = f'<p class="lede">{lede}</p>' if lede else ""
    body = "".join(b for b in blocks if b)
    return (
        f'<section id="{_e(anchor)}"><h2>{_e(heading)}</h2>{intro}{body}</section>'
    )


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]], *, caption: str = "") -> str:
    """Rows are pre-escaped HTML fragments; headers are escaped here."""
    head = "".join(f"<th scope=\"col\">{_e(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )
    cap = f"<caption>{_e(caption)}</caption>" if caption else ""
    if not body:
        body = (
            f'<tr><td colspan="{len(headers)}" class="muted">nothing to report'
            "</td></tr>"
        )
    return f'<div class="scroll"><table>{cap}<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _note(text: str) -> str:
    return f'<p class="note">{text}</p>'


def _callout(text: str, *, kind: str = "info") -> str:
    return f'<div class="callout {_e(kind)}">{text}</div>'


def _counts_by(findings: Sequence[Finding], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        value = getattr(finding, key, None) or "(unrecorded)"
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


# --------------------------------------------------------------------------- #
# Rendering a rate honestly
# --------------------------------------------------------------------------- #

def _rate_html(rate: Rate, ctx: _Ctx, *, topic: str = "") -> str:
    """A proportion, or an explicit refusal to state one.

    Two bounds can appear for a clean run, and they are not the same statistic:
    the Wilson interval that `Rate` carries, and the rule-of-three upper bound
    from `stats.zero_events_upper_bound`. Both are labelled. A reader who sees
    "0/10" next to "95% upper bound 26%" cannot come away thinking the harness
    was measured at zero.
    """
    if rate.n == 0:
        if topic:
            ctx.refuse(topic, "no observations — the denominator is zero")
        return '<span class="withheld">no observations</span>'

    counts = f'<span class="counts">{rate.successes}/{rate.n}</span>'
    if not rate.reportable:
        if topic:
            ctx.refuse(
                topic,
                f"n = {rate.n} is below the reporting minimum of {rate.min_n}; "
                f"the counts are published ({rate.successes} of {rate.n}) and "
                "the rate is not",
            )
        extra = ""
        if rate.successes == 0:
            extra = (
                f' <span class="muted">· rule-of-three 95% upper bound '
                f"{zero_events_upper_bound(rate.n):.1%}</span>"
            )
        return (
            f'{counts} <span class="withheld">rate withheld — n below the '
            f"reporting minimum of {rate.min_n}</span>{extra}"
        )

    lo, hi = rate.interval  # type: ignore[misc]
    point = rate.point
    assert point is not None
    out = (
        f'{counts} = <strong>{point:.1%}</strong> '
        f'<span class="muted">[95% Wilson CI {lo:.1%}–{hi:.1%}]</span>'
    )
    if rate.successes == 0:
        out += (
            f' <span class="muted">· rule-of-three 95% upper bound '
            f"{zero_events_upper_bound(rate.n):.1%}</span>"
        )
    return out


def _tau_value(result: TauResult | None) -> float | None:
    if result is None:
        return None
    try:
        return result.recommended_tau()
    except InsufficientData:
        return None


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #

_POLICY_TEXT = (
    "Pramaan's corpus is real Semgrep output from live Razorpay payment plugins. "
    "Razorpay's bug bounty programme excludes open-source repositories, so there "
    "is no safe harbour covering this work. A public <code>file:line</code> on an "
    "unfixed defect in a payment plugin is a free exploit primitive, so this "
    "report publishes counts, classes, confidence distributions and per-rule "
    "precision — and withholds paths, snippets and exploit detail for everything "
    "that is not a synthetic target with a proven fix. True positives go to "
    "maintainers privately, as a private annex containing what this page omits."
)


def _header(inputs: ReportInputs, ctx: _Ctx, stamp: datetime) -> str:
    meta_rows = [
        ("generated", stamp.isoformat()),
        ("commit", inputs.commit_sha or "(not stamped)"),
        ("model", inputs.model_id or "(not stamped)"),
        ("run epoch", inputs.run_epoch or (inputs.suite.run_epoch if inputs.suite else "") or "(not stamped)"),
        ("eval tier", inputs.suite.tier if inputs.suite else "(no eval suite supplied)"),
    ]
    meta = "".join(
        f"<div><dt>{_e(k)}</dt><dd>{_e(v)}</dd></div>" for k, v in meta_rows
    )
    return (
        f"<header><h1>{_e(inputs.title)}</h1>"
        f'<p class="lede">Pramaan (प्रमाण, <em>proof</em>) triages scanner findings with an '
        "agent and publishes what the triage is actually worth. Every number below "
        "re-derives from the published verdict table with no API key and no network."
        "</p>"
        f'<dl class="meta">{meta}</dl></header>'
    )


def _disclosure_section(inputs: ReportInputs, ctx: _Ctx) -> str:
    ledger = ctx.ledger
    rows = [
        (
            _e(reason),
            f'<span class="counts">{count}</span>',
        )
        for reason, count in ledger.reasons().items()
    ]
    repo_rows = [
        (_e(repo), f'<span class="counts">{count}</span>')
        for repo, count in ledger.withheld_repos().items()
    ]
    notes = "".join(_note(ctx.clean(n)) for n in ledger.notes)
    return _section(
        "disclosure",
        "Disclosure policy (D17), enforced in code",
        _callout(_POLICY_TEXT, kind="policy"),
        _table(
            ["gate outcome", "findings"],
            [
                (
                    "full evidence — synthetic target with a full-proof funnel",
                    f'<span class="counts">{ledger.n_full}</span>',
                ),
                (
                    "aggregate only",
                    f'<span class="counts">{ledger.n_withheld}</span>',
                ),
            ],
            caption="How each finding was classified",
        ),
        _table(["reason withheld", "findings"], rows) if rows else "",
        _table(["repository", "findings withheld"], repo_rows) if repo_rows else "",
        notes,
        _note(
            "The gate is two conditions, both required: the funnel must be "
            "<code>full_proof</code> and the repository must be on the "
            "synthetic-target allowlist (OWASP Benchmark, OWASP Juice Shop). A "
            "finding whose funnel or repository cannot be determined is treated "
            "as real and unfixed. After rendering, the finished HTML is scanned "
            "for every withheld path, its encodings, its basename and the "
            "distinctive lines of its snippet; a hit raises and the report is "
            "not produced. That scan is the policy — this paragraph is the "
            "explanation."
        ),
        lede=(
            "This report is aggregate-only for real findings. The renderer "
            "enforces that rather than trusting an author to remember it."
        ),
    )


def _corpus_section(inputs: ReportInputs, ctx: _Ctx) -> str:
    findings = list(inputs.findings)
    if not findings:
        return _section(
            "corpus",
            "The corpus",
            _callout(
                "No findings were supplied to this report. Nothing below is a "
                "measurement of zero; it is an absence of measurement.",
                kind="empty",
            ),
        )

    by_repo = _counts_by(findings, "repo")
    by_rule = _counts_by(findings, "rule_id")
    by_cwe = _counts_by(findings, "cwe")
    by_sev = _counts_by(findings, "severity_reported")

    # A Semgrep message can interpolate matched source. Publishing one is only
    # safe when it is a rule-level constant, so it is published only when every
    # finding of that rule carries byte-identical text.
    message_of: dict[str, str | None] = {}
    for finding in findings:
        seen = message_of.get(finding.rule_id, ...)
        if seen is ...:
            message_of[finding.rule_id] = finding.message
        elif seen != finding.message:
            message_of[finding.rule_id] = None
    variable = [r for r, m in message_of.items() if m is None]
    if variable:
        ctx.refuse(
            "Semgrep rule messages",
            f"{len(variable)} rules produced per-finding message text; a Semgrep "
            "message can interpolate matched source, so only rule-level "
            "constant messages are published",
        )

    rule_rows = [
        (
            f"<code>{_e(rule)}</code>",
            f'<span class="counts">{count}</span>',
            ctx.clean(message_of.get(rule) or "")
            or '<span class="withheld">message varies per finding — withheld</span>',
        )
        for rule, count in by_rule.items()
    ]

    return _section(
        "corpus",
        "The corpus",
        _table(
            ["repository", "findings"],
            [(_e(k), f'<span class="counts">{v}</span>') for k, v in by_repo.items()],
            caption=f"{len(findings)} findings across {len(by_repo)} repositories",
        ),
        _table(["rule", "findings", "rule message"], rule_rows),
        _table(
            ["CWE", "findings"],
            [(_e(k), f'<span class="counts">{v}</span>') for k, v in by_cwe.items()],
        ),
        _table(
            ["scanner severity", "findings"],
            [(_e(k), f'<span class="counts">{v}</span>') for k, v in by_sev.items()],
        ),
        _note(
            "Counts by repository, rule and CWE are publishable under D17. "
            "Paths, line numbers and snippets are not, and do not appear "
            "anywhere on this page — including in chart labels and SVG titles."
        ),
        lede="Counts and classes. No paths, no lines, no code.",
    )


def _verdict_section(inputs: ReportInputs, ctx: _Ctx) -> str:
    suite = inputs.suite
    if suite is None or not suite.corpora:
        ctx.refuse(
            "FP-class precision, recall, miss rate",
            "no eval suite result was supplied, so there is no confusion matrix "
            "to publish",
        )
        return _section(
            "verdict",
            "Is the verdict right?",
            _callout(
                "No eval suite result was supplied. Precision, recall and the "
                "miss rate are unavailable — not zero.",
                kind="empty",
            ),
            charts.confusion_matrix_svg(None),
        )

    blocks: list[str] = []
    if not inputs.corpus_labelled:
        blocks.append(
            _callout(
                "The hand-labelled corpus is not complete. Everything in this "
                "section is measured over whatever rows carried a ground-truth "
                "label, and the label sheet is published alongside this report "
                "so the denominator is checkable.",
                kind="warn",
            )
        )

    for name, report in sorted(suite.corpora.items()):
        blocks.append(f'<h3>{_e(name)}</h3>')
        metrics = report.metrics
        if metrics is None:
            ctx.refuse(
                f"FP-class metrics for {name}",
                "the eval suite could not score this corpus: "
                + (", ".join(report.unavailable) or "no reason recorded"),
            )
            blocks.append(
                _callout(
                    "Not scored: "
                    + ctx.clean(", ".join(report.unavailable) or "no reason recorded"),
                    kind="empty",
                )
            )
            blocks.append(charts.confusion_matrix_svg(None, chart_id=f"cm-{name}"))
            continue

        blocks.append(
            charts.confusion_matrix_svg(
                metrics.matrix, tau=metrics.tau, chart_id=f"cm-{name}"
            )
        )
        rows = [
            (
                "FP-class precision",
                _rate_html(metrics.precision, ctx, topic=f"FP-class precision ({name})"),
            ),
            (
                "FP-class recall",
                _rate_html(metrics.recall, ctx, topic=f"FP-class recall ({name})"),
            ),
            (
                "miss rate (real defects suppressed)",
                _rate_html(metrics.miss_rate, ctx, topic=f"miss rate ({name})"),
            ),
            (
                "needless-review rate",
                _rate_html(
                    metrics.needless_review_rate, ctx, topic=f"needless-review rate ({name})"
                ),
            ),
        ]
        if metrics.f1 is None:
            ctx.refuse(
                f"F1 ({name})",
                "precision and recall are not both defined on this corpus",
            )
            rows.append(("F1", '<span class="withheld">undefined</span>'))
        else:
            rows.append(("F1", f"<strong>{metrics.f1:.3f}</strong>"))
        blocks.append(_table(["metric", "value"], rows))

        cost = metrics.cost
        blocks.append(
            _table(
                ["asymmetric cost", "value"],
                [
                    (
                        f"total at {cost.miss_weight:g}× miss weight",
                        f"{cost.total:.1f} review-equivalents "
                        f'<span class="muted">({cost.miss_share:.0%} of it from '
                        "suppressed defects)</span>",
                    ),
                    (
                        "baseline: review everything",
                        f"{cost.review_everything:.1f}",
                    ),
                    (
                        "baseline: close everything",
                        f"{cost.close_everything:.1f}",
                    ),
                    (
                        "harness ÷ review-everything",
                        f"<strong>{cost.vs_review_everything:.2f}×</strong>"
                        + (
                            ' <span class="warn-inline">— the harness is not '
                            "earning its place under this cost model</span>"
                            if cost.vs_review_everything >= 1.0
                            else ""
                        ),
                    ),
                ],
                caption="A miss costs four needless reviews (THOR convention)",
            )
        )
        for note in metrics.notes:
            blocks.append(_note(ctx.clean(note)))

    return _section(
        "verdict",
        "Is the verdict right?",
        *blocks,
        lede=(
            "The positive class is <em>false positive</em>, because that is the "
            "class the harness acts on. A miss — a real defect closed without a "
            "human seeing it — is not a needless review with the sign flipped, "
            "and it is reported on its own."
        ),
    )


def _calibration_section(inputs: ReportInputs, ctx: _Ctx) -> str:
    suite = inputs.suite
    if suite is None or not suite.corpora:
        ctx.refuse(
            "calibration (ECE, reliability diagram, tau)",
            "no eval suite result was supplied",
        )
        return _section(
            "calibration",
            "Does the stated confidence mean anything?",
            charts.reliability_diagram_svg(None),
            charts.confidence_histogram_svg(None),
        )

    blocks: list[str] = []
    for name, report in sorted(suite.corpora.items()):
        blocks.append(f"<h3>{_e(name)}</h3>")
        diagram: ReliabilityDiagram | None = report.reliability
        tau_result: TauResult | None = report.tau
        tau_value = _tau_value(tau_result)

        blocks.append(
            charts.reliability_diagram_svg(
                diagram,
                tau=tau_value,
                tau_spread=tau_result.spread if tau_result else None,
                chart_id=f"rel-{name}",
            )
        )
        blocks.append(
            charts.confidence_histogram_svg(
                diagram, tau=tau_value, chart_id=f"hist-{name}"
            )
        )

        if diagram is None:
            ctx.refuse(
                f"ECE ({name})",
                "no reliability diagram was produced for this corpus",
            )
        else:
            if diagram.ece_ci is None:
                ctx.refuse(
                    f"ECE as a headline ({name})",
                    "no bootstrap interval was computed (the CI tier skips it); "
                    f"the point value {diagram.ece:.4f} is shown on the chart but "
                    "is not published as a headline number",
                )
            ece_cell = (
                f"<strong>{diagram.ece:.4f}</strong> "
                + (
                    f'<span class="muted">[95% CI {diagram.ece_ci[0]:.4f}–'
                    f"{diagram.ece_ci[1]:.4f}, seed {_e(diagram.ece_seed)}]</span>"
                    if diagram.ece_ci
                    else '<span class="withheld">no interval computed — not a '
                    "headline number</span>"
                )
            )
            blocks.append(
                _table(
                    ["calibration", "value"],
                    [
                        ("expected calibration error", ece_cell),
                        ("maximum calibration error", f"{diagram.mce:.4f}"),
                        (
                            "verdicts scored / excluded",
                            f'<span class="counts">{diagram.n_scored}</span> / '
                            f'<span class="counts">{diagram.n_excluded}</span> '
                            f'<span class="muted">('
                            + _e(
                                ", ".join(
                                    f"{k} {v}"
                                    for k, v in sorted(diagram.excluded_by_status.items())
                                )
                                or "none"
                            )
                            + ")</span>",
                        ),
                        (
                            "bins too small to read",
                            f'<span class="counts">{len(diagram.underpowered_bins)}</span>',
                        ),
                    ],
                )
            )
            for note in diagram.notes:
                blocks.append(_note(ctx.clean(note)))

        if tau_result is None:
            ctx.refuse(f"tau ({name})", "tau was not derived for this corpus")
            blocks.append(
                _callout("tau was not derived for this corpus.", kind="empty")
            )
            continue

        spread = tau_result.spread
        tau_cell = (
            f"<strong>{tau_value:.3f}</strong>"
            if tau_value is not None
            else '<span class="withheld">no defensible tau on this data</span>'
        )
        if tau_value is None:
            ctx.refuse(
                f"tau ({name})",
                f"only {tau_result.achieved_folds} of {len(tau_result.folds)} "
                f"folds reached precision {tau_result.target_precision:.2f}; a "
                "derivation that mostly failed must not become a production gate",
            )
        blocks.append(
            _table(
                ["derived gate", "value"],
                [
                    (
                        f"tau (p75 of achieved folds, {tau_result.repeats}×"
                        f"{tau_result.k}-fold, seed {_e(tau_result.seed)})",
                        tau_cell,
                    ),
                    (
                        "fold spread",
                        _e(spread.render()),
                    ),
                    (
                        "folds reaching the target",
                        f'<span class="counts">{tau_result.achieved_folds}/'
                        f"{len(tau_result.folds)}</span>",
                    ),
                    (
                        "held-out precision at tau",
                        _rate_html(
                            tau_result.heldout_precision,
                            ctx,
                            topic=f"held-out precision at tau ({name})",
                        ),
                    ),
                    (
                        "held-out coverage at tau",
                        _rate_html(
                            tau_result.heldout_coverage,
                            ctx,
                            topic=f"held-out coverage at tau ({name})",
                        ),
                    ),
                ],
                caption=(
                    "tau is reported as a spread, not a point (D3). A gate fitted "
                    "and scored on the same rows generalises to nothing."
                ),
            )
        )
        if tau_result.underpowered:
            blocks.append(
                _note(
                    "This derivation is underpowered: the folds carry few "
                    "false-positive verdicts each, so the spread is wide and the "
                    "gate should be read as provisional."
                )
            )
        for note in tau_result.notes:
            blocks.append(_note(ctx.clean(note)))

    return _section(
        "calibration",
        "Does the stated confidence mean anything?",
        *blocks,
        lede=(
            "A confidence gate is only worth having if the confidence is "
            "calibrated. The reliability diagram is the test, the derived tau is "
            "the consequence, and both are published with their uncertainty."
        ),
    )


def _consistency_section(inputs: ReportInputs, ctx: _Ctx) -> str:
    suite = inputs.suite
    if suite is None or not suite.corpora:
        ctx.refuse("pass^k consistency", "no eval suite result was supplied")
        # The section still renders. A missing section is an absence a reader has
        # to notice; an empty one is an absence the page states.
        return _section(
            "consistency",
            "Does it give the same answer twice?",
            _callout(
                "No repeated-run measurement was supplied. pass^k is unavailable "
                "— not 1.0.",
                kind="empty",
            ),
        )

    rows: list[tuple[str, ...]] = []
    notes: list[str] = []
    for name, report in sorted(suite.corpora.items()):
        result = report.consistency
        if result is None:
            ctx.refuse(
                f"pass^k ({name})", "no repeated-run group was scored for this corpus"
            )
            rows.append(
                (
                    _e(name),
                    '<span class="withheld">not measured</span>',
                    '<span class="withheld">not measured</span>',
                )
            )
            continue
        rows.append(
            (
                _e(name),
                _rate_html(result.pass_k, ctx, topic=f"pass^{result.k} ({name})"),
                _rate_html(
                    result.schema_failure, ctx, topic=f"schema-failure rate ({name})"
                ),
            )
        )
        notes.extend(result.notes)

    tier_note = ""
    if suite.tier == "ci":
        tier_note = _note(
            "This is the CI tier, which replays cached verdicts. A pass^k over "
            "cached rows is a replay of a consistency measurement, not a new "
            "one — the nightly tier mints a fresh run epoch that misses every "
            "cached row by construction (D19), and that is the number to trust "
            "for drift."
        )

    return _section(
        "consistency",
        "Does it give the same answer twice?",
        _table(["corpus", "pass^k (all k runs identical)", "schema-failure rate"], rows),
        tier_note,
        *[_note(ctx.clean(n)) for n in notes],
        lede=(
            "pass^k, not pass@k: nobody re-runs a finding five times and keeps "
            "the verdict they like. A <code>schema_invalid</code> attempt counts "
            "as a non-match (D10) rather than being retried away."
        ),
    )


def _build_funnels(
    bundles: Sequence[ProofBundle],
) -> dict[FunnelKind, FunnelReport]:
    out: dict[FunnelKind, FunnelReport] = {}
    for kind, group in split_by_funnel(bundles).items():
        if group:
            out[kind] = funnel_report(group)
    return out


def _proof_section(inputs: ReportInputs, ctx: _Ctx) -> str:
    bundles = list(inputs.bundles)
    if not bundles:
        ctx.refuse(
            "proof-of-fix funnel",
            "no proof bundles were supplied; there is no denominator, so no "
            "survival rate is published",
        )
        return _section(
            "proof",
            "Does the fix actually fix it?",
            charts.funnel_svg(None),
            lede="No fixes were drafted in this run.",
        )

    funnels = _build_funnels(bundles)
    blocks: list[str] = []
    for kind in ("full_proof", "partial_proof"):
        report = funnels.get(kind)  # type: ignore[arg-type]
        blocks.append(charts.funnel_svg(report, chart_id=f"funnel-{kind}"))
        if report is None:
            ctx.refuse(
                f"{kind} funnel",
                "no bundles carry this funnel label, so it has no denominator",
            )

    return _section(
        "proof",
        "Does the fix actually fix it?",
        *blocks,
        _note(
            "Two funnels, never blended (D4). The full-proof funnel carries a PoC "
            "exploit because a synthetic target can be exploited freely. The "
            "partial-proof funnel, on real findings, cannot and does not — and "
            "saying so is more honest than reporting one blended number. "
            "AutoPatchBench found around 60% of patches “work” until fuzzing and "
            "differential testing cut that to 5–11%; a funnel is what makes the "
            "difference visible."
        ),
        lede=(
            "Every validator is graded ran / skipped / unavailable, so “all "
            "validators passed” can never mean “all validators, two of which "
            "never executed”."
        ),
    )


def _injection_section(inputs: ReportInputs, ctx: _Ctx) -> str:
    result = inputs.injection or (inputs.suite.injection if inputs.suite else None)
    if result is None:
        ctx.refuse(
            "prompt-injection attack success rate",
            "no paired injection run was supplied; the nightly tier produces it "
            "and a hardened-arm number without its control arm measures nothing",
        )
        return _section(
            "injection",
            "Is it injectable?",
            charts.injection_channel_svg(None),
            lede="No paired injection run in this report.",
        )

    blocks = [charts.injection_channel_svg(result, chart_id="inj")]
    if not result.control_compromised:
        blocks.append(
            _callout(
                "The unguarded control arm was <strong>not</strong> compromised "
                "on "
                + _e(", ".join(result.control.uncompromised_channels))
                + ". The positive control did not fire, so the hardened arm's "
                "result on those channels measures the plumbing, not the "
                "guardrail. Read it as no measurement at all.",
                kind="warn",
            )
        )
        ctx.refuse(
            "hardened injection ASR on uncompromised channels",
            "the control arm was not compromised on "
            + ", ".join(result.control.uncompromised_channels)
            + "; an unpaired zero is not evidence of a defence",
        )

    rows: list[tuple[str, ...]] = []
    for channel in sorted(result.control.per_channel):
        control = result.control.per_channel[channel]
        hardened = result.hardened.per_channel.get(channel)
        hardened_cell = '<span class="withheld">not run</span>'
        if hardened is not None:
            if hardened.zero_by_construction:
                hardened_cell = (
                    '<span class="withheld">0 by construction — these '
                    f"{hardened.asr.n} payloads are never delivered "
                    "(<code>setting_sources=[]</code>), so this is a "
                    "configuration fact, not a measurement</span>"
                )
                ctx.refuse(
                    f"hardened ASR on {channel}",
                    "setting_sources=[] means these payloads never reach the "
                    "model; reporting 0% would credit the guardrail with attacks "
                    "that were never possible",
                )
            else:
                hardened_cell = _rate_html(
                    hardened.asr, ctx, topic=f"hardened ASR ({channel})"
                )
        rows.append(
            (
                f"<code>{_e(channel)}</code>",
                _rate_html(control.asr, ctx, topic=f"control ASR ({channel})"),
                hardened_cell,
            )
        )

    blocks.append(
        _table(
            ["channel", "unguarded control ASR", "hardened ASR"],
            rows,
            caption=f"Paired run over {result.n_payloads} payloads (D12)",
        )
    )
    blocks.append(
        _table(
            ["arm", "pooled over deliverable channels", "pooled over all channels"],
            [
                (
                    _e(arm.arm.name),
                    _rate_html(
                        arm.pooled_deliverable, ctx, topic=f"pooled deliverable ASR ({arm.arm.name})"
                    ),
                    _rate_html(arm.pooled_all, ctx, topic=f"pooled ASR ({arm.arm.name})"),
                )
                for arm in (result.control, result.hardened)
            ],
            caption=(
                "Two pooled figures, separately labelled. Folding the "
                "never-delivered channel into one denominator would turn 0/30 "
                "into 0/40 and credit the guardrail with ten attacks that could "
                "not have happened."
            ),
        )
    )
    for note in result.notes:
        blocks.append(_note(ctx.clean(note)))

    return _section(
        "injection",
        "Is it injectable?",
        *blocks,
        lede=(
            "Paired: one payload corpus against a deliberately unguarded, "
            "containerised control and against the shipped configuration. An "
            "unpaired injection eval is close to worthless — “zero of forty "
            "succeeded” is equally consistent with a working guardrail and with "
            "a harness that never delivered a payload."
        ),
    )


def _agreement_section(inputs: ReportInputs, ctx: _Ctx) -> str:
    blocks: list[str] = []
    intra = inputs.intra_rater
    if intra is None:
        ctx.refuse(
            "intra-rater agreement",
            "no wash-out re-labelling pass was supplied",
        )
    else:
        kappa_cell = (
            f"<strong>{intra.intra_rater_kappa:.3f}</strong>"
            if intra.intra_rater_kappa is not None
            else '<span class="withheld">undefined on this data</span>'
        )
        if intra.intra_rater_kappa is None:
            ctx.refuse(
                "intra-rater kappa",
                "the coefficient is undefined on this label distribution",
            )
        if intra.intra_rater_degenerate:
            blocks.append(
                _callout(
                    "This coefficient is degenerate: one label dominates the "
                    "subset, and at that prevalence a chance-corrected statistic "
                    "collapses towards zero however well the two passes agree. "
                    "Read the raw agreement and the flip list instead.",
                    kind="warn",
                )
            )
        blocks.append(
            _table(
                ["intra-rater (one rater, two passes)", "value"],
                [
                    ("intra-rater kappa", kappa_cell),
                    (
                        "raw agreement",
                        _rate_html(
                            intra.intra_rater_observed_agreement,
                            ctx,
                            topic="intra-rater raw agreement",
                        ),
                    ),
                    (
                        "wash-out satisfied",
                        "yes" if intra.intra_rater_washout_satisfied else "no",
                    ),
                    (
                        "wash-out (min / median days)",
                        f"{intra.intra_rater_washout_days_min:.1f} / "
                        f"{intra.intra_rater_washout_days_median:.1f}",
                    ),
                ],
                caption=(
                    "Named intra-rater everywhere. There is one human on this "
                    "project, so this measures rater stability and says nothing "
                    "about whether the labels are right (D18)."
                ),
            )
        )
        for note in intra.notes:
            blocks.append(_note(ctx.clean(note)))

    mh = inputs.model_human
    if mh is None:
        ctx.refuse(
            "model-vs-human agreement", "no paired model/human rating set was supplied"
        )
    else:
        blocks.append(
            _table(
                ["model vs human", "value"],
                [
                    (
                        "raw agreement",
                        _rate_html(mh.raw_agreement, ctx, topic="model-vs-human agreement"),
                    ),
                    (
                        "excluded as undecidable",
                        f'<span class="counts">{mh.excluded_undecidable}</span>',
                    ),
                ],
                caption=(
                    "Deliberately not called kappa and carrying no chance "
                    "correction: the model is the system under test, not a "
                    "second rater (D18)."
                ),
            )
        )
        for note in mh.notes:
            blocks.append(_note(ctx.clean(note)))

    if not blocks:
        blocks.append(
            _callout(
                "No wash-out re-labelling pass and no paired model/human rating "
                "set were supplied, so the stability of the labels every number "
                "above is scored against is unmeasured.",
                kind="empty",
            )
        )
    return _section(
        "agreement",
        "How stable are the labels this is scored against?",
        *blocks,
        lede=(
            "Every number above is scored against one human's labels. This "
            "section is what that human's consistency is worth."
        ),
    )


def _summary_section(inputs: ReportInputs, ctx: _Ctx, stamp: datetime) -> str:
    summary = inputs.summary
    if summary is None:
        summary = summarise(inputs.findings, now=stamp)

    state_rows = [
        (_e(state), f'<span class="counts">{count}</span>')
        for state, count in sorted(summary.by_state.items())
    ]
    control_rows = [
        (
            _e(control),
            _e(", ".join(f"{k} {v}" for k, v in sorted(states.items()))),
        )
        for control, states in sorted(summary.by_control.items())
    ]

    forecast = summary.forecast
    forecast_rows: list[tuple[str, ...]] = [
        ("already breached", f'<span class="counts">{forecast.already_breached}</span>'),
        (
            f"breaching within {forecast.horizon_days} days if nothing is remediated",
            f'<span class="counts">{forecast.total_if_nothing_closed}</span>',
        ),
    ]
    if forecast.remediation_rate is not None:
        forecast_rows.append(
            (
                "observed remediation throughput",
                _rate_html(
                    forecast.remediation_rate, ctx, topic="remediation throughput"
                ),
            )
        )
    if forecast.expected_remaining is None:
        ctx.refuse(
            "expected breach count after remediation",
            "there is no closure history the corpus can support a throughput "
            "estimate from; only the no-remediation projection is published, and "
            "it has no fitted parameter",
        )
        forecast_rows.append(
            (
                "expected breaches after remediation",
                '<span class="withheld">not published — no closure history to '
                "fit a throughput on</span>",
            )
        )
    else:
        forecast_rows.append(
            (
                "expected breaches after remediation",
                f"<strong>{forecast.expected_remaining:.1f}</strong>",
            )
        )

    schedule_rows = [
        (f"day +{day}", f'<span class="counts">{count}</span>')
        for day, count in forecast.scheduled
    ]

    return _section(
        "summary",
        "Weekly risk summary and compliance clocks",
        _table(["clock state", "count"], state_rows),
        _table(["control", "states"], control_rows),
        _table(
            ["breach forecast", "value"],
            forecast_rows,
            caption=f"Method: {forecast.method}",
        ),
        _table(["due", "clocks breaching"], schedule_rows) if schedule_rows else "",
        *[_note(ctx.clean(c)) for c in forecast.caveats],
        *[_note(ctx.clean(n)) for n in summary.notes],
        _note(
            "PCI DSS 4.0.1 req 6.3.3 gives critical and high findings 30 days "
            "from first detection. RBI Cyber Resilience MD for PSOs (2024) "
            "para 21 says critical patches go out immediately, which is a paging "
            "rule rather than a countdown, so those clocks are reported as "
            "paging events and excluded from the day-by-day schedule. DPDP Rules "
            "2025 rule 7 needs a personal-data tag to evaluate; where no tags "
            "were supplied the clock is reported as unevaluated, never as "
            "satisfied."
        ),
        lede=(
            "Findings are counted by clock state and control. No finding is "
            "named — a breached SLA on a named file is the same disclosure this "
            "report exists to withhold."
        ),
    )


def _evidence_section(inputs: ReportInputs, ctx: _Ctx) -> str:
    """Full evidence, and only for targets that exist to be exploited."""
    ledger = ctx.ledger
    publishable = {d.finding_id for d in ledger.full_disclosures}
    if not publishable:
        return _section(
            "evidence",
            "Full evidence bundles",
            _callout(
                "No finding in this run qualified for full disclosure. Full "
                "evidence — path, line, snippet, exploit before and after — is "
                "published only for OWASP Benchmark and OWASP Juice Shop, and "
                "only where the fix carries a full-proof bundle.",
                kind="empty",
            ),
        )

    by_id = {f.finding_id: f for f in inputs.findings}
    rows = []
    for finding_id in sorted(publishable):
        finding = by_id.get(finding_id)
        if finding is None:
            continue
        rows.append(
            (
                _e(finding.repo),
                f"<code>{_e(finding.path)}:{finding.line_start}</code>",
                f"<code>{_e(finding.rule_id)}</code>",
                _e(finding.cwe or "—"),
            )
        )
    return _section(
        "evidence",
        "Full evidence bundles",
        _table(["repository", "location", "rule", "CWE"], rows),
        _note(
            "These targets are deliberately vulnerable and run only in a local "
            "container. Nothing here is somebody's production code."
        ),
        lede=(
            f"{len(rows)} findings on synthetic targets carry a full-proof "
            "bundle and are published in full."
        ),
    )


def _refusals_section(ctx: _Ctx) -> str:
    if not ctx.withheld:
        return _section(
            "refusals",
            "Numbers this report will not print",
            _callout(
                "Every quantity this report attempted was supported by its "
                "denominator.",
                kind="empty",
            ),
        )
    rows = [(_e(w.topic), ctx.clean(w.reason)) for w in ctx.withheld]
    return _section(
        "refusals",
        "Numbers this report will not print",
        _table(["quantity", "why it is withheld"], rows),
        lede=(
            "A trust report that overstates its own confidence fails at its one "
            "job. These are the quantities the corpus could not support, listed "
            "rather than quietly rounded into existence."
        ),
    )


def _reproduce_section(inputs: ReportInputs) -> str:
    return _section(
        "reproduce",
        "How to check this",
        _note(
            "Every statistic on this page is a pure function over the published "
            "verdict table and the label sheet. No network, no clock, no model, "
            "no API key: given <code>verdict_table.jsonl</code> and "
            "<code>data/corpus/labels.csv</code>, the whole thing re-derives on "
            "a laptop with the network off. The seeds are printed beside the "
            "numbers they generate. The payload corpus for the injection run is "
            "published so that someone other than its author can grade it."
        ),
        _note(
            "What this page cannot show you: the paths. Those go to maintainers "
            "privately through the process in the target's "
            "<code>SECURITY.md</code>. Choosing the boring artifact costs this "
            "project its most vivid material, and that tradeoff is the answer to "
            "a question a security team should be asking."
        ),
    )


# --------------------------------------------------------------------------- #
# Page
# --------------------------------------------------------------------------- #

_CSS = """
:root {
  color-scheme: light dark;
  --pr-bg: #ffffff; --pr-ink: #1a1d23; --pr-muted: #5b6470;
  --pr-rule: #c8ced8; --pr-grid: #e4e8ee; --pr-surface: #f4f6fa;
  --pr-series-a: #2f5fd0; --pr-series-b: #b4530a; --pr-warn: #a3122b;
  --pr-accent-bg: #eef2fb; --pr-warn-bg: #fdeef1;
}
@media (prefers-color-scheme: dark) {
  :root {
    --pr-bg: #12151a; --pr-ink: #e8ecf2; --pr-muted: #9aa4b2;
    --pr-rule: #39414d; --pr-grid: #262c35; --pr-surface: #1a1f26;
    --pr-series-a: #7ea6ff; --pr-series-b: #f0a35e; --pr-warn: #ff8b9c;
    --pr-accent-bg: #1a2436; --pr-warn-bg: #2c1a20;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--pr-bg); color: var(--pr-ink);
  font: 15px/1.6 ui-sans-serif, -apple-system, "Segoe UI", Roboto,
        "Helvetica Neue", Arial, sans-serif;
}
main { max-width: 60rem; margin: 0 auto; padding: 2.5rem 1.25rem 5rem; }
h1 { font-size: 1.9rem; margin: 0 0 .4rem; letter-spacing: -.01em; }
h2 { font-size: 1.3rem; margin: 0 0 .5rem; letter-spacing: -.005em; }
h3 { font-size: 1rem; margin: 1.75rem 0 .5rem; color: var(--pr-muted);
     text-transform: lowercase; letter-spacing: .04em; }
section { margin: 3rem 0 0; padding-top: 1.5rem; border-top: 1px solid var(--pr-rule); }
header { padding-bottom: .5rem; }
p { margin: .6rem 0; }
.lede { color: var(--pr-muted); max-width: 46rem; margin-bottom: 1.25rem; }
.note { color: var(--pr-muted); font-size: .875rem; max-width: 48rem;
        border-left: 2px solid var(--pr-rule); padding-left: .75rem; }
.muted { color: var(--pr-muted); }
.counts { font-variant-numeric: tabular-nums; font-weight: 600; }
.withheld { color: var(--pr-warn); font-size: .875rem; }
.warn-inline { color: var(--pr-warn); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
       font-size: .875em; background: var(--pr-surface);
       padding: .1em .35em; border-radius: 3px; overflow-wrap: anywhere; }
dl.meta { display: flex; flex-wrap: wrap; gap: .25rem 2rem; margin: 1.25rem 0 0;
          font-size: .8125rem; }
dl.meta dt { color: var(--pr-muted); text-transform: uppercase;
             letter-spacing: .06em; font-size: .6875rem; }
dl.meta dd { margin: 0; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
.scroll { overflow-x: auto; margin: 1rem 0; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
caption { text-align: left; color: var(--pr-muted); font-size: .8125rem;
          padding-bottom: .5rem; }
th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid var(--pr-rule);
         vertical-align: top; }
th { font-size: .75rem; text-transform: uppercase; letter-spacing: .06em;
     color: var(--pr-muted); font-weight: 600; }
tbody tr:last-child td { border-bottom: none; }
.callout { border: 1px solid var(--pr-rule); border-radius: 6px;
           padding: .9rem 1.1rem; margin: 1rem 0; font-size: .9rem;
           background: var(--pr-surface); }
.callout.policy { background: var(--pr-accent-bg); border-color: var(--pr-series-a); }
.callout.warn { background: var(--pr-warn-bg); border-color: var(--pr-warn); }
.callout.empty { border-style: dashed; color: var(--pr-muted); }
svg.pr-chart { display: block; width: 100%; height: auto; margin: 1.25rem 0;
               max-width: 46rem; }
nav.toc { font-size: .875rem; margin: 1.5rem 0 0; }
nav.toc a { color: var(--pr-series-a); margin-right: 1rem;
            display: inline-block; padding: .1rem 0; }
footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--pr-rule);
         color: var(--pr-muted); font-size: .8125rem; }
@media print {
  body { background: #fff; color: #000; }
  section { break-inside: avoid; }
  nav.toc { display: none; }
}
"""

_TOC = (
    ("disclosure", "Disclosure"),
    ("corpus", "Corpus"),
    ("verdict", "Verdict quality"),
    ("calibration", "Calibration"),
    ("consistency", "Consistency"),
    ("proof", "Proof of fix"),
    ("injection", "Injection"),
    ("agreement", "Label stability"),
    ("summary", "Risk summary"),
    ("evidence", "Evidence"),
    ("refusals", "Refusals"),
    ("reproduce", "Reproducing this"),
)


def render(inputs: ReportInputs) -> str:
    """Render the trust report, or raise rather than disclose.

    The last thing this function does before returning is scan its own output
    for every token the disclosure ledger withholds. There is no argument that
    disables that scan, and no code path that returns a document which failed
    it.
    """
    stamp = inputs.generated_at or datetime.now(timezone.utc)
    ledger = build_ledger(
        inputs.findings,
        bundles=inputs.bundles,
        funnels=inputs.funnels,
        allowlist=inputs.allowlist,
    )
    ctx = _Ctx(ledger=ledger)

    body = "".join(
        [
            _header(inputs, ctx, stamp),
            '<nav class="toc">'
            + "".join(f'<a href="#{_e(a)}">{_e(label)}</a>' for a, label in _TOC)
            + "</nav>",
            _disclosure_section(inputs, ctx),
            _corpus_section(inputs, ctx),
            _verdict_section(inputs, ctx),
            _calibration_section(inputs, ctx),
            _consistency_section(inputs, ctx),
            _proof_section(inputs, ctx),
            _injection_section(inputs, ctx),
            _agreement_section(inputs, ctx),
            _summary_section(inputs, ctx, stamp),
            _evidence_section(inputs, ctx),
            # Built last: the refusal ledger records what every section above
            # declined to print, so it has to be assembled after them.
            _refusals_section(ctx),
            _reproduce_section(inputs),
            "<footer>Pramaan · aggregate-only for real findings under the "
            "disclosure policy (D17) · this page contains no script, no external "
            "asset and no network request.</footer>",
        ]
    )

    document = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        '<meta name="robots" content="noindex">'
        f"<title>{_e(inputs.title)}</title><style>{_CSS}</style></head>"
        f"<body><main>{body}</main></body></html>"
    )

    assert_clean(document, ledger)
    return document


def render_to_file(inputs: ReportInputs, path: str) -> str:
    """Render and write. Writes nothing if the disclosure gate raises."""
    document = render(inputs)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(document)
    return document


def _corpus_reports(suite: SuiteResult | None) -> dict[str, CorpusReport]:
    """Kept for callers that want the scored corpora without the page."""
    return dict(suite.corpora) if suite else {}


def report_manifest(inputs: ReportInputs) -> dict[str, Any]:
    """A publication-safe JSON sidecar describing what the page discloses.

    Useful for a CI job that wants to assert on the gate's behaviour without
    parsing HTML. Contains no path, by construction: the ledger's `to_dict` is
    built from counts and reasons only.
    """
    ledger = build_ledger(
        inputs.findings,
        bundles=inputs.bundles,
        funnels=inputs.funnels,
        allowlist=inputs.allowlist,
    )
    return {
        "generated_at": (inputs.generated_at or datetime.now(timezone.utc)).isoformat(),
        "commit_sha": inputs.commit_sha,
        "model_id": inputs.model_id,
        "run_epoch": inputs.run_epoch,
        "disclosure": ledger.to_dict(),
        "n_findings": len(inputs.findings),
        "n_bundles": len(inputs.bundles),
        "corpora": sorted(_corpus_reports(inputs.suite)),
    }
