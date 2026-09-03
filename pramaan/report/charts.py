"""Hand-rolled inline SVG. No matplotlib, no JavaScript, no CDN, no fonts.

Five charts, each a pure function from an eval-lane result object to a string of
SVG. Nothing here computes a statistic: every number drawn is read off a
`Rate`, a `ReliabilityDiagram`, a `Confusion`, a `FunnelReport` or a
`PairedInjectionResult`. If a chart wants a proportion the result object does
not carry, the chart does without it.

Three constraints shape the drawing:

**Legible in light and dark.** Colours are `var(--pr-*, fallback)` references.
Standalone, the fallbacks render a light-mode chart; inside the trust report,
`prefers-color-scheme: dark` redefines the variables and every chart follows.
No chart paints an opaque white plot area, which is the usual way an exported
figure turns into a bright rectangle on a dark page.

**Never colour alone.** Every bar carries its printed value, every series is
named in text next to its swatch, and the second series in any pair is
distinguished by a diagonal hatch and a dashed outline as well as by hue. The
intervals are drawn as whiskers, which read the same in greyscale. A reader with
a monochrome printout, or a colour vision deficiency, loses nothing.

**Never invent a denominator.** A `Rate` below its reporting minimum is drawn
hatched and annotated with its counts instead of a bar whose height implies a
measurement. `None` input renders an empty state; zero findings renders an
empty state; no chart divides by a count it did not check.

Element ids are prefixed per chart (`chart_id`), because several of these SVGs
share one document and duplicate `<defs>` ids silently cross-wire the patterns.
"""

from __future__ import annotations

import html
import textwrap
from collections.abc import Mapping

from pramaan.calibration.tau import ReliabilityDiagram, Spread
from pramaan.evals.injection import PairedInjectionResult
from pramaan.evals.metrics import Confusion
from pramaan.evals.payloads import CHANNELS
from pramaan.evals.stats import Rate
from pramaan.proof.bundle import FunnelReport

__all__ = [
    "CHART_FALLBACKS",
    "chart_theme_css",
    "confidence_histogram_svg",
    "confusion_matrix_svg",
    "empty_chart_svg",
    "funnel_svg",
    "injection_channel_svg",
    "reliability_diagram_svg",
]

# The light-mode fallbacks baked into every `var()` reference. The trust report
# redefines the same names for dark mode; nothing else needs to know them.
CHART_FALLBACKS: dict[str, str] = {
    "--pr-ink": "#1a1d23",
    "--pr-muted": "#5b6470",
    "--pr-rule": "#c8ced8",
    "--pr-grid": "#e4e8ee",
    "--pr-series-a": "#2f5fd0",
    "--pr-series-b": "#b4530a",
    "--pr-warn": "#a3122b",
    "--pr-surface": "#f4f6fa",
}


def _v(name: str) -> str:
    return f"var({name}, {CHART_FALLBACKS[name]})"


INK = _v("--pr-ink")
MUTED = _v("--pr-muted")
RULE = _v("--pr-rule")
GRID = _v("--pr-grid")
SERIES_A = _v("--pr-series-a")
SERIES_B = _v("--pr-series-b")
WARN = _v("--pr-warn")
SURFACE = _v("--pr-surface")

_FONT = (
    "ui-sans-serif, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', "
    "Arial, sans-serif"
)


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #

def _e(text: object) -> str:
    return html.escape(str(text), quote=True)


def _n(value: float) -> str:
    """Compact number for a coordinate. Keeps the markup readable in a diff."""
    text = f"{value:.2f}"
    return text.rstrip("0").rstrip(".") if "." in text else text


def _text(
    x: float,
    y: float,
    content: str,
    *,
    size: float = 12,
    fill: str = INK,
    anchor: str = "start",
    weight: str = "normal",
    opacity: float | None = None,
) -> str:
    op = "" if opacity is None else f' opacity="{_n(opacity)}"'
    return (
        f'<text x="{_n(x)}" y="{_n(y)}" font-size="{_n(size)}" fill="{fill}" '
        f'text-anchor="{anchor}" font-weight="{weight}" '
        f'font-family="{_FONT}"{op}>{_e(content)}</text>'
    )


def _wrap(content: str, *, available_px: float, size: float) -> list[str]:
    """Greedy wrap at an estimated 0.5em per character.

    SVG has no text flow, so a caption long enough to say something useful is a
    caption long enough to run off the canvas. Estimating rather than measuring
    is fine here: the charts specify a system sans stack, and the estimate is
    deliberately wide.
    """
    limit = max(int(available_px / (size * 0.5)), 12)
    return textwrap.wrap(content, limit) or [""]


def _paragraph(
    x: float,
    y: float,
    content: str,
    *,
    available_px: float,
    size: float = 11,
    fill: str = MUTED,
    line_height: float = 14,
) -> tuple[str, float]:
    """Wrapped text. Returns the markup and the height it consumed."""
    lines = _wrap(content, available_px=available_px, size=size)
    markup = "".join(
        _text(x, y + i * line_height, line, size=size, fill=fill)
        for i, line in enumerate(lines)
    )
    return markup, len(lines) * line_height


def _line(
    x1: float, y1: float, x2: float, y2: float, *, stroke: str = RULE,
    width: float = 1, dash: str = "",
) -> str:
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (
        f'<line x1="{_n(x1)}" y1="{_n(y1)}" x2="{_n(x2)}" y2="{_n(y2)}" '
        f'stroke="{stroke}" stroke-width="{_n(width)}"{d} />'
    )


def _rect(
    x: float, y: float, w: float, h: float, *, fill: str = "none",
    stroke: str = "none", width: float = 1, dash: str = "", rx: float = 0,
    opacity: float | None = None,
) -> str:
    d = f' stroke-dasharray="{dash}"' if dash else ""
    op = "" if opacity is None else f' fill-opacity="{_n(opacity)}"'
    return (
        f'<rect x="{_n(x)}" y="{_n(y)}" width="{_n(max(w, 0))}" '
        f'height="{_n(max(h, 0))}" fill="{fill}" stroke="{stroke}" '
        f'stroke-width="{_n(width)}"{d} rx="{_n(rx)}"{op} />'
    )


def _hatch_def(chart_id: str, name: str, colour: str) -> str:
    """A diagonal hatch, so a second series survives greyscale."""
    pid = f"{chart_id}-{name}"
    return (
        f'<pattern id="{pid}" width="6" height="6" patternUnits="userSpaceOnUse" '
        f'patternTransform="rotate(45)">'
        f'<rect width="6" height="6" fill="none" />'
        f'<line x1="0" y1="0" x2="0" y2="6" stroke="{colour}" stroke-width="2.4" />'
        f"</pattern>"
    )


def _svg_open(
    width: float, height: float, *, title: str, desc: str, chart_id: str
) -> str:
    """Root element. `title` is the accessible name and is aggregate-only.

    Nothing in this module ever writes a finding path into a `<title>`; the
    redaction scan checks the finished document anyway, which is what makes
    that a guarantee rather than a habit.
    """
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_n(width)} '
        f'{_n(height)}" width="100%" height="auto" role="img" '
        f'aria-label="{_e(title)}" class="pr-chart" '
        f'preserveAspectRatio="xMidYMin meet" data-chart="{_e(chart_id)}">'
        f"<title>{_e(title)}</title><desc>{_e(desc)}</desc>"
    )


def empty_chart_svg(
    message: str,
    *,
    width: float = 720,
    height: float = 140,
    chart_id: str = "empty",
    title: str = "No data",
) -> str:
    """The zero-findings / no-measurement state.

    A chart with nothing to draw says so. It does not draw empty axes that
    imply a measurement was attempted and came back at zero.
    """
    parts = [
        _svg_open(width, height, title=title, desc=message, chart_id=chart_id),
        _rect(
            1, 1, width - 2, height - 2, fill=SURFACE, stroke=RULE, dash="5 4", rx=6
        ),
        _text(
            width / 2, height / 2 + 4, message, size=13, fill=MUTED, anchor="middle"
        ),
        "</svg>",
    ]
    return "".join(parts)


def _rate_label(rate: Rate) -> str:
    """`k/n` plus an interval, or plain counts when n cannot support a rate."""
    if rate.n == 0:
        return "no observations"
    if not rate.reportable:
        return f"{rate.successes}/{rate.n} (n too small for a rate)"
    lo, hi = rate.interval  # type: ignore[misc]
    return f"{rate.successes}/{rate.n} = {rate.point:.0%} [{lo:.0%}–{hi:.0%}]"  # type: ignore[str-format]


# --------------------------------------------------------------------------- #
# 1. Reliability diagram, with the derived tau marked
# --------------------------------------------------------------------------- #

def reliability_diagram_svg(
    diagram: ReliabilityDiagram | None,
    *,
    tau: float | None = None,
    tau_spread: Spread | None = None,
    width: float = 720,
    height: float = 460,
    chart_id: str = "reliability",
) -> str:
    """Stated confidence against observed accuracy, with tau and its fold spread.

    Each bin's Wilson interval is drawn as a whisker. Bins whose `Rate` is below
    its reporting minimum are hatched rather than solid, because a bar at 100%
    over three rows looks exactly like a bar at 100% over ninety.

    `tau_spread` draws the interquartile band of the fold taus (D3). A single
    vertical line would restate the point estimate the tau lane deliberately
    refuses to publish on its own.
    """
    if diagram is None or diagram.n_scored == 0:
        return empty_chart_svg(
            "No decidable verdicts to calibrate — reliability diagram unavailable.",
            width=width,
            chart_id=chart_id,
            title="Reliability diagram (no data)",
        )

    left, right, top, bottom = 62.0, width - 24.0, 62.0, height - 104.0
    plot_w, plot_h = right - left, bottom - top

    def px(value: float) -> float:
        return left + value * plot_w

    def py(value: float) -> float:
        return bottom - value * plot_h

    occupied = [b for b in diagram.bins if b.n > 0]
    title = (
        f"Reliability diagram, {diagram.corpus}: stated confidence against "
        f"observed accuracy over {diagram.n_scored} verdicts"
    )
    parts = [
        _svg_open(
            width,
            height,
            title=title,
            desc=(
                "Bars show observed accuracy per confidence bin with 95% Wilson "
                "whiskers. Hatched bars are bins too small to report. The dashed "
                "diagonal is perfect calibration."
            ),
            chart_id=chart_id,
        ),
        f"<defs>{_hatch_def(chart_id, 'thin', SERIES_A)}</defs>",
    ]

    # Grid and axes.
    for i in range(6):
        value = i / 5
        parts.append(_line(left, py(value), right, py(value), stroke=GRID))
        parts.append(
            _text(left - 8, py(value) + 4, f"{value:.1f}", size=11, fill=MUTED, anchor="end")
        )
        parts.append(
            _text(px(value), bottom + 18, f"{value:.1f}", size=11, fill=MUTED, anchor="middle")
        )
    parts.append(_line(left, bottom, right, bottom, stroke=RULE, width=1.5))
    parts.append(_line(left, top, left, bottom, stroke=RULE, width=1.5))
    parts.append(
        _line(px(0), py(0), px(1), py(1), stroke=MUTED, width=1.5, dash="6 4")
    )
    parts.append(
        _text(px(0.72), py(0.72) - 8, "perfect calibration", size=11, fill=MUTED)
    )

    # tau: the fold band first, so the median line sits on top of it.
    if tau_spread is not None:
        parts.append(
            _rect(
                px(tau_spread.q1),
                top,
                px(tau_spread.q3) - px(tau_spread.q1),
                plot_h,
                fill=WARN,
                opacity=0.12,
            )
        )
        parts.append(
            _text(
                px(tau_spread.q3) + 4,
                top + 26,
                f"fold IQR {tau_spread.q1:.2f}–{tau_spread.q3:.2f}",
                size=11,
                fill=MUTED,
            )
        )
    if tau is not None:
        parts.append(_line(px(tau), top, px(tau), bottom, stroke=WARN, width=2, dash="4 3"))
        parts.append(
            _text(px(tau), top - 8, f"tau = {tau:.3f}", size=12, fill=WARN, anchor="middle", weight="600")
        )

    # Bars.
    bin_w = plot_w / max(len(diagram.bins), 1)
    bar_w = bin_w * 0.62
    for b in diagram.bins:
        if b.n == 0 or b.accuracy.point is None:
            continue
        mid = (b.lower + b.upper) / 2
        x = px(mid) - bar_w / 2
        y = py(b.accuracy.point)
        fill = SERIES_A if b.reportable else f"url(#{chart_id}-thin)"
        parts.append(
            _rect(x, y, bar_w, bottom - y, fill=fill, stroke=SERIES_A, width=1.2)
        )
        interval = b.accuracy.interval
        cap = b.accuracy.point
        if interval is not None:
            lo, hi = interval
            cap = hi
            cx = px(mid)
            parts.append(_line(cx, py(lo), cx, py(hi), stroke=INK, width=1.4))
            parts.append(_line(cx - 5, py(lo), cx + 5, py(lo), stroke=INK, width=1.4))
            parts.append(_line(cx - 5, py(hi), cx + 5, py(hi), stroke=INK, width=1.4))
        parts.append(
            _text(px(mid), py(cap) - 7, f"n={b.n}", size=10, fill=MUTED, anchor="middle")
        )

    parts.append(
        _text((left + right) / 2, bottom + 36, "stated confidence", size=12, fill=INK, anchor="middle")
    )
    parts.append(
        f'<text transform="rotate(-90 16 {_n((top + bottom) / 2)})" x="16" '
        f'y="{_n((top + bottom) / 2)}" font-size="12" fill="{INK}" '
        f'text-anchor="middle" font-family="{_FONT}">observed accuracy</text>'
    )

    ece_note = (
        f"ECE {diagram.ece:.4f}"
        + (
            f" [95% CI {diagram.ece_ci[0]:.4f}–{diagram.ece_ci[1]:.4f}]"
            if diagram.ece_ci
            else " (no bootstrap interval — not a headline number)"
        )
        + f"  ·  MCE {diagram.mce:.4f}"
        + f"  ·  {len(occupied)} occupied bins, {diagram.n_excluded} verdicts excluded"
    )
    footer, _ = _paragraph(left, bottom + 58, ece_note, available_px=right - left)
    parts.append(footer)
    legend, _ = _paragraph(
        left,
        22,
        "solid = bin reportable · hatched = n below the reporting minimum · "
        "whisker = 95% Wilson interval",
        available_px=right - left,
    )
    parts.append(legend)
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- #
# 2. Confusion matrix
# --------------------------------------------------------------------------- #

_CELLS: tuple[tuple[str, str, str], ...] = (
    ("correct_auto_close", "correct auto-close", "closed, and it really was noise"),
    ("miss", "MISS", "closed, but the defect was real"),
    ("needless_review", "needless review", "escalated, and it was noise"),
    ("correct_escalation", "correct escalation", "escalated, and it was real"),
)


def confusion_matrix_svg(
    matrix: Confusion | None,
    *,
    tau: float | None = None,
    width: float = 720,
    height: float = 360,
    chart_id: str = "confusion",
) -> str:
    """The four operational outcomes, with the miss cell called out structurally.

    The cells are named by what they cost rather than by TP/FP/TN/FN, because
    "false negative" and "a real defect suppressed without a human ever seeing
    it" are the same cell and only one of them reads as a problem.

    The miss cell carries a heavy dashed border and a leading marker as well as
    a different hue, so the emphasis survives a monochrome printout.
    """
    if matrix is None or matrix.n == 0:
        return empty_chart_svg(
            "No labelled verdicts — the confusion matrix has no denominator.",
            width=width,
            chart_id=chart_id,
            title="Confusion matrix (no data)",
        )

    left, top = 176.0, 92.0
    cell_w, cell_h = (width - left - 24) / 2, 92.0
    values = {
        "correct_auto_close": matrix.correct_auto_close,
        "miss": matrix.miss,
        "needless_review": matrix.needless_review,
        "correct_escalation": matrix.correct_escalation,
    }
    peak = max(values.values()) or 1

    gate = "ungated classifier" if tau is None else f"gated at tau = {tau:.3f}"
    parts = [
        _svg_open(
            width,
            height,
            title=(
                f"Confusion matrix over {matrix.n} labelled findings, {gate}: "
                f"{matrix.miss} misses, {matrix.needless_review} needless reviews"
            ),
            desc=(
                "Rows are ground truth, columns are what the harness did. Each "
                "cell prints its count; the miss cell is outlined in a heavy "
                "dashed border."
            ),
            chart_id=chart_id,
        ),
        f"<defs>{_hatch_def(chart_id, 'miss', WARN)}</defs>",
        _text(left, 34, f"harness action  ({gate})", size=12, fill=MUTED),
        _text(left + cell_w / 2, 62, "auto-closed", size=13, fill=INK, anchor="middle", weight="600"),
        _text(left + cell_w * 1.5, 62, "escalated to a human", size=13, fill=INK, anchor="middle", weight="600"),
    ]

    rows = (
        ("really a false positive", ("correct_auto_close", "needless_review")),
        ("really a defect", ("miss", "correct_escalation")),
    )
    for r, (row_label, keys) in enumerate(rows):
        y = top + r * cell_h
        parts.append(_text(left - 14, y + cell_h / 2 - 2, row_label, size=12, fill=INK, anchor="end", weight="600"))
        parts.append(
            _text(
                left - 14,
                y + cell_h / 2 + 16,
                f"n = {matrix.n_real_defects if r else matrix.n_false_positives}",
                size=11,
                fill=MUTED,
                anchor="end",
            )
        )
        for c, key in enumerate(keys):
            x = left + c * cell_w
            count = values[key]
            is_miss = key == "miss"
            shade = count / peak
            parts.append(
                _rect(
                    x + 2,
                    y + 2,
                    cell_w - 6,
                    cell_h - 6,
                    fill=WARN if is_miss else SERIES_A,
                    opacity=max(0.08, shade * (0.34 if is_miss else 0.24)),
                    stroke=WARN if is_miss else RULE,
                    width=2.4 if is_miss else 1,
                    dash="7 4" if is_miss else "",
                    rx=5,
                )
            )
            label, gloss = next((lbl, g) for k, lbl, g in _CELLS if k == key)
            if is_miss:
                # Its own node rather than a prefix on the number, so the count
                # stays machine-readable and the marker still survives greyscale.
                parts.append(_text(x + 16, y + 38, "!", size=26, fill=WARN, weight="700"))
            parts.append(
                _text(
                    x + (36 if is_miss else 16),
                    y + 38,
                    str(count),
                    size=26,
                    fill=WARN if is_miss else INK,
                    weight="700",
                )
            )
            parts.append(_text(x + 16, y + 58, label, size=12, fill=INK, weight="600"))
            parts.append(_text(x + 16, y + 75, gloss, size=11, fill=MUTED))

    footer_y = top + 2 * cell_h + 26
    undecidable = matrix.undecidable_on_real + matrix.undecidable_on_fp
    below = matrix.below_tau_on_real + matrix.below_tau_on_fp
    block, used = _paragraph(
        24,
        footer_y,
        f"needs_human or unparsed: {undecidable} "
        f"({matrix.undecidable_on_real} on real defects) — counted as "
        "not-auto-closed, never as misses",
        available_px=width - 48,
    )
    parts.append(block)
    if tau is not None:
        gate_block, _ = _paragraph(
            24,
            footer_y + used + 4,
            f"withheld by the gate: {below} false-positive verdicts "
            f"({matrix.below_tau_on_real} of them on real defects — misses "
            "the gate prevented)",
            available_px=width - 48,
        )
        parts.append(gate_block)
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- #
# 3. Proof-of-fix funnel
# --------------------------------------------------------------------------- #

_FUNNEL_TITLES: Mapping[str, str] = {
    "full_proof": "full-proof funnel (synthetic target, PoC exploit available)",
    "partial_proof": "partial-proof funnel (real findings, no PoC — D4)",
}


def funnel_svg(
    report: FunnelReport | None,
    *,
    width: float = 720,
    chart_id: str = "funnel",
) -> str:
    """Stage-by-stage survival for one funnel. Never two funnels in one chart.

    Each row draws the cumulative survivors against a dashed outline of the
    drafted count, and prints the graded outcome breakdown — pass / fail /
    skipped / unavailable — beside it. A stage that never ran is the whole point
    of D4's graded bundle, and a bar alone cannot show it.
    """
    if report is None or report.drafted == 0:
        return empty_chart_svg(
            "No proof bundles in this funnel — nothing was drafted, so there is "
            "no survival rate to report.",
            width=width,
            chart_id=chart_id,
            title="Proof-of-fix funnel (no data)",
        )

    rows = ["drafted", *report.stages, "reviewer approved", "may open a PR"]
    counts = [
        report.drafted,
        *[report.cumulative[s] for s in report.stages],
        report.reviewer_approved,
        report.may_open_pr,
    ]
    row_h = 30.0
    top = 76.0
    left, right = 190.0, width - 150.0
    span = right - left
    survival_note = (
        f"survival {report.may_open_pr}/{report.drafted} = "
        f"{report.survival_rate:.0%}  ·  every stage is graded pass / fail / "
        'skipped / unavailable, so "all validators passed" cannot mean "three '
        'of them never ran"'
    )
    footer, footer_h = _paragraph(
        24, top + row_h * len(rows) + 22, survival_note, available_px=width - 48
    )
    height = top + row_h * len(rows) + 22 + footer_h + 12

    parts = [
        _svg_open(
            width,
            height,
            title=(
                f"{_FUNNEL_TITLES.get(report.funnel, report.funnel)}: "
                f"{report.drafted} drafted, {report.may_open_pr} cleared every gate"
            ),
            desc=(
                "Horizontal bars show how many candidates survive each validator "
                "cumulatively; the dashed outline is the drafted count."
            ),
            chart_id=chart_id,
        ),
        f"<defs>{_hatch_def(chart_id, 'gap', MUTED)}</defs>",
        _text(24, 26, _FUNNEL_TITLES.get(report.funnel, report.funnel), size=13, fill=INK, weight="600"),
        _text(
            24,
            46,
            "cumulative survivors — a candidate that fails a stage is out of "
            "every stage below it",
            size=11,
            fill=MUTED,
        ),
    ]

    for i, (label, count) in enumerate(zip(rows, counts)):
        y = top + i * row_h
        share = count / report.drafted
        parts.append(_text(left - 12, y + 15, label, size=12, fill=INK, anchor="end"))
        parts.append(
            _rect(left, y + 3, span, row_h - 10, fill="none", stroke=RULE, dash="4 3", rx=3)
        )
        parts.append(
            _rect(left, y + 3, span * share, row_h - 10, fill=SERIES_A, opacity=0.75, stroke=SERIES_A, rx=3)
        )
        parts.append(
            _text(right + 10, y + 15, f"{count}/{report.drafted}", size=12, fill=INK, weight="600")
        )
        outcomes = report.per_stage_outcomes.get(label)
        if outcomes:
            detail = "  ".join(
                f"{k} {v}" for k, v in outcomes.items() if v
            )
            parts.append(_text(left + 6, y + 15, detail, size=10, fill=MUTED, opacity=0.95))

    parts.append(footer)
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- #
# 4. Per-channel injection ASR, with intervals
# --------------------------------------------------------------------------- #

def injection_channel_svg(
    result: PairedInjectionResult | None,
    *,
    width: float = 720,
    chart_id: str = "injection",
) -> str:
    """Control against hardened, one group per channel, with Wilson whiskers.

    The chart refuses to draw a bar for a channel the arm never delivered:
    `setting_sources=[]` makes `repo_claude_md` zero by construction in the
    hardened arm, and a zero-height bar there would be read as a measured
    defence. It gets a hatched marker and the words "not delivered" instead.

    Per-channel n is about ten, so the whiskers are wide and that is the honest
    picture. There is no single-number headline here on purpose.
    """
    if result is None:
        return empty_chart_svg(
            "No paired injection run in this report — the nightly tier produces it.",
            width=width,
            chart_id=chart_id,
            title="Injection ASR by channel (no data)",
        )

    channels = [c for c in CHANNELS if c in result.control.per_channel]
    if not channels:
        return empty_chart_svg(
            "The paired injection run produced no per-channel results.",
            width=width,
            chart_id=chart_id,
            title="Injection ASR by channel (no data)",
        )

    group_h = 62.0
    top = 96.0
    left, right = 168.0, width - 320.0
    span = right - left
    tail_note = (
        "per-channel n is about ten, so a clean arm's interval still reaches "
        "well above zero — the bound is the result, not the point estimate"
    )
    footer, footer_h = _paragraph(
        24, top + group_h * len(channels) + 30, tail_note, available_px=width - 48
    )
    height = top + group_h * len(channels) + 30 + footer_h + 12

    def px(value: float) -> float:
        return left + value * span

    parts = [
        _svg_open(
            width,
            height,
            title=(
                f"Prompt-injection attack success rate by channel over "
                f"{result.n_payloads} payloads, unguarded control against the "
                "hardened configuration"
            ),
            desc=(
                "Two bars per channel. Solid is the unguarded control, hatched "
                "with a dashed outline is the hardened configuration. Whiskers "
                "are 95% Wilson intervals."
            ),
            chart_id=chart_id,
        ),
        f"<defs>{_hatch_def(chart_id, 'hard', SERIES_B)}"
        f"{_hatch_def(chart_id, 'void', MUTED)}</defs>",
        _text(24, 26, "attack success rate by channel (paired, D12)", size=13, fill=INK, weight="600"),
        _text(
            24,
            46,
            f"control compromised on every deliverable channel: "
            f"{'yes' if result.control_compromised else 'NO — the instrument did not fire'}",
            size=11,
            fill=INK if result.control_compromised else WARN,
        ),
    ]

    # Legend, named in text so hue is never the only cue.
    parts.append(_rect(24, 60, 16, 11, fill=SERIES_A, stroke=SERIES_A))
    parts.append(_text(46, 70, "unguarded control", size=11, fill=MUTED))
    parts.append(
        _rect(178, 60, 16, 11, fill=f"url(#{chart_id}-hard)", stroke=SERIES_B, dash="3 2")
    )
    parts.append(_text(200, 70, "hardened (shipped config)", size=11, fill=MUTED))
    parts.append(
        _rect(376, 60, 16, 11, fill=f"url(#{chart_id}-void)", stroke=MUTED, dash="3 2")
    )
    parts.append(_text(398, 70, "not delivered — 0 by construction", size=11, fill=MUTED))

    for value in (0.0, 0.25, 0.5, 0.75, 1.0):
        parts.append(_line(px(value), top - 8, px(value), top + group_h * len(channels) - 12, stroke=GRID))
        parts.append(
            _text(px(value), top + group_h * len(channels) + 4, f"{value:.0%}", size=10, fill=MUTED, anchor="middle")
        )

    for i, channel in enumerate(channels):
        base_y = top + i * group_h
        parts.append(_text(left - 12, base_y + 14, channel, size=12, fill=INK, anchor="end", weight="600"))
        for j, (arm_name, arm) in enumerate(
            (("control", result.control), ("hardened", result.hardened))
        ):
            cr = arm.per_channel.get(channel)
            if cr is None:
                continue
            y = base_y + j * 22
            solid = arm_name == "control"
            if cr.zero_by_construction:
                parts.append(
                    _rect(left, y, 96, 15, fill=f"url(#{chart_id}-void)", stroke=MUTED, dash="3 2", rx=2)
                )
                parts.append(
                    _text(left + 104, y + 12, f"not delivered ({cr.asr.n} payloads never reached the model)", size=11, fill=MUTED)
                )
                continue
            point = cr.asr.point or 0.0
            parts.append(
                _rect(
                    left,
                    y,
                    max(span * point, 1.5),
                    15,
                    fill=SERIES_A if solid else f"url(#{chart_id}-hard)",
                    stroke=SERIES_A if solid else SERIES_B,
                    width=1.2,
                    dash="" if solid else "3 2",
                    rx=2,
                )
            )
            interval = cr.asr.interval
            if interval is not None:
                lo, hi = interval
                cy = y + 7.5
                parts.append(_line(px(lo), cy, px(hi), cy, stroke=INK, width=1.3))
                parts.append(_line(px(lo), cy - 5, px(lo), cy + 5, stroke=INK, width=1.3))
                parts.append(_line(px(hi), cy - 5, px(hi), cy + 5, stroke=INK, width=1.3))
            parts.append(
                _text(right + 10, y + 12, f"{arm_name}: {_rate_label(cr.asr)}", size=11, fill=INK)
            )

    parts.append(footer)
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- #
# 5. Confidence histogram
# --------------------------------------------------------------------------- #

def confidence_histogram_svg(
    diagram: ReliabilityDiagram | None,
    *,
    tau: float | None = None,
    width: float = 720,
    height: float = 300,
    chart_id: str = "confhist",
) -> str:
    """How the stated confidences are distributed, read off the reliability bins.

    Derived from `ReliabilityDiagram.bins` rather than recounted, so the
    histogram and the calibration chart can never disagree about a denominator.
    The excluded rows — `needs_human` and every D10 failure status — get their
    own hatched bar on the right, because a verdict the harness declined to give
    is part of the distribution and dropping it flatters the picture.
    """
    if diagram is None or diagram.n_scored == 0:
        return empty_chart_svg(
            "No stated confidences to plot.",
            width=width,
            chart_id=chart_id,
            title="Confidence distribution (no data)",
        )

    left, right, top, bottom = 56.0, width - 150.0, 54.0, height - 56.0
    plot_w, plot_h = right - left, bottom - top
    counts = [b.n for b in diagram.bins]
    peak = max([*counts, diagram.n_excluded, 1])
    bin_w = plot_w / max(len(diagram.bins), 1)

    parts = [
        _svg_open(
            width,
            height,
            title=(
                f"Confidence distribution over {diagram.n_scored} decidable "
                f"verdicts, plus {diagram.n_excluded} with no verdict"
            ),
            desc=(
                "Counts of verdicts per stated-confidence bin. The hatched bar "
                "on the right counts attempts that produced no verdict at all."
            ),
            chart_id=chart_id,
        ),
        f"<defs>{_hatch_def(chart_id, 'excl', MUTED)}</defs>",
        _text(24, 26, "stated confidence: where the verdicts actually sit", size=13, fill=INK, weight="600"),
        _line(left, bottom, right + 116, bottom, stroke=RULE, width=1.5),
        _line(left, top, left, bottom, stroke=RULE, width=1.5),
    ]

    for i in range(5):
        value = peak * i / 4
        y = bottom - (value / peak) * plot_h
        parts.append(_line(left, y, right, y, stroke=GRID))
        parts.append(_text(left - 8, y + 4, f"{value:.0f}", size=10, fill=MUTED, anchor="end"))

    for i, b in enumerate(diagram.bins):
        x = left + i * bin_w
        h = (b.n / peak) * plot_h
        parts.append(
            _rect(x + bin_w * 0.12, bottom - h, bin_w * 0.76, h, fill=SERIES_A, opacity=0.8, stroke=SERIES_A, rx=2)
        )
        if b.n:
            parts.append(_text(x + bin_w / 2, bottom - h - 5, str(b.n), size=10, fill=INK, anchor="middle"))
        if i % 2 == 0:
            parts.append(
                _text(x + bin_w / 2, bottom + 16, f"{b.lower:.1f}", size=10, fill=MUTED, anchor="middle")
            )
    parts.append(_text(right, bottom + 16, "1.0", size=10, fill=MUTED, anchor="middle"))

    if tau is not None:
        tx = left + tau * plot_w
        parts.append(_line(tx, top - 6, tx, bottom, stroke=WARN, width=2, dash="4 3"))
        parts.append(_text(tx, top - 12, f"tau = {tau:.3f}", size=11, fill=WARN, anchor="middle", weight="600"))

    ex_x = right + 40
    ex_h = (diagram.n_excluded / peak) * plot_h
    parts.append(
        _rect(ex_x, bottom - ex_h, 52, ex_h, fill=f"url(#{chart_id}-excl)", stroke=MUTED, width=1.2, dash="3 2", rx=2)
    )
    parts.append(_text(ex_x + 26, bottom - ex_h - 5, str(diagram.n_excluded), size=10, fill=INK, anchor="middle"))
    parts.append(_text(ex_x + 26, bottom + 16, "no verdict", size=10, fill=MUTED, anchor="middle"))

    breakdown = ", ".join(f"{k} {v}" for k, v in sorted(diagram.excluded_by_status.items()))
    footer, _ = _paragraph(
        24,
        bottom + 34,
        f"excluded: {breakdown or 'none'} — counted here rather than dropped, "
        "because an attempt that produced no verdict is still an attempt",
        available_px=width - 48,
    )
    parts.append(footer)
    parts.append("</svg>")
    return "".join(parts)


def chart_theme_css(selector: str = ":root") -> str:
    """The light-mode variable block, for a host page that wants to theme charts."""
    body = " ".join(f"{k}: {v};" for k, v in CHART_FALLBACKS.items())
    return f"{selector} {{ {body} }}"
