"""Hand-rolled SVG: no dependencies, no colour-only meaning, no invented data.

The charts are checked for three properties rather than for pixels:

  * **Self-contained.** No `<script>`, no external URL, no font import, no
    matplotlib. A trust report that phones home while claiming to be auditable
    is not auditable.
  * **Legible without colour.** Every bar carries a printed number, every
    series is named in text, and the second series in a pair is hatched as well
    as recoloured.
  * **Honest about absence.** `None` and zero-count inputs render an empty
    state that says so, rather than axes implying a measurement of zero.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest
from evals_fixtures import CORPUS, tau_corpus
from report_fixtures import full_proof_bundle, no_suite_bundle, paired_injection

from pramaan.calibration.tau import derive, reliability_diagram
from pramaan.evals.metrics import confusion, fp_class_metrics
from pramaan.proof.bundle import funnel_report
from pramaan.report import charts

ALL_CHARTS = (
    "reliability_diagram_svg",
    "confusion_matrix_svg",
    "funnel_svg",
    "injection_channel_svg",
    "confidence_histogram_svg",
)


@pytest.fixture(scope="module")
def rows():
    return tau_corpus()


@pytest.fixture(scope="module")
def diagram(rows):
    return reliability_diagram(rows, bootstrap=200, seed="charts-test")


@pytest.fixture(scope="module")
def tau_result(rows):
    return derive(rows, k=5, repeats=2)


@pytest.fixture(scope="module")
def matrix(rows):
    return confusion(rows, tau=0.6)


@pytest.fixture(scope="module")
def funnel():
    bundles = [full_proof_bundle(f"F{i}") for i in range(6)]
    bundles.append(no_suite_bundle("F-nosuite"))
    return funnel_report([b for b in bundles if b.funnel == "full_proof"])


@pytest.fixture(scope="module")
def injection():
    return paired_injection(hardened_wins=set())


def _all_rendered(diagram, tau_result, matrix, funnel, injection) -> dict[str, str]:
    return {
        "reliability": charts.reliability_diagram_svg(
            diagram, tau=tau_result.recommended_tau(), tau_spread=tau_result.spread
        ),
        "confusion": charts.confusion_matrix_svg(matrix, tau=0.6),
        "funnel": charts.funnel_svg(funnel),
        "injection": charts.injection_channel_svg(injection),
        "histogram": charts.confidence_histogram_svg(diagram, tau=0.6),
    }


@pytest.fixture(scope="module")
def rendered(diagram, tau_result, matrix, funnel, injection):
    return _all_rendered(diagram, tau_result, matrix, funnel, injection)


# --------------------------------------------------------------------------- #
# Self-contained
# --------------------------------------------------------------------------- #

def test_every_chart_is_well_formed_xml(rendered):
    for name, svg in rendered.items():
        ET.fromstring(svg), name


def test_no_chart_loads_anything(rendered):
    for name, svg in rendered.items():
        lowered = svg.lower()
        assert "<script" not in lowered, name
        assert "http://" not in lowered.replace("http://www.w3.org/2000/svg", ""), name
        assert "https://" not in lowered, name
        assert "@import" not in lowered, name
        assert "<image" not in lowered, name
        assert "xlink:href" not in lowered, name


def test_charts_import_no_plotting_library():
    import sys

    for banned in ("matplotlib", "plotly", "pygal", "seaborn", "bokeh", "altair"):
        assert banned not in sys.modules, f"{banned} was imported"
    source = charts.__file__ or ""
    assert source
    imports = [
        line
        for line in open(source, encoding="utf-8").read().splitlines()
        if line.startswith(("import ", "from ")) or line.strip().startswith("from ")
    ]
    joined = " ".join(imports)
    for banned in ("matplotlib", "plotly", "pygal", "seaborn", "bokeh", "altair"):
        assert banned not in joined


# --------------------------------------------------------------------------- #
# Theming
# --------------------------------------------------------------------------- #

def test_every_colour_is_a_themeable_variable_with_a_fallback(rendered):
    """`var(--pr-x, #hex)` renders standalone and follows the page in dark mode."""
    for name, svg in rendered.items():
        hexes = re.findall(r'(?:fill|stroke)="(#[0-9a-fA-F]{3,8})"', svg)
        assert not hexes, f"{name} hard-codes {hexes}"
        assert "var(--pr-" in svg, name


def test_theme_css_names_every_variable_the_charts_use(rendered):
    css = charts.chart_theme_css()
    used = set()
    for svg in rendered.values():
        used |= set(re.findall(r"var\((--pr-[a-z-]+),", svg))
    for name in used:
        assert f"{name}:" in css


def test_no_chart_paints_an_opaque_page_background(rendered):
    """A white plot rectangle is how a chart turns into a torch on a dark page."""
    for name, svg in rendered.items():
        assert "#fff" not in svg.lower(), name
        assert "white" not in svg.lower(), name


# --------------------------------------------------------------------------- #
# Not colour alone
# --------------------------------------------------------------------------- #

def test_reliability_bars_carry_counts_and_intervals(rendered, diagram):
    svg = rendered["reliability"]
    assert "n=" in svg
    occupied = [b for b in diagram.bins if b.n > 0]
    for b in occupied:
        assert f"n={b.n}" in svg
    assert "95% Wilson interval" in svg
    assert "perfect calibration" in svg


def test_reliability_marks_tau_and_its_fold_spread(rendered, tau_result):
    svg = rendered["reliability"]
    assert f"tau = {tau_result.recommended_tau():.3f}" in svg
    assert "fold IQR" in svg


def test_underpowered_bins_are_hatched_not_merely_recoloured(rows):
    """A bar at 100% over three rows must not look like one over ninety."""
    sparse = [r for r in rows if r.confidence < 0.25][:3]
    sparse += [r for r in rows if r.confidence > 0.9][:20]
    diagram = reliability_diagram(sparse, min_bin_n=10)
    svg = charts.reliability_diagram_svg(diagram)
    assert "url(#reliability-thin)" in svg
    assert "hatched" in svg


def test_confusion_prints_every_count_and_names_the_miss_cell(rendered, matrix):
    svg = rendered["confusion"]
    for value in (
        matrix.correct_auto_close,
        matrix.miss,
        matrix.needless_review,
        matrix.correct_escalation,
    ):
        assert f">{value}<" in svg
    assert "MISS" in svg
    assert "closed, but the defect was real" in svg
    # The miss cell is distinguished structurally, not only by hue.
    assert 'stroke-dasharray="7 4"' in svg


def test_confusion_reports_undecidable_and_gated_rows(rendered):
    svg = rendered["confusion"]
    assert "needs_human or unparsed" in svg
    assert "withheld by the gate" in svg


def test_funnel_prints_counts_and_graded_outcomes(rendered, funnel):
    svg = rendered["funnel"]
    assert f"{funnel.drafted}/{funnel.drafted}" in svg
    assert "may open a PR" in svg
    assert "pass" in svg  # the per-stage grade breakdown
    assert "skipped / unavailable" in svg


def test_funnel_names_its_kind_so_two_funnels_cannot_be_confused(rendered):
    assert "full-proof funnel" in rendered["funnel"]


def test_injection_marks_the_never_delivered_channel(rendered):
    """`setting_sources=[]` makes that channel zero by construction, not defended."""
    svg = rendered["injection"]
    assert "not delivered" in svg
    assert "0 by construction" in svg


def test_injection_names_both_arms_in_text(rendered):
    svg = rendered["injection"]
    assert "unguarded control" in svg
    assert "hardened (shipped config)" in svg
    assert "control:" in svg and "hardened:" in svg


def test_injection_prints_counts_not_only_percentages(rendered, injection):
    svg = rendered["injection"]
    channel = injection.control.per_channel["code_comment"]
    assert f"{channel.asr.successes}/{channel.asr.n}" in svg


def test_histogram_counts_the_verdicts_that_never_happened(rendered, diagram):
    svg = rendered["histogram"]
    assert "no verdict" in svg
    assert "excluded:" in svg
    for b in diagram.bins:
        if b.n:
            assert f">{b.n}<" in svg


# --------------------------------------------------------------------------- #
# Absence
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", ALL_CHARTS)
def test_every_chart_renders_an_empty_state_on_none(name):
    svg = getattr(charts, name)(None)
    root = ET.fromstring(svg)
    title = root.find("{http://www.w3.org/2000/svg}title")
    assert title is not None and "no data" in (title.text or "").lower(), name
    # A dashed placeholder box and one sentence — no axes, no bars, no ticks.
    assert len(list(root.iter("{http://www.w3.org/2000/svg}rect"))) == 1, name
    assert not list(root.iter("{http://www.w3.org/2000/svg}line")), name


def test_empty_state_does_not_imply_a_measurement_of_zero():
    svg = charts.funnel_svg(None)
    assert "there is no survival rate to report" in svg
    root = ET.fromstring(svg)
    for node in root.iter("{http://www.w3.org/2000/svg}text"):
        assert "%" not in (node.text or ""), "an empty state must not print a rate"


def test_confusion_on_an_empty_matrix_does_not_divide_by_zero():
    from pramaan.evals.metrics import Confusion

    empty = Confusion(0, 0, 0, 0, 0, 0, 0, 0)
    svg = charts.confusion_matrix_svg(empty)
    ET.fromstring(svg)
    assert "no denominator" in svg


# --------------------------------------------------------------------------- #
# Geometry
# --------------------------------------------------------------------------- #

def test_no_chart_emits_nan_or_infinity(rendered):
    for name, svg in rendered.items():
        assert "nan" not in svg.lower(), name
        assert "inf" not in svg.lower().replace("information", ""), name


def test_every_chart_declares_an_accessible_name(rendered):
    for name, svg in rendered.items():
        root = ET.fromstring(svg)
        assert root.attrib.get("role") == "img", name
        assert root.attrib.get("aria-label"), name
        title = root.find("{http://www.w3.org/2000/svg}title")
        assert title is not None and title.text, name


def test_chart_titles_are_aggregate_only(rendered):
    """The accessible name is a substring of the page like any other."""
    for name, svg in rendered.items():
        root = ET.fromstring(svg)
        title = root.find("{http://www.w3.org/2000/svg}title")
        assert ".php" not in (title.text or ""), name
        assert ".js" not in (title.text or ""), name


def test_pattern_ids_are_namespaced_per_chart(diagram, matrix):
    """Two SVGs in one document must not share a `<defs>` id."""
    a = charts.reliability_diagram_svg(diagram, chart_id="rel-a")
    b = charts.reliability_diagram_svg(diagram, chart_id="rel-b")
    assert 'id="rel-a-thin"' in a
    assert 'id="rel-b-thin"' in b
    assert 'id="rel-a-thin"' not in b


def test_coordinates_stay_inside_the_viewbox(rendered):
    """A bar drawn off-canvas is a silently missing bar."""
    for name, svg in rendered.items():
        root = ET.fromstring(svg)
        _, _, width, height = (float(v) for v in root.attrib["viewBox"].split())
        for rect in root.iter("{http://www.w3.org/2000/svg}rect"):
            if rect.attrib.get("width") == "6":
                continue  # the hatch tile inside <defs>, not a plotted rect
            x = float(rect.attrib.get("x", 0))
            y = float(rect.attrib.get("y", 0))
            w = float(rect.attrib["width"])
            h = float(rect.attrib["height"])
            assert -1 <= x and x + w <= width + 1, f"{name}: rect overflows width"
            assert -1 <= y and y + h <= height + 1, f"{name}: rect overflows height"


def test_no_label_runs_off_the_canvas(rendered):
    """Text that overflows the viewBox is a silently clipped label.

    Width is estimated at 0.5em per character, which is conservative for the
    system sans stack these charts specify. It catches the real failure — a
    sentence anchored near the right edge — without being brittle about kerning.
    """
    for name, svg in rendered.items():
        root = ET.fromstring(svg)
        width = float(root.attrib["viewBox"].split()[2])
        for node in root.iter("{http://www.w3.org/2000/svg}text"):
            if "transform" in node.attrib:
                continue  # rotated axis titles
            text = node.text or ""
            size = float(node.attrib.get("font-size", 12))
            span = len(text) * size * 0.5
            x = float(node.attrib["x"])
            anchor = node.attrib.get("text-anchor", "start")
            left = x if anchor == "start" else (x - span / 2 if anchor == "middle" else x - span)
            assert left >= -1, f"{name}: {text[:40]!r} starts off-canvas"
            assert left + span <= width + 1, f"{name}: {text[:40]!r} overflows"


def test_charts_do_not_recompute_anything(rows):
    """Every drawn number is read off the result object it was handed."""
    metrics = fp_class_metrics(rows, tau=0.6)
    svg = charts.confusion_matrix_svg(metrics.matrix, tau=metrics.tau)
    assert f">{metrics.matrix.miss}<" in svg
    # The chart never sees the labelled rows, only the computed matrix.
    assert CORPUS not in svg
