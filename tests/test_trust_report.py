"""The rendered page: what it says, what it refuses to say, and what it needs.

The disclosure guarantee is tested in `test_report_redaction.py`. This file
covers the other two obligations:

  * It **renders** on zero findings and on all-`NO_SUITE` input rather than
    dividing by zero, and on a suite that could not score a corpus at all.
  * It **does not print a number the corpus cannot support**. Where the eval
    lane hands over a `Rate` below its reporting minimum, the page prints the
    counts and says the rate is withheld; where a tau derivation mostly failed,
    it prints no tau. Every such refusal is listed in one section, so a reader
    can see the shape of the ignorance rather than having to notice an absence.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

import pytest
from report_fixtures import (
    STAMP,
    full_proof_bundle,
    no_suite_bundle,
    paired_injection,
    partial_proof_bundle,
    real_corpus,
    suite_result,
    synthetic_finding,
)

from pramaan.evals.stats import Rate
from pramaan.report import trust_report
from pramaan.report.trust_report import _TOC, ReportInputs, render, report_manifest


@pytest.fixture(scope="module")
def suite():
    return suite_result()


@pytest.fixture(scope="module")
def full_page(suite):
    corpus = real_corpus()
    js = synthetic_finding()
    return render(
        ReportInputs(
            findings=[*corpus, js],
            bundles=[
                full_proof_bundle(js.finding_id),
                *[partial_proof_bundle(f.finding_id) for f in corpus[:12]],
            ],
            suite=suite,
            injection=paired_injection(),
            generated_at=STAMP,
            commit_sha="0f1e2d3c",
            model_id="claude-sonnet-5",
            run_epoch="20260903T000000Z-abcd1234",
            corpus_labelled=False,
        )
    )


# --------------------------------------------------------------------------- #
# It renders on nothing
# --------------------------------------------------------------------------- #

def test_renders_on_zero_findings():
    document = render(ReportInputs(generated_at=STAMP))
    assert document.startswith("<!doctype html>")
    assert "No findings were supplied" in document
    assert "%" not in _visible_rates(document), "no rate over an empty corpus"


def _visible_rates(document: str) -> str:
    """Percentages in rendered text, not in CSS or SVG sizing attributes."""
    body = document.split("</style>", 1)[-1]
    text = " ".join(re.findall(r">([^<>]+)<", body))
    return " ".join(re.findall(r"\d+\.?\d*%", text))


def test_renders_on_all_no_suite_bundles():
    """D5: NO_SUITE fails closed, and the funnel still has a denominator."""
    corpus = real_corpus()[:8]
    document = render(
        ReportInputs(
            findings=corpus,
            bundles=[no_suite_bundle(f.finding_id) for f in corpus],
            generated_at=STAMP,
        )
    )
    assert "partial-proof funnel" in document
    assert "unavailable" in document
    assert "may open a PR" in document


def test_renders_when_the_suite_could_not_score_a_corpus():
    from pramaan.evals.runner import CorpusReport, SuiteResult

    suite = SuiteResult(
        tier="ci",
        run_epoch=None,
        n_attempts=0,
        corpora={
            "php-121": CorpusReport(
                corpus="php-121",
                n_rows=0,
                unavailable=("no labelled rows",),
            )
        },
    )
    document = render(ReportInputs(suite=suite, generated_at=STAMP))
    assert "Not scored" in document
    assert "no labelled rows" in document


def test_renders_with_no_bundles_and_no_injection():
    document = render(ReportInputs(findings=real_corpus()[:3], generated_at=STAMP))
    assert "No fixes were drafted" in document
    assert "No paired injection run" in document


def test_no_section_divides_by_zero():
    """Every combination of empty inputs, rendered."""
    corpus = real_corpus()[:2]
    for kwargs in (
        {},
        {"findings": corpus},
        {"bundles": [partial_proof_bundle("nope")]},
        {"findings": corpus, "bundles": []},
        {"injection": paired_injection()},
    ):
        assert render(ReportInputs(generated_at=STAMP, **kwargs))


# --------------------------------------------------------------------------- #
# It refuses to overstate
# --------------------------------------------------------------------------- #

def test_a_zero_over_forty_seven_rate_carries_both_bounds():
    """The two bounds are different statistics and the page labels both.

    A 0/47 miss rate has a 95% Wilson upper bound of 7.6% and a rule-of-three
    upper bound of 6.2%. Neither of them is 0%.
    """
    ctx = trust_report._Ctx(ledger=trust_report.build_ledger([]))
    html = trust_report._rate_html(Rate(0, 47, label="miss rate"), ctx)
    assert "0/47" in html
    assert "95% Wilson CI 0.0%–7.6%" in html
    assert "rule-of-three 95% upper bound 6.2%" in html
    # The point estimate may appear, but never on its own: the interval is in
    # the same fragment, which is the whole contract of `_rate_html`.
    assert html.index("0.0%</strong>") < html.index("95% Wilson CI")


def test_a_clean_ten_trial_run_states_its_upper_bound():
    """`injection.py`: a clean 0/10 has a 95% upper bound of about 0.26."""
    ctx = trust_report._Ctx(ledger=trust_report.build_ledger([]))
    html = trust_report._rate_html(Rate(0, 10, label="hardened ASR"), ctx)
    assert "0/10" in html
    assert "rule-of-three 95% upper bound 25.9%" in html


def test_a_rate_below_the_reporting_minimum_is_withheld_and_logged():
    ctx = trust_report._Ctx(ledger=trust_report.build_ledger([]))
    html = trust_report._rate_html(
        Rate(1, 3, min_n=5, label="miss rate"), ctx, topic="miss rate"
    )
    assert "1/3" in html
    assert "rate withheld" in html
    assert "33" not in html, "the point estimate must not appear at all"
    assert ctx.withheld and "below the reporting minimum" in ctx.withheld[0].reason


def test_an_empty_denominator_is_not_zero_percent():
    ctx = trust_report._Ctx(ledger=trust_report.build_ledger([]))
    html = trust_report._rate_html(Rate(0, 0, label="x"), ctx, topic="x")
    assert "no observations" in html
    assert "%" not in html


def test_the_refusals_section_lists_every_withheld_number(full_page):
    assert "Numbers this report will not print" in full_page
    assert "why it is withheld" in full_page
    for topic in (
        "ECE as a headline",
        "hardened ASR on repo_claude_md",
        "intra-rater agreement",
        "model-vs-human agreement",
        "expected breach count after remediation",
    ):
        assert topic in full_page, topic


def test_a_page_with_nothing_withheld_says_so():
    ctx = trust_report._Ctx(ledger=trust_report.build_ledger([]))
    assert "supported by its denominator" in trust_report._refusals_section(ctx)


def test_a_never_delivered_channel_is_not_reported_as_a_defence(full_page):
    assert "0 by construction" in full_page
    assert "setting_sources=[]" in full_page
    assert "attacks that were never possible" in full_page


def test_both_pooled_injection_figures_are_labelled_separately(full_page):
    assert "pooled over deliverable channels" in full_page
    assert "pooled over all channels" in full_page


def test_ece_without_a_bootstrap_interval_is_not_a_headline(suite):
    """The CI tier skips the bootstrap, so the page must say so."""
    document = render(ReportInputs(suite=suite, generated_at=STAMP))
    assert "no interval computed" in document
    assert "not a headline number" in document


def test_tau_is_published_with_its_fold_spread(full_page):
    assert "fold spread" in full_page
    assert "IQR" in full_page
    assert "folds reaching the target" in full_page


def test_the_two_funnels_are_never_blended(full_page):
    assert "full-proof funnel" in full_page
    assert "partial-proof funnel" in full_page
    assert "never blended" in full_page


def test_the_ci_tier_says_its_pass_k_is_a_replay(full_page):
    assert "replays cached verdicts" in full_page
    assert "fresh run epoch" in full_page


# --------------------------------------------------------------------------- #
# Self-contained page
# --------------------------------------------------------------------------- #

def test_page_makes_no_network_request(full_page):
    lowered = full_page.lower()
    assert "<script" not in lowered
    assert "https://" not in lowered
    assert "http://" not in lowered.replace("http://www.w3.org/2000/svg", "")
    assert "@import" not in lowered
    assert "<link" not in lowered
    assert "<img" not in lowered


def test_page_is_themed_for_light_and_dark(full_page):
    assert "prefers-color-scheme: dark" in full_page
    assert 'name="color-scheme" content="light dark"' in full_page
    assert "--pr-ink" in full_page


def test_page_has_a_print_stylesheet(full_page):
    assert "@media print" in full_page


def test_every_toc_anchor_resolves(full_page):
    for anchor, _label in _TOC:
        assert f'id="{anchor}"' in full_page, anchor
        assert f'href="#{anchor}"' in full_page, anchor


def test_charts_are_inline_svg_and_well_formed(full_page):
    svgs = re.findall(r"<svg\b.*?</svg>", full_page, flags=re.S)
    assert len(svgs) >= 5, "reliability, confusion, two funnels, injection, histogram"
    for svg in svgs:
        ET.fromstring(svg)


def test_chart_element_ids_are_unique_across_the_page(full_page):
    ids = re.findall(r'\sid="([^"]+)"', full_page)
    assert len(ids) == len(set(ids)), "duplicate ids cross-wire SVG patterns"


def test_the_disclosure_policy_is_stated_on_the_page(full_page):
    """D17: 'Policy stated in the report.'"""
    assert "Disclosure policy" in full_page
    assert "bug bounty programme excludes open-source" in full_page
    assert "synthetic-target allowlist" in full_page


def test_the_page_says_how_to_rederive_its_numbers(full_page):
    assert "no API key" in full_page
    assert "verdict_table.jsonl" in full_page


def test_run_metadata_is_stamped(full_page):
    assert "0f1e2d3c" in full_page
    assert "claude-sonnet-5" in full_page
    assert "20260903T000000Z-abcd1234" in full_page


# --------------------------------------------------------------------------- #
# Escaping and the manifest
# --------------------------------------------------------------------------- #

def test_repository_names_are_escaped():
    hostile = synthetic_finding(
        finding_id="semgrep:x:<script>alert(1)</script>:a/b.js:1",
        repo="<script>alert(1)</script>",
        path="a/b.js",
    )
    document = render(ReportInputs(findings=[hostile], generated_at=STAMP))
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;" in document


def test_report_manifest_is_publication_safe():
    corpus = real_corpus()
    manifest = report_manifest(ReportInputs(findings=corpus, generated_at=STAMP))
    blob = json.dumps(manifest).lower()
    for finding in corpus:
        assert finding.path.lower() not in blob
    assert manifest["disclosure"]["n_aggregate_only"] == len(corpus)


def test_render_to_file_writes_nothing_when_the_gate_raises(tmp_path, monkeypatch):
    """A refused render must not leave a partial artifact on disk."""
    from pramaan.report.redaction import DisclosureViolation

    def boom(_document, _ledger):
        raise DisclosureViolation("simulated leak")

    monkeypatch.setattr(trust_report, "assert_clean", boom)
    target = tmp_path / "report.html"
    with pytest.raises(DisclosureViolation):
        trust_report.render_to_file(
            ReportInputs(findings=real_corpus(), generated_at=STAMP), str(target)
        )
    assert not target.exists()


def test_render_to_file_writes_a_clean_document(tmp_path):
    corpus = real_corpus()
    target = tmp_path / "report.html"
    trust_report.render_to_file(
        ReportInputs(findings=corpus, generated_at=STAMP), str(target)
    )
    written = target.read_text(encoding="utf-8").lower()
    for finding in corpus:
        assert finding.path.lower() not in written


def test_evidence_section_is_empty_without_a_qualifying_finding():
    document = render(ReportInputs(findings=real_corpus(), generated_at=STAMP))
    assert "No finding in this run qualified for full disclosure" in document


def test_evidence_section_publishes_the_synthetic_target(full_page):
    assert "routes/search.js" in full_page
    assert "deliberately vulnerable" in full_page
