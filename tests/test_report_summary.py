"""Compliance clocks and the breach forecast.

Two behaviours are worth more than the arithmetic:

  * A control that could not be evaluated is reported as **not evaluated**,
    never as satisfied. Claiming a control you did not check is the failure this
    project argues against, and the DPDP clock is the easy place to commit it.
  * The forecast publishes the projection with no fitted parameter, and refuses
    to publish one that needs a remediation velocity it does not have.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from report_fixtures import real_corpus, synthetic_finding

from pramaan.report.summary import (
    AT_RISK_DAYS,
    CLOCKS,
    clocks_for,
    forecast_breaches,
    summarise,
    vapt_period_export,
)
from pramaan.schemas import BusinessImpact, Finding

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)


def _finding(severity: str = "high", finding_id: str = "F1") -> Finding:
    return Finding(
        finding_id=finding_id,
        fingerprint=f"fp-{finding_id}",
        tool="semgrep",
        rule_id="rule",
        message="m",
        severity_reported=severity,  # type: ignore[arg-type]
        repo="razorpay-opencart",
        path="catalog/controller/payment/razorpay.php",
        line_start=1,
        line_end=1,
    )


# --------------------------------------------------------------------------- #
# PCI DSS 6.3.3 — the 30-day clock
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "age_days,expected",
    [(0, "on_track"), (10, "on_track"), (24, "at_risk"), (31, "breached")],
)
def test_pci_clock_states(age_days, expected):
    detected = NOW - timedelta(days=age_days)
    clocks = clocks_for(
        _finding("high"), severity="high", first_detected=detected, now=NOW
    )
    pci = [c for c in clocks if c.clock_key == "pci_6_3_3"]
    assert len(pci) == 1
    assert pci[0].state == expected


def test_at_risk_window_is_one_summary_cycle():
    """Anything closer than a week breaches before the next summary is written."""
    detected = NOW - timedelta(days=30 - AT_RISK_DAYS)
    clocks = clocks_for(_finding(), severity="high", first_detected=detected, now=NOW)
    assert clocks[0].state == "at_risk"


def test_medium_severity_is_not_on_the_pci_clock():
    clocks = clocks_for(
        _finding("medium"), severity="medium", first_detected=NOW, now=NOW
    )
    assert not [c for c in clocks if c.clock_key == "pci_6_3_3"]


# --------------------------------------------------------------------------- #
# RBI para 21 — "immediately" is not a countdown
# --------------------------------------------------------------------------- #

def test_critical_findings_are_due_immediately_not_in_thirty_days():
    clocks = clocks_for(
        _finding("critical"), severity="critical", first_detected=NOW, now=NOW
    )
    rbi = [c for c in clocks if c.clock_key == "rbi_para_21"]
    assert len(rbi) == 1
    assert rbi[0].state == "due_immediately"
    assert rbi[0].days_remaining == 0.0


def test_a_critical_finding_carries_every_applicable_clock():
    """Including the DPDP one, which is emitted as unevaluated rather than dropped."""
    clocks = clocks_for(
        _finding("critical"), severity="critical", first_detected=NOW, now=NOW
    )
    assert {c.clock_key for c in clocks} == {"pci_6_3_3", "rbi_para_21", "dpdp_rule_7"}
    assert {c.clock_key: c.state for c in clocks}["dpdp_rule_7"] == "not_evaluated"


def test_immediate_clocks_are_excluded_from_the_day_by_day_schedule():
    clocks = clocks_for(
        _finding("critical"), severity="critical", first_detected=NOW, now=NOW
    )
    forecast = forecast_breaches(clocks, now=NOW)
    assert any("no countdown" in c for c in forecast.caveats)
    scheduled_total = sum(count for _day, count in forecast.scheduled)
    assert scheduled_total == 1  # the PCI clock only


# --------------------------------------------------------------------------- #
# DPDP rule 7 — unevaluated is not satisfied
# --------------------------------------------------------------------------- #

def test_dpdp_clock_is_unevaluated_without_tags():
    clocks = clocks_for(_finding(), severity="high", first_detected=NOW, now=NOW)
    dpdp = [c for c in clocks if c.clock_key == "dpdp_rule_7"]
    assert len(dpdp) == 1
    assert dpdp[0].state == "not_evaluated"
    assert dpdp[0].due_at is None
    assert "never assessed" in dpdp[0].detail


def test_dpdp_clock_applies_when_the_path_policy_tagged_personal_data():
    clocks = clocks_for(
        _finding(),
        severity="high",
        first_detected=NOW - timedelta(hours=80),
        now=NOW,
        tags=BusinessImpact(kyc_or_settlement=True),
    )
    dpdp = [c for c in clocks if c.clock_key == "dpdp_rule_7"]
    assert dpdp[0].state == "breached"


def test_dpdp_clock_is_absent_when_tags_say_no_personal_data():
    clocks = clocks_for(
        _finding(),
        severity="high",
        first_detected=NOW,
        now=NOW,
        tags=BusinessImpact(payment_path=True),
    )
    assert not [c for c in clocks if c.clock_key == "dpdp_rule_7"]


def test_every_documented_control_is_represented():
    controls = {c.control for c in CLOCKS}
    assert any("PCI DSS 4.0.1 req 6.3.3" in c for c in controls)
    assert any("para 21" in c for c in controls)
    assert any("DPDP Rules 2025 rule 7" in c for c in controls)


# --------------------------------------------------------------------------- #
# The forecast
# --------------------------------------------------------------------------- #

def test_forecast_without_closure_history_publishes_no_expected_count():
    clocks = clocks_for(
        _finding(), severity="high", first_detected=NOW - timedelta(days=20), now=NOW
    )
    forecast = forecast_breaches(clocks, now=NOW, horizon_days=30)
    assert forecast.total_if_nothing_closed == 1
    assert forecast.expected_remaining is None
    assert forecast.remediation_rate is None
    assert any("invented rather than measured" in c for c in forecast.caveats)


def test_forecast_refuses_a_throughput_below_the_reporting_minimum():
    clocks = clocks_for(
        _finding(), severity="high", first_detected=NOW - timedelta(days=20), now=NOW
    )
    forecast = forecast_breaches(clocks, now=NOW, closed=2, opened=3)
    assert forecast.expected_remaining is None
    assert forecast.remediation_rate is not None
    assert not forecast.remediation_rate.reportable
    assert any("below the reporting minimum" in c for c in forecast.caveats)


def test_forecast_uses_throughput_once_the_denominator_supports_it():
    clocks = [
        c
        for i in range(10)
        for c in clocks_for(
            _finding("high", f"F{i}"),
            severity="high",
            first_detected=NOW - timedelta(days=20),
            now=NOW,
        )
        if c.clock_key == "pci_6_3_3"
    ]
    forecast = forecast_breaches(clocks, now=NOW, closed=6, opened=20)
    assert forecast.remediation_rate is not None
    assert forecast.remediation_rate.reportable
    assert forecast.expected_remaining == pytest.approx(10 * (1 - 0.3))
    assert "throughput" in forecast.method


def test_forecast_on_no_clocks_does_not_divide_by_zero():
    forecast = forecast_breaches([], now=NOW)
    assert forecast.total_if_nothing_closed == 0
    assert forecast.already_breached == 0
    assert forecast.expected_remaining is None


def test_forecast_rejects_a_negative_horizon():
    with pytest.raises(ValueError):
        forecast_breaches([], now=NOW, horizon_days=-1)


# --------------------------------------------------------------------------- #
# summarise()
# --------------------------------------------------------------------------- #

def test_summarise_on_zero_findings():
    summary = summarise([], now=NOW)
    assert summary.n_findings == 0
    assert summary.by_state == {}
    assert summary.forecast.total_if_nothing_closed == 0
    assert summary.render()


def test_summarise_notes_the_missing_detection_timestamps():
    summary = summarise([_finding()], now=NOW)
    assert any("no recorded first-detection" in n for n in summary.notes)


def test_summarise_notes_the_scanner_severity_fallback():
    """PCI 6.3.1 wants a risk rank with a rationale. A Semgrep severity is not one."""
    summary = summarise([_finding()], now=NOW)
    assert any("scanner's reported severity" in n for n in summary.notes)


def test_summarise_uses_the_policy_severity_when_it_is_supplied():
    finding = _finding("medium")
    summary = summarise(
        [finding], now=NOW, severities={finding.finding_id: "critical"}
    )
    assert summary.by_severity == {"critical": 1}
    assert summary.paged_immediately == (finding.fingerprint,)


def test_remediated_findings_carry_no_clock():
    finding = _finding()
    summary = summarise([finding], now=NOW, closed_ids={finding.finding_id})
    assert summary.clocks == ()
    assert summary.n_open == 0
    assert any("remediated" in n for n in summary.notes)


def test_summary_to_dict_names_no_finding():
    corpus = real_corpus()
    summary = summarise(corpus, now=NOW)
    import json

    blob = json.dumps(summary.to_dict()).lower()
    for finding in corpus:
        assert finding.path.lower() not in blob
        assert finding.finding_id.lower() not in blob


def test_summarise_over_the_real_corpus_counts_every_finding():
    corpus = real_corpus()
    summary = summarise(corpus, now=NOW)
    assert summary.n_findings == len(corpus)
    assert sum(summary.by_severity.values()) == len(corpus)
    # 47 high-severity findings are on the PCI clock; the 74 mediums are not.
    pci = summary.clocks_for_control("pci_6_3_3")
    assert len(pci) == 47


# --------------------------------------------------------------------------- #
# VAPT export
# --------------------------------------------------------------------------- #

def test_vapt_export_excludes_undated_findings_rather_than_assigning_them():
    finding = _finding()
    dated = synthetic_finding()
    export = vapt_period_export(
        [finding, dated],
        period_start=NOW - timedelta(days=180),
        period_end=NOW,
        first_detected={dated.finding_id: NOW - timedelta(days=5)},
    )
    assert export["opened"] == 1
    assert export["undated_findings_excluded"] == 1


def test_vapt_export_counts_closures_inside_the_period():
    dated = synthetic_finding()
    export = vapt_period_export(
        [dated],
        period_start=NOW - timedelta(days=180),
        period_end=NOW,
        first_detected={dated.finding_id: NOW - timedelta(days=30)},
        closed_at={dated.finding_id: NOW - timedelta(days=2)},
    )
    assert export["closed"] == 1
    assert export["still_open"] == 0


def test_vapt_export_rejects_an_inverted_period():
    with pytest.raises(ValueError):
        vapt_period_export([], period_start=NOW, period_end=NOW - timedelta(days=1))
