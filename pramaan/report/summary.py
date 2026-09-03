"""The weekly risk summary: compliance clocks and a breach forecast.

Two regimes are on the clock for a payments company operating in India, and
they disagree about what "fast" means:

  * **PCI DSS 4.0.1 req 6.3.3** — critical and high findings are remediated
    within 30 days of first detection. That is a deadline you can put in a
    calendar, which is why it is the clock the summary is built around.
  * **RBI Cyber Resilience MD for PSOs (2024) para 21** — critical patches
    "immediately". There is no number to count down to, so this clock does not
    pretend to be a countdown: a critical finding is due the moment it is
    detected and the summary's job is to say that a human was paged, not to
    render a bar that is already full.

`DPDP Rules 2025 rule 7` adds a 72-hour escalation for personal-data exposure,
which needs a business-impact tag to evaluate. When no tags are supplied the
clock is reported as **not evaluated**, not as satisfied. Claiming a control you
did not check is the failure mode this whole project is arguing against, and it
would be a strange place to commit it.

The forecast
------------
`forecast_breaches` publishes the number the data can actually support: given
the open findings and their due dates, how many breach in the next N days **if
nothing is remediated**. That projection has no fitted parameter, so it cannot
be wrong in the way a velocity model can.

A throughput-based projection is offered only when there is closure history to
fit it on, and it goes through `stats.Rate`: below the reporting minimum the
expected count is `None` and the caveat says why. At the sizes this project
works at that is the usual outcome, and printing "we expect 3.2 breaches" off
four closures would be exactly the overconfidence the trust report exists to
avoid.

Purity: `now` is a parameter everywhere. It defaults to `datetime.now(UTC)` at
the top-level entry point only, so a test can pin the clock and get a byte-identical
summary.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pramaan.evals.stats import Rate
from pramaan.schemas import BusinessImpact, Finding

__all__ = [
    "CLOCKS",
    "AT_RISK_DAYS",
    "BreachForecast",
    "ClockSpec",
    "ClockState",
    "RiskSummary",
    "SlaClock",
    "clocks_for",
    "forecast_breaches",
    "summarise",
    "vapt_period_export",
]

ClockState = Literal["breached", "due_immediately", "at_risk", "on_track", "not_evaluated"]

# Inside this many days of the deadline, a finding is reported as at risk. Seven
# because the summary is weekly: anything closer than one cycle will breach
# before the next summary is written, which is the only thing that makes an
# early warning early.
AT_RISK_DAYS = 7


@dataclass(frozen=True, slots=True)
class ClockSpec:
    """One compliance control expressed as a deadline rule."""

    key: str
    control: str
    window: timedelta | None
    severities: frozenset[str]
    requires_tag: str | None
    summary: str

    @property
    def is_immediate(self) -> bool:
        """A zero-length window. Not a countdown — a paging rule."""
        return self.window is not None and self.window == timedelta(0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "control": self.control,
            "window_days": None if self.window is None else self.window.days,
            "severities": sorted(self.severities),
            "requires_tag": self.requires_tag,
            "summary": self.summary,
        }


CLOCKS: tuple[ClockSpec, ...] = (
    ClockSpec(
        key="pci_6_3_3",
        control="PCI DSS 4.0.1 req 6.3.3",
        window=timedelta(days=30),
        severities=frozenset({"critical", "high"}),
        requires_tag=None,
        summary=(
            "critical and high findings remediated within 30 days of first "
            "detection; the summary forecasts breaches"
        ),
    ),
    ClockSpec(
        key="rbi_para_21",
        control="RBI Cyber Resilience MD for PSOs (2024) para 21",
        window=timedelta(0),
        severities=frozenset({"critical"}),
        requires_tag=None,
        summary=(
            "critical patches applied immediately: a critical finding pages a "
            "human and never waits for the batch"
        ),
    ),
    ClockSpec(
        key="dpdp_rule_7",
        control="DPDP Rules 2025 rule 7",
        window=timedelta(hours=72),
        severities=frozenset({"critical", "high", "medium", "low", "info"}),
        requires_tag="personal_data",
        summary=(
            "findings tagged as personal-data exposure carry a 72-hour "
            "escalation flag"
        ),
    ),
)

_CLOCK_BY_KEY = {c.key: c for c in CLOCKS}


def _tag_says_personal_data(tags: BusinessImpact | None) -> bool | None:
    """Tri-state. `None` means the question was never asked.

    The path tagger names payment, auth/session, PCI-scope and KYC/settlement.
    KYC and settlement records are the personal data in this system, so those
    two are what the DPDP clock keys off. With no tags at all the answer is
    unknown, and unknown is reported as unknown.
    """
    if tags is None:
        return None
    return tags.kyc_or_settlement or tags.auth_or_session


@dataclass(frozen=True, slots=True)
class SlaClock:
    """One (finding, control) deadline.

    `finding_id` embeds the file path, so it is present for joining and absent
    from `to_dict()`. The renderer aggregates these; it never prints a row for a
    withheld finding.
    """

    finding_id: str
    fingerprint: str
    repo: str
    control: str
    clock_key: str
    severity: str
    first_detected: datetime
    due_at: datetime | None
    state: ClockState
    days_remaining: float | None
    detail: str = ""

    @property
    def is_open_breach(self) -> bool:
        return self.state == "breached"

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "repo": self.repo,
            "control": self.control,
            "clock_key": self.clock_key,
            "severity": self.severity,
            "first_detected": self.first_detected.isoformat(),
            "due_at": None if self.due_at is None else self.due_at.isoformat(),
            "state": self.state,
            "days_remaining": self.days_remaining,
            "detail": self.detail,
        }


def _state_for(
    spec: ClockSpec, due_at: datetime | None, now: datetime, at_risk_days: int
) -> tuple[ClockState, float | None]:
    if due_at is None:
        return "not_evaluated", None
    if spec.is_immediate:
        return "due_immediately", 0.0
    remaining = (due_at - now).total_seconds() / 86400.0
    if remaining < 0:
        return "breached", remaining
    if remaining <= at_risk_days:
        return "at_risk", remaining
    return "on_track", remaining


def clocks_for(
    finding: Finding,
    *,
    severity: str,
    first_detected: datetime,
    now: datetime,
    tags: BusinessImpact | None = None,
    specs: Sequence[ClockSpec] = CLOCKS,
    at_risk_days: int = AT_RISK_DAYS,
) -> list[SlaClock]:
    """Every clock that applies to one finding.

    A control whose applicability cannot be determined produces a
    `not_evaluated` clock rather than no clock at all, so the summary can report
    the gap instead of silently omitting the control.
    """
    out: list[SlaClock] = []
    for spec in specs:
        if severity not in spec.severities:
            continue
        detail = ""
        due_at: datetime | None
        if spec.requires_tag == "personal_data":
            answer = _tag_says_personal_data(tags)
            if answer is None:
                out.append(
                    SlaClock(
                        finding_id=finding.finding_id,
                        fingerprint=finding.fingerprint,
                        repo=finding.repo,
                        control=spec.control,
                        clock_key=spec.key,
                        severity=severity,
                        first_detected=first_detected,
                        due_at=None,
                        state="not_evaluated",
                        days_remaining=None,
                        detail=(
                            "no business-impact tags were supplied, so "
                            "personal-data exposure was never assessed for this "
                            "finding; the clock is unevaluated, not satisfied"
                        ),
                    )
                )
                continue
            if not answer:
                continue
            detail = "tagged kyc_or_settlement / auth_or_session by the path policy"
        due_at = first_detected + (spec.window or timedelta(0))
        state, remaining = _state_for(spec, due_at, now, at_risk_days)
        out.append(
            SlaClock(
                finding_id=finding.finding_id,
                fingerprint=finding.fingerprint,
                repo=finding.repo,
                control=spec.control,
                clock_key=spec.key,
                severity=severity,
                first_detected=first_detected,
                due_at=due_at,
                state=state,
                days_remaining=remaining,
                detail=detail,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Forecast
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class BreachForecast:
    """What breaches next, and how confident that is allowed to sound."""

    horizon_days: int
    already_breached: int
    scheduled: tuple[tuple[int, int], ...]
    total_if_nothing_closed: int
    remediation_rate: Rate | None
    expected_remaining: float | None
    method: str
    caveats: tuple[str, ...] = ()

    @property
    def has_velocity_model(self) -> bool:
        return self.expected_remaining is not None

    def render(self) -> str:
        lines = [
            f"breach forecast over {self.horizon_days} days "
            f"({self.method})",
            f"  already breached: {self.already_breached}",
            f"  breaching within the horizon if nothing is remediated: "
            f"{self.total_if_nothing_closed}",
        ]
        if self.remediation_rate is not None:
            lines.append(f"  {self.remediation_rate.render()}")
        if self.expected_remaining is None:
            lines.append(
                "  expected breaches after remediation: not published — no "
                "closure history the corpus can support a rate from"
            )
        else:
            lines.append(
                f"  expected breaches after remediation: "
                f"{self.expected_remaining:.1f}"
            )
        lines.extend(f"  caveat: {c}" for c in self.caveats)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon_days": self.horizon_days,
            "already_breached": self.already_breached,
            "scheduled_by_day": [list(pair) for pair in self.scheduled],
            "total_if_nothing_closed": self.total_if_nothing_closed,
            "remediation_rate": (
                None if self.remediation_rate is None else self.remediation_rate.to_dict()
            ),
            "expected_remaining": self.expected_remaining,
            "method": self.method,
            "caveats": list(self.caveats),
        }


def forecast_breaches(
    clocks: Sequence[SlaClock],
    *,
    now: datetime,
    horizon_days: int = 30,
    closed: int = 0,
    opened: int = 0,
    min_n: int = 5,
) -> BreachForecast:
    """Deterministic projection first; a fitted one only if the data allows.

    `closed` / `opened` describe the observation window used to estimate
    remediation throughput. Left at zero — which is the state of this project,
    with no remediation history — the rate is `None`, the expected count is
    `None`, and the caveat says so. Nothing here divides by `opened`.
    """
    if horizon_days < 0:
        raise ValueError("horizon_days must be >= 0")

    already = sum(1 for c in clocks if c.state == "breached")
    per_day: dict[int, int] = {}
    for clock in clocks:
        # `due_immediately` has a due date equal to detection, so it would land
        # on day 0 of the schedule and be read as "one breach expected today".
        # It is a paging rule with no countdown, and it is reported as one.
        if clock.due_at is None or clock.state in ("breached", "due_immediately"):
            continue
        offset = (clock.due_at - now).total_seconds() / 86400.0
        if 0 <= offset <= horizon_days:
            per_day[int(offset)] = per_day.get(int(offset), 0) + 1
    scheduled = tuple(sorted(per_day.items()))
    total = sum(count for _day, count in scheduled)

    caveats: list[str] = [
        "the deterministic projection assumes nothing is remediated; it is a "
        "worst case with no fitted parameter, which is the only forecast this "
        "corpus supports without qualification"
    ]

    rate: Rate | None = None
    expected: float | None = None
    method = "deterministic (no remediation assumed)"
    if opened > 0:
        rate = Rate(
            min(closed, opened),
            opened,
            min_n=min_n,
            label="remediation throughput (findings closed / findings opened)",
        )
        if rate.reportable:
            expected = total * (1.0 - (rate.point or 0.0))
            method = "deterministic, adjusted by observed remediation throughput"
        else:
            caveats.append(
                f"remediation throughput is {closed}/{opened}; below the "
                f"reporting minimum of {min_n}, so no adjusted forecast is "
                "published"
            )
    else:
        caveats.append(
            "no findings have been opened and closed in this deployment, so "
            "there is no throughput to fit; a velocity model here would be "
            "invented rather than measured"
        )

    immediate = sum(1 for c in clocks if c.state == "due_immediately")
    if immediate:
        caveats.append(
            f"{immediate} clocks are 'immediately' (RBI para 21) and have no "
            "countdown; they are excluded from the day-by-day schedule and "
            "reported as paging events"
        )
    unevaluated = sum(1 for c in clocks if c.state == "not_evaluated")
    if unevaluated:
        caveats.append(
            f"{unevaluated} clocks could not be evaluated and are excluded from "
            "every count above"
        )

    return BreachForecast(
        horizon_days=horizon_days,
        already_breached=already,
        scheduled=scheduled,
        total_if_nothing_closed=total,
        remediation_rate=rate,
        expected_remaining=expected,
        method=method,
        caveats=tuple(caveats),
    )


# --------------------------------------------------------------------------- #
# The summary
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class RiskSummary:
    generated_at: datetime
    window_days: int
    n_findings: int
    n_open: int
    by_state: dict[str, int]
    by_control: dict[str, dict[str, int]]
    by_severity: dict[str, int]
    clocks: tuple[SlaClock, ...]
    paged_immediately: tuple[str, ...]
    forecast: BreachForecast
    unevaluated_controls: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def clocks_for_control(self, key: str) -> tuple[SlaClock, ...]:
        return tuple(c for c in self.clocks if c.clock_key == key)

    def render(self) -> str:
        lines = [
            f"weekly risk summary — {self.generated_at.isoformat()} "
            f"({self.window_days}-day window)",
            f"  findings: {self.n_findings} ({self.n_open} open)",
            "  clock states: "
            + ", ".join(f"{k} {v}" for k, v in sorted(self.by_state.items())),
        ]
        for control, states in sorted(self.by_control.items()):
            lines.append(
                f"  {control}: "
                + ", ".join(f"{k} {v}" for k, v in sorted(states.items()))
            )
        if self.paged_immediately:
            lines.append(
                f"  paged immediately (RBI para 21): {len(self.paged_immediately)}"
            )
        lines.append("  " + self.forecast.render().replace("\n", "\n  "))
        lines.extend(f"  note: {n}" for n in self.notes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "window_days": self.window_days,
            "n_findings": self.n_findings,
            "n_open": self.n_open,
            "by_state": dict(self.by_state),
            "by_control": {k: dict(v) for k, v in self.by_control.items()},
            "by_severity": dict(self.by_severity),
            "paged_immediately": list(self.paged_immediately),
            "forecast": self.forecast.to_dict(),
            "unevaluated_controls": list(self.unevaluated_controls),
            "notes": list(self.notes),
        }


def summarise(
    findings: Iterable[Finding],
    *,
    now: datetime | None = None,
    severities: Mapping[str, str] | None = None,
    first_detected: Mapping[str, datetime] | None = None,
    tags: Mapping[str, BusinessImpact] | None = None,
    closed_ids: Collection[str] = (),
    window_days: int = 7,
    horizon_days: int = 30,
    opened_in_window: int = 0,
    closed_in_window: int = 0,
    specs: Sequence[ClockSpec] = CLOCKS,
    at_risk_days: int = AT_RISK_DAYS,
) -> RiskSummary:
    """Build the weekly summary. Renders on zero findings.

    Args:
        severities: `finding_id` -> the policy engine's computed severity (D8).
            Falls back to `Finding.severity_reported`, with a note, because the
            scanner's own severity is not a risk rank.
        first_detected: `finding_id` -> first detection timestamp. Missing
            entries default to `now` and are noted: a clock that starts today
            because nobody recorded when the finding appeared is a clock with no
            information in it, and the summary says so rather than implying 30
            days of headroom.
        closed_ids: findings already remediated. They keep their clocks out of
            every count.
    """
    resolved_now = now or datetime.now(timezone.utc)
    rows = list(findings)
    closed = set(closed_ids)

    clocks: list[SlaClock] = []
    by_severity: dict[str, int] = {}
    missing_detection = 0
    fell_back_severity = 0

    for finding in rows:
        severity = (severities or {}).get(finding.finding_id)
        if severity is None:
            severity = finding.severity_reported
            fell_back_severity += 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if finding.finding_id in closed:
            continue
        detected = (first_detected or {}).get(finding.finding_id)
        if detected is None:
            detected = resolved_now
            missing_detection += 1
        clocks.extend(
            clocks_for(
                finding,
                severity=severity,
                first_detected=detected,
                now=resolved_now,
                tags=(tags or {}).get(finding.finding_id),
                specs=specs,
                at_risk_days=at_risk_days,
            )
        )

    by_state: dict[str, int] = {}
    by_control: dict[str, dict[str, int]] = {}
    for clock in clocks:
        by_state[clock.state] = by_state.get(clock.state, 0) + 1
        bucket = by_control.setdefault(clock.control, {})
        bucket[clock.state] = bucket.get(clock.state, 0) + 1

    forecast = forecast_breaches(
        clocks,
        now=resolved_now,
        horizon_days=horizon_days,
        closed=closed_in_window,
        opened=opened_in_window,
    )

    notes: list[str] = []
    if missing_detection:
        notes.append(
            f"{missing_detection} findings had no recorded first-detection "
            "timestamp; their clocks start now, which understates elapsed time "
            "rather than overstating remaining headroom"
        )
    if fell_back_severity:
        notes.append(
            f"{fell_back_severity} findings used the scanner's reported "
            "severity because no policy decision was supplied; PCI 6.3.1 wants "
            "a risk rank with a rationale, and a Semgrep severity is not one"
        )
    if closed:
        notes.append(f"{len(closed)} findings are recorded as remediated and carry no clock")

    unevaluated = tuple(
        sorted({c.control for c in clocks if c.state == "not_evaluated"})
    )
    if unevaluated:
        notes.append(
            "controls reported as not evaluated: " + ", ".join(unevaluated)
        )

    return RiskSummary(
        generated_at=resolved_now,
        window_days=window_days,
        n_findings=len(rows),
        n_open=len(rows) - len([f for f in rows if f.finding_id in closed]),
        by_state=by_state,
        by_control=by_control,
        by_severity=by_severity,
        clocks=tuple(clocks),
        paged_immediately=tuple(
            sorted({c.fingerprint for c in clocks if c.state == "due_immediately"})
        ),
        forecast=forecast,
        unevaluated_controls=unevaluated,
        notes=tuple(notes),
    )


def vapt_period_export(
    findings: Iterable[Finding],
    *,
    period_start: datetime,
    period_end: datetime,
    first_detected: Mapping[str, datetime] | None = None,
    closed_at: Mapping[str, datetime] | None = None,
) -> dict[str, Any]:
    """Open/closed counts for one period — RBI PA Directions 2025 Annex 1 §1.5.

    Bi-annual VAPT evidence needs a per-period export, and this is the shape of
    it: counts by repository and severity, no paths. Findings with no recorded
    detection timestamp are counted separately rather than assigned to the
    period, because assigning them would fabricate the evidence the control
    asks for.
    """
    if period_end < period_start:
        raise ValueError("period_end must not precede period_start")
    detected = first_detected or {}
    closures = closed_at or {}

    opened_in_period = 0
    closed_in_period = 0
    undated = 0
    by_repo: dict[str, int] = {}
    by_severity: dict[str, int] = {}

    for finding in findings:
        stamp = detected.get(finding.finding_id)
        if stamp is None:
            undated += 1
            continue
        if not (period_start <= stamp <= period_end):
            continue
        opened_in_period += 1
        by_repo[finding.repo] = by_repo.get(finding.repo, 0) + 1
        by_severity[finding.severity_reported] = (
            by_severity.get(finding.severity_reported, 0) + 1
        )
        shut = closures.get(finding.finding_id)
        if shut is not None and shut <= period_end:
            closed_in_period += 1

    return {
        "control": "RBI PA Directions 2025 Annex 1 §1.5 (bi-annual VAPT evidence)",
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "opened": opened_in_period,
        "closed": closed_in_period,
        "still_open": opened_in_period - closed_in_period,
        "by_repo": dict(sorted(by_repo.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "undated_findings_excluded": undated,
    }
