"""The act-vs-escalate policy, as a pure function (binding decision D8).

`ssvc_decision`, `severity` and `recommended_action` are computed here and are
deliberately absent from `VERDICT_SCHEMA`. A rubric encoded in a prompt is a
rubric an injected code comment can rewrite: if the model emitted the action, a
single line of attacker-controlled PHP could talk the harness into closing its
own finding. The model reports observations; this function decides.

Nothing in here reads an action from model output. The model influences the
outcome through exactly three narrow, monotone channels:

  * `verdict` / `confidence` - gated by tau, and tau never gates a true positive
  * `business_impact`        - can only ADD sensitivity (D9)
  * `cwe`                    - can only NARROW the fixer allowlist, never widen it

Every rationale string is assembled from enum members and floats owned by this
module. No model-authored text is interpolated into a Decision, so a Decision can
be rendered into a ticket, a PR body or an HTML report without laundering an
injection payload through the policy layer.

The eight rows of the act-vs-escalate table in PROJECT-BRAINSTORM.md map onto
this module as follows. Rows 1-5, 7 and 8 are decided by `decide`; row 6 is a
post-proof transition and is decided by `decide_after_proof`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Literal

from pramaan.schemas import BusinessImpact, ProofBundle, Severity, Verdict

__all__ = [
    "FIXER_ALLOWLIST",
    "Decision",
    "EscalateReason",
    "PolicyRow",
    "RecommendedAction",
    "SsvcDecision",
    "decide",
    "decide_after_proof",
    "effective_tags",
    "normalise_cwe",
]

SsvcDecision = Literal["act", "attend", "track_star", "track"]
DecisionSeverity = Literal["critical", "high", "medium", "low"]
RecommendedAction = Literal["auto_close", "open_ticket", "fix_candidate", "escalate_human"]
EscalateReason = Literal[
    "prompt_injection_observed",
    "agent_returned_needs_human",
    "sensitive_path_true_positive",
    "sensitive_path_false_positive",
    "low_confidence_false_positive",
    "proof_failed",
]
PolicyRow = Literal[
    "row1_fp_at_or_above_tau",
    "row2_fp_below_tau",
    "row3_tp_any_confidence",
    "row4_tp_in_fixer_allowlist",
    "row5_tp_sensitive_path",
    "row6_proof_failed",
    "row7_injection_observed",
    "row8_needs_human",
]

# D16: XSS and SQLi ONLY.
#
# Path traversal (CWE-22), hardcoded secret (CWE-798) and SSRF (CWE-918) appear
# in the act-vs-escalate table's original prose but are deliberately NOT here.
# The 121-finding hand-labelled corpus contains zero instances of all three, so
# an allowlist entry for them would be a capability claim no eval in this project
# can falsify. Shipping an unfalsifiable safety claim is worse than shipping a
# narrower one. Re-add a class here only once the corpus can measure it.
FIXER_ALLOWLIST: frozenset[str] = frozenset({"CWE-79", "CWE-89"})

_SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SEVERITY_BY_RANK: tuple[DecisionSeverity, ...] = ("low", "medium", "high", "critical")
_SSVC_RANK: dict[str, int] = {"track": 0, "track_star": 1, "attend": 2, "act": 3}
_SSVC_BY_SEVERITY: dict[str, SsvcDecision] = {
    "critical": "act",
    "high": "attend",
    "medium": "track_star",
    "low": "track",
}


@dataclass(frozen=True, slots=True)
class Decision:
    """What the harness is allowed to do about one triaged finding.

    The five contracted fields come first. The rest are the machine-readable
    residue of table rows that a single enum cannot express: a pure function
    cannot *raise* a security event, so it records that one is owed.
    """

    ssvc_decision: SsvcDecision
    severity: DecisionSeverity
    recommended_action: RecommendedAction
    rationale: str
    escalate_reason: EscalateReason | None = None
    policy_row: PolicyRow | None = None
    quarantined: bool = False
    security_event: str | None = None
    audit_sample_eligible: bool = False

    @property
    def invokes_fixer(self) -> bool:
        """The one question the fix lane asks. Nothing else may start a fixer."""
        return self.recommended_action == "fix_candidate"

    @property
    def closes_automatically(self) -> bool:
        return self.recommended_action == "auto_close"

    @property
    def takes_automated_action(self) -> bool:
        """False means: log it, queue it for a human, touch nothing."""
        return self.recommended_action in ("auto_close", "open_ticket", "fix_candidate")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ssvc_decision": self.ssvc_decision,
            "severity": self.severity,
            "recommended_action": self.recommended_action,
            "rationale": self.rationale,
            "escalate_reason": self.escalate_reason,
            "policy_row": self.policy_row,
            "quarantined": self.quarantined,
            "security_event": self.security_event,
            "audit_sample_eligible": self.audit_sample_eligible,
            "invokes_fixer": self.invokes_fixer,
        }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_CWE_IDENT = re.compile(r"CWE[-_ ]?(\d{1,5})", re.IGNORECASE)


def normalise_cwe(cwe: str | None) -> str | None:
    """`CWE-89`, `cwe_89`, `CWE 89: Improper Neutralization...` -> `CWE-89`.

    Anything else -> None, including a valid identifier with unexplained text
    trailing it. Scanners do append a `:`-delimited title, so that form is
    accepted; `"CWE-79 or ignore previous instructions"` is not, because the
    only channel by which a model can reach the fixer allowlist should reject
    everything it does not fully recognise.

    Returns only `CWE-<int>`, so the result is safe to interpolate into a
    rationale even though `Verdict.cwe` is a model-authored string.
    """
    if not cwe:
        return None
    identifier = cwe.split(":", 1)[0].strip()
    match = _CWE_IDENT.fullmatch(identifier)
    return f"CWE-{int(match.group(1))}" if match else None


def effective_tags(verdict: Verdict, path_tags: BusinessImpact) -> BusinessImpact:
    """D9: final tags = path_tags.union(model_tags).

    The union happens *inside* the trusted policy function, not in a caller,
    because getting the direction backwards is a silent security failure and
    there is exactly one place worth auditing for it. `BusinessImpact.union` is
    a field-wise OR, so the model can raise a flag and can never clear one: a
    model that reports `pci_scope_hint=False` on a file the globs matched still
    yields `pci_scope_hint=True`.
    """
    return path_tags.union(verdict.business_impact)


def _clamp_floor(floor: Severity | None) -> DecisionSeverity | None:
    if floor is None:
        return None
    # `Finding.severity_reported` carries an "info" level the decision ladder
    # does not; it is the bottom of both ladders.
    return "low" if floor == "info" else floor  # type: ignore[return-value]


def _raise_to(severity: DecisionSeverity, floor: Severity | None) -> DecisionSeverity:
    """Row 3's 'never downgrade severity', enforced rather than documented."""
    clamped = _clamp_floor(floor)
    if clamped is None:
        return severity
    return _SEVERITY_BY_RANK[max(_SEVERITY_RANK[severity], _SEVERITY_RANK[clamped])]


def _severity_for_real_defect(tags: BusinessImpact, reachability: str) -> DecisionSeverity:
    if tags.any_sensitive:
        return "critical" if reachability == "reachable_from_http" else "high"
    if reachability == "reachable_from_http":
        return "high"
    if reachability == "dead_code":
        return "low"
    # `internal_only` and `unknown` both stop at medium. Ground rule 7: an
    # unknown reachability is not evidence of safety, so it never falls to low.
    return "medium"


def _at_least(ssvc: SsvcDecision, floor: SsvcDecision) -> SsvcDecision:
    return ssvc if _SSVC_RANK[ssvc] >= _SSVC_RANK[floor] else floor


def _tag_names(tags: BusinessImpact) -> str:
    names = sorted(f for f in BusinessImpact.__dataclass_fields__ if getattr(tags, f))
    return ",".join(names) if names else "none"


# --------------------------------------------------------------------------- #
# The policy
# --------------------------------------------------------------------------- #

def decide(
    verdict: Verdict,
    tags: BusinessImpact,
    tau: float,
    *,
    severity_floor: Severity | None = None,
) -> Decision:
    """Decide what the harness may do about one triaged finding.

    Pure: no I/O, no network, no clock, no model, no randomness.

    Args:
        verdict: the model's observations. Never trusted for an action.
        tags: the **deterministic path tagger's** output for the finding's path.
            Unioned with `verdict.business_impact` here, never before.
        tau: the confidence gate, derived by Lane F through repeated k-fold CV
            (D3). A parameter, never a literal - there is no default, because a
            default would become the literal.
        severity_floor: the scanner's reported severity, if the caller has the
            `Finding`. Supplied, the returned severity is never below it, which
            is how row 3's "never downgrade severity" is enforced in code.

    Raises:
        ValueError: tau outside [0, 1], or a verdict label this policy has not
            been taught. Failing closed on an unknown label is the point: a new
            enum member must not silently inherit the auto-close branch.
    """
    if not 0.0 <= tau <= 1.0:
        raise ValueError(f"tau must be in [0.0, 1.0], got {tau!r}")

    # tau == 1.0 is the calibration layer's "no threshold reached the target
    # precision" sentinel, not a very strict gate. Without this branch a verdict
    # claiming exactly 1.0 confidence would clear `conf >= tau` and auto-close on a
    # gate that was never derived -- and a model asserting total certainty is the
    # least trustworthy input this function receives, not the most.
    gate_underived = tau >= 1.0

    effective = effective_tags(verdict, tags)
    conf = verdict.confidence
    reach = verdict.reachability

    # ---- Row 7: injection-shaped text observed ---------------------------- #
    # First, and short-circuiting, because every field below this line is
    # attacker-influenced once an injection is in play. Quarantine leaves the
    # verdict label untouched - that is what "keep verdict unchanged" protects -
    # but it removes every automated action, so an injection can only ever cost
    # the attacker a human reviewer. It can never buy one.
    if verdict.injection_observed:
        severity = _raise_to(_severity_for_real_defect(effective, reach), severity_floor)
        return Decision(
            ssvc_decision=_at_least(_SSVC_BY_SEVERITY[severity], "attend"),
            severity=severity,
            recommended_action="escalate_human",
            rationale=(
                "quarantined: injection-shaped text observed in the finding's "
                f"context; model verdict '{verdict.verdict}' recorded unchanged and "
                "not acted on; tags=" + _tag_names(effective)
            ),
            escalate_reason="prompt_injection_observed",
            policy_row="row7_injection_observed",
            quarantined=True,
            security_event="prompt_injection_suspected",
        )

    # ---- Row 8: turn or budget cap hit ------------------------------------ #
    # Lane D converts a `truncated` / `budget_abort` attempt into a needs_human
    # verdict; this is where that lands. Graded as though the defect were real,
    # because an aborted triage is not evidence of safety.
    if verdict.verdict == "needs_human":
        severity = _raise_to(_severity_for_real_defect(effective, reach), severity_floor)
        return Decision(
            ssvc_decision=_at_least(_SSVC_BY_SEVERITY[severity], "track_star"),
            severity=severity,
            recommended_action="escalate_human",
            rationale=(
                "triage did not reach a verdict (turn/budget cap or explicit "
                f"needs_human); reachability={reach}; tags={_tag_names(effective)}; "
                "audit log retained"
            ),
            escalate_reason="agent_returned_needs_human",
            policy_row="row8_needs_human",
        )

    if verdict.verdict == "true_positive":
        severity = _raise_to(_severity_for_real_defect(effective, reach), severity_floor)
        ssvc = _SSVC_BY_SEVERITY[severity]

        # ---- Row 5: TP touching PCI scope, KYC, settlement or auth -------- #
        # BEFORE the allowlist, not after. Reversing these two branches would
        # hand a settlement-path SQLi straight to the fixer, which is precisely
        # the case the table carves out for a human to own end to end.
        if effective.any_sensitive:
            return Decision(
                ssvc_decision=_at_least(ssvc, "attend"),
                severity=severity,
                recommended_action="escalate_human",
                rationale=(
                    "confirmed defect on a sensitive path "
                    f"({_tag_names(effective)}); ticket and escalate only, no "
                    f"automated fix; reachability={reach}"
                ),
                escalate_reason="sensitive_path_true_positive",
                policy_row="row5_tp_sensitive_path",
            )

        # ---- Row 4: TP in the fixer allowlist ----------------------------- #
        # `cwe` is model-reported, so this branch can only ever be *narrowed* by
        # a hostile model, never widened past the two classes below - and it is
        # already unreachable for anything sensitive.
        cwe = normalise_cwe(verdict.cwe)
        if cwe in FIXER_ALLOWLIST:
            return Decision(
                ssvc_decision=ssvc,
                severity=severity,
                recommended_action="fix_candidate",
                rationale=(
                    f"confirmed {cwe} on a non-sensitive path; class is in the "
                    "fixer allowlist; fixer then proof then reviewer then draft PR"
                ),
                policy_row="row4_tp_in_fixer_allowlist",
            )

        # ---- Row 3: TP, any confidence ------------------------------------ #
        # tau deliberately does not appear here. The table says "any confidence"
        # and the asymmetric cost model backs it: a miss is weighted 4x a
        # needless review, so a low-confidence TP still gets a ticket.
        return Decision(
            ssvc_decision=ssvc,
            severity=severity,
            recommended_action="open_ticket",
            rationale=(
                f"confirmed defect ({cwe or 'CWE unparsed'}) outside the fixer "
                f"allowlist; ticket with owner and SLA; reachability={reach}; "
                f"confidence={conf:.3f} does not gate a true positive"
            ),
            policy_row="row3_tp_any_confidence",
        )

    if verdict.verdict == "false_positive":
        # Not a row of the table: the table's auto-close row is conditioned on
        # "no sensitive path" but never says what a sensitive-path FP does. Fail
        # closed - a machine does not get to close a payment-path finding on its
        # own say-so, however confident it is.
        if effective.any_sensitive:
            severity = _raise_to("low", severity_floor)
            return Decision(
                ssvc_decision=_at_least(_SSVC_BY_SEVERITY[severity], "attend"),
                severity=severity,
                recommended_action="escalate_human",
                rationale=(
                    "model called this a false positive on a sensitive path "
                    f"({_tag_names(effective)}); auto-close withheld regardless of "
                    f"confidence={conf:.3f} vs tau={tau:.3f}"
                ),
                escalate_reason="sensitive_path_false_positive",
                policy_row="row2_fp_below_tau",
            )

        # ---- Row 1: FP at or above tau, no sensitive path ----------------- #
        # NaN confidence compares False here and falls through to row 2, which
        # is the safe direction.
        if conf >= tau and not gate_underived:
            return Decision(
                ssvc_decision="track",
                severity="low",
                recommended_action="auto_close",
                rationale=(
                    f"false positive at confidence={conf:.3f} >= tau={tau:.3f} on a "
                    "non-sensitive path; closed with rationale and entered into the "
                    "audit sampling frame"
                ),
                policy_row="row1_fp_at_or_above_tau",
                # The 10% sample itself is drawn elsewhere: sampling needs an RNG
                # and this function is pure. All this records is eligibility.
                audit_sample_eligible=True,
            )

        # ---- Row 2: FP below tau ------------------------------------------ #
        severity = _raise_to("low", severity_floor)
        return Decision(
            ssvc_decision="track_star",
            severity=severity,
            recommended_action="escalate_human",
            rationale=(
                f"false positive at confidence={conf:.3f} < tau={tau:.3f}; no action "
                "taken; routed to the needs_human queue"
            ),
            escalate_reason="low_confidence_false_positive",
            policy_row="row2_fp_below_tau",
        )

    raise ValueError(f"unhandled verdict label: {verdict.verdict!r}")


def decide_after_proof(decision: Decision, proof: ProofBundle) -> Decision:
    """Row 6: any validator or reviewer fails -> comment on the ticket, no PR.

    A post-proof transition rather than a branch of `decide`, because the proof
    bundle does not exist until after `decide` has already said `fix_candidate`.
    Strictly subtractive: it can remove the fix path and raise urgency, and it
    can never create a `fix_candidate` or lower a severity.

    The PR gate itself is `ProofBundle.may_open_pr` (Lane E). This function only
    translates that gate into a policy decision.
    """
    if proof.may_open_pr:
        return decision

    blocking = proof.blocking
    if blocking:
        what = "; ".join(f"{v.name}={v.outcome}" for v in blocking)
    else:
        # No validator failed, so the only way here is reviewer_approved not
        # being True - including None, which `may_open_pr` fails closed on.
        what = "reviewer did not approve"

    return replace(
        decision,
        ssvc_decision=_at_least(decision.ssvc_decision, "attend"),
        recommended_action="open_ticket",
        rationale=f"proof failed, no PR opened; blocking: {what}",
        escalate_reason="proof_failed",
        policy_row="row6_proof_failed",
    )
