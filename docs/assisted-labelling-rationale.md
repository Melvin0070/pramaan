# Assisted labelling: what it is, why the design is this specific, and what it costs

`scripts/label.py --assist` exists because 121 findings cold is a real time cost, and
a second opinion — used correctly — genuinely helps a human catch what they missed.
This document is the "used correctly" part. Read it before turning assist on, because
the failure mode it guards against is not hypothetical: it is the exact thing this
corpus already caught a model doing to itself.

## The one-sentence version

Assist can suggest a label. It can never see your label first, it can never be the
production triage agent, and every disagreement is logged whether or not you change
your mind.

## Why not just let a model propose the label and the human confirm it?

Two separate failure modes, and "use a cheaper model" fixes neither.

**Anchoring.** Shown an answer before forming your own, a human doesn't evaluate it
independently — they check it for plausibility, and a plausible-sounding wrong answer
clears that bar most of the time. This is why the tool asks for your label, confidence
and notes *before* it will show you anything. The assist step only runs after you have
already committed to a view; disagreement then genuinely means something, because it
survived contact with your own read of the code first.

**Contamination of the metric the label is actually for.** `labels.csv` isn't just data
— it's what the production triage agent's own verdicts get scored against, via
`model_vs_human_agreement`. If the assist suggestion came from that same agent (same
system prompt, same rubric framing), showing it to the human before they label would
mean the "ground truth" and the "thing being measured against ground truth" stop being
independent. The agreement score you'd compute afterward wouldn't tell you whether the
triage agent is accurate — it would just tell you how often a human, shown the triage
agent's answer, decided to agree with it. Those are very different numbers wearing the
same label.

So the assist model here is deliberately **not** `pramaan.agent.triage_runner` and
deliberately **not** primed with `docs/labelling-rubric.md`'s specific language. It is
a separate, minimal, generic prompt — "read this code, is the flagged sink a real
vulnerability, one line why" — run on Haiku. It is a genuinely different opinion, not
a preview of the system under evaluation.

## Why this isn't theoretical

Today's live pilot measured a model — the same family, same lineage as anything you'd
plug in as an assist — disagreeing with **itself** on a real, independently-confirmed
SQL injection: 2 false_positive / 3 true_positive on one line, 3/2 the other way on the
sibling line, same rule, same file, same repo. A model's answer is evidence. It is not
ground truth, and treating it as ground truth by routing it through a human who never
gets the chance to disagree independently would launder exactly the failure this corpus
exists to catch.

## What gets logged, and where

`labels.csv` itself is untouched in shape — still `finding_id,label,confidence,rater,
labelled_at,notes` — because `pramaan calibrate` and `pramaan.evals.labels` already
consume that exact schema and nothing about assist should require touching either.

Every assisted row also writes to `data/corpus/labels-assist-log.csv`, tracked the same
way `labels.csv` already is (committed, not gitignored — the repo is private, and the
corpus and its labels are already git-tracked working files, not the published report):
your pre-suggestion label and confidence, the assist's label and one-line rationale,
whether you revised, and your final label if you did. Commit it whenever you'd commit
`labels.csv` itself; there's no separate rule for it. This is what makes the assist mode
auditable rather than merely trusted — someone reading the methodology later can see
exactly how often the assist was consulted, how often it disagreed, and how often a
disagreement changed the outcome.

`labels.csv`'s own `notes` column gets a short suffix on assisted rows —
`[assist: agreed]`, `[assist: disagreed, kept own]`, or `[assist: disagreed, revised]`
— so the row is self-describing even without cross-referencing the sidecar log.

## What assist mode is not for

**Not for the official pass 1 / pass 2 wash-out.** D18's intra-rater kappa measures
*your own* fatigue-driven inconsistency across a 7-day gap — the same phenomenon
Razorpay's own post admits to. If assist is used in one pass and not the other, or if
the assist model itself drifts between passes (measured, live, as a real phenomenon
today — see `docs/LIVE-EVIDENCE.md`'s incident-timing note), you can no longer tell
whether a change between passes reflects your fatigue or the assist's drift. The
metric becomes uninterpretable. Both passes should be the same condition: both
unaided, or both assisted with that fact reported alongside the kappa figure rather
than folded into it silently.

**Not a speed-up on `confidence` or `notes`.** Those are still typed by hand, because
they are the parts of a `needs_human` row that make it auditable, and an assist tool
optimising them away would just move the corner-cutting one field over.

**Not silent.** `--assist` prints this file's core warning once per session before
letting you start, and refuses to run without an explicit `--assist` flag — the tool's
default, bare invocation, is exactly the unaided process it was before this mode
existed.

## The honest tradeoff, stated plainly

Assisted labelling is faster and it is real human judgement — the label is still yours,
formed before you saw the suggestion, and free to disagree with it. It is a weaker
claim than a fully cold pass in one specific way: a human who has just seen a plausible
counter-opinion is, even when unmoved, no longer in exactly the same epistemic position
as one who hasn't. Report which condition produced which pass. Don't blend them.
