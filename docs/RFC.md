# RFC: Pramaan — an evidence-gated triage and remediation harness

| | |
|---|---|
| **Status** | Implemented, unmeasured. Shadow mode only. |
| **Author** | Melvin |
| **Reviewers** | — |
| **Target** | Razorpay AppSec / Security Engineering |

Written in the shape of the RFC template in Razorpay's AI Playbook
(`appendices/I-templates/RFC-template.md`), the one their Staff+ council reviews.

## Summary

Pramaan takes Semgrep findings from Razorpay's open-source PHP repositories, triages
them through a **calibrated** confidence gate, and opens a draft pull request only once
the fix carries a **proof bundle**: the scanner is clean on the patched tree, the test
suite is green with the counts to show it, the exploit that worked before is blocked
after, the diff stays in scope, and an independent fresh-context reviewer approves.

Every verdict is schema-validated JSON with `file:line` evidence. Every tool call is
audit-logged. The output is a trust report that publishes the numbers, including the
unflattering ones.

## The differentiator is not the architecture

This is the section most likely to be skipped, so it goes first.

**Almost every architectural element of Pramaan already ships in the box.** Stating that
plainly is stronger than implying a novelty that is not there:

| Prior art | What it already does |
|---|---|
| **Claude Security plugin** (`/claude-security`) | Multi-agent scan; independent verifier agents review every finding before it enters the report; "suggest patches" drafts each patch **in a scratch copy**, has a **different agent review it**, and **runs project tests**; patches are never auto-applied. That is Pramaan's fixer → reviewer → gate, shipped. |
| **Code Review** (Team/Enterprise preview) | A fleet of specialised agents per PR, then a verification step checking candidates against actual code behaviour; `REVIEW.md` lets you set a **verification bar such as requiring `file:line` evidence**. That is Pramaan's evidence requirement, shipped. |
| **Anthropic's own SDLC writeup** | Describes **shadow mode** for new automated reviewers and risk-weighted sampling of automated approvals. That is Pramaan's rollout plan and its 10% audit sample, shipped. |
| **Razorpay's own L1/L2** (Jun 2026 engineering blog) | 29 context-aware sub-skills at 75–80% accuracy, an 85% confidence gate for auto-remediation, L2 bots opening PRs. That is Pramaan's pipeline, in production, at a scale this project will never touch. |

So the claim is narrow and, I think, defensible: **the differentiator is the published
measurement, not the pipeline.** None of the systems above publishes a calibration curve
for its confidence gate, a miss rate under an asymmetric cost, or a proof-of-fix funnel
showing where fixes die. The `claude-code-security-review` action ships an `evals/`
folder and publishes no accuracy numbers; its own README says it is not hardened against
prompt injection. Razorpay's post measures accuracy against a "Manual TP rate" it admits
had "significant fatigue-driven inconsistency."

Pramaan is a small system that measures itself honestly, aimed at an open question, not
a big system claiming to be new.

## Why this problem

Three failures make an unmeasured triage agent worse than no triage agent:

1. **Silent suppression.** A false-positive filter that quietly suppresses true
   positives looks identical, from the outside, to one that works. No vendor publishes
   a miss rate. Pramaan weights a miss at 4× a needless review and fails CI if it rises.
2. **Patches that only look right.** AutoPatchBench found ~60% of LLM patches "work"
   until fuzzing and differential testing cut that to 5–11%. Pramaan publishes the
   funnel per stage rather than the final count.
3. **Injection through the data the agent must read.** Anthropic's own security-review
   action interpolated a PR title unsanitised and was made to exfiltrate its
   `ANTHROPIC_API_KEY` as a "finding". Cline's issue-triage bot led to a tampered npm
   CLI on ~4,000 machines. Scanner messages, ticket text and repo `CLAUDE.md` files are
   attacker-influenced **by construction** — and `razorpay-woocommerce` ships
   `CLAUDE.md`, `AGENTS.md`, `.claude/`, `.gemini/` and `.kimi/` today.

## Design

The load-bearing decisions, each of which is a constraint rather than a feature:

**The model emits observations; a pure function decides.** `ssvc_decision`, `severity`
and `recommended_action` are absent from the model's output schema and computed by
`policy.engine.decide()`, which touches no I/O. A rubric encoded in a prompt is a rubric
an injected code comment can rewrite.

**Sensitivity is monotonic.** Final business-impact tags are
`path_globs.union(model_tags)`. The model can add sensitivity and can never remove it.
Inverting that direction is a silent security failure, so a test asserts the direction
rather than the value.

**The actuator has four verbs.** `create_draft_pr`, `comment`, `get_finding`,
`update_finding`. No delete, no merge, no close-true-positive method exists anywhere in
either client protocol. A tool that does not exist cannot be talked into firing.

**Failure statuses are data.** Every triage call yields one of `valid | schema_invalid |
truncated | budget_abort | refused`, and a `schema_invalid` is never retried away —
silently retrying inflates the consistency number this project exists to make
trustworthy.

**Nothing that cannot be proved may open a PR.** `NO_SUITE` fails closed. A patched tree
running fewer tests than the base tree is a cheating patch, not a pass. A PoC that fails
*before* the patch is `INVALID_POC`. An unknown reviewer verdict fails closed.

## What is deliberately out of scope

PHP and Semgrep only. Deferred: Trivy, Checkov, Dependabot as graded sources; the
`bhadra` and Go targets; Vul4J, TerraGoat, CVEfixes; cross-repo propagation; L3 rule
auto-tuning; the SIEM module; DevRev and Jira adapters beyond a stub. The day-0 corpus
spike is why: 121 findings, 94% of them one CWE, across five distinct rules. That
supports a calibration study on one CWE family, not the four the original plan assumed.

## Risks

**The corpus is too small for some of what it is asked to carry.** 121 findings, 94%
CWE-79, three SQLi instances total. Weighted kappa on severity was dropped as degenerate
rather than reported as weak. Per-channel injection rates will have n≈8–12 and must be
reported with that uncertainty attached, not as bare percentages.

**There is one rater.** Inter-rater agreement is not available, so what is measured is
**intra-rater** agreement with a ≥7-day wash-out, named as such everywhere. That is a
weaker claim, and it happens to measure exactly the fatigue-driven inconsistency
Razorpay's own post admits to.

**`setting_sources=[]` makes one injection channel unwinnable by construction.** Hostile
`CLAUDE.md` payloads cannot succeed against the hardened config no matter what they say.
Pooling them into a single denominator would inflate the headline number with attacks
that were never possible, so channels are reported separately and the payload corpus is
published — including any payload that succeeded.

**Nothing has been measured yet.** Every number in the eventual trust report is
currently absent, not provisional. The harness is built and tested; the labelling has
not been done, and no live API call has been made.

## Rollout

Shadow mode first: the full pipeline runs, every verdict is logged, and zero external
actions are taken — proven by a test that runs the pipeline against recording fakes and
asserts they recorded nothing, rather than by trusting a flag. Actuation switches on per
verb, only after the eval gates pass, and only on forks. No pull request is ever opened
against `razorpay/*`.

## Open questions

1. Where should tau actually sit, and does it move by CWE family?
2. When the Semgrep rule itself is wrong, what changes — the skill, the rule, or the gate?
3. What does the fixer/reviewer disagreement rate look like, and which one is right more often?
4. How much context is enough? The ablation is built; it has not been run.
