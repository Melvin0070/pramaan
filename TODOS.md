# TODOS — Pramaan

Captured by `/plan-eng-review` on 2026-09-02. Each item has enough context to pick up
cold in three months. See `## GSTACK REVIEW REPORT` at the end of
[PROJECT-BRAINSTORM.md](PROJECT-BRAINSTORM.md) for the decisions these came out of.

---

## 1. Report injection ASR per channel, and publish the payload corpus

**What:** Break attack success rate out by injection channel — code comment, Semgrep
message field, PR title, repo `CLAUDE.md` — rather than reporting one pooled number.
Publish the 30–50 payload corpus, and explicitly name any payload that succeeded.

**Why:** `setting_sources=[]` makes the hostile-`CLAUDE.md` channel ASR = 0 *by
construction* — those payloads cannot succeed against the hardened config no matter
what. Pooling them into a single denominator inflates the headline number with attacks
that were never possible. Separately, 30–50 payloads written by the same person building
the defence is a self-graded exam; publishing the corpus lets someone else grade it.

**Pros:** Per-channel numbers show which guardrail is doing which work, which is far more
informative than one aggregate. Publishing the payloads (including failures to stop) is
the strongest honesty signal available.

**Cons:** Per-channel n drops to roughly 8–12, so individual channel rates carry wide
confidence intervals and need to be reported with that caveat.

**Context:** Channels are enumerated at PROJECT-BRAINSTORM.md:114. D12 established the
paired control/hardened run; this is the reporting discipline layered on top of it.

**Depends on:** D12 paired injection harness.

---

## 2. Name an auditor for the 10% audit sample, or state that no audit was performed

**What:** The act-vs-escalate policy routes 10% of auto-closed false positives to an audit
queue. No auditor exists. Either audit the sample yourself on a stated cadence and publish
the results, or write plainly that the sample was queued but not audited in this build.

**Why:** Same class of gap as the missing second rater (D18). An audit queue that nobody
audits is a control that exists on paper only, and a security reviewer will spot it
immediately. At 121 findings, a 10% sample is about twelve items — roughly an hour using
the rubric you already wrote for labelling.

**Pros:** Closes a governance hole cheaply. Reusing the labelling rubric means no new
methodology to design.

**Cons:** If the audit surfaces errors in the auto-close decisions, you have to publish
them, which will make one of your headline numbers look worse.

**Context:** The policy table row reads "Close in DefectDojo with rationale; 10% random
sample queued for audit." You are the only human in the loop on this project.

**Depends on:** Labelling pass 1 (needed for the auto-close decisions to exist).

---

## 3. Human-provenance artifacts: failure log, timestamped labelling sheet, "what I got wrong"

**What:** Ship three things alongside the trust report — a running log of what broke and
why, the raw labelling sheet with per-session timestamps, and a section in the write-up
listing calls you got wrong.

**Why:** In 2026 the default prior on a polished AI-security repo with a generated HTML
report is "an agent produced this." The cheapest available counter-evidence is the mess:
timestamps showing labelling happened across real sessions, a log of dead ends, an honest
account of wrong calls. This is also the natural companion to D18's intra-rater framing —
if you are measuring your own inconsistency, showing the working is consistent with that.

**Pros:** Nearly free, because you generate the raw material anyway; it only needs
capturing. Answers the credibility question that nobody will ask you out loud.

**Cons:** Must be captured continuously from day one. A failure log reconstructed in week
three is worse than none, because it will read as reconstructed.

**Depends on:** Nothing. Start day 1.

---

## 4. Position explicitly against Anthropic's shipped architecture

**What:** Add a section to the RFC and README naming the closest prior art and stating what
Pramaan does that it does not: the Claude Security plugin (patches in a scratch copy, has a
*different* agent review the patch, runs project tests), Code Review's `file:line`
verification bar, and Anthropic's SDLC guidance already describing shadow mode.

**Why:** The plan positions carefully against Razorpay's own version at
PROJECT-BRAINSTORM.md:16–22 and not at all against Anthropic's, which is nearer prior art.
Omitting it reads as an incomplete survey to anyone who knows the space — and the people
evaluating this will. The differentiator is not the trust layer; it is the *published
measurement*. Saying so directly is stronger than implying novelty that is not there.

**Pros:** Sharpens the real claim. Pre-empts "how is this different from what ships in the
box?" Citations already sit in `research/landscape-research.md` L24 and L26, so this is a
writing task, not a research one.

**Cons:** Makes the architecture look less novel by naming how much of it already exists.

**Depends on:** Nothing.

---

## 5. Land one substantive PR in `razorpay/ai-playbook`

**What:** One real contribution to `razorpay/ai-playbook` — public, active (pushed
2026-09-01), non-security — started day 1 and run in parallel with the Pramaan build.

**Why:** The plan budgets three weeks of engineering and zero days for the artifact to
reach a human. A merged PR puts your name in their commit log somewhere their engineers
already look, before anyone reads an application. This is not barred by the non-goal at
PROJECT-BRAINSTORM.md:198, which excludes opening *vulnerability* PRs against
`razorpay/*` — a docs or tooling contribution to `ai-playbook` is a different act
entirely.

**Pros:** Highest ratio of signal to effort anywhere in this project. Fully parallel — it
needs nothing from Pramaan. Creates a genuine interaction with their engineers rather than
a one-way artifact.

**Cons:** Merge timing is entirely outside your control. A PR still open when you apply is
neutral rather than harmful, but it is not the win.

**Depends on:** Nothing. Start day 1, in parallel.

---

## 6. Verify the target role exists, and re-pitch for an intern reader

> **Flagged, not decided.** This is a strategy question and belongs in
> `/plan-ceo-review`, not an engineering review.

**What:** Two linked concerns. First, `research/razorpay-research.md:133` records "Intern,
Security Engineering — not found on the Greenhouse board, **unverified publicly**," while
the JD mapping table at PROJECT-BRAINSTORM.md:25–33 reads as the *Senior* Security
Engineer – AI posting, and the AI Builder Internship (verified open, judged on audit
trails, exception handling and failure recovery) sits in a footnote at :189. Second, the
document opens at :13 by telling the team their published 85% confidence gate may be
wrong, using N≈121 against their production corpus.

**Why:** You may be optimising for a posting that is not open, in a register aimed at a
different reader. From a senior candidate, challenging a published number reads as
confidence. From an intern applicant it invites them to defend it, and they have far more
data than you do. Reframing to "I reproduced your published L1 result on public data and
measured what I could" keeps every technical result and drops the confrontation.

**Pros:** Costs nothing technically — only framing changes. Confirms the door is open
before three weeks go through it.

**Cons:** Not an engineering call. Resolve it in `/plan-ceo-review`.

**Depends on:** Checking which roles are actually posted.

---

## 7. Adopt `enable_file_checkpointing`; evaluate `task_budget`

**What:** The D7 SDK probe found `ClaudeAgentOptions` carries 48 fields in
`claude_agent_sdk` 0.2.151; the plan uses roughly twelve. Two are directly useful:
`enable_file_checkpointing` gives the fixer a rollback path, and `task_budget` is a second
budget primitive alongside `max_budget_usd`.

**Why:** The buildathon criteria cited at PROJECT-BRAINSTORM.md:189 judge on "audit trails,
exception handling and failure recovery." File checkpointing *is* failure recovery, and it
is one configuration field rather than a subsystem.

**Pros:** Nearly free. Directly satisfies a criterion the plan already targets. Gives the
fixer clean rollback when a patch attempt goes wrong mid-run.

**Cons:** `task_budget` overlaps `max_budget_usd` and the semantics need confirming;
using both without understanding the difference is worse than using one.

**Context:** Full field list captured during the D7 probe. Verify semantics against the
installed package before wiring either in.

**Depends on:** D7 (done).

---

## 8. Reconcile the budget table

**What:** Fix the arithmetic at PROJECT-BRAINSTORM.md:229–234. `max_budget_usd=5` × ~30 fix
attempts is a $150 ceiling, but the table says "$50–120" for fixes. The context-scope
ablation (8 configs) has no line item at all. D12's paired injection run doubles that
eval's cost. D19's nightly uncached pass^k adds a recurring line that did not exist.

**Why:** The budget table is one of the few places the document commits to hard numbers.
Getting it wrong is a small, entirely avoidable precision error in a project whose selling
point is precision. The trust report is meant to publish *measured* cost anyway, so the
table becomes a prediction you can check yourself against.

**Pros:** Thirty minutes. No downside.

**Cons:** None material.

**Depends on:** Nothing.
