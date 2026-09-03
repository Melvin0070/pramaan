# Disclosure policy

Binding. This is decision D17, and the trust report renderer enforces it in code rather
than relying on an author to remember it.

## The situation

Pramaan's corpus is 121 real Semgrep findings across 13 live Razorpay PHP repositories —
payment plugins that merchants run in production against real card flows. They are not a
benchmark. Razorpay's bug bounty programme **excludes open-source repositories**, so
there is no safe harbour covering this work and no reward channel that would make
publication normal. A public `file:line` on an unfixed defect in a live payment plugin is
a free exploit primitive, and the fact that Semgrep found it means anyone else can too —
which is an argument for telling the maintainers, not for telling everyone.

## What the public report may contain

| Published | Withheld |
|---|---|
| Counts by repository, rule and CWE | `file:line` for any unfixed finding |
| Per-rule precision and the confusion matrix | Code snippets from unfixed findings |
| Confidence distributions, the reliability diagram, derived tau | Exploit paths or proof-of-concept payloads for real repos |
| Verdict labels and their agreement statistics | Anything that turns "there is an XSS in this file" into "here is how" |
| Cost, latency and consistency measurements | |

Aggregate numbers are the entire point of the trust report. None of them require naming
a line of somebody's production code.

## Where full evidence *is* published

Complete evidence bundles — `file:line`, snippets, the exploit before and after — appear
only for targets that exist to be exploited:

- **OWASP Benchmark v1.2** — a synthetic labelled corpus whose purpose is measurement.
- **OWASP Juice Shop** — deliberately vulnerable, run only in a local container.

This is also why the proof-of-fix funnel is reported as two funnels that are never
blended (D4). The full-proof funnel carries PoC evidence because Juice Shop can be
exploited freely. The partial-proof funnel, on real Razorpay findings, cannot and does
not — and saying so is more honest than quietly reporting one blended number.

## What happens to real findings

1. Verdicts, tickets and any draft PRs stay on **forks**. No pull request is ever opened
   against `razorpay/*`. This is a non-goal in the design doc and a hard rule here.
2. Findings that survive triage as true positives go to maintainers privately, through
   the process in `razorpay-mcp-server/SECURITY.md`, as a private annex containing the
   detail the public report withholds.
3. Exploits run only against local containers. Never a hosted target, never a merchant's
   site, never a Razorpay-operated endpoint.
4. `razorpay-woocommerce` is GPL-2.0. Scanning and forking are fine; attribution stays.

## Enforcement, not intention

The report renderer must make a leak structurally difficult rather than merely
discouraged:

- A finding is publishable in full only if its funnel is `full_proof` **and** its
  repository is on the synthetic-target allowlist. Everything else renders as aggregate.
- A test asserts that a real unfixed finding's `path` never reaches the rendered HTML.
  That test is the actual policy; this document is the explanation.
- The audit log redacts secrets, and no token is ever written to a report artifact.

## The uncomfortable part

This policy costs the project its most vivid material. "Here is a real SQL injection in a
payment plugin, and here is my agent fixing it" is a far better demo than a confusion
matrix. Publishing it would also be the single most irresponsible thing in the build, and
a security team evaluating this work would notice the tradeoff being made either way.
Choosing the boring artifact is the answer to a question they should be asking.
