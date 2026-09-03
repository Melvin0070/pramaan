# Pramaan (प्रमाण, "proof")

An evidence-gated vulnerability triage-and-remediation harness built on the Claude
Agent SDK. It takes Semgrep findings, triages them through a **calibrated**
confidence gate, and only opens a draft PR once the fix carries a **proof bundle**:
the scanner is clean on the patched tree, the test suite is green, the exploit that
worked before is blocked after, the diff stays in scope, and an independent
fresh-context reviewer approves.

Every verdict is schema-validated JSON with `file:line` evidence. Every tool call is
audit-logged. The trust report publishes the numbers, including the ones that look bad.

## Status: built, live-piloted, not yet corpus-measured

The harness is complete and tested — 1,219 tests, no skips — and has now run live
against the real API on a stratified pilot. It has **not** yet produced a corpus-wide,
labelled result, and that distinction matters more than either number:

| | |
|---|---|
| Corpus | 121 real Semgrep findings across 13 Razorpay PHP repos, with clone SHAs |
| Labels | **0 of 121.** `data/corpus/labels.csv` is deliberately blank |
| Live API calls made | **Yes** — pilot only (n=20 stratified), see [docs/LIVE-EVIDENCE.md](docs/LIVE-EVIDENCE.md) |
| pass^5 (pilot) | Haiku 4.5 55%, Sonnet 5 65% — both well below the 0.9 target |
| Injection ASR, hardened (pilot) | 6.7% (2/30 deliverable), down from 30.0% unguarded |
| Proof-of-fix, real target | Ran against a real unfixed SQLi; correctly refused to open a PR |
| Numbers in the trust report | still none for the real corpus — precision, miss rate, tau, calibration all require the labelling pass, which has not started |

Every *corpus-wide* number — precision, miss rate, calibration, tau, per-rule
breakdowns — still requires the labelling pass; nothing above substitutes for it. What
changed is that pass^k and injection ASR don't need labels, so those are now real,
live-measured numbers rather than projections. Full detail, every caveat, and what the
pilot explicitly is not: [docs/LIVE-EVIDENCE.md](docs/LIVE-EVIDENCE.md).

See [PROJECT-BRAINSTORM.md](PROJECT-BRAINSTORM.md) for the design and the binding review
decisions (D2–D21), [docs/RFC.md](docs/RFC.md) for how this positions against the prior
art that already ships, [docs/disclosure-policy.md](docs/disclosure-policy.md) for what
may and may not be published, and [docs/failure-log.md](docs/failure-log.md) for what
broke along the way.

## Why it is not another triage bot

The differentiator is not the architecture — much of it ships in the box with
Claude Code today. It is the **published measurement**: a calibration curve for the
confidence gate, a miss rate under asymmetric cost, a proof-of-fix funnel that shows
where fixes die, and a paired prompt-injection run against a deliberately unguarded
control.

## Layout

| Path | What lives there |
|---|---|
| `pramaan/schemas/` | The shared contract: Finding, Verdict, Attempt, ProofBundle |
| `pramaan/policy/` | Pure act-vs-escalate engine and the sensitive-path tagger |
| `pramaan/store/` | FindingStore and the content-addressed verdict cache |
| `pramaan/ingest/` | Semgrep SARIF/JSON normalisation and dedup |
| `pramaan/agent/` | Triage runner, reviewer subagent, SDK harness |
| `pramaan/validators/`, `pramaan/proof/` | Deterministic proof-of-fix validators |
| `pramaan/evals/`, `pramaan/calibration/` | The Kasauti eval suite; tau derivation |
| `pramaan/report/` | Trust report |
| `pramaan/mcp/`, `pramaan/tickets/` | The four verbs that can change the outside world |
| `pramaan/cli.py` | Entry points; half of them run with no API key |
| `docs/SDK-SURFACE.md` | Probed SDK facts — do not guess the API, read this |

## Licence and scope

Runs only against forks and local containers. Never opens PRs against `razorpay/*`.
See `docs/disclosure-policy.md`.


## Try it without an API key

Roughly half the CLI is pure computation over cached verdicts, by design: the
calibration has to be reproducible by someone who cannot call the model that produced
it.

```bash
# Render the trust report over the real corpus. Aggregate-only, and the renderer
# re-scans its own output and raises rather than emitting a leak.
pramaan report render --findings data/corpus/findings.jsonl --out trust-report.html

# Decide one finding. Pure function, no model, no network.
pramaan policy --verdict verdict.json --tau 0.9 --path includes/api/order.php

# Draw the 10% auto-close audit sample. Seeded, so the report can name the draw.
pramaan evals audit --auto-closed closed.json --seed 2026-09-w36 --out audit.json
```

Commands that need a live model exit `3` with an explanation and write nothing — an
empty artifact is indistinguishable from a real result that measured nothing.
