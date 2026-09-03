# Pramaan (प्रमाण, "proof")

An evidence-gated vulnerability triage-and-remediation harness built on the Claude
Agent SDK. It takes Semgrep findings, triages them through a **calibrated**
confidence gate, and only opens a draft PR once the fix carries a **proof bundle**:
the scanner is clean on the patched tree, the test suite is green, the exploit that
worked before is blocked after, the diff stays in scope, and an independent
fresh-context reviewer approves.

Every verdict is schema-validated JSON with `file:line` evidence. Every tool call is
audit-logged. The trust report publishes the numbers, including the ones that look bad.

## Status: built, unmeasured

The harness is complete and tested — 1,219 tests, no skips. **It has not measured
anything yet**, and the distinction matters more than the line count:

| | |
|---|---|
| Corpus | 121 real Semgrep findings across 13 Razorpay PHP repos, with clone SHAs |
| Labels | **0 of 121.** `data/corpus/labels.csv` is deliberately blank |
| Live API calls made | **0** |
| Numbers in the trust report | none — it renders the list of what it refuses to print |

Every number the project exists to publish — precision, miss rate, calibration, tau,
pass^k, injection ASR — requires the labelling pass first. The report renders today and
says so on its face rather than filling the gap with plausible values.

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
