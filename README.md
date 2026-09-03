# Pramaan (प्रमाण, "proof")

An evidence-gated vulnerability triage-and-remediation harness built on the Claude
Agent SDK. It takes Semgrep findings, triages them through a **calibrated**
confidence gate, and only opens a draft PR once the fix carries a **proof bundle**:
the scanner is clean on the patched tree, the test suite is green, the exploit that
worked before is blocked after, the diff stays in scope, and an independent
fresh-context reviewer approves.

Every verdict is schema-validated JSON with `file:line` evidence. Every tool call is
audit-logged. The trust report publishes the numbers, including the ones that look bad.

> Status: in active development. See [PROJECT-BRAINSTORM.md](PROJECT-BRAINSTORM.md)
> for the design and the binding review decisions (D2–D21), and
> [docs/CONTRACTS.md](docs/CONTRACTS.md) for module interfaces.

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
| `docs/SDK-SURFACE.md` | Probed SDK facts — do not guess the API, read this |

## Licence and scope

Runs only against forks and local containers. Never opens PRs against `razorpay/*`.
See `docs/disclosure-policy.md`.
