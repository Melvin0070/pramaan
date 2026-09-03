# Module contracts

Read this before writing code in any lane. `pramaan/schemas/` is already written and
is **frozen** — if you believe it is wrong, say so in your report rather than editing
it, because every other lane is compiling against it right now.

Binding decisions live in `PROJECT-BRAINSTORM.md` under "Binding decisions" (D2–D21).
They supersede the prose above them in that file. SDK facts live in
`docs/SDK-SURFACE.md`, probed from the installed package — **do not guess the API.**

## Ground rules for every lane

1. Python 3.12, standard library first. Deps already available: `claude-agent-sdk`,
   `jsonschema`, `pyyaml`, `pytest`. Adding anything else needs a note in your report.
2. `from __future__ import annotations` at the top of every module.
3. Type-annotate public functions. No `Any` in a signature you control.
4. Pure functions do not touch the network, the clock or the filesystem. Where a
   timestamp is genuinely needed, take it as a parameter with a default.
5. Tests go in `tests/test_<module>.py` and must pass with `pytest -q`.
6. Comment only non-obvious *why* — intent, tradeoffs, workarounds. Never restate
   what the code does.
7. Fail closed. An unknown state is not a pass.

## Lane A — store (`pramaan/store/`)

```python
class FindingStore(Protocol):
    def upsert(self, finding: Finding) -> None: ...
    def get(self, finding_id: str) -> Finding | None: ...
    def by_fingerprint(self, fingerprint: str) -> list[Finding]: ...
    def all(self) -> Iterator[Finding]: ...
    def count(self) -> int: ...
```

- `SqliteFindingStore(path)` is the default; `JsonlFindingStore(path)` for the corpus.
- `DefectDojoAdapter` is a **week-2 stub** implementing the same Protocol (D6).
- Verdict cache (D13) is content-addressed on the tuple
  `(fingerprint, model, effort, context_config, prompt_hash, run_index, run_epoch)`.
  It persists `Attempt` rows **including failure statuses** — a `schema_invalid`
  attempt is data, not an error to swallow.
- D19: a nightly run passes a fresh `run_epoch`, which misses every cached row by
  construction. `CachedVerdictStore.get(...)` must never coerce a differing epoch to
  a hit. The CI subset reads the cache; the nightly pass^k must not.
- Skill-scoped invalidation: editing one CWE skill invalidates only the entries whose
  `prompt_hash` includes that skill, not the whole table.

## Lane B — policy (`pramaan/policy/`)

`engine.decide(verdict: Verdict, tags: BusinessImpact, tau: float) -> Decision`

Pure. No I/O, no model. `Decision` is a frozen dataclass carrying
`ssvc_decision`, `severity`, `recommended_action`, `rationale`, `escalate_reason`.
One unit test per row of the act-vs-escalate table in `PROJECT-BRAINSTORM.md`.

- D8: these three fields are computed **here** and are absent from `VERDICT_SCHEMA`.
- D9: `sensitive_paths.tag(path) -> BusinessImpact` from globs in
  `config/sensitive_paths.yaml`. Final tags are `path_tags.union(model_tags)`. The
  model can add sensitivity and can **never** remove it. Assert this direction in a
  test, because getting it backwards is a silent security failure.
- `injection_observed=True` ⇒ quarantine, verdict unchanged, security event raised.
- Any sensitive tag on a true positive ⇒ escalate, and the fixer is never invoked.
- Fixer allowlist is **XSS + SQLi only** (D16 — the corpus has no instances of the
  other three classes, so claiming them would be unfalsifiable).

## Lane C — ingest (`pramaan/ingest/`)

`semgrep.parse_sarif(text) -> list[Finding]` and `semgrep.parse_json(text) -> list[Finding]`.
Malformed input raises `IngestError`, never returns a partial list silently.
Dedup by `fingerprint`; a collision keeps the earliest `line_start` and records the
duplicate count in `metadata["dup_count"]`.

## Lane D — agent (`pramaan/agent/`)

The triage runner wraps `claude_agent_sdk.query`. Config comes straight from the
guardrails table: `allowed_tools=["Read","Grep","Glob"]`,
`disallowed_tools=["Bash","Write","Edit","WebFetch","WebSearch"]`,
`permission_mode="dontAsk"`, `setting_sources=[]` (never load the scanned repo's
`CLAUDE.md`), `output_format={"type":"json_schema","schema":VERDICT_SCHEMA}`,
`max_turns=25`, `max_budget_usd=0.50`.

- **Finding text is never interpolated into `system_prompt`.** It is passed as
  delimited data in the user turn, wrapped in a marker the prompt tells the model to
  treat as untrusted.
- Every call returns an `Attempt` with one of the five D10 statuses. Never retry a
  `schema_invalid` away.
- D19: stamp the API-returned model id / system fingerprint on every attempt.

## Lane E — validators + proof (`pramaan/validators/`, `pramaan/proof/`)

Four deterministic validators, no model: `rescan_clean`, `tests_green` (tri-state,
D5), `poc_blocked`, `diff_in_scope`. Plus a cheating-patch detector: new
`nosemgrep` / `@SuppressWarnings`, deleted tests, unrelated files, added deps.

- A PoC that fails **before** the patch is `INVALID_POC`, not a pass.
- `ProofBundle.may_open_pr` is already implemented in `schemas/proof.py`. Use it;
  do not reimplement the gate.

## Lane F — evals + calibration (`pramaan/evals/`, `pramaan/calibration/`)

- `tau.derive(attempts, labels, k=5, repeats=10) -> TauResult` by repeated k-fold CV,
  reporting **fold spread**, not a point estimate (D3). Fold isolation is the thing to
  test: tau derived on a fold must never see that fold's labels.
- `consistency.pass_at_k(attempts) -> float` where `schema_invalid` counts as a
  non-match (D10).
- `agreement.intra_rater_kappa(...)` — named intra-rater everywhere, never plain
  "kappa". Model-vs-human agreement is reported separately and is not kappa (D18).
- `injection.py` runs the **paired** design (D12): identical payload corpus against a
  containerised unguarded control and against the hardened config. Report both ASRs,
  **broken out per channel** (TODO 1): code comment, Semgrep message field, PR title,
  repo `CLAUDE.md`. The control run must actually be compromised or the harness is
  not measuring anything — assert that in a test.
- Calibration: reliability diagram + ECE. Pure functions over cached attempts, so the
  whole thing reruns from the published verdict table with no API key.

## Lane G — report (`pramaan/report/`)

Renders the trust report from the store. No API calls. Must render on zero findings
and on all-`NO_SUITE` input rather than dividing by zero.

- D17 disclosure: aggregate-only for real findings — counts, classes, confidence
  distributions, per-rule precision. **No `file:line` for anything unfixed.** Full
  evidence bundles only for Juice Shop and OWASP Benchmark. The renderer must enforce
  this, not merely document it; a test should prove a real unfixed finding's path
  never reaches the HTML.
- Charts are hand-rolled inline SVG. No matplotlib.
