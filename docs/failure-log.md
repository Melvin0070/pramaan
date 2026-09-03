# Failure log

Kept continuously from day 1, per TODO 3. The point of this file is that a
reconstructed failure log is worse than none — it reads as reconstructed. So this
records what actually broke, in order, including the things that were my own fault.

Format: date — what broke — why — what it cost.

---

**2026-09-03 — the day-0 corpus was lost.**
The spike ran on 2026-09-02 and produced 121 findings across 13 repos, but only the
summary table survived into `PROJECT-BRAINSTORM.md`; the raw Semgrep JSON was never
written anywhere durable. Re-running it is cheap, but the corpus is now measured a day
later against repos that may have moved, so the reproduction is not guaranteed to be
identical. Fixed by making the corpus a committed artifact with clone SHAs in
`data/corpus/MANIFEST.md`, which is what should have happened the first time.
Cost: one re-scan, and a permanent asterisk on "the spike found 121".

**2026-09-03 — `git init` had not been run before the build started.**
The working directory held a 34 KB design document, a task list and two research files,
none of it under version control. Any of it could have been lost the way the corpus was.
Fixed at the start of the build. Cost: nothing, by luck.

**2026-09-03 — worktree isolation was unavailable to the agent harness.**
Because the session began in a non-git directory, the harness had already decided the
project was not a git repo and refused to create agent worktrees, even after `git init`.
Worked around by creating the five lane worktrees manually with `git worktree add`.
Cost: a few minutes, and worth recording because the failure mode was a stale cached
fact rather than anything about the repo's actual state.

**2026-09-03 — hatchling could not find the package.**
`uv pip install -e .` failed with a build error pointing at `[tool.hatch.build.targets.wheel]`.
The `pramaan/` directory existed but had no `__init__.py` files, so there was no package to
discover. Fixed by adding the inits and an explicit `packages = ["pramaan"]`.
Cost: two minutes and one timed-out install.

**2026-09-03 — the frozen schema was wrong, and the store lane caught it.**
`Attempt` carried six of the seven verdict-cache key fields but not `fingerprint`, so
the cache could not derive its own key from an attempt; the store lane worked around it
with `put(fingerprint, attempt)` and flagged it rather than quietly editing a file it
had been told was frozen. Separately, the D13 row in the design doc listed a six-tuple
while D19 and `CONTRACTS.md` listed seven — two documents disagreeing about the cache
key, which is exactly the drift the `KEY_FIELDS` constant exists to prevent in code.
Both fixed. Cost: nothing, because it was caught before three other lanes built on it —
but it is the second time the freeze has been the thing that surfaced a defect rather
than hidden one.

**2026-09-03 — I broke 39 tests by "fixing" the frozen schema mid-build.**
Adding a required `fingerprint` field to `Attempt` was the right call, but I landed it
on `main` while the store lane's 93 tests were already written against the old shape,
so the merge went red immediately: `Attempt.__init__() missing 1 required positional
argument`. The lesson is not "don't change frozen schemas" — the change was correct and
the store lane is what surfaced the need. It is that a schema change is an integration
event and has to be landed with its call sites, not before them. Fixed by threading the
fingerprint through the test factory and adding a mismatch guard to
`CacheKey.for_attempt`, which then caught three more places where the caller and the
attempt disagreed about which defect a row belonged to. Cost: about fifteen minutes, and
the guard is now real coverage rather than a comment.

**2026-09-03 — the corpus lane found two real defects in the "frozen" schema.**
First, `make_finding_id` had no `repo` term. Two Razorpay payment-button plugins
(`payment-button-siteorigin-plugin` and `payment-button-visual-composer`) vendor a
byte-identical PHP file, so six ids collided across repos in the real corpus — and
`FindingStore` keys on `finding_id`, so those six findings would have been silently
dropped on import. Not hypothetical: it was demonstrated on the actual data.

Second, and worse, `make_fingerprint` excluded the line number by design so a defect
shifting down a file would still hit the verdict cache. That is right, but it meant two
byte-identical vulnerable lines in one file hashed to the same fingerprint and `dedup`
folded them into one record. A fix would land on the first and the second would survive
behind a green report — the exact failure the cheating-patch detector exists to catch,
happening one layer earlier. The corpus shipped 119 records where the scan found 121,
and only the lane's own note made that visible; nothing in the code would have said so.

Fixed by adding a per-distinct-line `occurrence` term to the fingerprint, which keeps
all three properties at once: two identical lines stay two defects, the same line
reported twice still collapses, and an unrelated edit above the defect still hits the
cache. Three regression tests pin exactly that, because the properties are in tension
and a future simplification would quietly break one.

Worth recording that the freeze is what produced both findings: the lane was told to
report rather than edit, so it reported instead of patching around them locally.

**2026-09-03 — the eval lane found a hole in the policy gate, and reported it.**
`calibration.tau` returns `1.0` when no threshold reaches the target precision — a
sentinel meaning "no usable gate was derived". But `policy.engine.decide` gated on
`confidence >= tau`, so a verdict claiming exactly 1.0 confidence would satisfy a gate
that had never been derived and auto-close. Narrow, since `recommended_tau()` already
raises unless 90% of folds achieve the target, but the failure mode is the worst kind:
a model asserting total certainty is the least trustworthy input that function receives,
not the most, and it would have been the one input that slipped through.

Two lanes each held half the picture and neither could see it alone. It surfaced because
the eval lane was told to report cross-lane problems rather than reach into `policy/` and
patch them, and an existing policy test had pinned the buggy behaviour at `tau=1.0` —
so a quiet fix would have looked like a test regression to whoever hit it next.

Same session, same cause: the triage envelope and the payload corpus each defined a list
called "channel" and the two lists were different. Both were right about different
things — one names delivery slots, one names attack channels — so they are now mapped
explicitly, with a test asserting every envelope slot is either covered by a payload or
named as uncovered. A silently untested slot is an untested attack surface.

**2026-09-03 — 1036 green tests, and two packages that could not be imported.**
`import pramaan.calibration` and `import pramaan.tickets` both raised ImportError from a
circular import, while the entire suite passed. The tests import submodules directly
(`pramaan.evals.labels`), which never runs the sibling `__init__` that closes the cycle;
anyone using the library the ordinary way would have hit it immediately. Two independent
cycles, each created where two lanes met: `evals/__init__` eagerly imported `runner`,
which imports `calibration.tau`, which imports `evals.labels` — and `mcp/__init__`
eagerly imported `shadow`, which imports `tickets.adapter`, which imports back into
`mcp`. Neither lane could have seen it; each half was fine.

Fixed by deferring exactly those two edges with PEP 562 `__getattr__`, which keeps the
package surface identical. The regression test runs each import in a **fresh
interpreter**, because import cycles are order-dependent and a process that has already
imported the modules cannot reproduce them — and it also asserts every name in `__all__`
actually resolves, since a lazy loader that quietly returns nothing is worse than the
cycle it replaced.

The lesson is about the shape of the test suite, not the code: a green suite proved the
units worked and said nothing about whether the package could be used.

**2026-09-03 — I wrote a CLI against an API that did not exist yet.**
`pramaan report render` called `trust_report.render(suite=..., injection=..., ablation=...)`
because I wrote the CLI while the report lane was still building, and guessed the
signature. The real one takes a single `ReportInputs` dataclass. Both sides were fully
unit-tested and both suites were green; nothing exercised the seam between them, and my
own CLI tests had skipped the one command whose dependency was still in flight — which
is precisely the command that needed the test. Caught by rendering the report by hand
rather than by any test.

Third integration failure of the day, same shape every time: the lanes were right and
the joins were wrong. The fix is a test that runs the real CLI over the real 121-finding
corpus and greps the real output, which is slower than a unit test and is the only kind
that would have caught this.
