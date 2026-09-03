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
