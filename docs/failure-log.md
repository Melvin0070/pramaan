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
