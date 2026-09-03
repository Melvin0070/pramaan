"""Run the triage agent against real findings and persist every attempt.

Deliberately a script, not library code: it spends money and touches the network,
which is exactly what `pramaan/` is built not to do. Cost and latency are recorded per
attempt so the trust report can publish measured numbers rather than estimates.
"""

from __future__ import annotations

import anyio
import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

from pramaan.agent.context import ContextConfig, build_context
from pramaan.agent.triage_runner import TriageRunner
from pramaan.schemas import Finding
from pramaan.store.verdict_cache import CachedVerdictStore, new_run_epoch

ROOT = Path(__file__).resolve().parent.parent


def load_corpus() -> list[Finding]:
    path = ROOT / "data" / "corpus" / "findings.jsonl"
    return [Finding.from_dict(json.loads(l)) for l in path.read_text().splitlines() if l.strip()]


def source_for(finding: Finding) -> str | None:
    p = ROOT / "targets" / finding.repo / finding.path
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8", errors="replace")


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1, help="findings to triage")
    ap.add_argument("-k", type=int, default=1, help="runs per finding (pass^k)")
    ap.add_argument("--model", default="claude-sonnet-5")
    ap.add_argument("--effort", default="medium")
    ap.add_argument("--max-turns", type=int, default=25)
    ap.add_argument("--budget", type=float, default=0.50, help="max_budget_usd per attempt")
    ap.add_argument("--callers", action="store_true")
    ap.add_argument("--window", type=int, default=50)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--db", default="data/verdicts.sqlite")
    ap.add_argument("--stratify", action="store_true", help="one finding per rule first")
    ap.add_argument("--fingerprints", help="file, one fingerprint per line -- exact set, for a fair model comparison")
    ap.add_argument("--concurrency", type=int, default=1)
    args = ap.parse_args()

    corpus = load_corpus()
    rng = random.Random(args.seed)

    if args.fingerprints:
        wanted = set(Path(args.fingerprints).read_text().split())
        chosen = [f for f in corpus if f.fingerprint in wanted]
        missing = wanted - {f.fingerprint for f in chosen}
        if missing:
            print(f"WARNING: {len(missing)} fingerprints not found in corpus", file=sys.stderr)
        print(f"exact-set mode: {len(chosen)} findings from --fingerprints", flush=True)
    elif args.stratify:
        # The corpus is 94% one CWE, so a uniform sample of 10 would very likely be
        # ten copies of the same rule and would measure almost nothing.
        by_rule: dict[str, list[Finding]] = {}
        for f in corpus:
            by_rule.setdefault(f.rule_id, []).append(f)
        picked: list[Finding] = []
        pools = [rng.sample(v, len(v)) for v in by_rule.values()]
        while len(picked) < args.n and any(pools):
            for pool in pools:
                if pool and len(picked) < args.n:
                    picked.append(pool.pop())
        chosen = picked
    else:
        chosen = rng.sample(corpus, min(args.n, len(corpus)))

    chosen = [f for f in chosen if source_for(f) is not None]
    epoch = new_run_epoch()
    store = CachedVerdictStore(ROOT / args.db)
    runner = TriageRunner(
        cwd=str(ROOT / "targets"),
        model=args.model,
        effort=args.effort,
        max_budget_usd=args.budget,
        max_turns=args.max_turns,
    )
    cfg = ContextConfig(window=args.window, callers=args.callers)
    context_name = getattr(cfg, "name", None) or f"w{args.window}{'_callers' if args.callers else ''}"

    stats: Counter[str] = Counter()
    total_cost = 0.0
    t_start = time.time()
    rows = []
    limiter = anyio.CapacityLimiter(args.concurrency)
    lock = anyio.Lock()
    jobs = [(i, f, r) for i, f in enumerate(chosen, 1) for r in range(args.k)]

    async def one(i: int, finding: Finding, run_index: int) -> None:
        nonlocal total_cost
        async with limiter:
            src = source_for(finding)
            ctx = build_context(
                finding_id=finding.finding_id, path=finding.path,
                line_start=finding.line_start, line_end=finding.line_end,
                source=src, config=cfg,
            )
            t0 = time.time()
            try:
                attempt = await runner.run(
                    finding=finding, context=ctx, run_index=run_index,
                    run_epoch=epoch, context_config=context_name,
                )
            except Exception as exc:
                async with lock:
                    stats["exception"] += 1
                print(f"  [{i}#{run_index}] EXCEPTION {type(exc).__name__}: {exc}"[:150], flush=True)
                return
            dt = time.time() - t0
            v = (attempt.verdict or {}).get("verdict") if attempt.verdict else None
            conf = (attempt.verdict or {}).get("confidence") if attempt.verdict else None
            async with lock:
                stats[attempt.status] += 1
                total_cost += attempt.cost_usd or 0.0
                store.put(finding.fingerprint, attempt)
                rows.append({
                    "finding_id": finding.finding_id, "repo": finding.repo,
                    "rule": finding.rule_id.rsplit(".", 1)[-1], "run": run_index,
                    "status": attempt.status, "verdict": v, "confidence": conf,
                    "cost_usd": attempt.cost_usd, "seconds": round(dt, 1),
                    "num_turns": attempt.num_turns,
                    "injection_observed": (attempt.verdict or {}).get("injection_observed") if attempt.verdict else None,
                })
            print(f"  [{i}#{run_index}] {attempt.status:<14} {str(v):<15} "
                  f"conf={conf} ${attempt.cost_usd:.4f} {dt:.0f}s t={attempt.num_turns}", flush=True)

    async with anyio.create_task_group() as tg:
        for i, finding, run_index in jobs:
            tg.start_soon(one, i, finding, run_index)

    elapsed = time.time() - t_start
    n_att = sum(stats.values())
    print("\n" + "=" * 62)
    print(f"attempts        : {n_att} over {len(chosen)} findings x {args.k} runs")
    print(f"statuses        : {dict(stats)}")
    print(f"total cost      : ${total_cost:.4f}")
    if n_att:
        print(f"cost per attempt: ${total_cost / n_att:.4f}")
        print(f"latency per att : {elapsed / n_att:.1f}s  (wall {elapsed:.0f}s)")
    print(f"run_epoch       : {epoch}")
    out = ROOT / "data" / "live" / f"triage-{epoch}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "epoch": epoch, "model": args.model, "effort": args.effort,
        "context_config": context_name, "k": args.k,
        "statuses": dict(stats), "total_cost_usd": round(total_cost, 4),
        "attempts": rows,
    }, indent=2))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(anyio.run(main))
