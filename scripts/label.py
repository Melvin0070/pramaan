"""Interactive labelling for data/corpus/labels.csv.

Not library code, and does not label anything itself -- it shows one finding at a
time (the real code, at the pinned commit, not just the truncated snippet) and asks
a human. Every design choice here follows a rule from docs/labelling-rubric.md;
read that first, this only enforces the mechanics of it.

Run:  .venv/bin/python scripts/label.py
Resume any time -- already-labelled rows are skipped automatically.
"""

from __future__ import annotations

import csv
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FINDINGS = ROOT / "data" / "corpus" / "findings.jsonl"
LABELS = ROOT / "data" / "corpus" / "labels.csv"
TARGETS = ROOT / "targets"

FIELDS = ["finding_id", "label", "confidence", "rater", "labelled_at", "notes"]
LABELS_ALLOWED = {"t": "true_positive", "f": "false_positive", "n": "needs_human"}
NEEDS_HUMAN_REASONS = [
    "reachability-unclear", "mitigation-unclear",
    "out-of-corpus-dependency", "time-boxed",
]

SINK_HINTS = {
    "var-in-href": "HTML-attribute output. Trace the variable to its origin; check "
                   "whether it is escaped before the href.",
    "unquoted-attribute-var": "HTML-attribute output, same family as var-in-href.",
    "echoed-request": "Raw echo of request data. Snippet is often truncated -- read "
                       "the real file, this rule frequently spans dozens of lines.",
    "tainted-sql-string": "SQL string construction. Check for escaping/parameterisation "
                          "between the source and the query -- pSQL(), prepare(), "
                          "an ORM call all count even if the rule doesn't recognise them.",
    "curl-ssl-verifypeer-off": "TLS verification config, not a taint question. Different "
                               "reasoning path -- see the rubric's own section for it.",
}


def load_findings() -> dict[str, dict]:
    out = {}
    for line in FINDINGS.read_text(encoding="utf-8").splitlines():
        if line.strip():
            import json
            f = json.loads(line)
            out[f["finding_id"]] = f
    return out


def load_rows() -> list[dict[str, str]]:
    with LABELS.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def save_rows(rows: list[dict[str, str]]) -> None:
    # Write to a sibling temp file and replace atomically, so a crash mid-write
    # never leaves labels.csv truncated -- every prior row's timestamp is real
    # work and must survive a bad exit.
    tmp = LABELS.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    tmp.replace(LABELS)


def show_code(finding: dict, context: int = 8) -> None:
    path = TARGETS / finding["repo"] / finding["path"]
    if not path.exists():
        print(f"  [code unavailable -- {path} not found; is targets/ populated?]")
        if finding.get("snippet"):
            print(f"  stored snippet (may be truncated): {finding['snippet'][:400]}")
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lo = max(1, finding["line_start"] - context)
    hi = min(len(lines), finding["line_end"] + context)
    for n in range(lo, hi + 1):
        marker = ">>" if finding["line_start"] <= n <= finding["line_end"] else "  "
        text = lines[n - 1] if n - 1 < len(lines) else ""
        print(f"  {marker} {n:>5} | {text}")


def prompt(text: str, *, allowed: set[str] | None = None, default: str | None = None) -> str:
    while True:
        raw = input(text).strip()
        if not raw and default is not None:
            return default
        if allowed is None or raw.lower() in allowed:
            return raw
        print(f"  (expected one of {sorted(allowed)})")


def main() -> int:
    if not FINDINGS.exists() or not LABELS.exists():
        print("run this from the repo root; data/corpus/{findings.jsonl,labels.csv} not found")
        return 1

    findings = load_findings()
    rows = load_rows()
    by_id = {r["finding_id"]: r for r in rows}
    pending = [r for r in rows if not r["label"].strip()]

    if not pending:
        print("every row already has a label. Nothing to do.")
        print("Starting pass 2? Copy labels.csv to labels-pass1.csv first (see the")
        print("instructions), then clear the label/confidence/notes columns before")
        print("running this again -- pramaan.evals.agreement needs two separate passes.")
        return 0

    print(f"{len(pending)} of {len(rows)} findings unlabelled.\n")
    rater = prompt("Your name/initials (used for every row this session): ").strip()
    if not rater:
        print("a rater id is required -- it is how D18 tells passes apart"); return 1

    backup = LABELS.with_name(f"labels.csv.bak-{int(time.time())}")
    shutil.copy(LABELS, backup)
    print(f"(backup saved to {backup.name})\n")

    session_start = time.monotonic()
    n_done_this_session = 0

    for row in pending:
        fid = row["finding_id"]
        f = findings.get(fid)
        if f is None:
            print(f"WARNING: {fid} not in findings.jsonl, skipping"); continue

        row_start = time.monotonic()
        print("\n" + "=" * 78)
        print(f"[{n_done_this_session + 1} this session | "
              f"{len(pending) - n_done_this_session - 1} left after this one]")
        print(f"repo:     {f['repo']}")
        print(f"rule:     {f['rule_id'].rsplit('.', 1)[-1]}")
        print(f"cwe:      {f.get('cwe')}    severity_reported: {f['severity_reported']}")
        print(f"path:     {f['path']}:{f['line_start']}-{f['line_end']}")
        print(f"message:  {f['message']}")
        rule_short = f["rule_id"].rsplit(".", 1)[-1]
        if rule_short in SINK_HINTS:
            print(f"hint:     {SINK_HINTS[rule_short]}")
        if f.get("metadata", {}).get("dup_count"):
            print(f"          (dup_count={f['metadata']['dup_count']} -- same defect, "
                  f"one row survives)")
        print()
        show_code(f)

        print()
        choice = prompt(
            "label  [t]rue_positive / [f]alse_positive / [n]eeds_human / "
            "[s]kip / [q]uit: ",
            allowed={"t", "f", "n", "s", "q"},
        ).lower()
        if choice == "q":
            break
        if choice == "s":
            continue

        label = LABELS_ALLOWED[choice]
        confidence = prompt(
            "confidence 1-5 (1=guess, 5=verified end-to-end): ",
            allowed={"1", "2", "3", "4", "5"},
        )
        if label == "needs_human":
            print(f"  fixed vocabulary: {', '.join(NEEDS_HUMAN_REASONS)}")
            if confidence in {"4", "5"}:
                print("  (needs_human at 4-5 is almost always wrong -- if you're that "
                      "confident, give a real label instead)")
        notes = input("notes (required for needs_human, optional otherwise): ").strip()
        if label == "needs_human" and not notes:
            notes = prompt("  notes cannot be empty for needs_human -- give a reason: ")

        elapsed = time.monotonic() - row_start
        if elapsed > 600:
            print(f"  (this row took {elapsed/60:.0f} min -- the rubric time-boxes at "
                  f"~10; consider needs_human/time-boxed for anything over that from "
                  f"here on)")

        row["label"] = label
        row["confidence"] = confidence
        row["rater"] = rater
        row["labelled_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        row["notes"] = notes

        save_rows(rows)  # every row, immediately -- see save_rows' docstring
        n_done_this_session += 1

    total_elapsed = time.monotonic() - session_start
    remaining = sum(1 for r in rows if not r["label"].strip())
    print(f"\n{'=' * 78}")
    print(f"{n_done_this_session} labelled this session in {total_elapsed/60:.1f} min "
          f"({total_elapsed/max(n_done_this_session,1):.0f}s/finding avg).")
    print(f"{remaining} of {len(rows)} remain unlabelled.")
    if remaining == 0:
        print("\nPass complete. Before starting the wash-out pass: "
              "cp data/corpus/labels.csv data/corpus/labels-pass1.csv")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n\ninterrupted -- everything up to the last completed row is saved.")
        raise SystemExit(130)
