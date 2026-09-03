"""Interactive labelling for data/corpus/labels.csv.

Not library code, and does not label anything itself -- it shows one finding at a
time (the real code, at the pinned commit, not just the truncated snippet) and asks
a human. Every design choice here follows a rule from docs/labelling-rubric.md;
read that first, this only enforces the mechanics of it.

Run:  .venv/bin/python scripts/label.py
Resume any time -- already-labelled rows are skipped automatically.

Optional: --assist shows an independent second opinion AFTER you have already
committed to your own label -- never before. Read docs/assisted-labelling-rationale.md
before turning it on; the ordering and the model-independence below are load-bearing,
not incidental, and the file explains why.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FINDINGS = ROOT / "data" / "corpus" / "findings.jsonl"
LABELS = ROOT / "data" / "corpus" / "labels.csv"
ASSIST_LOG = ROOT / "data" / "corpus" / "labels-assist-log.csv"
TARGETS = ROOT / "targets"

FIELDS = ["finding_id", "label", "confidence", "rater", "labelled_at", "notes"]
ASSIST_LOG_FIELDS = [
    "finding_id", "human_prelabel", "human_preconfidence",
    "assist_label", "assist_rationale", "assist_model",
    "agreed", "revised", "human_final_label", "logged_at",
]
LABELS_ALLOWED = {"t": "true_positive", "f": "false_positive", "n": "needs_human"}
ASSIST_LABEL_MAP = {"true_positive": "t", "false_positive": "f"}
NEEDS_HUMAN_REASONS = [
    "reachability-unclear", "mitigation-unclear",
    "out-of-corpus-dependency", "time-boxed",
]

# Deliberately not pramaan.agent.prompts.TRIAGE_SYSTEM_PROMPT, and deliberately not
# the same tool access as pramaan.agent.triage_runner.TriageRunner. If the assist
# suggestion came from the actual production triage agent, showing it to the human
# would preview the very system model_vs_human_agreement is meant to check them
# against -- see docs/assisted-labelling-rationale.md. This is a separate, minimal,
# no-tool-use opinion: read the pasted code, answer, one line why.
ASSIST_SYSTEM_PROMPT = (
    "You are a second, independent reviewer of a static-analysis finding. You will "
    "be shown a rule name, a message, and a code excerpt. Decide whether the flagged "
    "line is a real, exploitable instance of the issue the rule describes -- not how "
    "severe it is, just whether the flag is correct. Answer only from the pasted "
    "code; you have no tools and cannot read any other file. If you cannot tell from "
    "the excerpt alone, say so plainly in the rationale rather than guessing."
)
ASSIST_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["label", "rationale"],
    "properties": {
        "label": {"enum": ["true_positive", "false_positive"]},
        "rationale": {"type": "string", "maxLength": 240},
    },
}

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


VARIABLE_PATTERN = __import__("re").compile(
    r'\$[A-Za-z_][A-Za-z0-9_]*(?:\[[\'\"]?[A-Za-z0-9_]+[\'\"]?\])?'
)
REACHABILITY_SIGNALS = [
    (r"current_user_can\s*\(\s*['\"]([^'\"]+)['\"]", "capability gate: current_user_can({!r})"),
    (r"add_(?:sub)?menu_page\s*\([^;]*", "menu registration on this line -- check its capability argument"),
    (r"wp_verify_nonce", "nonce check present in this file"),
    (r"is_admin\s*\(\s*\)", "is_admin() check present in this file"),
    (r"add_action\s*\(\s*['\"]admin_post_", "registered via an admin_post_* action"),
    (r"add_action\s*\(\s*['\"]wp_ajax_(?!nopriv)", "registered via wp_ajax_* (logged-in users only, no privilege check by itself)"),
    (r"add_action\s*\(\s*['\"]wp_ajax_nopriv_", "registered via wp_ajax_nopriv_* -- reachable UNAUTHENTICATED"),
]
ESCAPE_FUNCTIONS = [
    "esc_html", "esc_attr", "esc_url", "esc_js", "htmlentities",
    "htmlspecialchars", "wp_kses", "pSQL", "prepare", "bindParam", "bindValue",
]


def gather_trace_hints(finding: dict) -> None:
    """Mechanical fact-gathering only -- never a verdict, never a suggestion.

    Automates the grep legwork steps 1/3/4/5 of the rubric actually require (find
    where the flagged variable comes from, check for a capability gate, check
    whether the file has an established escaping convention) so the human's time
    goes into the decision, not into re-discovering facts by hand for every row.
    Every one of these can be wrong or incomplete -- it is a starting point for
    your own read of the code above, not a substitute for it.
    """
    path = TARGETS / finding["repo"] / finding["path"]
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    flagged_start = finding["line_start"]

    flagged_lines = "\n".join(
        lines[finding["line_start"] - 1: finding["line_end"]]
    )
    variables = sorted(set(VARIABLE_PATTERN.findall(flagged_lines)))
    base_vars = sorted({v.split("[")[0] for v in variables})

    printed_anything = False

    if base_vars:
        for var in base_vars[:3]:  # cap noise on lines with many variables
            assign_re = __import__("re").compile(
                __import__("re").escape(var) + r"\s*=(?!=)"
            )
            hit = None
            for n in range(min(flagged_start, len(lines)), 0, -1):
                if assign_re.search(lines[n - 1]):
                    hit = n
                    break
            if hit:
                printed_anything = True
                print(f"  trace: {var} last assigned at line {hit}:")
                print(f"         {lines[hit - 1].strip()[:110]}")

    for pattern, template in REACHABILITY_SIGNALS:
        m = __import__("re").search(pattern, text)
        if m:
            printed_anything = True
            msg = template.format(m.group(1)) if "{" in template and m.groups() else template
            print(f"  reachability signal: {msg}")

    used_escapes = sorted({fn for fn in ESCAPE_FUNCTIONS if fn + "(" in text})
    if used_escapes:
        printed_anything = True
        print(f"  file already uses: {', '.join(used_escapes)} elsewhere "
              f"-- is this line missing a convention the rest of the file follows?")

    if not printed_anything:
        print("  trace: no automatic hints found -- nothing wrong with that, just "
              "means this one needs a normal manual read")


def prompt(text: str, *, allowed: set[str] | None = None, default: str | None = None) -> str:
    while True:
        raw = input(text).strip()
        if not raw and default is not None:
            return default
        if allowed is None or raw.lower() in allowed:
            return raw
        print(f"  (expected one of {sorted(allowed)})")


def load_assist_log() -> list[dict[str, str]]:
    if not ASSIST_LOG.exists():
        return []
    with ASSIST_LOG.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def append_assist_log(entry: dict[str, str]) -> None:
    exists = ASSIST_LOG.exists()
    with ASSIST_LOG.open("a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=ASSIST_LOG_FIELDS)
        if not exists:
            w.writeheader()
        w.writerow(entry)


def get_code_text(finding: dict, context: int = 8) -> str:
    """Same window show_code() prints, as a string for the assist prompt."""
    path = TARGETS / finding["repo"] / finding["path"]
    if not path.exists():
        return finding.get("snippet") or "(no code available)"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lo = max(1, finding["line_start"] - context)
    hi = min(len(lines), finding["line_end"] + context)
    out = []
    for n in range(lo, hi + 1):
        marker = ">>" if finding["line_start"] <= n <= finding["line_end"] else "  "
        text = lines[n - 1] if n - 1 < len(lines) else ""
        out.append(f"{marker} {n:>5} | {text}")
    return "\n".join(out)


def assist_suggestion(finding: dict, model: str) -> tuple[str, str] | None:
    """One independent opinion: (label, rationale), or None if the call failed.

    A failure here is not fatal to the row -- assist is a convenience, not a
    dependency, and the human's own label already stands regardless of whether
    this succeeds.
    """
    import anyio
    from claude_agent_sdk import ClaudeAgentOptions, query

    body = (
        f"rule: {finding['rule_id']}\n"
        f"message: {finding['message']}\n"
        f"cwe: {finding.get('cwe')}\n\n"
        f"code (>> marks the flagged line(s)):\n{get_code_text(finding)}\n"
    )
    options = ClaudeAgentOptions(
        model=model,
        system_prompt=ASSIST_SYSTEM_PROMPT,
        allowed_tools=[],
        disallowed_tools=["Bash", "Read", "Write", "Edit", "Grep", "Glob",
                          "WebFetch", "WebSearch"],
        permission_mode="dontAsk",
        setting_sources=[],
        output_format={"type": "json_schema", "schema": ASSIST_SCHEMA},
        max_turns=1,
        max_budget_usd=0.10,
    )

    async def _call() -> tuple[str, str] | None:
        # Explicit aclose() rather than an early `return` inside the `async for`:
        # returning mid-iteration abandons query()'s generator, and the SDK later
        # tries to close it from whatever context GC runs in -- by then anyio.run()
        # has already torn the event loop down, which is what raised the
        # 'aclose(): asynchronous generator is already running' warning here on the
        # first live test. Closing it explicitly, in the loop it was opened in, is
        # what makes the warning go away rather than just becoming intermittent.
        agen = query(prompt=body, options=options).__aiter__()
        try:
            while True:
                msg = await agen.__anext__()
                if type(msg).__name__ == "ResultMessage":
                    so = getattr(msg, "structured_output", None)
                    if isinstance(so, dict) and "label" in so:
                        return so["label"], so.get("rationale", "")
        except StopAsyncIteration:
            return None
        finally:
            await agen.aclose()

    try:
        return anyio.run(_call)
    except Exception as exc:  # noqa: BLE001 -- convenience path, never fatal
        print(f"  (assist call failed: {type(exc).__name__}: {exc} -- continuing without it)")
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--assist", action="store_true",
        help="show an independent second opinion after you commit your own label "
             "(read docs/assisted-labelling-rationale.md first)",
    )
    ap.add_argument("--assist-model", default="claude-haiku-4-5-20251001")
    args = ap.parse_args()

    if not FINDINGS.exists() or not LABELS.exists():
        print("run this from the repo root; data/corpus/{findings.jsonl,labels.csv} not found")
        return 1

    if args.assist:
        print("=" * 78)
        print("ASSIST MODE. The assist opinion is shown only AFTER you commit your own")
        print("label -- it cannot anchor a judgement you haven't made yet. It is a")
        print("separate, minimal, tool-free model, not the production triage agent.")
        print("Not for the official pass 1/pass 2 wash-out unless BOTH passes use it")
        print("and you report that. Full reasoning: docs/assisted-labelling-rationale.md")
        print("=" * 78)
        if prompt("Continue with assist on? [y/n]: ", allowed={"y", "n"}) != "y":
            return 0
        print()

    findings = load_findings()
    rows = load_rows()
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
        gather_trace_hints(f)

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

        # Assist runs here, and only here: after label/confidence/notes are already
        # committed. Nothing above this line changes when --assist is on -- that is
        # what makes the human's initial call independent of the suggestion below.
        if args.assist and label in ASSIST_LABEL_MAP:
            print("\n  (consulting assist...)")
            result = assist_suggestion(f, args.assist_model)
            if result is not None:
                assist_label, assist_rationale = result
                human_original_label = label  # captured before any revision below
                human_original_confidence = confidence
                agreed = assist_label == label
                print(f"  assist: {assist_label}  ({assist_rationale})")
                print(f"  {'agrees with you' if agreed else 'DISAGREES with you'}")

                revised = False
                if not agreed:
                    switch = prompt(
                        "  revise your label to match assist, or keep your own? "
                        "[k]eep / [r]evise: ",
                        allowed={"k", "r"},
                    )
                    if switch == "r":
                        revised = True
                        confidence = prompt(
                            "  confidence in the revised label, 1-5: ",
                            allowed={"1", "2", "3", "4", "5"},
                        )
                        label = assist_label

                append_assist_log({
                    "finding_id": fid,
                    "human_prelabel": human_original_label,
                    "human_preconfidence": human_original_confidence,
                    "assist_label": assist_label,
                    "assist_rationale": assist_rationale,
                    "assist_model": args.assist_model,
                    "agreed": str(agreed),
                    "revised": str(revised),
                    "human_final_label": label,
                    "logged_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                })
                suffix = (
                    "[assist: agreed]" if agreed
                    else "[assist: disagreed, revised]" if revised
                    else "[assist: disagreed, kept own]"
                )
                notes = f"{notes} {suffix}".strip()

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
