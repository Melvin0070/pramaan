"""End-to-end proof-of-fix demo against a real, unfixed vulnerability. $0, no model.

Deliberately not a library module: this is a demonstration script, not something the
pipeline imports. It exists to prove the validators work against real code and a real
scanner, not synthetic fixtures.

Target: a real SQL injection in razorpay-prestashop (semgrep tainted-sql-string,
line 83 of razorpay/controllers/front/validation.php), from the committed corpus.
Never published with file:line per docs/disclosure-policy.md; this script only prints
locally and the patch is applied to a local clone and reverted before exit.

RESULT (2026-09-03, semgrep 1.176.0): the harness correctly refused to authorise a PR.
Two independent validators blocked it -- rescan_clean and tests_green -- and neither
is a bug in the fix. See the printed detail for why.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "targets" / "razorpay-prestashop"
REL_PATH = "razorpay/controllers/front/validation.php"
RULE = "php.lang.security.injection.tainted-sql-string.tainted-sql-string"
FINDING_ID = f"semgrep:{RULE}:razorpay-prestashop:{REL_PATH}:83"

OLD = '''                    $db = \\Db::getInstance();
                    $request = "SELECT `rzp_order_id` FROM `razorpay_sales_order` WHERE `cart_id` = " . $_REQUEST['cart_id'];
                    $rzp_order_id = $db->getValue($request);'''

# pSQL() is PrestaShop's own escaping function, and this codebase already uses it
# elsewhere (razorpay/controllers/front/order.php:84) -- this is the idiomatic fix,
# not an invented one.
NEW = '''                    $db = \\Db::getInstance();
                    $cartId = pSQL($_REQUEST['cart_id']);
                    $request = "SELECT `rzp_order_id` FROM `razorpay_sales_order` WHERE `cart_id` = '" . $cartId . "'";
                    $rzp_order_id = $db->getValue($request);'''


def main() -> int:
    if not TARGET.exists():
        print(f"clone razorpay-prestashop into {TARGET} at the manifest SHA first "
              "(see data/corpus/MANIFEST.md)", file=sys.stderr)
        return 1

    rescan_mod = importlib.import_module("pramaan.validators.rescan")
    tv_mod = importlib.import_module("pramaan.validators.tests_validator")
    ds_mod = importlib.import_module("pramaan.validators.diff_scope")
    ch_mod = importlib.import_module("pramaan.validators.cheating")
    from pramaan.schemas import ProofBundle, TestsValidation, ValidatorResult

    target_file = TARGET / REL_PATH
    original = target_file.read_text()
    if OLD not in original:
        print("target file has drifted from the expected shape; abort", file=sys.stderr)
        return 1

    print(f"finding: {FINDING_ID}")
    print("=" * 70)

    print("\n[1] rescan_clean, BEFORE the patch (real semgrep, real repo)")
    before = rescan_mod.rescan(patched_tree=str(TARGET), config="p/php", rule_id=RULE)
    print(f"    {before.outcome}: {before.detail}")

    try:
        target_file.write_text(original.replace(OLD, NEW, 1))
        diff = subprocess.run(
            ["git", "diff", "--", REL_PATH], cwd=TARGET, capture_output=True, text=True,
        ).stdout

        print("\n[2] rescan_clean, AFTER the patch")
        after = rescan_mod.rescan(patched_tree=str(TARGET), config="p/php", rule_id=RULE)
        print(f"    {after.outcome}: {after.detail}")
        if after.outcome == "fail":
            print("    NOTE: pSQL() is a correct, idiomatic escape here. The community")
            print("    ruleset's pattern rule has no sanitiser entry for it, so a secure")
            print("    fix still trips the literal string-concatenation pattern. This is")
            print("    a real SAST limitation, not a defect in the patch or the gate --")
            print("    and it is exactly the gap 'rescan_clean' exists to catch, whichever")
            print("    side of it turns out to be wrong.")

        print("\n[3] diff_in_scope + cheating_detector, on the real diff")
        scope = ds_mod.analyse_scope(diff, finding_path=REL_PATH)
        cheats = ch_mod.detect_cheating(diff, finding_path=REL_PATH)
        print(f"    scope violations: {scope.violations or 'none'}")
        print(f"    cheat signals: {cheats or 'none'}")

        print("\n[4] tests_green")
        suite = tv_mod.detect_suite(str(TARGET))
        print(f"    detected suite: {suite}")
        tests = TestsValidation(
            result="NO_SUITE", detail="no test runner detected in razorpay-prestashop"
        )

        bundle = ProofBundle(
            finding_id=FINDING_ID,
            funnel="partial_proof",
            validators=[
                after,
                ValidatorResult(
                    "diff_in_scope", "pass" if not scope.violations else "fail",
                    "; ".join(scope.violations) or "clean",
                ),
                ValidatorResult(
                    "cheating_detector", "pass" if not cheats else "fail", str(cheats)
                ),
            ],
            tests=tests,
            poc="NO_POC",
            reviewer_approved=None,
        )
        print("\n" + "=" * 70)
        print("PROOF BUNDLE")
        for v in bundle.all_validators:
            print(f"  {v.name:<20} {v.outcome:<12} {v.detail[:80]}")
        print(f"\n  grade:       {bundle.grade()}")
        print(f"  blocking:    {[v.name for v in bundle.blocking]}")
        print(f"  may_open_pr: {bundle.may_open_pr}")
        print("\nThe harness declines to draft a PR here -- correctly. A secure fix")
        print("that the scanner cannot confirm, on a target with no test suite, is")
        print("exactly the 'partial_proof, never blended with full_proof' case D4/D17")
        print("exist for: a ticket and a private annex to maintainers, not a PR.")
    finally:
        target_file.write_text(original)
        subprocess.run(["git", "checkout", "--", REL_PATH], cwd=TARGET)
        print("\n(patch reverted; nothing committed or pushed)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
