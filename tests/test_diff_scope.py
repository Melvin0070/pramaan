"""Lane E — the unified-diff parser and the `diff_in_scope` validator."""

from __future__ import annotations

import pytest

from pramaan.validators.diff_scope import (
    DiffParseError,
    analyse_scope,
    is_dependency_manifest,
    is_test_path,
    normalise_path,
    parse_unified_diff,
    validate_diff_scope,
)

SIMPLE = """\
diff --git a/includes/order.php b/includes/order.php
index 1111111..2222222 100644
--- a/includes/order.php
+++ b/includes/order.php
@@ -10,7 +10,7 @@ class Order {
     public function render($id) {
-        echo "<a href='" . $_GET['back'] . "'>back</a>";
+        echo "<a href='" . esc_url($_GET['back']) . "'>back</a>";
     }
 }
"""

NEW_TEST = """\
diff --git a/tests/OrderTest.php b/tests/OrderTest.php
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/tests/OrderTest.php
@@ -0,0 +1,6 @@
+<?php
+class OrderTest extends TestCase {
+    public function testBackLinkIsEscaped() {
+        $this->assertSame('', (new Order)->render(1));
+    }
+}
"""


def test_parses_a_single_file_hunk():
    (fd,) = parse_unified_diff(SIMPLE)
    assert fd.path == "includes/order.php"
    assert fd.old_path == "includes/order.php"
    assert len(fd.added) == 1 and len(fd.removed) == 1
    assert fd.added[0].line_no == 11
    assert "esc_url" in fd.added[0].text
    assert fd.changed_lines == 2


def test_parses_new_deleted_rename_binary_and_mode():
    text = """\
diff --git a/a.php b/a.php
deleted file mode 100644
--- a/a.php
+++ /dev/null
@@ -1,2 +0,0 @@
-<?php
-echo 1;
diff --git a/old.php b/new.php
similarity index 90%
rename from old.php
rename to new.php
diff --git a/logo.png b/logo.png
index 111..222 100644
Binary files a/logo.png and b/logo.png differ
diff --git a/run.sh b/run.sh
old mode 100644
new mode 100755
"""
    deleted, renamed, binary, mode = parse_unified_diff(text)
    assert deleted.is_deleted and deleted.path == "a.php"
    assert renamed.is_rename and renamed.old_path == "old.php" and renamed.new_path == "new.php"
    assert binary.is_binary
    assert mode.mode_change == "new mode 100755"


def test_hunk_line_numbers_track_context():
    text = """\
diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -100,4 +200,5 @@
 keep
 keep
+inserted
 keep
"""
    (fd,) = parse_unified_diff(text)
    assert fd.added[0].line_no == 202


def test_malformed_hunk_header_raises():
    with pytest.raises(DiffParseError):
        parse_unified_diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ nonsense @@\n+hi\n")


def test_normalise_path_strips_prefixes_and_dev_null():
    assert normalise_path("a/includes/x.php") == "includes/x.php"
    assert normalise_path("./x.php") == "x.php"
    assert normalise_path("/dev/null") is None


@pytest.mark.parametrize(
    "path",
    [
        "tests/OrderTest.php",
        "test/foo.py",
        "src/__tests__/x.spec.ts",
        "pkg/thing_test.go",
        "test_ingest.py",
        "conftest.py",
    ],
)
def test_test_paths_are_recognised(path):
    assert is_test_path(path)


@pytest.mark.parametrize("path", ["includes/order.php", "src/testimonials.php"])
def test_non_test_paths_are_not(path):
    assert not is_test_path(path)


def test_dependency_manifests_are_recognised():
    assert is_dependency_manifest("composer.json")
    assert is_dependency_manifest("a/b/package-lock.json")
    assert not is_dependency_manifest("includes/package.php")


def test_in_scope_patch_passes():
    result = validate_diff_scope(SIMPLE + NEW_TEST, finding_path="includes/order.php")
    assert result.outcome == "pass"
    assert result.blocks_pr is False
    assert result.evidence["files_changed"] == 2


def test_unrelated_file_fails():
    unrelated = SIMPLE + """\
diff --git a/includes/settings.php b/includes/settings.php
--- a/includes/settings.php
+++ b/includes/settings.php
@@ -1,1 +1,2 @@
 <?php
+define('DEBUG', true);
"""
    result = validate_diff_scope(unrelated, finding_path="includes/order.php")
    assert result.outcome == "fail"
    assert "unrelated files" in result.detail
    assert "includes/settings.php" in result.evidence["unrelated"]


def test_dependency_addition_fails():
    with_dep = SIMPLE + """\
diff --git a/composer.json b/composer.json
--- a/composer.json
+++ b/composer.json
@@ -3,3 +3,4 @@
   "require": {
+    "ezyang/htmlpurifier": "^4.16",
     "php": ">=7.4"
"""
    result = validate_diff_scope(with_dep, finding_path="includes/order.php")
    assert result.outcome == "fail"
    assert "dependency manifest" in result.detail
    assert result.evidence["dependency_edits"] == ["composer.json"]


def test_vendored_code_fails():
    vendored = SIMPLE + """\
diff --git a/vendor/acme/lib/x.php b/vendor/acme/lib/x.php
--- a/vendor/acme/lib/x.php
+++ b/vendor/acme/lib/x.php
@@ -1,1 +1,2 @@
 <?php
+// patched upstream
"""
    result = validate_diff_scope(vendored, finding_path="includes/order.php")
    assert result.outcome == "fail"
    assert "vendored code" in result.detail


def test_empty_diff_fails_rather_than_trivially_passing():
    result = validate_diff_scope("", finding_path="includes/order.php")
    assert result.outcome == "fail"
    assert "empty diff" in result.detail


def test_diff_that_misses_the_findings_file_fails():
    result = validate_diff_scope(NEW_TEST, finding_path="includes/order.php")
    assert result.outcome == "fail"
    assert "does not touch the finding's file" in result.detail


def test_oversized_diff_fails():
    body = "".join(f"+line {i}\n" for i in range(60))
    big = (
        "diff --git a/includes/order.php b/includes/order.php\n"
        "--- a/includes/order.php\n+++ b/includes/order.php\n"
        f"@@ -1,1 +1,61 @@\n {body}"
    )
    result = validate_diff_scope(
        big, finding_path="includes/order.php", max_changed_lines=10
    )
    assert result.outcome == "fail"
    assert "lines changed, limit is 10" in result.detail


def test_too_many_files_fails():
    parts = []
    for i in range(4):
        parts.append(
            f"diff --git a/tests/t{i}_test.py b/tests/t{i}_test.py\n"
            f"--- a/tests/t{i}_test.py\n+++ b/tests/t{i}_test.py\n"
            "@@ -1,1 +1,2 @@\n x\n+y\n"
        )
    result = validate_diff_scope(
        SIMPLE + "".join(parts), finding_path="includes/order.php", max_files=3
    )
    assert result.outcome == "fail"
    assert "files changed, limit is 3" in result.detail


def test_missing_diff_is_unavailable_not_pass():
    result = validate_diff_scope(None, finding_path="includes/order.php")
    assert result.outcome == "unavailable"
    assert result.blocks_pr is True


def test_unparseable_diff_is_unavailable_not_pass():
    result = validate_diff_scope(
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ broken @@\n", finding_path="x"
    )
    assert result.outcome == "unavailable"


def test_extra_allowed_widens_scope_only_when_asked():
    diff = SIMPLE + """\
diff --git a/includes/helpers/escape.php b/includes/helpers/escape.php
--- a/includes/helpers/escape.php
+++ b/includes/helpers/escape.php
@@ -1,1 +1,2 @@
 <?php
+function esc_url($u) { return htmlspecialchars($u); }
"""
    assert validate_diff_scope(diff, finding_path="includes/order.php").outcome == "fail"
    widened = validate_diff_scope(
        diff, finding_path="includes/order.php", extra_allowed=("includes/helpers/*",)
    )
    assert widened.outcome == "pass"


def test_analyse_scope_reports_every_category():
    report = analyse_scope(SIMPLE + NEW_TEST, finding_path="includes/order.php")
    assert report.clean
    assert set(report.in_scope) == {"includes/order.php", "tests/OrderTest.php"}
    assert report.changed_lines == 8
