"""Lane D — context assembly and the `context_config` string the cache keys on."""

from __future__ import annotations

import pytest

from pramaan.agent.context import (
    ABLATION_CONFIGS,
    DEFAULT_CONTEXT_CONFIG,
    CallerSite,
    ContextConfig,
    ContextError,
    build_context,
    enclosing_symbol,
    read_source,
    split_source,
)

PHP = "\n".join(
    [
        "<?php",                                    # 1
        "class OrderController {",                  # 2
        "    function build_query($id) {",          # 3
        "        global $wpdb;",                    # 4
        "        $sql = \"SELECT * FROM o WHERE id = $id\";",  # 5
        "        return $wpdb->get_results($sql);", # 6
        "    }",                                    # 7
        "}",                                        # 8
    ]
)


class StubLookup:
    def __init__(self, sites: list[CallerSite]) -> None:
        self.sites = sites
        self.calls: list[tuple[str, str]] = []

    def find_callers(self, symbol: str, exclude_path: str) -> list[CallerSite]:
        self.calls.append((symbol, exclude_path))
        return self.sites


# --- ContextConfig: the cache key ------------------------------------------


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (ContextConfig(window=0), "w0"),
        (ContextConfig(window=50), "w50"),
        (ContextConfig(window=100, callers=True), "w100+callers"),
    ],
)
def test_context_config_renders_canonically(config: ContextConfig, expected: str) -> None:
    assert str(config) == expected
    assert config.name == expected


@pytest.mark.parametrize("config", ABLATION_CONFIGS)
def test_context_config_round_trips(config: ContextConfig) -> None:
    """Lane F caches on this exact string. If parse/str ever disagree the cache
    silently splits one population into two."""
    assert ContextConfig.parse(str(config)) == config


@pytest.mark.parametrize("bad", ["", "50", "w", "w50+callers+extra", "W50", "w-1", "wide"])
def test_context_config_rejects_unknown_strings(bad: str) -> None:
    with pytest.raises(ContextError):
        ContextConfig.parse(bad)


def test_ablation_grid_names_are_unique() -> None:
    names = [str(c) for c in ABLATION_CONFIGS]
    assert len(names) == len(set(names))


def test_negative_window_rejected() -> None:
    with pytest.raises(ContextError):
        ContextConfig(window=-1)


# --- windowing --------------------------------------------------------------


def test_window_zero_returns_only_the_finding_lines() -> None:
    ctx = build_context(
        finding_id="f1", path="a.php", line_start=5, line_end=5,
        source=PHP, config=ContextConfig(window=0),
    )
    assert [n for n, _ in ctx.lines] == [5]
    assert ctx.context_config == "w0"


def test_window_expands_symmetrically_and_clamps_to_file() -> None:
    ctx = build_context(
        finding_id="f1", path="a.php", line_start=5, line_end=5,
        source=PHP, config=ContextConfig(window=2),
    )
    assert [n for n, _ in ctx.lines] == [3, 4, 5, 6, 7]

    wide = build_context(
        finding_id="f1", path="a.php", line_start=5, line_end=5,
        source=PHP, config=ContextConfig(window=500),
    )
    assert [n for n, _ in wide.lines] == list(range(1, 9))
    assert wide.total_lines == 8


def test_line_end_below_line_start_is_treated_as_single_line() -> None:
    ctx = build_context(
        finding_id="f1", path="a.php", line_start=5, line_end=0,
        source=PHP, config=ContextConfig(window=0),
    )
    assert ctx.line_end == 5


def test_out_of_range_and_empty_sources_fail_closed() -> None:
    with pytest.raises(ContextError):
        build_context(finding_id="f", path="a.php", line_start=99, line_end=99, source=PHP)
    with pytest.raises(ContextError):
        build_context(finding_id="f", path="a.php", line_start=1, line_end=1, source="")
    with pytest.raises(ContextError):
        build_context(finding_id="f", path="a.php", line_start=0, line_end=0, source=PHP)


def test_split_source_ignores_a_single_trailing_newline() -> None:
    assert split_source("a\nb\n") == ["a", "b"]
    assert split_source("a\nb") == ["a", "b"]
    assert split_source("") == []


# --- rendering --------------------------------------------------------------


def test_render_numbers_lines_and_marks_the_finding() -> None:
    ctx = build_context(
        finding_id="f1", path="a.php", line_start=5, line_end=5,
        source=PHP, config=ContextConfig(window=1),
    )
    rendered = ctx.render()
    assert ">5 | " in rendered
    assert " 4 | " in rendered
    assert "file: a.php" in rendered
    assert "context window: w1" in rendered
    assert "enclosing symbol: build_query" in rendered


def test_enclosing_symbol_scans_upward_for_php_and_python() -> None:
    assert enclosing_symbol(PHP.split("\n"), 6) == "build_query"
    assert enclosing_symbol(["x = 1", "y = 2"], 2) is None
    assert enclosing_symbol(["def handler(req):", "    q = req.a"], 2) == "handler"


# --- callers ----------------------------------------------------------------


def test_callers_config_without_lookup_fails_closed() -> None:
    """A `+callers` context with no callers in it would quietly turn the ablation
    into a comparison of two identical arms."""
    with pytest.raises(ContextError, match="requires callers"):
        build_context(
            finding_id="f1", path="a.php", line_start=5, line_end=5,
            source=PHP, config=ContextConfig(window=10, callers=True),
        )


def test_callers_are_looked_up_and_rendered() -> None:
    lookup = StubLookup([CallerSite(path="b.php", line=12, text="build_query($_GET['id'])")])
    ctx = build_context(
        finding_id="f1", path="a.php", line_start=5, line_end=5,
        source=PHP, config=ContextConfig(window=1, callers=True), lookup=lookup,
    )
    assert lookup.calls == [("build_query", "a.php")]
    assert ctx.callers[0].line == 12
    assert "b.php:12" in ctx.render()


def test_callers_render_states_when_none_were_found() -> None:
    ctx = build_context(
        finding_id="f1", path="a.php", line_start=5, line_end=5,
        source=PHP, config=ContextConfig(window=1, callers=True), lookup=StubLookup([]),
    )
    assert "none found" in ctx.render()


def test_no_lookup_needed_when_callers_disabled() -> None:
    ctx = build_context(
        finding_id="f1", path="a.php", line_start=5, line_end=5,
        source=PHP, config=DEFAULT_CONTEXT_CONFIG,
    )
    assert ctx.callers == ()
    assert ctx.context_config == "w50"


# --- the impure edge --------------------------------------------------------


def test_read_source_confines_paths_to_the_repository_root(tmp_path) -> None:
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "ok.php").write_text("<?php\n")
    (tmp_path / "outside.php").write_text("secret\n")

    assert read_source(tmp_path / "repo", "ok.php") == "<?php\n"
    with pytest.raises(ContextError, match="escapes repository root"):
        read_source(tmp_path / "repo", "../outside.php")
    with pytest.raises(ContextError, match="not a file"):
        read_source(tmp_path / "repo", "missing.php")
