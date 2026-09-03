"""Code context assembly for one finding.

Lane F runs an ablation over how much context the triage agent gets, and the
verdict cache (D13) keys on `context_config` as an exact string. So the config is
a value object with one canonical rendering and a strict parser: if
`str(parse(s)) != s` for any `s` the cache silently splits into two populations
that look like one, and the ablation measures nothing. `parse` is therefore
round-trip tested and rejects anything it does not fully understand rather than
falling back to a default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence


class ContextError(Exception):
    """Context could not be assembled as the config specifies. Never downgrade
    this to a smaller context: a run labelled `w100+callers` that silently
    contains `w100` corrupts the ablation."""


_CONFIG_RE = re.compile(r"^w(?P<window>\d+)(?P<callers>\+callers)?$")


@dataclass(frozen=True, slots=True)
class ContextConfig:
    """`window` lines either side of the finding; `callers` pulls in call sites."""

    window: int = 50
    callers: bool = False

    def __post_init__(self) -> None:
        if self.window < 0:
            raise ContextError(f"window must be >= 0, got {self.window}")

    def __str__(self) -> str:
        return f"w{self.window}" + ("+callers" if self.callers else "")

    @property
    def name(self) -> str:
        return str(self)

    @classmethod
    def parse(cls, text: str) -> ContextConfig:
        m = _CONFIG_RE.match(text.strip())
        if m is None:
            raise ContextError(
                f"unparseable context_config {text!r}; expected e.g. 'w50' or 'w100+callers'"
            )
        return cls(window=int(m.group("window")), callers=bool(m.group("callers")))


# The ablation grid. Razorpay's own post quotes "50-100 lines of context", so the
# grid brackets that claim rather than assuming it.
ABLATION_CONFIGS: tuple[ContextConfig, ...] = (
    ContextConfig(window=0),
    ContextConfig(window=25),
    ContextConfig(window=50),
    ContextConfig(window=100),
    ContextConfig(window=50, callers=True),
    ContextConfig(window=100, callers=True),
)

DEFAULT_CONTEXT_CONFIG = ContextConfig(window=50)


@dataclass(frozen=True, slots=True)
class CallerSite:
    """One call site of the symbol enclosing the finding."""

    path: str
    line: int
    text: str


class CallerLookup(Protocol):
    """Supplied by the caller because finding call sites means walking the repo,
    and this module stays pure."""

    def find_callers(self, symbol: str, exclude_path: str) -> Sequence[CallerSite]: ...


@dataclass(frozen=True, slots=True)
class CodeContext:
    finding_id: str
    path: str
    context_config: str
    line_start: int
    line_end: int
    first_line: int
    last_line: int
    total_lines: int
    symbol: str | None
    lines: tuple[tuple[int, str], ...]
    callers: tuple[CallerSite, ...] = ()

    def render(self) -> str:
        """The text handed to the model. Line numbers are load-bearing: the
        model's `evidence[].line` values are checked against real file lines."""
        head = [
            f"file: {self.path}",
            f"finding lines: {self.line_start}-{self.line_end}"
            f" (file has {self.total_lines} lines)",
            f"context window: {self.context_config}",
        ]
        if self.symbol:
            head.append(f"enclosing symbol: {self.symbol}")
        head.append("")
        width = len(str(self.last_line)) if self.lines else 1
        for number, text in self.lines:
            marker = ">" if self.line_start <= number <= self.line_end else " "
            head.append(f"{marker}{str(number).rjust(width)} | {text}")
        if self.callers:
            head += ["", "call sites of the enclosing symbol:", ""]
            for c in self.callers:
                head.append(f"  {c.path}:{c.line} | {c.text}")
        elif "+callers" in self.context_config:
            head += ["", "call sites of the enclosing symbol: none found", ""]
        return "\n".join(head)


_PHP_SYMBOL = re.compile(r"\bfunction\s+&?(?P<name>[A-Za-z_]\w*)\s*\(")
_PY_SYMBOL = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\(")


def enclosing_symbol(lines: Sequence[str], line_start: int) -> str | None:
    """Nearest function declaration at or above `line_start` (1-based).

    A textual scan, not a parser: the ablation only needs a name good enough to
    grep for, and vendoring a PHP parser to get a slightly better one is not a
    trade this project should make.
    """
    index = min(max(line_start, 1), len(lines)) - 1
    for i in range(index, -1, -1):
        for pattern in (_PHP_SYMBOL, _PY_SYMBOL):
            m = pattern.search(lines[i])
            if m:
                return m.group("name")
    return None


def split_source(source: str) -> list[str]:
    """Line list without terminators. A trailing newline does not create a line."""
    text = source[:-1] if source.endswith("\n") else source
    return text.split("\n") if text else []


def build_context(
    *,
    finding_id: str,
    path: str,
    line_start: int,
    line_end: int,
    source: str,
    config: ContextConfig = DEFAULT_CONTEXT_CONFIG,
    lookup: CallerLookup | None = None,
) -> CodeContext:
    """Pure. `source` is the file's text; nothing here touches the filesystem.

    Raises `ContextError` when `config.callers` is set but no lookup is available,
    rather than returning a caller-free context wearing a `+callers` label.
    """
    lines = split_source(source)
    total = len(lines)
    if total == 0:
        raise ContextError(f"{path}: empty source, nothing to triage")
    if line_start < 1:
        raise ContextError(f"{path}: line_start must be >= 1, got {line_start}")
    if line_start > total:
        raise ContextError(
            f"{path}: line_start {line_start} is past end of file ({total} lines)"
        )

    end = max(line_end, line_start)
    end = min(end, total)
    first = max(1, line_start - config.window)
    last = min(total, end + config.window)

    symbol = enclosing_symbol(lines, line_start)

    callers: tuple[CallerSite, ...] = ()
    if config.callers:
        if lookup is None:
            raise ContextError(
                f"context_config {config} requires callers but no CallerLookup was "
                "supplied; refusing to emit a context mislabelled as +callers"
            )
        if symbol is not None:
            callers = tuple(lookup.find_callers(symbol, path))

    return CodeContext(
        finding_id=finding_id,
        path=path,
        context_config=str(config),
        line_start=line_start,
        line_end=end,
        first_line=first,
        last_line=last,
        total_lines=total,
        symbol=symbol,
        lines=tuple((n, lines[n - 1]) for n in range(first, last + 1)),
        callers=callers,
    )


def read_source(root: str | Path, path: str) -> str:
    """The impure edge. Confines the finding's path to `root` — a scanner report
    is attacker-influenced input, and `../../etc/passwd` is a valid string."""
    base = Path(root).resolve()
    target = (base / path).resolve()
    if not target.is_relative_to(base):
        raise ContextError(f"path escapes repository root: {path!r}")
    if not target.is_file():
        raise ContextError(f"not a file: {path!r}")
    return target.read_text(encoding="utf-8", errors="replace")
