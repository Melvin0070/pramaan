"""Deterministic, glob-driven business-impact tagging (binding decision D9).

This module is the half of the sensitivity signal that a prompt injection cannot
touch. The model's `business_impact` observations are unioned *on top of* what
these globs say; the union is monotonic, so the model can add a tag and can never
clear one. See `pramaan.policy.engine.effective_tags`.

Matching is deliberately **case-insensitive** and errs towards over-tagging. The
two error directions are not symmetric: an over-tagged file is escalated to a
human, an under-tagged file may be auto-closed or auto-fixed. Only the second is
a security failure.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pramaan.schemas import BusinessImpact

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "KNOWN_TAGS",
    "PathRule",
    "SensitivePathConfigError",
    "default_rules",
    "explain",
    "load_rules",
    "normalise_path",
    "tag",
]

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "sensitive_paths.yaml"

# Derived from the frozen schema rather than restated, so that a new field on
# BusinessImpact fails config validation loudly instead of being silently ignored.
KNOWN_TAGS: frozenset[str] = frozenset(BusinessImpact.__dataclass_fields__)


class SensitivePathConfigError(ValueError):
    """The rule file is malformed. Never degrade to an empty ruleset: a ruleset
    that tags nothing makes every finding look non-sensitive."""


# --------------------------------------------------------------------------- #
# Glob -> regex
# --------------------------------------------------------------------------- #

def _translate(glob: str) -> str:
    """Translate one glob to a regex source string.

    Hand-rolled rather than `fnmatch` because `fnmatch`'s `*` crosses `/`, which
    would make `includes/api/*.php` match `includes/api/v2/order.php` and make
    `**` meaningless. `PurePath.full_match` would do, but it only landed in 3.13
    and this project targets 3.12.
    """
    out: list[str] = []
    i, n = 0, len(glob)
    while i < n:
        c = glob[i]
        if c == "*":
            j = i
            while j < n and glob[j] == "*":
                j += 1
            if j - i >= 2:  # '**'
                if glob[j : j + 1] == "/":
                    out.append("(?:[^/]+/)*")  # zero or more whole path segments
                    i = j + 1
                else:
                    out.append(".*")
                    i = j
            else:
                out.append("[^/]*")
                i = j
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = i + 1
            if j < n and glob[j] in "!^":
                j += 1
            if j < n and glob[j] == "]":
                j += 1
            while j < n and glob[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape("["))  # unterminated class is a literal bracket
                i += 1
            else:
                body = glob[i + 1 : j].replace("\\", "\\\\")
                if body[:1] in ("!", "^"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _compile(glob: str) -> re.Pattern[str]:
    return re.compile(_translate(glob), re.IGNORECASE)


_DUP_SLASH = re.compile(r"/{2,}")


def normalise_path(path: str) -> str:
    """Canonicalise a scanner-reported path before matching.

    Semgrep SARIF, Semgrep JSON and DefectDojo all disagree about leading `./`,
    leading `/` and (on Windows runners) separator direction.
    """
    p = path.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = _DUP_SLASH.sub("/", p).lstrip("/")
    return p


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class PathRule:
    name: str
    tags: tuple[str, ...]
    globs: tuple[str, ...]
    intent: str = ""
    patterns: tuple[re.Pattern[str], ...] = ()

    @classmethod
    def build(
        cls, name: str, tags: Iterable[str], globs: Iterable[str], intent: str = ""
    ) -> PathRule:
        tag_tuple = tuple(tags)
        glob_tuple = tuple(globs)
        if not name:
            raise SensitivePathConfigError("rule is missing a name")
        if not tag_tuple:
            raise SensitivePathConfigError(f"rule {name!r} sets no tags")
        if not glob_tuple:
            raise SensitivePathConfigError(f"rule {name!r} has no globs")
        unknown = sorted(set(tag_tuple) - KNOWN_TAGS)
        if unknown:
            # A typo'd tag name that quietly tags nothing is exactly the silent
            # failure D9 exists to prevent.
            raise SensitivePathConfigError(
                f"rule {name!r} sets unknown tag(s) {unknown}; "
                f"known tags are {sorted(KNOWN_TAGS)}"
            )
        return cls(
            name=name,
            tags=tag_tuple,
            globs=glob_tuple,
            intent=intent,
            patterns=tuple(_compile(g) for g in glob_tuple),
        )

    def matches(self, normalised: str) -> bool:
        return any(p.fullmatch(normalised) for p in self.patterns)

    def impact(self) -> BusinessImpact:
        return BusinessImpact(**{t: True for t in self.tags})


def load_rules(config_path: Path | str | None = None) -> tuple[PathRule, ...]:
    """Read and validate the rule file. This is the only I/O in the policy lane."""
    path = Path(config_path) if config_path is not None else DEFAULT_CONFIG_PATH
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SensitivePathConfigError(f"rule file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise SensitivePathConfigError(f"rule file is not valid YAML: {path}") from exc
    return parse_rules(raw, source=str(path))


def parse_rules(raw: Any, source: str = "<memory>") -> tuple[PathRule, ...]:
    """Validate an already-loaded rule document. Pure; the unit tests use this."""
    if not isinstance(raw, dict):
        raise SensitivePathConfigError(f"{source}: top level must be a mapping")
    rules = raw.get("rules")
    if not isinstance(rules, list) or not rules:
        raise SensitivePathConfigError(f"{source}: 'rules' must be a non-empty list")
    built: list[PathRule] = []
    seen: set[str] = set()
    for idx, entry in enumerate(rules):
        if not isinstance(entry, dict):
            raise SensitivePathConfigError(f"{source}: rules[{idx}] is not a mapping")
        name = str(entry.get("name", "")).strip()
        if name in seen:
            raise SensitivePathConfigError(f"{source}: duplicate rule name {name!r}")
        seen.add(name)
        built.append(
            PathRule.build(
                name=name,
                tags=entry.get("tags") or (),
                globs=entry.get("globs") or (),
                intent=str(entry.get("intent", "")).strip(),
            )
        )
    return tuple(built)


_DEFAULT_RULES: tuple[PathRule, ...] | None = None


def default_rules() -> tuple[PathRule, ...]:
    """Process-lifetime cache of the shipped ruleset.

    Cached so that `tag()` stays cheap in a loop over thousands of findings and
    so that the file is read once per process rather than once per finding.
    """
    global _DEFAULT_RULES
    if _DEFAULT_RULES is None:
        _DEFAULT_RULES = load_rules()
    return _DEFAULT_RULES


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def explain(path: str, rules: Sequence[PathRule] | None = None) -> tuple[PathRule, ...]:
    """Which rules fired, in file order. Used by the report to justify an escalation."""
    if not path or not path.strip():
        raise ValueError("sensitive_paths: empty path")
    normalised = normalise_path(path)
    if not normalised:
        raise ValueError(f"sensitive_paths: path normalises to nothing: {path!r}")
    candidates = default_rules() if rules is None else rules
    return tuple(r for r in candidates if r.matches(normalised))


def tag(path: str, rules: Sequence[PathRule] | None = None) -> BusinessImpact:
    """Deterministic business-impact tags for one scanner-reported path.

    Raises on an empty path rather than returning an all-false impact: "we have
    no path" is an unknown state, and an unknown state that reads as
    `any_sensitive=False` is auto-closeable (ground rule 7, fail closed).
    """
    impact = BusinessImpact()
    for rule in explain(path, rules):
        impact = impact.union(rule.impact())
    return impact
