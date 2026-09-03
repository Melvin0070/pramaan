"""The disclosure gate (D17). This module is the policy, not a description of it.

`docs/disclosure-policy.md` explains *why* Pramaan does not publish `file:line`
for an unfixed defect in a live payment plugin. This module is what makes the
leak structurally difficult rather than merely discouraged, and it does it in
three layers so that no single mistake is enough:

  1. **Classification.** `classify()` grants full disclosure only when a
     finding's funnel is `full_proof` *and* its repository is on the
     synthetic-target allowlist. Everything else is aggregate. An unknown
     funnel, an unknown repository, a contradictory pair of bundles: all
     aggregate. Fail closed (ground rule 7).

  2. **A withheld-token ledger.** `build_ledger()` derives, for every
     aggregate-only finding, the strings that must never reach the page — the
     path, its encodings, its basename, and the distinctive lines of its
     snippet. `finding_id` is covered for free, because the path is a substring
     of it; that is not an accident, it is the reason the check is a substring
     scan over the finished document rather than a review of each renderer.

  3. **A final scan.** `assert_clean()` runs over the *rendered string* and
     raises. `trust_report.render()` calls it on its own output before
     returning, so a leaked path is a crashed build rather than a published
     page. A chart label, a tooltip, an SVG `<title>`, a `data-` attribute and
     an HTML comment are all just substrings of that string, which is exactly
     why the check lives at that level.

Two details worth stating plainly:

**The violation report never contains the leaked string.** CI logs on a public
repository are themselves a publication channel, so `Leak` carries a SHA-256
prefix of the offending token and its kind, never the token. `token_hash()` is
exported so a developer can hash a candidate path locally and match it.

**A basename collision between a publishable target and a withheld one is a
refusal, not a carve-out.** If a Juice Shop file ever shared a basename with a
withheld Razorpay file, the render fails. That is the correct direction to fail
in, and it has not happened: the withheld basenames are PHP and Twig files from
payment plugins.
"""

from __future__ import annotations

import hashlib
import html
import posixpath
import re
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import quote

from pramaan.schemas import Finding, FunnelKind, ProofBundle

__all__ = [
    "MIN_TOKEN_LEN",
    "REDACTED",
    "SECRET_PATTERNS",
    "SYNTHETIC_TARGET_ALLOWLIST",
    "DisclosureLevel",
    "DisclosureViolation",
    "Disclosure",
    "Leak",
    "RedactionLedger",
    "assert_clean",
    "build_ledger",
    "classify",
    "find_secrets",
    "is_synthetic_target",
    "normalise_repo",
    "path_tokens",
    "scan",
    "scrub_secrets",
    "token_hash",
]

DisclosureLevel = Literal["full", "aggregate"]

REDACTED = "[redacted — D17]"

# Short tokens are not evidence of anything and produce false positives against
# ordinary prose. Every real corpus path and basename is far longer than this.
MIN_TOKEN_LEN = 6

# Exact, normalised repository names whose findings may carry full evidence.
#
# Membership is exact rather than substring: `is_synthetic_target` must not be
# talked into publishing `razorpay-juice-shop-mirror` because the word
# "juice-shop" appears in it. Everything that is not literally one of these
# strings after normalisation is a real target.
SYNTHETIC_TARGET_ALLOWLIST: frozenset[str] = frozenset(
    {
        # OWASP Juice Shop — deliberately vulnerable, run only in a local container.
        "juice-shop",
        "owasp-juice-shop",
        "bkimminich/juice-shop",
        "juice-shop/juice-shop",
        "owasp/juice-shop",
        # OWASP Benchmark v1.2 — a synthetic labelled corpus whose purpose is
        # measurement. It exists to be scanned and scored.
        "benchmark",
        "benchmarkjava",
        "owasp-benchmark",
        "owasp-benchmark-1.2",
        "owasp-benchmark-v1.2",
        "owasp/benchmark",
        "owasp-benchmark-java",
    }
)

# Token shapes that must never reach a report artifact, whatever else happens.
# The disclosure policy's third enforcement bullet: "no token is ever written to
# a report artifact."
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}")),
    ("github_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{32,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer_header", re.compile(r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{24,}={0,2}")),
)


class DisclosureViolation(Exception):
    """The rendered document contains something D17 withholds.

    Raised by `assert_clean`, and therefore by `trust_report.render`. It is not
    recoverable by design: there is no code path that publishes the document
    anyway with a warning.
    """


def token_hash(token: str) -> str:
    """Stable short hash of a withheld token.

    Exists so a violation can be reported without restating the secret it is
    about. To find what leaked, hash the candidate locally and compare.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

def normalise_repo(repo: str | None) -> str:
    """Canonical form for allowlist comparison.

    Deliberately conservative: it lowercases, trims, drops a URL prefix and a
    trailing `.git`, and stops. It does **not** strip an owner segment, because
    doing so would let `attacker/juice-shop` inherit the allowlist entry for the
    real one.
    """
    if not repo:
        return ""
    value = repo.strip().lower()
    for prefix in ("https://github.com/", "http://github.com/", "git@github.com:"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    if value.endswith(".git"):
        value = value[: -len(".git")]
    return value.strip("/")


def is_synthetic_target(
    repo: str | None, allowlist: Collection[str] = SYNTHETIC_TARGET_ALLOWLIST
) -> bool:
    """Is this repository one that exists to be exploited?

    Empty, missing or unrecognised repositories are not. There is no partial
    match and no default-allow.
    """
    normalised = normalise_repo(repo)
    if not normalised:
        return False
    return normalised in {normalise_repo(entry) for entry in allowlist}


@dataclass(frozen=True, slots=True)
class Disclosure:
    """What may be published about one finding, and on what grounds."""

    finding_id: str
    fingerprint: str
    repo: str
    funnel: FunnelKind | None
    level: DisclosureLevel
    reason: str

    @property
    def is_full(self) -> bool:
        return self.level == "full"

    def to_dict(self) -> dict[str, Any]:
        return {
            # `finding_id` embeds the path, so it is deliberately absent from the
            # serialised form: this dict is safe to write into a public artifact.
            "fingerprint": self.fingerprint,
            "repo": self.repo,
            "funnel": self.funnel,
            "level": self.level,
            "reason": self.reason,
        }


def classify(
    finding: Finding,
    *,
    funnel: FunnelKind | None,
    allowlist: Collection[str] = SYNTHETIC_TARGET_ALLOWLIST,
) -> Disclosure:
    """The gate, in one place.

    Full disclosure requires **both** conditions. The two are checked
    independently and both reasons are reported, because "it was on the
    allowlist" and "it had a PoC" are different claims and a reader deserves to
    know which one was missing.
    """
    synthetic = is_synthetic_target(finding.repo, allowlist)
    proven = funnel == "full_proof"

    if synthetic and proven:
        reason = (
            f"{finding.repo} is a synthetic target that exists to be exploited, "
            "and the fix carries a full-proof bundle with a PoC"
        )
        level: DisclosureLevel = "full"
    else:
        missing: list[str] = []
        if not synthetic:
            missing.append(
                "repository is not on the synthetic-target allowlist"
                if finding.repo
                else "repository could not be determined"
            )
        if not proven:
            missing.append(
                "no full-proof funnel"
                if funnel is not None
                else "funnel could not be determined; treated as unfixed"
            )
        reason = "aggregate only (D17): " + "; ".join(missing)
        level = "aggregate"

    return Disclosure(
        finding_id=finding.finding_id,
        fingerprint=finding.fingerprint,
        repo=finding.repo,
        funnel=funnel,
        level=level,
        reason=reason,
    )


# --------------------------------------------------------------------------- #
# The withheld-token ledger
# --------------------------------------------------------------------------- #

def path_tokens(path: str, *, include_basenames: bool = True) -> frozenset[str]:
    """Every spelling of `path` that would count as a disclosure.

    The renderer escapes what it emits, template engines percent-encode, JSON
    escapes forward slashes and someone will eventually print a Windows-style
    path. Each of those is the same disclosure wearing a different coat, so all
    of them are tokens.
    """
    if not path or not path.strip():
        return frozenset()
    raw = path.strip()
    stripped = raw.lstrip("./").lstrip("/")

    candidates: set[str] = set()
    for value in (raw, stripped):
        if not value:
            continue
        candidates.update(
            {
                value,
                value.replace("/", "\\"),
                value.replace("/", "\\/"),      # JSON-escaped
                value.replace("/", "&#47;"),    # numeric entity
                value.replace("/", "&#x2F;"),
                html.escape(value, quote=True),
                quote(value, safe=""),          # percent-encoded
            }
        )
        if include_basenames:
            base = posixpath.basename(value)
            if base:
                candidates.add(base)
                candidates.add(html.escape(base, quote=True))

    return frozenset(t.lower() for t in candidates if len(t) >= MIN_TOKEN_LEN)


def _snippet_tokens(snippet: str | None, *, max_lines: int = 5) -> frozenset[str]:
    """Distinctive lines of a withheld code snippet.

    Whole-snippet matching is useless once the renderer reflows or escapes it,
    and single tokens like `echo` match everything. A stripped source line of
    real length is the unit that is both distinctive and likely to survive
    accidental rendering intact.
    """
    if not snippet:
        return frozenset()
    out: set[str] = set()
    for line in snippet.splitlines():
        value = line.strip()
        if len(value) < 32:
            continue
        out.add(value.lower())
        out.add(html.escape(value, quote=True).lower())
        if len(out) >= max_lines * 2:
            break
    return frozenset(out)


@dataclass(frozen=True, slots=True)
class Leak:
    """One withheld token found in a rendered document.

    Carries a hash, never the token. See the module docstring.
    """

    kind: Literal["path", "snippet", "secret"]
    token_hash: str
    token_len: int
    fingerprint: str = ""
    detail: str = ""

    def render(self) -> str:
        who = f" (finding fingerprint {self.fingerprint})" if self.fingerprint else ""
        extra = f" — {self.detail}" if self.detail else ""
        return (
            f"{self.kind} token sha256:{self.token_hash} "
            f"(len {self.token_len}){who}{extra}"
        )


@dataclass(frozen=True)
class RedactionLedger:
    """Which findings may be published in full, and what must never appear.

    Not slotted: `_lookup` is a derived index built in `__post_init__`, and the
    class is frozen, so the cache is installed with `object.__setattr__`.
    """

    disclosures: tuple[Disclosure, ...]
    withheld_paths: frozenset[str] = frozenset()
    withheld_snippets: frozenset[str] = frozenset()
    include_basenames: bool = True
    notes: tuple[str, ...] = ()
    _by_id: dict[str, Disclosure] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "_by_id", {d.finding_id: d for d in self.disclosures}
        )

    # -- queries ----------------------------------------------------------- #

    def level(self, finding_id: str) -> DisclosureLevel:
        """Fail closed: a finding this ledger has never seen is aggregate-only."""
        entry = self._by_id.get(finding_id)
        return entry.level if entry is not None else "aggregate"

    def may_publish_evidence(self, finding_id: str) -> bool:
        return self.level(finding_id) == "full"

    def disclosure(self, finding_id: str) -> Disclosure | None:
        return self._by_id.get(finding_id)

    @property
    def full_disclosures(self) -> tuple[Disclosure, ...]:
        return tuple(d for d in self.disclosures if d.is_full)

    @property
    def withheld(self) -> tuple[Disclosure, ...]:
        return tuple(d for d in self.disclosures if not d.is_full)

    @property
    def n_full(self) -> int:
        return len(self.full_disclosures)

    @property
    def n_withheld(self) -> int:
        return len(self.withheld)

    def reasons(self) -> dict[str, int]:
        """Withholding reasons and their counts, for the report's own ledger."""
        counts: dict[str, int] = {}
        for d in self.withheld:
            counts[d.reason] = counts.get(d.reason, 0) + 1
        return dict(sorted(counts.items()))

    def withheld_repos(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.withheld:
            key = d.repo or "(repository unknown)"
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    # -- enforcement -------------------------------------------------------- #

    def scrub(self, text: str) -> str:
        """Replace any withheld token in free text with a marker.

        Applied to strings that pass through the renderer from elsewhere — a
        validator `detail`, a metric `note`, an eval caveat — where the content
        is not under this lane's control. Structured sections do not need it,
        because they never read a withheld field in the first place; this is the
        second layer, and `assert_clean` is the third.
        """
        if not text:
            return text
        out = scrub_secrets(text)
        lowered = out.lower()
        for token in sorted(
            self.withheld_paths | self.withheld_snippets, key=len, reverse=True
        ):
            start = lowered.find(token)
            while start != -1:
                out = out[:start] + REDACTED + out[start + len(token):]
                lowered = out.lower()
                start = lowered.find(token)
        return out

    def to_dict(self) -> dict[str, Any]:
        """Publication-safe summary. Contains no withheld token, by construction."""
        return {
            "n_findings": len(self.disclosures),
            "n_full_disclosure": self.n_full,
            "n_aggregate_only": self.n_withheld,
            "withholding_reasons": self.reasons(),
            "withheld_by_repo": self.withheld_repos(),
            "n_withheld_tokens": len(self.withheld_paths),
            "n_withheld_snippet_lines": len(self.withheld_snippets),
            "include_basenames": self.include_basenames,
            "notes": list(self.notes),
        }


def _funnel_index(
    bundles: Iterable[ProofBundle],
) -> tuple[dict[str, FunnelKind | None], list[str]]:
    """finding_id -> funnel, with contradictions collapsed to unknown.

    Two bundles disagreeing about a finding's funnel is exactly the state D4
    forbids, and resolving it by picking one would be inventing evidence. It
    becomes `None`, which the gate reads as unfixed.
    """
    index: dict[str, FunnelKind | None] = {}
    conflicts: list[str] = []
    for bundle in bundles:
        existing = index.get(bundle.finding_id, ...)
        if existing is ...:
            index[bundle.finding_id] = bundle.funnel
        elif existing != bundle.funnel:
            index[bundle.finding_id] = None
            conflicts.append(bundle.finding_id)
    return index, conflicts


def build_ledger(
    findings: Iterable[Finding],
    *,
    bundles: Iterable[ProofBundle] = (),
    funnels: Mapping[str, FunnelKind | None] | None = None,
    allowlist: Collection[str] = SYNTHETIC_TARGET_ALLOWLIST,
    include_basenames: bool = True,
) -> RedactionLedger:
    """Classify every finding and collect what must never be rendered.

    Args:
        bundles: proof bundles, read only for their `finding_id` and `funnel`.
        funnels: an explicit override map, for callers that have funnel labels
            without bundles. A finding present in neither is unknown, which the
            gate treats as unfixed.
    """
    index, conflicts = _funnel_index(bundles)
    if funnels:
        index.update(funnels)

    rows: list[tuple[Finding, Disclosure]] = [
        (
            finding,
            classify(
                finding, funnel=index.get(finding.finding_id), allowlist=allowlist
            ),
        )
        for finding in findings
    ]

    paths: set[str] = set()
    snippets: set[str] = set()
    for finding, disclosure in rows:
        if disclosure.is_full:
            continue
        paths |= path_tokens(finding.path, include_basenames=include_basenames)
        snippets |= _snippet_tokens(finding.snippet)

    notes: list[str] = []
    if conflicts:
        notes.append(
            f"{len(conflicts)} findings carried proof bundles labelled with "
            "different funnels; each was treated as unfixed (D4 forbids "
            "blending them, and picking one would be inventing evidence)"
        )

    # A publishable path that collides with a withheld one — same basename, say —
    # would trip the final scan and fail the whole render. Downgrade the
    # publishable finding instead: losing one Juice Shop evidence block is the
    # cheap side of that trade, and silently publishing is not on the menu.
    disclosures: list[Disclosure] = []
    downgraded = 0
    for finding, disclosure in rows:
        if disclosure.is_full and (
            path_tokens(finding.path, include_basenames=include_basenames) & paths
        ):
            downgraded += 1
            disclosure = Disclosure(
                finding_id=disclosure.finding_id,
                fingerprint=disclosure.fingerprint,
                repo=disclosure.repo,
                funnel=disclosure.funnel,
                level="aggregate",
                reason=(
                    "aggregate only (D17): this publishable path collides with a "
                    "withheld one, so publishing it would disclose the withheld "
                    "finding by proxy"
                ),
            )
        disclosures.append(disclosure)
    if downgraded:
        notes.append(
            f"{downgraded} otherwise-publishable findings were downgraded to "
            "aggregate because their path collided with a withheld one"
        )

    return RedactionLedger(
        disclosures=tuple(disclosures),
        withheld_paths=frozenset(paths),
        withheld_snippets=frozenset(snippets),
        include_basenames=include_basenames,
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #

def find_secrets(text: str) -> list[tuple[str, str]]:
    """(pattern name, matched text) for every credential-shaped string."""
    hits: list[tuple[str, str]] = []
    for name, pattern in SECRET_PATTERNS:
        hits.extend((name, m.group(0)) for m in pattern.finditer(text))
    return hits


def scrub_secrets(text: str) -> str:
    out = text
    for _name, pattern in SECRET_PATTERNS:
        out = pattern.sub(REDACTED, out)
    return out


# --------------------------------------------------------------------------- #
# The final scan
# --------------------------------------------------------------------------- #

def scan(document: str, ledger: RedactionLedger) -> list[Leak]:
    """Every withheld token present in the rendered document.

    A substring scan over the finished string, on purpose. Chart labels,
    tooltips, hidden attributes, SVG `<title>` elements, HTML comments and
    JSON blobs are all substrings of it; enumerating the places a path could
    hide would be a list that goes stale, and this does not.
    """
    hay = document.lower()
    leaks: list[Leak] = []
    for token in sorted(ledger.withheld_paths):
        if token in hay:
            leaks.append(
                Leak(
                    kind="path",
                    token_hash=token_hash(token),
                    token_len=len(token),
                    detail="a withheld finding's path (or an encoding of it) "
                    "reached the rendered document",
                )
            )
    for token in sorted(ledger.withheld_snippets):
        if token in hay:
            leaks.append(
                Leak(
                    kind="snippet",
                    token_hash=token_hash(token),
                    token_len=len(token),
                    detail="a line of a withheld finding's code snippet reached "
                    "the rendered document",
                )
            )
    for name, match in find_secrets(document):
        leaks.append(
            Leak(
                kind="secret",
                token_hash=token_hash(match),
                token_len=len(match),
                detail=f"credential-shaped string matching {name}",
            )
        )
    return leaks


def assert_clean(document: str, ledger: RedactionLedger) -> None:
    """Raise `DisclosureViolation` if the document discloses anything withheld.

    Called by `trust_report.render` on its own output. The report cannot be
    produced without passing this, which is what makes the policy enforced
    rather than intended.
    """
    leaks = scan(document, ledger)
    if not leaks:
        return
    kinds = sorted({leak.kind for leak in leaks})
    detail = "\n  ".join(leak.render() for leak in leaks[:20])
    more = "" if len(leaks) <= 20 else f"\n  ... and {len(leaks) - 20} more"
    raise DisclosureViolation(
        f"D17 disclosure gate: {len(leaks)} withheld token(s) of kind {kinds} "
        f"reached the rendered document. Tokens are reported as hashes because "
        f"a CI log is a publication channel too; use "
        f"pramaan.report.redaction.token_hash() to identify them locally."
        f"\n  {detail}{more}"
    )
