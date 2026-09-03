"""DefectDojo backend for `FindingStore` — a week-2 STUB (binding decision D6).

Razorpay run a DefectDojo-derived vulnerability platform called Bhadra, so the
system of record this project would actually plug into is DefectDojo-shaped.
D6 makes that a week-2 adapter behind the same Protocol rather than a week-1
dependency: SQLite carries weeks 1-2, and swapping backends is a constructor
change.

**Bhadra-compatible naming.** DefectDojo's hierarchy is
product -> engagement -> test -> finding, and Bhadra's convention maps onto it as:

    product     = the repository            e.g. `razorpay-php`
    engagement  = the tool that produced it e.g. `pramaan_Semgrep_Scan`
    test        = one scan run of that tool against one commit
    finding     = one normalised `Finding`

Dedup rides on DefectDojo's own two identity fields, which is why
`pramaan.schemas.finding` computes both:

    hash_code            = `Finding.fingerprint`  (line-number-free, so an edit
                                                   above the defect does not
                                                   fork it into two findings)
    unique_id_from_tool  = `Finding.finding_id`   (stable within a commit;
                                                   what `reimport-scan` matches
                                                   on for PR idempotency)

**No HTTP lives here yet, by design.** Every Protocol method raises
`NotImplementedError`. What *is* implemented is the pure part — the naming
convention and the payload mapping — because that is the part worth reviewing
now and the part that has to be right before any request is ever sent. Writing
a half-working client that silently no-ops would be worse than a stub that
says so.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from pramaan.schemas import Finding

__all__ = [
    "DEFECTDOJO_SEVERITY",
    "DefectDojoAdapter",
    "engagement_name",
    "product_name",
    "scan_type_for",
    "to_defectdojo_finding",
]

_WEEK2 = (
    "DefectDojoAdapter is a week-2 stub (D6): no HTTP client is implemented. "
    "Use SqliteFindingStore as the system of record until the adapter lands."
)

# DefectDojo's severity vocabulary is title-cased and has no 'informational'.
DEFECTDOJO_SEVERITY: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

# DefectDojo parses an upload by `scan_type`; the wrong value parses the file
# into zero findings and reports success, so an unknown tool fails closed.
_SCAN_TYPES: dict[str, str] = {
    "semgrep": "Semgrep JSON Report",
    "trivy": "Trivy Scan",
    "checkov": "Checkov Scan",
    "govulncheck": "Govulncheck Scanner",
}


def product_name(repo: str) -> str:
    """Product = repository. `razorpay/razorpay-php` and a clone path both map
    to `razorpay-php`, so the same repo never opens two products."""
    cleaned = repo.strip().rstrip("/")
    if not cleaned:
        raise ValueError("repo must be non-empty")
    if cleaned.endswith(".git"):
        cleaned = cleaned[: -len(".git")]
    return cleaned.rsplit("/", 1)[-1]


def engagement_name(tool: str, prefix: str = "pramaan") -> str:
    """Engagement = tool, e.g. `pramaan_Semgrep_Scan`."""
    tokens = [t for t in "".join(c if c.isalnum() else " " for c in tool).split() if t]
    if not tokens:
        raise ValueError("tool must contain at least one alphanumeric character")
    return "_".join([prefix, *(t.capitalize() for t in tokens), "Scan"])


def scan_type_for(tool: str) -> str:
    key = tool.strip().lower()
    if key not in _SCAN_TYPES:
        raise ValueError(
            f"no DefectDojo scan_type mapped for tool {tool!r}; "
            f"known: {sorted(_SCAN_TYPES)}"
        )
    return _SCAN_TYPES[key]


def to_defectdojo_finding(finding: Finding) -> dict[str, Any]:
    """Map a `Finding` onto DefectDojo's finding payload. Pure; no request."""
    return {
        "title": f"{finding.rule_id}: {finding.message}"[:511],
        "description": finding.message,
        "severity": DEFECTDOJO_SEVERITY[finding.severity_reported],
        "file_path": finding.path,
        "line": finding.line_start,
        "cwe": _cwe_number(finding.cwe),
        "vuln_id_from_tool": finding.rule_id,
        "unique_id_from_tool": finding.finding_id,
        "hash_code": finding.fingerprint,
        "static_finding": True,
        "dynamic_finding": False,
        "active": True,
        "verified": False,  # a model verdict is not a DefectDojo verification
    }


def _cwe_number(cwe: str | None) -> int:
    """DefectDojo stores CWE as an int. `CWE-89` -> 89, anything unparseable -> 0."""
    if not cwe:
        return 0
    digits = "".join(c for c in cwe if c.isdigit())
    return int(digits) if digits else 0


class DefectDojoAdapter:
    """Same Protocol as `SqliteFindingStore`; every method is a week-2 stub."""

    def __init__(
        self,
        base_url: str,
        *,
        repo: str,
        tool: str = "semgrep",
        api_token: str | None = None,
        engagement_prefix: str = "pramaan",
    ):
        self.base_url = base_url.rstrip("/")
        self.repo = repo
        self.tool = tool
        # Held only so a caller can see whether credentials were supplied; never
        # logged, and there is nothing here that could transmit it yet.
        self._api_token = api_token
        self.engagement_prefix = engagement_prefix

    @property
    def product(self) -> str:
        return product_name(self.repo)

    @property
    def engagement(self) -> str:
        return engagement_name(self.tool, self.engagement_prefix)

    @property
    def scan_type(self) -> str:
        return scan_type_for(self.tool)

    def import_scan_payload(self, commit_sha: str | None = None) -> dict[str, Any]:
        """The `/import-scan/` form fields, minus the file. Pure; no request."""
        return {
            "product_name": self.product,
            "engagement_name": self.engagement,
            "scan_type": self.scan_type,
            "auto_create_context": True,
            "deduplication_on_engagement": True,
            "commit_hash": commit_sha,
        }

    # -- FindingStore (all unimplemented) ---------------------------------

    def upsert(self, finding: Finding) -> None:
        raise NotImplementedError(f"{_WEEK2} (upsert -> POST /reimport-scan/)")

    def upsert_many(self, findings: object) -> int:
        raise NotImplementedError(f"{_WEEK2} (upsert_many -> POST /import-scan/)")

    def get(self, finding_id: str) -> Finding | None:
        raise NotImplementedError(
            f"{_WEEK2} (get -> GET /findings/?unique_id_from_tool=...)"
        )

    def by_fingerprint(self, fingerprint: str) -> list[Finding]:
        raise NotImplementedError(f"{_WEEK2} (by_fingerprint -> GET /findings/?hash_code=...)")

    def all(self) -> Iterator[Finding]:
        raise NotImplementedError(f"{_WEEK2} (all -> paginated GET /findings/)")

    def count(self) -> int:
        raise NotImplementedError(f"{_WEEK2} (count -> GET /findings/?limit=1 .count)")

    def close(self) -> None:
        """No connection is held; present so callers can be uniform."""
