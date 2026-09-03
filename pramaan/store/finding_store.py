"""Persistence boundary for normalised scanner findings (binding decision D6).

Two concrete stores sit behind one Protocol:

  - `SqliteFindingStore` is the **system of record**. Everything downstream
    (triage, policy, proof, report) reads findings from here.
  - `JsonlFindingStore` backs the **frozen corpus file** — the 121 hand-labelled
    real PHP findings that D16 says must be reported separately and never
    blended. A plain-text, line-oriented file is what makes that corpus
    reviewable in a diff and citable in the write-up.

`DefectDojoAdapter` (see `defectdojo_adapter.py`) implements the same Protocol
so the week-2 swap is a constructor change, not a rewrite.

Fail-closed notes, since a store is a place where silent data loss hides:
  - a corrupt JSONL line raises, naming the line number. It is never skipped.
    A corpus that quietly shrinks by one row invalidates every count in the
    trust report and nothing would announce it.
  - findings are schema-validated on write by default, so a bad severity enum
    is caught at the boundary rather than at render time.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

import jsonschema

from pramaan.schemas import FINDING_SCHEMA, Finding

__all__ = [
    "FindingStore",
    "JsonlFindingStore",
    "SqliteFindingStore",
    "StoreError",
    "copy_findings",
]

_MEMORY = ":memory:"


class StoreError(Exception):
    """Raised when persisted state is unreadable, malformed or self-inconsistent."""


@runtime_checkable
class FindingStore(Protocol):
    """The contract every finding backend implements."""

    def upsert(self, finding: Finding) -> None: ...

    def get(self, finding_id: str) -> Finding | None: ...

    def by_fingerprint(self, fingerprint: str) -> list[Finding]: ...

    def all(self) -> Iterator[Finding]: ...

    def count(self) -> int: ...


def _validate(finding: Finding) -> dict[str, object]:
    payload = finding.to_dict()
    try:
        jsonschema.validate(payload, FINDING_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise StoreError(
            f"finding {finding.finding_id!r} fails FINDING_SCHEMA: {exc.message}"
        ) from exc
    return payload


def _dumps(payload: object) -> str:
    # sort_keys so the corpus file and the sqlite blobs are byte-stable across
    # runs; a corpus that reorders itself is a corpus nobody can diff-review.
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class SqliteFindingStore:
    """Default store. Durable, indexed by fingerprint, stable iteration order."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS findings (
        finding_id        TEXT PRIMARY KEY,
        fingerprint       TEXT NOT NULL,
        tool              TEXT NOT NULL,
        rule_id           TEXT NOT NULL,
        repo              TEXT NOT NULL,
        path              TEXT NOT NULL,
        line_start        INTEGER NOT NULL,
        severity_reported TEXT NOT NULL,
        seq               INTEGER NOT NULL,
        data              TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_findings_seq ON findings(seq);
    """

    def __init__(self, path: str | os.PathLike[str] = _MEMORY, *, validate: bool = True):
        self.path = str(path)
        self.validate = validate
        if self.path != _MEMORY:
            parent = Path(self.path).parent
            if str(parent):
                parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()

    # -- FindingStore -----------------------------------------------------

    def upsert(self, finding: Finding) -> None:
        self.upsert_many((finding,))

    def get(self, finding_id: str) -> Finding | None:
        row = self._conn.execute(
            "SELECT data FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return None if row is None else self._decode(row["data"], finding_id)

    def by_fingerprint(self, fingerprint: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT finding_id, data FROM findings WHERE fingerprint = ? ORDER BY seq",
            (fingerprint,),
        ).fetchall()
        return [self._decode(r["data"], r["finding_id"]) for r in rows]

    def all(self) -> Iterator[Finding]:
        # Materialise before yielding: callers legitimately upsert while walking
        # the corpus, and a live cursor would give them undefined behaviour.
        rows = self._conn.execute(
            "SELECT finding_id, data FROM findings ORDER BY seq"
        ).fetchall()
        return iter([self._decode(r["data"], r["finding_id"]) for r in rows])

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])

    # -- extras -----------------------------------------------------------

    def upsert_many(self, findings: Iterable[Finding]) -> int:
        n = 0
        with self._conn:
            for finding in findings:
                payload = _validate(finding) if self.validate else finding.to_dict()
                self._conn.execute(
                    """
                    INSERT INTO findings (
                        finding_id, fingerprint, tool, rule_id, repo, path,
                        line_start, severity_reported, seq, data
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?,
                        (SELECT IFNULL(MAX(seq), -1) + 1 FROM findings), ?
                    )
                    ON CONFLICT(finding_id) DO UPDATE SET
                        fingerprint       = excluded.fingerprint,
                        tool              = excluded.tool,
                        rule_id           = excluded.rule_id,
                        repo              = excluded.repo,
                        path              = excluded.path,
                        line_start        = excluded.line_start,
                        severity_reported = excluded.severity_reported,
                        data              = excluded.data
                    """,
                    (
                        finding.finding_id,
                        finding.fingerprint,
                        finding.tool,
                        finding.rule_id,
                        finding.repo,
                        finding.path,
                        finding.line_start,
                        finding.severity_reported,
                        _dumps(payload),
                    ),
                )
                n += 1
        return n

    def fingerprints(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT fingerprint, MIN(seq) AS s FROM findings GROUP BY fingerprint"
            " ORDER BY s"
        ).fetchall()
        return [r["fingerprint"] for r in rows]

    def export_jsonl(self, path: str | os.PathLike[str]) -> int:
        """Write the store out as the corpus file. Inverse of `JsonlFindingStore`."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with out.open("w", encoding="utf-8") as fh:
            for finding in self.all():
                fh.write(_dumps(finding.to_dict()) + "\n")
                n += 1
        return n

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SqliteFindingStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals --------------------------------------------------------

    @staticmethod
    def _decode(blob: str, finding_id: str) -> Finding:
        try:
            return Finding.from_dict(json.loads(blob))
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            raise StoreError(f"corrupt row for finding {finding_id!r}: {exc}") from exc


class JsonlFindingStore:
    """Append-only JSONL backing the frozen corpus.

    The file is a log; the store is the materialised view over it. Re-upserting
    a `finding_id` appends a new line and the later line wins on read, while the
    finding keeps its original position so the corpus does not reshuffle.
    `compact()` collapses the log to one line per finding for publication.
    """

    def __init__(self, path: str | os.PathLike[str], *, validate: bool = True):
        self.path = Path(path)
        self.validate = validate
        self._index: dict[str, Finding] = {}
        if self.path.exists():
            self._load()

    # -- FindingStore -----------------------------------------------------

    def upsert(self, finding: Finding) -> None:
        self.upsert_many((finding,))

    def get(self, finding_id: str) -> Finding | None:
        return self._index.get(finding_id)

    def by_fingerprint(self, fingerprint: str) -> list[Finding]:
        return [f for f in self._index.values() if f.fingerprint == fingerprint]

    def all(self) -> Iterator[Finding]:
        return iter(list(self._index.values()))

    def count(self) -> int:
        return len(self._index)

    # -- extras -----------------------------------------------------------

    def upsert_many(self, findings: Iterable[Finding]) -> int:
        batch = list(findings)
        payloads = [
            _validate(f) if self.validate else f.to_dict() for f in batch
        ]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            for payload in payloads:
                fh.write(_dumps(payload) + "\n")
        for finding in batch:
            self._index[finding.finding_id] = finding
        return len(batch)

    def compact(self) -> int:
        """Rewrite the log as exactly one line per finding, atomically."""
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("w", encoding="utf-8") as fh:
            for finding in self._index.values():
                fh.write(_dumps(finding.to_dict()) + "\n")
        os.replace(tmp, self.path)
        return len(self._index)

    def reload(self) -> None:
        self._index.clear()
        if self.path.exists():
            self._load()

    def close(self) -> None:
        """No handle is held between writes; present so callers can be uniform."""

    def __enter__(self) -> JsonlFindingStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals --------------------------------------------------------

    def _load(self) -> None:
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise StoreError(
                        f"{self.path}:{lineno}: malformed JSON in corpus file: {exc}"
                    ) from exc
                if not isinstance(payload, dict):
                    raise StoreError(
                        f"{self.path}:{lineno}: expected a JSON object, got "
                        f"{type(payload).__name__}"
                    )
                try:
                    finding = Finding.from_dict(payload)
                except (TypeError, KeyError) as exc:
                    raise StoreError(
                        f"{self.path}:{lineno}: not a Finding: {exc}"
                    ) from exc
                if self.validate:
                    _validate(finding)
                self._index[finding.finding_id] = finding


def copy_findings(src: FindingStore, dst: FindingStore) -> int:
    """Move a corpus between backends — e.g. frozen JSONL into the sqlite record."""
    n = 0
    for finding in src.all():
        dst.upsert(finding)
        n += 1
    return n
