"""Content-addressed cache of triage `Attempt` rows (binding decisions D13, D19).

The cache key is the full seven-tuple

    (fingerprint, model, effort, context_config, prompt_hash, run_index, run_epoch)

and every one of those fields is load-bearing:

  - `fingerprint` rather than `finding_id`, so a defect that shifts down a file
    by an unrelated edit above it still hits (`make_fingerprint` excludes the
    line number for exactly that reason).
  - `model`, `effort`, `context_config` keep the ablation arms apart. A blank
    `context_config` would silently merge the 20-line and 200-line arms into one
    bucket and quietly corrupt the ablation, so blanks are rejected.
  - `prompt_hash` is a hash *over named components* (see `compute_prompt_hash`),
    which is what makes skill-scoped invalidation possible: editing the CWE-89
    skill drops the rows whose prompt included it and leaves the rest of the
    table alone.
  - `run_index` keeps the k runs of a pass^k measurement distinct.
  - `run_epoch` (D19) is the nightly bypass. A nightly run mints a fresh epoch
    and therefore misses every existing row *by construction* — the epoch is a
    column in the lookup, not a hint. `get()` takes one argument, a whole
    `CacheKey`; there is deliberately no parameter that relaxes the epoch.
    Replaying a cached pass^k instead of measuring it would hide provider-side
    model drift, which is the one thing the `system_fingerprint` stamp exists
    to expose.

All five D10 statuses persist. A `schema_invalid` or `budget_abort` attempt is
data: it counts as a non-match in pass^k and it feeds the published
schema-failure rate. Swallowing it would inflate every consistency number in
the report.

`export_jsonl()` writes the published verdict table, from which tau, the
reliability diagram and ECE can all be re-derived with no API key.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pramaan.schemas import ALL_ATTEMPT_STATUSES, Attempt

__all__ = [
    "CacheError",
    "CacheKey",
    "CachedAttempt",
    "CachedVerdictStore",
    "component_hash",
    "compute_prompt_hash",
    "load_jsonl",
    "new_run_epoch",
]

_MEMORY = ":memory:"

# The seven-tuple, in key order. Named once so the SQL, the export and the
# tests cannot drift apart — in particular so run_epoch cannot be dropped from
# one of them without the others noticing.
KEY_FIELDS: tuple[str, ...] = (
    "fingerprint",
    "model",
    "effort",
    "context_config",
    "prompt_hash",
    "run_index",
    "run_epoch",
)


class CacheError(Exception):
    """Raised when cached state is unreadable or self-inconsistent."""


@dataclass(frozen=True, slots=True)
class CacheKey:
    fingerprint: str
    model: str
    effort: str
    context_config: str
    prompt_hash: str
    run_index: int
    run_epoch: str

    def __post_init__(self) -> None:
        for name in KEY_FIELDS:
            if name == "run_index":
                continue
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"cache key field {name!r} must be a non-empty string; "
                    "a blank field would silently merge distinct runs into one row"
                )
        if not isinstance(self.run_index, int) or isinstance(self.run_index, bool):
            raise ValueError("run_index must be an int")
        if self.run_index < 0:
            raise ValueError("run_index must be >= 0")

    @property
    def digest(self) -> str:
        payload = json.dumps(
            [getattr(self, name) for name in KEY_FIELDS], separators=(",", ":")
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in KEY_FIELDS}

    @classmethod
    def from_dict(cls, d: Mapping[str, object]) -> CacheKey:
        try:
            return cls(
                fingerprint=str(d["fingerprint"]),
                model=str(d["model"]),
                effort=str(d["effort"]),
                context_config=str(d["context_config"]),
                prompt_hash=str(d["prompt_hash"]),
                run_index=int(d["run_index"]),  # type: ignore[arg-type]
                run_epoch=str(d["run_epoch"]),
            )
        except KeyError as exc:
            raise CacheError(f"cache record missing key field {exc}") from exc

    @classmethod
    def for_attempt(cls, fingerprint: str, attempt: Attempt) -> CacheKey:
        """Build the key for an attempt.

        `Attempt` now carries its own `fingerprint`. The parameter is kept so
        existing call sites still read explicitly, but a mismatch means the caller
        and the attempt disagree about which defect this is -- which would file the
        row under the wrong key and silently poison every later lookup.
        """
        if attempt.fingerprint and attempt.fingerprint != fingerprint:
            raise ValueError(
                f"fingerprint mismatch: caller passed {fingerprint!r}, "
                f"attempt carries {attempt.fingerprint!r}"
            )
        return cls(
            fingerprint=fingerprint,
            model=attempt.model,
            effort=attempt.effort,
            context_config=attempt.context_config,
            prompt_hash=attempt.prompt_hash,
            run_index=attempt.run_index,
            run_epoch=attempt.run_epoch,
        )


@dataclass(frozen=True, slots=True)
class CachedAttempt:
    key: CacheKey
    attempt: Attempt


def component_hash(text: str) -> str:
    """Hash one prompt component — a CWE skill file, the system prompt, a rubric."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def compute_prompt_hash(components: Mapping[str, str]) -> str:
    """Hash a *named* component map. Values are component hashes, not raw text.

    Order-independent, so a caller reordering its skill list does not invalidate
    the table. Names are included in the payload so renaming a component is a
    real change.
    """
    if not components:
        raise ValueError("prompt_hash needs at least one named component")
    payload = json.dumps(sorted(components.items()), separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def new_run_epoch(now: datetime | None = None) -> str:
    """Mint a fresh epoch for a nightly run. Distinct epochs never share rows."""
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def load_jsonl(path: str | os.PathLike[str]) -> Iterator[CachedAttempt]:
    """Read a published verdict table. No database, no API key, no network."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CacheError(f"{p}:{lineno}: malformed JSON: {exc}") from exc
            if not isinstance(record, dict) or "attempt" not in record:
                raise CacheError(f"{p}:{lineno}: not a verdict-table record")
            yield CachedAttempt(
                key=CacheKey.from_dict(record),
                attempt=Attempt.from_dict(record["attempt"]),
            )


class CachedVerdictStore:
    """SQLite-backed verdict cache.

    Lookup is by the whole seven-tuple. There is no partial-key read path, and
    no argument that widens a lookup across epochs.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS attempts (
        key_digest     TEXT PRIMARY KEY,
        fingerprint    TEXT NOT NULL,
        model          TEXT NOT NULL,
        effort         TEXT NOT NULL,
        context_config TEXT NOT NULL,
        prompt_hash    TEXT NOT NULL,
        run_index      INTEGER NOT NULL,
        run_epoch      TEXT NOT NULL,
        status         TEXT NOT NULL,
        attempt        TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_attempts_key ON attempts(
        fingerprint, model, effort, context_config, prompt_hash, run_index, run_epoch
    );
    CREATE INDEX IF NOT EXISTS idx_attempts_fingerprint ON attempts(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_attempts_prompt ON attempts(prompt_hash);
    CREATE INDEX IF NOT EXISTS idx_attempts_epoch ON attempts(run_epoch);

    CREATE TABLE IF NOT EXISTS prompt_components (
        prompt_hash    TEXT NOT NULL,
        component      TEXT NOT NULL,
        component_hash TEXT NOT NULL,
        PRIMARY KEY (prompt_hash, component)
    );
    CREATE INDEX IF NOT EXISTS idx_components_name ON prompt_components(component);
    """

    def __init__(self, path: str | os.PathLike[str] = _MEMORY):
        self.path = str(path)
        if self.path != _MEMORY:
            parent = Path(self.path).parent
            if str(parent):
                parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()

    # -- read -------------------------------------------------------------

    def get(self, key: CacheKey) -> Attempt | None:
        """Exact seven-tuple lookup. A differing `run_epoch` is a MISS (D19).

        The signature takes one whole key on purpose: an `ignore_epoch=` style
        escape hatch is how the nightly pass^k would start replaying the cache
        instead of measuring it.
        """
        row = self._conn.execute(
            """
            SELECT attempt FROM attempts
             WHERE fingerprint    = ?
               AND model          = ?
               AND effort         = ?
               AND context_config = ?
               AND prompt_hash    = ?
               AND run_index      = ?
               AND run_epoch      = ?
            """,
            tuple(getattr(key, name) for name in KEY_FIELDS),
        ).fetchone()
        return None if row is None else self._decode(row["attempt"], key)

    def has(self, key: CacheKey) -> bool:
        return self.get(key) is not None

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])

    def all(self) -> Iterator[CachedAttempt]:
        return iter([self._row_to_cached(r) for r in self._ordered_rows()])

    def attempts_for_fingerprint(
        self, fingerprint: str, *, run_epoch: str | None = None
    ) -> list[CachedAttempt]:
        """Every stored run for one defect. `run_epoch` narrows, never widens."""
        sql = "SELECT * FROM attempts WHERE fingerprint = ?"
        params: list[object] = [fingerprint]
        if run_epoch is not None:
            sql += " AND run_epoch = ?"
            params.append(run_epoch)
        sql += (
            " ORDER BY model, effort, context_config, prompt_hash, run_epoch, run_index"
        )
        return [
            self._row_to_cached(r) for r in self._conn.execute(sql, params).fetchall()
        ]

    def status_counts(self) -> dict[str, int]:
        """Feeds the published schema-failure rate (D10)."""
        counts = {status: 0 for status in ALL_ATTEMPT_STATUSES}
        for row in self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM attempts GROUP BY status"
        ):
            counts[row["status"]] = int(row["n"])
        return counts

    def epochs(self) -> list[str]:
        return [
            r["run_epoch"]
            for r in self._conn.execute(
                "SELECT DISTINCT run_epoch FROM attempts ORDER BY run_epoch"
            )
        ]

    def unregistered_prompt_hashes(self) -> list[str]:
        """Prompt hashes with no component map — invisible to `invalidate_component`.

        Surfaced rather than swallowed: these rows survive a skill edit that
        should have evicted them, and a reviewer needs to be able to see that.
        """
        return [
            r["prompt_hash"]
            for r in self._conn.execute(
                "SELECT DISTINCT prompt_hash FROM attempts WHERE prompt_hash NOT IN"
                " (SELECT prompt_hash FROM prompt_components) ORDER BY prompt_hash"
            )
        ]

    # -- write ------------------------------------------------------------

    def put(
        self,
        fingerprint: str,
        attempt: Attempt,
        *,
        components: Mapping[str, str] | None = None,
    ) -> CacheKey:
        """Persist one attempt, whatever its status.

        `components`, when given, must hash to `attempt.prompt_hash`. A mismatch
        raises: a mislabelled component map makes skill-scoped invalidation miss
        rows it was supposed to evict, which is worse than not indexing at all.
        """
        if attempt.status not in ALL_ATTEMPT_STATUSES:
            raise ValueError(
                f"unknown attempt status {attempt.status!r}; "
                f"expected one of {ALL_ATTEMPT_STATUSES}"
            )
        key = CacheKey.for_attempt(fingerprint, attempt)
        if components is not None:
            declared = compute_prompt_hash(components)
            if declared != attempt.prompt_hash:
                raise ValueError(
                    f"components hash to {declared!r} but attempt.prompt_hash is "
                    f"{attempt.prompt_hash!r}"
                )
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO attempts (
                    key_digest, fingerprint, model, effort, context_config,
                    prompt_hash, run_index, run_epoch, status, attempt
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key_digest) DO UPDATE SET
                    status  = excluded.status,
                    attempt = excluded.attempt
                """,
                (
                    key.digest,
                    key.fingerprint,
                    key.model,
                    key.effort,
                    key.context_config,
                    key.prompt_hash,
                    key.run_index,
                    key.run_epoch,
                    attempt.status,
                    _dumps(attempt.to_dict()),
                ),
            )
            if components is not None:
                self._register(attempt.prompt_hash, components)
        return key

    def put_many(self, records: Iterable[tuple[str, Attempt]]) -> int:
        n = 0
        for fingerprint, attempt in records:
            self.put(fingerprint, attempt)
            n += 1
        return n

    def register_prompt(self, components: Mapping[str, str]) -> str:
        """Record which named components a prompt is built from; return its hash."""
        digest = compute_prompt_hash(components)
        with self._conn:
            self._register(digest, components)
        return digest

    def invalidate_component(
        self, component: str, *, current_hash: str | None = None
    ) -> int:
        """Skill-scoped eviction. Returns the number of attempts dropped.

        Only rows whose `prompt_hash` was registered as including `component`
        are touched — editing the CWE-89 skill must not evict the CWE-79 rows,
        or a one-skill edit silently costs a full re-run of the whole corpus.

        With `current_hash`, rows built from that exact component content
        survive, so re-registering an unchanged skill is free.
        """
        sql = "SELECT DISTINCT prompt_hash FROM prompt_components WHERE component = ?"
        params: list[object] = [component]
        if current_hash is not None:
            sql += " AND component_hash != ?"
            params.append(current_hash)
        stale = [r["prompt_hash"] for r in self._conn.execute(sql, params)]
        if not stale:
            return 0
        marks = ",".join("?" for _ in stale)
        with self._conn:
            cur = self._conn.execute(
                f"DELETE FROM attempts WHERE prompt_hash IN ({marks})", stale
            )
            deleted = cur.rowcount
            self._conn.execute(
                f"DELETE FROM prompt_components WHERE prompt_hash IN ({marks})", stale
            )
        return int(deleted)

    def import_jsonl(self, path: str | os.PathLike[str]) -> int:
        n = 0
        for record in load_jsonl(path):
            self.put(record.key.fingerprint, record.attempt)
            n += 1
        return n

    # -- export -----------------------------------------------------------

    def export_jsonl(self, path: str | os.PathLike[str]) -> int:
        """Write the published verdict table.

        One JSON object per row: the seven key fields (the fingerprint matters —
        `Attempt` does not carry one) plus the full attempt. Deterministically
        ordered so the published file diffs cleanly between runs, and complete
        enough that tau, the reliability diagram and ECE re-derive from it with
        no API key.
        """
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with out.open("w", encoding="utf-8") as fh:
            for row in self._ordered_rows():
                record: dict[str, object] = {
                    name: row[name] for name in KEY_FIELDS
                }
                record["key_digest"] = row["key_digest"]
                record["attempt"] = json.loads(row["attempt"])
                fh.write(_dumps(record) + "\n")
                n += 1
        return n

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> CachedVerdictStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals --------------------------------------------------------

    def _register(self, digest: str, components: Mapping[str, str]) -> None:
        self._conn.executemany(
            "INSERT INTO prompt_components (prompt_hash, component, component_hash)"
            " VALUES (?, ?, ?)"
            " ON CONFLICT(prompt_hash, component) DO UPDATE SET"
            " component_hash = excluded.component_hash",
            [(digest, name, value) for name, value in components.items()],
        )

    def _ordered_rows(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM attempts ORDER BY fingerprint, model, effort,"
            " context_config, prompt_hash, run_epoch, run_index"
        ).fetchall()

    def _row_to_cached(self, row: sqlite3.Row) -> CachedAttempt:
        key = CacheKey.from_dict({name: row[name] for name in KEY_FIELDS})
        return CachedAttempt(key=key, attempt=self._decode(row["attempt"], key))

    @staticmethod
    def _decode(blob: str, key: CacheKey) -> Attempt:
        try:
            return Attempt.from_dict(json.loads(blob))
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            raise CacheError(f"corrupt cached attempt for {key.digest}: {exc}") from exc


def _dumps(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
