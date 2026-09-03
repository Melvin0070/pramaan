"""A tiny idempotency ledger: string-keyed JSON records of actions this lane has
already taken.

This is deliberately *not* the source of truth for whether an action happened —
it is a cache. `github_tools.create_draft_pr` and `comment`, and
`tickets.adapter.GitHubIssuesAdapter`, all treat a miss here as "check the
remote", never as "the action never happened". That is what makes them tolerate
the crash this project's brief calls out explicitly: a process that dies between
a successful API call and the `put()` that should follow it leaves exactly this
kind of gap, and the caller re-derives the answer from the remote instead of
trusting this file to be complete.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

__all__ = ["RecordStore", "InMemoryRecordStore", "JsonFileRecordStore"]


@runtime_checkable
class RecordStore(Protocol):
    """Point lookups only — no query, no iteration. That is all idempotency
    needs, and a narrower interface is a smaller thing for a fake to get wrong."""

    def get(self, key: str) -> dict[str, Any] | None: ...

    def put(self, key: str, value: dict[str, Any]) -> None: ...


class InMemoryRecordStore:
    """Process-lifetime only. The default in tests, and a legitimate choice for
    a caller that supplies its own durability some other way."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}

    def get(self, key: str) -> dict[str, Any] | None:
        return self._data.get(key)

    def put(self, key: str, value: dict[str, Any]) -> None:
        self._data[key] = value

    def __len__(self) -> int:
        return len(self._data)


class JsonFileRecordStore:
    """Durable ledger: one JSON object per file, atomically rewritten on every
    write (temp file + `os.replace`, same idiom as `JsonlFindingStore.compact`)
    so a crash mid-write leaves either the old file or the new one, never a
    half-written one that would raise on the next read.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._data: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            text = self.path.read_text(encoding="utf-8").strip()
            self._data = json.loads(text) if text else {}

    def get(self, key: str) -> dict[str, Any] | None:
        return self._data.get(key)

    def put(self, key: str, value: dict[str, Any]) -> None:
        self._data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self._data, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        os.replace(tmp, self.path)

    def __len__(self) -> int:
        return len(self._data)
