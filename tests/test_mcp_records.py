"""The idempotency ledger. `JsonFileRecordStore`'s durability-across-instances is
what the crash-recovery tests in `test_mcp_github_tools.py` rely on to simulate
"the process died and a fresh one started with an empty local store" — proven
directly here first.
"""

from __future__ import annotations

from pramaan.mcp.records import InMemoryRecordStore, JsonFileRecordStore


def test_in_memory_store_round_trips() -> None:
    store = InMemoryRecordStore()
    store.put("f1", {"number": 1})
    assert store.get("f1") == {"number": 1}
    assert len(store) == 1


def test_in_memory_store_miss_returns_none() -> None:
    assert InMemoryRecordStore().get("absent") is None


def test_json_file_store_starts_empty_when_file_does_not_exist(tmp_path) -> None:
    store = JsonFileRecordStore(tmp_path / "records.json")
    assert store.get("f1") is None
    assert len(store) == 0


def test_json_file_store_persists_across_fresh_instances(tmp_path) -> None:
    """The literal mechanism behind the crash-recovery tests: writing with one
    instance and reading with a brand new one pointed at the same path."""
    path = tmp_path / "records.json"
    JsonFileRecordStore(path).put("f1", {"number": 101, "url": "https://x/101"})

    reopened = JsonFileRecordStore(path)
    assert reopened.get("f1") == {"number": 101, "url": "https://x/101"}


def test_json_file_store_write_is_atomic_no_tmp_file_left_behind(tmp_path) -> None:
    path = tmp_path / "records.json"
    JsonFileRecordStore(path).put("f1", {"a": 1})
    leftover = list(tmp_path.glob("*.tmp"))
    assert leftover == []
    assert path.exists()


def test_json_file_store_creates_parent_directories(tmp_path) -> None:
    path = tmp_path / "nested" / "dir" / "records.json"
    JsonFileRecordStore(path).put("f1", {"a": 1})
    assert path.exists()


def test_json_file_store_multiple_keys_do_not_clobber_each_other(tmp_path) -> None:
    path = tmp_path / "records.json"
    store = JsonFileRecordStore(path)
    store.put("f1", {"n": 1})
    store.put("f2", {"n": 2})

    reopened = JsonFileRecordStore(path)
    assert reopened.get("f1") == {"n": 1}
    assert reopened.get("f2") == {"n": 2}
    assert len(reopened) == 2
