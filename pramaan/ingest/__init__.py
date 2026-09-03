"""Semgrep ingest: parse scanner output into `Finding`s, then dedup them."""

from pramaan.ingest.dedup import dedup
from pramaan.ingest.errors import IngestError
from pramaan.ingest.semgrep import parse_json, parse_sarif

__all__ = ["IngestError", "dedup", "parse_json", "parse_sarif"]
