"""Ingest failure signal.

Ingest fails closed (CONTRACTS.md ground rule 7): anything that stops us
from confidently building every `Finding` in a batch — broken JSON, a
SARIF log with no runs, a result missing its location — raises this for
the whole call instead of returning the subset we did manage to parse.
A silently partial list would look identical to "the scanner found
nothing else," which is the one failure mode a security ingest pipeline
can't tolerate.
"""

from __future__ import annotations


class IngestError(Exception):
    pass
