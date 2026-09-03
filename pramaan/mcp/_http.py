"""Minimal stdlib HTTP-JSON helper shared by `RestGitHubClient` and
`RestDojoClient`.

Not a general HTTP library — one function, no retries, no pagination (each
caller handles its own if it needs it). Kept this small on purpose: this lane's
whole job is to do very little, and a hand-rolled requests-alike would be exactly
the kind of scope creep that contradicts it. Standard library only, per
CONTRACTS.md ground rule 1.
"""

from __future__ import annotations

import json
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

__all__ = ["HttpError", "request_json"]


class HttpError(Exception):
    """Any non-2xx response, or a transport failure that never got one."""

    def __init__(self, status: int, url: str, body: str) -> None:
        super().__init__(f"HTTP {status} from {url}: {body[:500]}")
        self.status = status
        self.url = url
        self.body = body


def request_json(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str],
    json_body: Any = None,
    timeout: float = 20.0,
) -> Any:
    """One request, JSON in, JSON out. Raises `HttpError` on anything but 2xx so
    a caller cannot mistake a 4xx/5xx body for a successful empty response."""
    data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
    request = Request(url, data=data, method=method, headers=dict(headers))
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https host
            raw = response.read()
            return json.loads(raw) if raw else None
    except HTTPError as exc:
        raise HttpError(exc.code, url, exc.read().decode("utf-8", "replace")) from exc
    except URLError as exc:
        raise HttpError(0, url, str(exc.reason)) from exc
