"""Rebuild a minimal HAR from explicitly allowed metadata, never redact in place."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from . import __version__

MAX_ENTRIES = 100_000
MAX_DURATION_MS = 31_536_000_000  # One year: reject pathological timing values.
METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
)
VERSIONS = frozenset(
    {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0", "HTTP/3", "HTTP/3.0", "h2", "h3"}
)
MIMES = frozenset(
    {
        "text/html",
        "text/css",
        "text/plain",
        "application/json",
        "application/javascript",
        "text/javascript",
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/svg+xml",
        "font/woff2",
        "application/octet-stream",
    }
)
TIMINGS = ("blocked", "dns", "connect", "send", "wait", "receive", "ssl")
EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)


class HarError(ValueError):
    """An input is unsupported or invalid; messages never include raw values."""


def _object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise HarError(f"{label} must be an object")
    return value


def _number(value: object, label: str, *, minimum: float = 0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HarError(f"{label} must be a finite number")
    try:
        result = float(value)
    except OverflowError as exc:
        raise HarError(f"{label} exceeds supported range") from exc
    if not math.isfinite(result) or not minimum <= result <= MAX_DURATION_MS:
        raise HarError(f"{label} exceeds supported range")
    return result


def _size(value: object) -> int:
    if type(value) is not int or not -1 <= value <= 2**53 - 1:
        raise HarError("size must be an integer between -1 and 2^53-1")
    return value


def _stamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise HarError("startedDateTime must be an ISO timestamp with a timezone")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError
        return stamp.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise HarError("startedDateTime must be an ISO timestamp with a timezone") from exc


def _url(value: object) -> tuple[str, str, str]:
    if not isinstance(value, str) or not value or len(value) > 65_536:
        raise HarError("request URL is missing or too long")
    if any(ord(char) < 32 for char in value):
        raise HarError("request URL contains control characters")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
            raise ValueError
        port = parsed.port
        origin = f"{parsed.scheme}://{parsed.hostname.lower()}:{port if port is not None else (443 if parsed.scheme in {'https', 'wss'} else 80)}"
        return parsed.scheme, origin, parsed.path or "/"
    except ValueError as exc:
        raise HarError("only absolute HTTP(S) and WS(S) request URLs are supported") from exc


def _listed_length(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


def sanitize(document: object) -> tuple[dict, dict]:
    """Return a fresh privacy-profile HAR and aggregate audit; never mutate input.

    Every free-form field is removed or converted to a closed vocabulary. Origin
    and complete path aliases preserve equality within this capture only. Timing,
    sizes, status codes, methods and traffic shape remain observable metadata.
    """
    root = _object(document, "HAR")
    log = _object(root.get("log"), "log")
    if log.get("version") != "1.2":
        raise HarError("only HAR version 1.2 is supported")
    entries = log.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise HarError("entries must be an array of at most 100000 requests")
    validated = []
    for item in entries:
        entry = _object(item, "entry")
        validated.append((entry, _stamp(entry.get("startedDateTime"))))
    first = min((stamp for _, stamp in validated), default=EPOCH)
    origins: dict[str, int] = {}
    paths: dict[tuple[str, str], int] = {}
    counts = dict(headers=0, cookies=0, query_parameters=0, request_bodies=0, response_bodies=0)
    clean = []
    for entry, stamp in validated:
        request = _object(entry.get("request"), "request")
        response = _object(entry.get("response"), "response")
        content = _object(response.get("content"), "content")
        timings = _object(entry.get("timings"), "timings")
        scheme, origin, path = _url(request.get("url"))
        origins.setdefault(origin, len(origins) + 1)
        paths.setdefault((origin, path), len(paths) + 1)
        safe_url = f"{scheme}://host-{origins[origin]:03d}.invalid/path-{paths[origin, path]:03d}"
        offset = (stamp - first).total_seconds() * 1000
        _number(offset, "capture span")
        duration = _number(entry.get("time"), "request duration")
        status = response.get("status")
        if type(status) is not int or not 0 <= status <= 599:
            raise HarError("response status must be an integer from 0 to 599")
        method = request.get("method")
        if not isinstance(method, str):
            raise HarError("request method must be a string")
        safe_method = method if method in METHODS else "OTHER"
        safe_timings = {}
        for name in TIMINGS:
            if name in timings:
                safe_timings[name] = _number(timings[name], "timing", minimum=-1)
                if -1 < safe_timings[name] < 0:
                    raise HarError("timings must be nonnegative or -1 when unavailable")
            elif name in {"send", "wait", "receive"}:
                raise HarError("send, wait and receive timings are required")
        mime = content.get("mimeType", "")
        if not isinstance(mime, str):
            raise HarError("mimeType must be a string")
        mime = mime.partition(";")[0].strip().lower()
        for side in (request, response):
            counts["headers"] += _listed_length(side.get("headers"))
            counts["cookies"] += _listed_length(side.get("cookies"))
        counts["query_parameters"] += _listed_length(request.get("queryString"))
        counts["request_bodies"] += int("postData" in request)
        counts["response_bodies"] += int("text" in content)

        def version(side: dict) -> str:
            candidate = side.get("httpVersion")
            return candidate if isinstance(candidate, str) and candidate in VERSIONS else "HTTP/1.1"

        clean.append(
            {
                "startedDateTime": (EPOCH + timedelta(milliseconds=offset))
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z"),
                "time": duration,
                "request": {
                    "method": safe_method,
                    "url": safe_url,
                    "httpVersion": version(request),
                    "cookies": [],
                    "headers": [],
                    "queryString": [],
                    "headersSize": _size(request.get("headersSize", -1)),
                    "bodySize": _size(request.get("bodySize", -1)),
                },
                "response": {
                    "status": status,
                    "statusText": "",
                    "httpVersion": version(response),
                    "cookies": [],
                    "headers": [],
                    "redirectURL": "",
                    "headersSize": _size(response.get("headersSize", -1)),
                    "bodySize": _size(response.get("bodySize", -1)),
                    "content": {
                        "size": _size(content.get("size", -1)),
                        "mimeType": mime if mime in MIMES else "application/octet-stream",
                    },
                },
                "cache": {},
                "timings": safe_timings,
            }
        )
    output = {
        "log": {
            "version": "1.2",
            "creator": {"name": "HARSieve", "version": __version__},
            "entries": clean,
        }
    }
    audit = {
        "profile": "metadata-only-v1",
        "tool_version": __version__,
        "requests": len(clean),
        "origins_aliased": len(origins),
        "paths_aliased": len(paths),
        "removed": counts,
        "policy": [
            "all headers and cookies removed",
            "URL credentials, query and fragment removed",
            "hosts and entire paths aliased",
            "request and response bodies removed",
            "timestamps rebased to 2000-01-01",
            "unknown fields, pages and extensions dropped",
        ],
        "retained": [
            "relative timing",
            "sizes",
            "status codes",
            "standard methods",
            "allowlisted MIME types",
            "within-capture endpoint equality",
        ],
        "warning": "Pseudonymized, not anonymous. Traffic metadata can identify activity. Review before sharing.",
    }
    return output, audit
