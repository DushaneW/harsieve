"""Bounded input, strict JSON and all-or-cleaned-up output bundles."""

from __future__ import annotations

import json
from pathlib import Path

from .core import HarError

MAX_BYTES = 64 * 1024 * 1024


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise HarError("duplicate JSON object keys are not supported")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise HarError("non-finite JSON numbers are not supported")


def load(path: Path) -> object:
    """Read at most 64 MiB + one byte, reject ambiguous JSON without echoing it."""
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise HarError("input exceeds the 64 MiB limit")
        document = json.loads(
            data.decode("utf-8-sig"), object_pairs_hook=_pairs, parse_constant=_constant
        )
        stack = [(document, 0)]
        while stack:
            item, depth = stack.pop()
            if depth > 64:
                raise HarError("JSON nesting exceeds 64 levels")
            if isinstance(item, dict):
                stack.extend((value, depth + 1) for value in item.values())
            elif isinstance(item, list):
                stack.extend((value, depth + 1) for value in item)
        return document
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, HarError):
            raise
        raise HarError("input must be valid, bounded-depth UTF-8 JSON") from exc
    except OSError as exc:
        raise HarError("cannot read input file; check path and permissions") from exc


def write_bundle(destination: Path, files: dict[str, str]) -> None:
    """Create a new directory exclusively; refuse all existing destinations.

    Completed files are individually fsynced. On ordinary write failure remove
    files created by this function. A process/power interruption can still leave
    a partial directory; no transactional filesystem guarantee is claimed.
    """
    import os

    if any(Path(name).name != name or name in {"", ".", ".."} for name in files):
        raise HarError("bundle file names must be plain names")
    try:
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as exc:
        raise HarError("output directory must be new and its parent must exist") from exc
    created = []
    try:
        for name, content in files.items():
            target = destination / name
            with target.open("x", encoding="utf-8", newline="\n") as stream:
                created.append(target)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError as exc:
        for target in created:
            target.unlink(missing_ok=True)
        destination.rmdir()
        raise HarError("could not finish output bundle") from exc
