"""CLI orchestration: raw captures never reach stdout, stderr or HTML."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import HarError, sanitize
from .demo import capture
from .io import load, write_bundle
from .report import render, summary


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Local HAR privacy projection and debugging reports."
    )
    root.add_argument("--version", action="version", version=f"HARSieve {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    clean = commands.add_parser(
        "clean", help="create a new sanitized bundle from a HAR 1.2 capture"
    )
    clean.add_argument("input", type=Path)
    clean.add_argument(
        "-o", "--output", required=True, type=Path, help="new output directory; never overwritten"
    )
    clean.add_argument(
        "--fail-on-http-errors",
        action="store_true",
        help="write bundle, then exit 1 on HTTP 400–599",
    )
    demo = commands.add_parser("demo", help="create a bundle from built-in synthetic traffic")
    demo.add_argument("-o", "--output", required=True, type=Path)
    inspect = commands.add_parser("summary", help="print aggregate JSON; no original strings")
    inspect.add_argument("input", type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        document = capture() if args.command == "demo" else load(args.input)
        clean, audit = sanitize(document)
        stats = summary(clean)
        if args.command == "summary":
            print(json.dumps(stats, indent=2, allow_nan=False))
        else:
            write_bundle(
                args.output,
                {
                    "capture.har": json.dumps(clean, indent=2, allow_nan=False) + "\n",
                    "audit.json": json.dumps(audit, indent=2, allow_nan=False) + "\n",
                    "report.html": render(clean, audit),
                },
            )
            print(f"HARSieve · {stats['requests']} requests · {stats['http_errors']} HTTP errors")
            print("Created capture.har, audit.json and report.html in the requested directory.")
            print(
                "Original addresses and payloads removed. Review retained metadata before sharing."
            )
        return int(bool(getattr(args, "fail_on_http_errors", False) and stats["http_errors"]))
    except (HarError, RecursionError, OverflowError) as exc:
        message = (
            str(exc) if isinstance(exc, HarError) else "input exceeds supported structural limits"
        )
        print(f"harsieve: {message}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
