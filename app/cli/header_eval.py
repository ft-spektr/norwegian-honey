"""CLI for header analysis without running the HTTP server."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.services.header_evaluator import parse_eml_file, parse_headers_only, parse_raw_email


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze phishing/scam email headers from .eml files or raw input.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--eml", type=Path, help="Path to an .eml file")
    group.add_argument("--headers-file", type=Path, help="Path to raw headers text file")
    group.add_argument("--stdin", action="store_true", help="Read raw email from stdin")
    parser.add_argument(
        "--headers-only",
        action="store_true",
        help="Treat stdin/file input as headers only (no body)",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    args = parser.parse_args(argv)

    if args.eml:
        result = parse_eml_file(args.eml)
    elif args.headers_file:
        text = args.headers_file.read_text(encoding="utf-8", errors="replace")
        result = parse_headers_only(text) if args.headers_only else parse_raw_email(text)
    else:
        text = sys.stdin.read()
        result = parse_headers_only(text) if args.headers_only else parse_raw_email(text)

    indent = 2 if args.pretty else None
    print(result.model_dump_json(indent=indent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
