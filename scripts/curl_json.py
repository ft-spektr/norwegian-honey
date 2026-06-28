#!/usr/bin/env python3
"""Run curl and emit JSON to stdout or a file (for Makefile API targets)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="curl wrapper for Makefile JSON targets")
    parser.add_argument("-o", "--out", type=Path, help="Write response body to file")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parser.add_argument("curl_args", nargs=argparse.REMAINDER, help="Arguments after --")
    args = parser.parse_args(argv)

    curl_args = args.curl_args
    if curl_args and curl_args[0] == "--":
        curl_args = curl_args[1:]
    if not curl_args:
        parser.error("pass curl arguments after --")

    result = subprocess.run(
        ["curl", "-s", *curl_args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return result.returncode

    body = result.stdout
    if args.pretty:
        body = json.dumps(json.loads(body), indent=2) + "\n"

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(body, encoding="utf-8")
        print(f"Wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
