#!/usr/bin/env python3
"""Extract pure JSON from a file that includes curl/Makefile noise."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.core.json_document import load_json_document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write clean JSON extracted from curl-capture or mixed text files.",
    )
    parser.add_argument("input", type=Path, help="Source file")
    parser.add_argument("-o", "--output", type=Path, help="Output file (default: stdout)")
    parser.add_argument("--compact", action="store_true", help="Minified JSON")
    args = parser.parse_args(argv)

    data = load_json_document(args.input)
    payload = json.dumps(data, separators=(",", ":") if args.compact else None, indent=None if args.compact else 2)
    payload += "\n"

    if args.output:
        args.output.write_text(payload, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
