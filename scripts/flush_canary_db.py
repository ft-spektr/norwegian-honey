#!/usr/bin/env python3
"""Flush canary hit logs and optionally registered tokens from SQLite."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def flush(db_path: Path, keep_tokens: bool) -> int:
    if not db_path.exists():
        print(f"error: database not found: {db_path}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(db_path)
    try:
        hit_count = conn.execute("SELECT COUNT(*) FROM canary_hits").fetchone()[0]
        token_count = 0 if keep_tokens else conn.execute("SELECT COUNT(*) FROM canary_tokens").fetchone()[0]
        conn.execute("DELETE FROM canary_hits")
        if not keep_tokens:
            conn.execute("DELETE FROM canary_tokens")
        conn.commit()
    finally:
        conn.close()

    if keep_tokens:
        print(f"flushed canary_hits ({hit_count} rows)")
    else:
        print(f"flushed canary_hits ({hit_count} rows) and canary_tokens ({token_count} rows)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Flush canary SQLite data.")
    parser.add_argument(
        "--db-path",
        default="./data/canary.db",
        help="SQLite path (default: ./data/canary.db)",
    )
    parser.add_argument(
        "--keep-tokens",
        action="store_true",
        help="Delete hits only; keep registered tokens",
    )
    args = parser.parse_args(argv)
    return flush(Path(args.db_path), keep_tokens=args.keep_tokens)


if __name__ == "__main__":
    raise SystemExit(main())
