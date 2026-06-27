#!/usr/bin/env python3
"""Register a canary token in the server database before embedding in email."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.core.limits import CANARY_TOKEN_RE
from app.services.canary.tokens import CanaryTokenRegistry


async def _register(db_path: Path, token: str) -> int:
    if not CANARY_TOKEN_RE.match(token):
        print("error: token format invalid", file=sys.stderr)
        return 1

    registry = CanaryTokenRegistry(db_path)
    await registry.init()
    created = await registry.register(token)
    if created:
        print(f"registered: {token}")
        return 0
    print(f"already registered: {token}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register a canary token for hit logging.")
    parser.add_argument("token", help="Token to register (from generate_canary_token.py)")
    parser.add_argument(
        "--db-path",
        default="./data/canary.db",
        help="SQLite path (default: ./data/canary.db)",
    )
    args = parser.parse_args(argv)
    return asyncio.run(_register(Path(args.db_path), args.token))


if __name__ == "__main__":
    raise SystemExit(main())
