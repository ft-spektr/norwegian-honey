#!/usr/bin/env python3
"""Generate cryptographically secure canary tokens for email embedding."""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def generate_token(length: int = 32) -> str:
    # URL-safe, high entropy — 32 bytes => 256 bits
    return secrets.token_urlsafe(length)


def build_pixel_embed(base_url: str, token: str) -> tuple[str, str]:
    base = base_url.rstrip("/")
    url = f"{base}/images/{token}.png"
    html = f'<img src="{url}" width="1" height="1" alt="" style="display:none" />'
    return url, html


def build_portfolio_embed(base_url: str, token: str) -> tuple[str, str]:
    base = base_url.rstrip("/")
    url = f"{base}/portfolio/{token}"
    html = f'<a href="{url}">View portfolio</a>'
    return url, html


async def _register_token(db_path: Path, token: str) -> None:
    from app.services.canary.tokens import CanaryTokenRegistry

    registry = CanaryTokenRegistry(db_path)
    await registry.init()
    await registry.register(token)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate canary tracking tokens.")
    parser.add_argument(
        "--base-url",
        default="https://canary.example.com",
        help="Public base URL where the honeypot is hosted",
    )
    parser.add_argument("--count", type=int, default=1, help="Number of tokens to generate")
    parser.add_argument(
        "--trap",
        choices=("pixel", "portfolio", "both"),
        default="pixel",
        help="Trap type: hidden image pixel, portfolio link, or both URLs",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON lines")
    parser.add_argument(
        "--register-db",
        metavar="PATH",
        help="Register each token in SQLite (required for hits to be logged)",
    )
    args = parser.parse_args(argv)

    db_path = Path(args.register_db) if args.register_db else None

    for _ in range(args.count):
        token = generate_token()
        if db_path:
            asyncio.run(_register_token(db_path, token))

        traps: list[tuple[str, str, str]] = []
        if args.trap in ("pixel", "both"):
            url, html = build_pixel_embed(args.base_url, token)
            traps.append(("images", url, html))
        if args.trap in ("portfolio", "both"):
            url, html = build_portfolio_embed(args.base_url, token)
            traps.append(("portfolio", url, html))

        if args.json:
            import json

            payload: dict[str, object] = {"token": token}
            if len(traps) == 1:
                trap, url, html = traps[0]
                payload.update(
                    {
                        "trap": trap,
                        "embed_url": url,
                        "html_snippet": html,
                    }
                )
            else:
                payload["traps"] = [
                    {"trap": trap, "embed_url": url, "html_snippet": html}
                    for trap, url, html in traps
                ]
            print(json.dumps(payload))
        else:
            print(f"token:       {token}")
            for trap, url, html in traps:
                print(f"trap:        {trap}")
                print(f"embed_url:   {url}")
                print(f"html:        {html}")
            if db_path:
                print(f"registered:  {db_path}")
            print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
