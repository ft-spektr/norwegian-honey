"""ipinfo.io client."""

from __future__ import annotations

from typing import Any

import httpx

from app.config import Settings


async def query_ipinfo(ip: str, settings: Settings) -> dict[str, Any]:
    base = f"https://ipinfo.io/{ip}/json"
    headers: dict[str, str] = {}
    if settings.ipinfo_api_key:
        headers["Authorization"] = f"Bearer {settings.ipinfo_api_key}"

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(base, headers=headers)
        response.raise_for_status()
        return response.json()
