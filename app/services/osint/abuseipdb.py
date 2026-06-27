"""AbuseIPDB client."""

from __future__ import annotations

from typing import Any

import httpx

from app.config import Settings


async def query_abuseipdb(ip: str, settings: Settings) -> dict[str, Any]:
    if not settings.abuseipdb_api_key:
        return {"skipped": True, "reason": "ABUSEIPDB_API_KEY not configured"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(url, headers=headers, params=params)
        response.raise_for_status()
        payload = response.json()
        return payload.get("data", payload)
