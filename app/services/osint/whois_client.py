"""WHOIS lookups (sync library wrapped for async execution)."""

from __future__ import annotations

import asyncio
from typing import Any

import whois


def _whois_lookup(domain: str) -> dict[str, Any]:
    try:
        record = whois.whois(domain)
        if record is None:
            return {"found": False}
        # python-whois returns mixed types; normalize to JSON-safe dict
        result: dict[str, Any] = {"found": True}
        for key in (
            "domain_name",
            "registrar",
            "creation_date",
            "expiration_date",
            "updated_date",
            "name_servers",
            "emails",
            "org",
            "country",
        ):
            val = getattr(record, key, None)
            if val is not None:
                if isinstance(val, list):
                    result[key] = [str(v) for v in val]
                elif hasattr(val, "isoformat"):
                    result[key] = val.isoformat()
                else:
                    result[key] = str(val)
        return result
    except Exception as exc:  # noqa: BLE001 — whois raises varied exceptions
        return {"found": False, "error": str(exc)}


async def query_whois(domain: str) -> dict[str, Any]:
    return await asyncio.to_thread(_whois_lookup, domain)
