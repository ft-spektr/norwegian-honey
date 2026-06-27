"""Async OSINT aggregation with TTL caching."""

from __future__ import annotations

import asyncio
from typing import Any

from app.config import Settings
from app.core.cache import osint_cache
from app.models.osint import (
    DomainIntelResult,
    EmailIntelResult,
    IPIntelResult,
    OSINTQueryRequest,
    OSINTQueryResponse,
)
from app.services.osint.abuseipdb import query_abuseipdb
from app.services.osint.ipinfo import query_ipinfo
from app.services.osint.whois_client import query_whois


async def _cached_fetch(cache_key: str, fetcher) -> tuple[dict[str, Any], bool]:
    cached = await osint_cache.get(cache_key)
    if cached is not None:
        return cached, True
    data = await fetcher()
    await osint_cache.set(cache_key, data)
    return data, False


async def _enrich_ip(ip: str, settings: Settings) -> list[IPIntelResult]:
    results: list[IPIntelResult] = []

    async def ipinfo_fetch():
        return await query_ipinfo(ip, settings)

    async def abuse_fetch():
        return await query_abuseipdb(ip, settings)

    for source, fetcher in (("ipinfo", ipinfo_fetch), ("abuseipdb", abuse_fetch)):
        cache_key = f"ip:{source}:{ip}"
        try:
            data, was_cached = await _cached_fetch(cache_key, fetcher)
            results.append(IPIntelResult(ip=ip, source=source, cached=was_cached, data=data))
        except Exception as exc:  # noqa: BLE001
            results.append(IPIntelResult(ip=ip, source=source, error=str(exc)))

    return results


async def _enrich_domain(domain: str) -> list[DomainIntelResult]:
    cache_key = f"domain:whois:{domain}"
    try:
        data, was_cached = await _cached_fetch(cache_key, lambda: query_whois(domain))
        return [DomainIntelResult(domain=domain, source="whois", cached=was_cached, data=data)]
    except Exception as exc:  # noqa: BLE001
        return [DomainIntelResult(domain=domain, source="whois", error=str(exc))]


async def _enrich_email(email: str) -> list[EmailIntelResult]:
    domain = email.rsplit("@", 1)[-1].lower()
    whois_results = await _enrich_domain(domain)
    return [
        EmailIntelResult(
            email=email,
            domain=domain,
            source=r.source,
            cached=r.cached,
            data=r.data,
            error=r.error,
        )
        for r in whois_results
    ]


async def aggregate_osint(request: OSINTQueryRequest, settings: Settings) -> OSINTQueryResponse:
    ips = list(dict.fromkeys(request.ips))
    domains = list(dict.fromkeys(request.domains))
    emails = list(dict.fromkeys(request.emails))

    ip_tasks = [_enrich_ip(ip, settings) for ip in ips]
    domain_tasks = [_enrich_domain(d) for d in domains]
    email_tasks = [_enrich_email(e) for e in emails]

    ip_groups = await asyncio.gather(*ip_tasks) if ip_tasks else []
    domain_groups = await asyncio.gather(*domain_tasks) if domain_tasks else []
    email_groups = await asyncio.gather(*email_tasks) if email_tasks else []

    return OSINTQueryResponse(
        ips=[item for group in ip_groups for item in group],
        domains=[item for group in domain_groups for item in group],
        emails=[item for group in email_groups for item in group],
    )
