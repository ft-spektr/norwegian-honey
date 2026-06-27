"""DNS-based SPF/DMARC record checks and Authentication-Results parsing."""

from __future__ import annotations

import re
from typing import Any

import dns.exception
import dns.resolver

from app.models.analyze import AuthCheckResult, AuthResultStatus

_AUTH_STATUS_MAP: dict[str, AuthResultStatus] = {
    "pass": AuthResultStatus.PASS,
    "fail": AuthResultStatus.FAIL,
    "neutral": AuthResultStatus.NEUTRAL,
    "softfail": AuthResultStatus.SOFTFAIL,
    "none": AuthResultStatus.NONE,
    "temperror": AuthResultStatus.TEMPERROR,
    "permerror": AuthResultStatus.PERMERROR,
}


def _normalize_status(raw: str | None) -> AuthResultStatus:
    if not raw:
        return AuthResultStatus.UNKNOWN
    return _AUTH_STATUS_MAP.get(raw.lower().strip(), AuthResultStatus.UNKNOWN)


def parse_authentication_results(headers: list[str]) -> list[AuthCheckResult]:
    """Parse Authentication-Results headers for SPF, DKIM, and DMARC outcomes."""
    results: list[AuthCheckResult] = []
    seen: set[tuple[str, str | None]] = set()

    for header in headers:
        for match in re.finditer(
            r"(spf|dkim|dmarc)\s*=\s*(\w+)(?:\s+\(([^)]*)\))?",
            header,
            re.IGNORECASE,
        ):
            mechanism = match.group(1).lower()
            status = _normalize_status(match.group(2))
            detail = match.group(3)

            domain: str | None = None
            selector: str | None = None
            if detail:
                domain_match = re.search(
                    r"(?:header\.[di]\s*=\s*|smtp\.mailfrom\s*=\s*)([^;\s]+)",
                    detail,
                    re.IGNORECASE,
                )
                if domain_match:
                    domain = domain_match.group(1).strip("<>")

                sel_match = re.search(r"header\.s\s*=\s*([^;\s]+)", detail, re.IGNORECASE)
                if sel_match:
                    selector = sel_match.group(1)

            key = (mechanism, domain)
            if key in seen:
                continue
            seen.add(key)

            results.append(
                AuthCheckResult(
                    mechanism=mechanism,
                    status=status,
                    domain=domain,
                    selector=selector,
                    detail=detail,
                )
            )

    return results


def lookup_spf_record(domain: str) -> dict[str, Any]:
    """Return SPF TXT record presence and raw value."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join(part.decode() if isinstance(part, bytes) else part for part in rdata.strings)
            if txt.lower().startswith("v=spf1"):
                return {"found": True, "record": txt}
        return {"found": False, "record": None}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return {"found": False, "record": None, "error": "dns_lookup_failed"}


def lookup_dmarc_record(domain: str) -> dict[str, Any]:
    """Return DMARC policy from _dmarc.<domain> TXT record."""
    name = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(name, "TXT")
        for rdata in answers:
            txt = "".join(part.decode() if isinstance(part, bytes) else part for part in rdata.strings)
            if txt.lower().startswith("v=dmarc1"):
                policy_match = re.search(r"\bp=([^;\s]+)", txt, re.IGNORECASE)
                return {
                    "found": True,
                    "record": txt,
                    "policy": policy_match.group(1).lower() if policy_match else None,
                }
        return {"found": False, "record": None}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return {"found": False, "record": None, "error": "dns_lookup_failed"}


def enrich_auth_with_dns(auth_results: list[AuthCheckResult], from_domain: str | None) -> list[AuthCheckResult]:
    """Attach DNS record presence flags to auth results."""
    enriched: list[AuthCheckResult] = []
    for item in auth_results:
        dns_found: bool | None = None
        if item.mechanism == "spf" and from_domain:
            dns_found = lookup_spf_record(from_domain).get("found")
        elif item.mechanism == "dmarc" and from_domain:
            dns_found = lookup_dmarc_record(from_domain).get("found")
        enriched.append(item.model_copy(update={"dns_record_found": dns_found}))
    return enriched
