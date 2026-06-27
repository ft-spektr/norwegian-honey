"""Extract client IP behind reverse proxies (OpSec-critical for canary accuracy)."""

from __future__ import annotations

import ipaddress

from fastapi import Request

_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


def _parse_ip(value: str) -> str | None:
    # Caddy/uvicorn may include :port for IPv4 in some edge cases
    host = value.strip().split(",", 1)[0].strip()
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif host.count(":") == 1 and "." in host:
        host = host.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _is_public_ip(value: str) -> bool:
    parsed = _parse_ip(value)
    if parsed is None:
        return False
    addr = ipaddress.ip_address(parsed)
    if addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return False
    return not any(addr in net for net in _PRIVATE_NETWORKS)


def _ip_from_forwarded(value: str) -> str | None:
    hops = [h.strip() for h in value.split(",") if h.strip()]
    if not hops:
        return None

    # Standard proxy chain: first public IP is the original client.
    for hop in hops:
        parsed = _parse_ip(hop)
        if parsed and _is_public_ip(parsed):
            return parsed

    # Single hop from our edge Caddy (replaces client XFF) — trust the only value.
    if len(hops) == 1:
        return _parse_ip(hops[0])

    # Multi-hop with only private IPs left — use rightmost (closest to edge).
    for hop in reversed(hops):
        parsed = _parse_ip(hop)
        if parsed:
            return parsed

    return None


def get_client_ip(request: Request, trust_proxy_headers: bool = True) -> str:
    """
    Resolve the requester's IP.

    Production: Caddy is the only public entrypoint and sets X-Real-IP /
    X-Forwarded-For from {client_ip} (the TCP peer connecting to :443).
    """
    if trust_proxy_headers:
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            parsed = _parse_ip(real_ip)
            if parsed:
                return parsed

        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            resolved = _ip_from_forwarded(forwarded)
            if resolved:
                return resolved

    if request.client and request.client.host:
        parsed = _parse_ip(request.client.host)
        if parsed and _is_public_ip(parsed):
            return parsed

    return "unknown"
