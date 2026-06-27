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
    try:
        return str(ipaddress.ip_address(value.strip()))
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


def get_client_ip(request: Request, trust_proxy_headers: bool = True) -> str:
    """
    Resolve the requester's IP.

    In production the API is only reachable from Caddy, which sets X-Real-IP
    from {remote_ip}. Trust that header when it contains a valid IP address.
    """
    if trust_proxy_headers:
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            parsed = _parse_ip(real_ip)
            if parsed:
                return parsed

        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            hops = [h.strip() for h in forwarded.split(",") if h.strip()]
            for hop in reversed(hops):
                parsed = _parse_ip(hop)
                if parsed and _is_public_ip(parsed):
                    return parsed

    if request.client and request.client.host:
        parsed = _parse_ip(request.client.host)
        if parsed and _is_public_ip(parsed):
            return parsed

    return "unknown"
