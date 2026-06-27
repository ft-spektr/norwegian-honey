"""Extract client IP behind reverse proxies (OpSec-critical for canary accuracy)."""

from __future__ import annotations

import ipaddress

from fastapi import Request

# RFC 1918 + Docker bridge ranges — never treat as the real client when spoofed in XFF.
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return False
    return not any(addr in net for net in _PRIVATE_NETWORKS)


def get_client_ip(request: Request, trust_proxy_headers: bool = True) -> str:
    """
    Resolve the requester's IP.

    OpSec: Only trust proxy headers when the app sits behind a known reverse
    proxy (Caddy). Prefer X-Real-IP (set by our proxy, not sent by browsers).
    """
    if trust_proxy_headers:
        real_ip = request.headers.get("x-real-ip")
        if real_ip and _is_public_ip(real_ip):
            return real_ip.strip()

        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Use the last public IP — our edge proxy appends the real client.
            for hop in reversed([h.strip() for h in forwarded.split(",") if h.strip()]):
                if _is_public_ip(hop):
                    return hop

    if request.client and request.client.host and _is_public_ip(request.client.host):
        return request.client.host
    return "unknown"
