"""Extract client IP behind reverse proxies (OpSec-critical for canary accuracy)."""

from fastapi import Request


def get_client_ip(request: Request, trust_proxy_headers: bool = True) -> str:
    """
  Resolve the requester's IP.

  OpSec: Only trust X-Forwarded-For / X-Real-IP when the app sits behind a
  known reverse proxy (nginx, Caddy, Traefik). Otherwise attackers can spoof
  these headers. Set TRUSTED_PROXY_HEADERS=false on direct exposure.
  """
    if trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # First hop is the original client per RFC 7239 convention.
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

    if request.client and request.client.host:
        return request.client.host
    return "unknown"
