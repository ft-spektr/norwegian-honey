"""
Canary / tracking-pixel honeypot router.

OpSec notes (read before deploying):
- Disable DEBUG and strip Server/X-Powered-By headers at the reverse proxy.
- Serve the pixel from a neutral-looking path (/images/) on a dedicated subdomain.
- Do not return JSON or error details to the requester — always serve the PNG.
- Rate-limit at the proxy to reduce scanning noise.
- Run on an isolated VPS; never co-host with production identity infrastructure.
"""

from __future__ import annotations

from datetime import datetime, timezone

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from app.config import Settings, get_settings
from app.core.client_ip import get_client_ip
from app.models.canary import CanaryHitRecord
from app.services.canary.pixel import TRANSPARENT_PNG
from app.services.canary.storage import CanaryStorage, build_canary_storage

router = APIRouter(tags=["canary"])
logger = logging.getLogger(__name__)

# Module-level storage set during app lifespan
_storage: CanaryStorage | None = None


def set_canary_storage(storage: CanaryStorage) -> None:
    global _storage
    _storage = storage


def get_canary_storage() -> CanaryStorage:
    if _storage is None:
        raise RuntimeError("Canary storage not initialized")
    return _storage


@router.get("/images/{token}.png")
async def canary_pixel(
    token: str,
    request: Request,
    settings: Settings = Depends(get_settings),
    storage: CanaryStorage = Depends(get_canary_storage),
) -> Response:
    """
    Serve a 1x1 transparent PNG and silently log the requester metadata.

    OpSec: response is always identical — no stack traces, no content negotiation.
    """
    client_ip = get_client_ip(request, trust_proxy_headers=settings.trusted_proxy_headers)

    # Redact sensitive proxy/auth headers before persistence
    skip_headers = {"authorization", "cookie", "x-api-key"}
    safe_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in skip_headers
    }

    hit = CanaryHitRecord(
        token=token,
        client_ip=client_ip,
        user_agent=request.headers.get("user-agent"),
        referer=request.headers.get("referer"),
        method=request.method,
        headers=safe_headers,
        timestamp=datetime.now(timezone.utc),
    )

    try:
        result = await storage.record_hit(hit)
        if settings.debug:
            logger.info(
                "canary hit recorded id=%s token=%s ip=%s",
                result.id,
                token,
                client_ip,
            )
    except Exception:
        if settings.debug:
            logger.exception("canary hit storage failed token=%s", token)
        # OpSec: never leak storage errors to the pixel consumer
        pass

    return Response(
        content=TRANSPARENT_PNG,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            # OpSec: generic server identity — override at reverse proxy too
            "Server": "nginx",
        },
    )
