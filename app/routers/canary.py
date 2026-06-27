"""
Canary / tracking-pixel honeypot router.

OpSec notes (read before deploying):
- Disable DEBUG and strip Server/X-Powered-By headers at the reverse proxy.
- Serve the pixel from a neutral-looking path (/images/) on a dedicated subdomain.
- Do not return JSON or error details to the requester — always serve the PNG.
- Rate-limit at the proxy to reduce scanning noise.
- Run on an isolated VPS; never co-host with production identity infrastructure.
- Register tokens server-side before embedding — unregistered tokens are ignored.
"""

from __future__ import annotations

from datetime import datetime, timezone

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from app.config import Settings, get_settings
from app.core.client_ip import get_client_ip
from app.core.limits import CANARY_LOG_HEADERS, CANARY_TOKEN_RE
from app.models.canary import CanaryHitRecord
from app.services.canary.pixel import TRANSPARENT_PNG
from app.services.canary.storage import CanaryStorage, build_canary_storage
from app.services.canary.tokens import CanaryTokenRegistry

router = APIRouter(tags=["canary"])
logger = logging.getLogger(__name__)

_storage: CanaryStorage | None = None
_registry: CanaryTokenRegistry | None = None


def set_canary_storage(storage: CanaryStorage) -> None:
    global _storage
    _storage = storage


def set_token_registry(registry: CanaryTokenRegistry) -> None:
    global _registry
    _registry = registry


def get_canary_storage() -> CanaryStorage:
    if _storage is None:
        raise RuntimeError("Canary storage not initialized")
    return _storage


def get_token_registry() -> CanaryTokenRegistry:
    if _registry is None:
        raise RuntimeError("Canary token registry not initialized")
    return _registry


def _valid_token_format(token: str) -> bool:
    return bool(CANARY_TOKEN_RE.match(token))


@router.get("/images/{token}.png")
async def canary_pixel(
    token: str,
    request: Request,
    settings: Settings = Depends(get_settings),
    storage: CanaryStorage = Depends(get_canary_storage),
    registry: CanaryTokenRegistry = Depends(get_token_registry),
) -> Response:
    """
    Serve a 1x1 transparent PNG and silently log the requester metadata.

    OpSec: response is always identical — no stack traces, no content negotiation.
    Unregistered or malformed tokens still get the PNG but are not persisted.
    """
    if not _valid_token_format(token):
        return _pixel_response()

    if settings.canary_require_registered_token:
        try:
            registered = await registry.is_registered(token)
        except Exception:
            registered = False
        if not registered:
            return _pixel_response()

    client_ip = get_client_ip(request, trust_proxy_headers=settings.trusted_proxy_headers)

    safe_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() in CANARY_LOG_HEADERS
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

    return _pixel_response()


def _pixel_response() -> Response:
    return Response(
        content=TRANSPARENT_PNG,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Server": "nginx",
        },
    )
