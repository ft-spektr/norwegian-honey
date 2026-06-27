"""
Canary / tracking-pixel honeypot router.

OpSec notes (read before deploying):
- Disable DEBUG and strip Server/X-Powered-By headers at the reverse proxy.
- Serve traps from neutral-looking paths (/images/, /portfolio/).
- Do not return JSON or error details to the requester — always serve the decoy.
- Rate-limit at the proxy to reduce scanning noise.
- Run on an isolated VPS; never co-host with production identity infrastructure.
- Register tokens server-side before embedding — unregistered tokens are ignored.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from app.config import Settings, get_settings
from app.core.client_ip import get_client_ip
from app.core.limits import CANARY_LOG_HEADERS, CANARY_TOKEN_RE
from app.models.canary import CanaryHitRecord
from app.services.canary.pixel import TRANSPARENT_PNG
from app.services.canary.portfolio import PORTFOLIO_HTML
from app.services.canary.storage import CanaryStorage
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


async def _should_log_hit(
    token: str,
    settings: Settings,
    registry: CanaryTokenRegistry,
) -> bool:
    if not _valid_token_format(token):
        return False
    if not settings.canary_require_registered_token:
        return True
    try:
        return await registry.is_registered(token)
    except Exception:
        return False


async def _record_hit_if_valid(
    *,
    token: str,
    trap: str,
    request: Request,
    settings: Settings,
    storage: CanaryStorage,
    registry: CanaryTokenRegistry,
) -> None:
    if not await _should_log_hit(token, settings, registry):
        return

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
        trap=trap,
    )

    try:
        result = await storage.record_hit(hit)
        if settings.debug:
            logger.info(
                "canary hit recorded id=%s trap=%s token=%s ip=%s",
                result.id,
                trap,
                token,
                client_ip,
            )
    except Exception:
        if settings.debug:
            logger.exception("canary hit storage failed trap=%s token=%s", trap, token)


async def _canary_handler(
    token: str,
    trap: str,
    request: Request,
    settings: Settings,
    storage: CanaryStorage,
    registry: CanaryTokenRegistry,
    respond: Callable[[], Response],
) -> Response:
    await _record_hit_if_valid(
        token=token,
        trap=trap,
        request=request,
        settings=settings,
        storage=storage,
        registry=registry,
    )
    return respond()


@router.get("/images/{token}.png")
async def canary_pixel(
    token: str,
    request: Request,
    settings: Settings = Depends(get_settings),
    storage: CanaryStorage = Depends(get_canary_storage),
    registry: CanaryTokenRegistry = Depends(get_token_registry),
) -> Response:
    """Serve a 1x1 transparent PNG and silently log the requester metadata."""
    return await _canary_handler(
        token, "images", request, settings, storage, registry, _pixel_response
    )


@router.get("/portfolio/{token}")
async def canary_portfolio(
    token: str,
    request: Request,
    settings: Settings = Depends(get_settings),
    storage: CanaryStorage = Depends(get_canary_storage),
    registry: CanaryTokenRegistry = Depends(get_token_registry),
) -> Response:
    """Serve a generic portfolio page and silently log the requester metadata."""
    return await _canary_handler(
        token, "portfolio", request, settings, storage, registry, _portfolio_response
    )


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


def _portfolio_response() -> Response:
    return Response(
        content=PORTFOLIO_HTML,
        media_type="text/html; charset=utf-8",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Server": "nginx",
        },
    )
