"""FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.config import get_settings
from app.core.cache import osint_cache
from app.core.middleware import MaxBodySizeMiddleware
from app.routers import analyze, canary, osint
from app.routers.canary import set_canary_storage, set_token_registry
from app.services.canary.storage import build_canary_storage
from app.services.canary.tokens import CanaryTokenRegistry


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    osint_cache._ttl = settings.osint_cache_ttl  # noqa: SLF001 — startup wiring

    storage = build_canary_storage(settings)
    await storage.init()
    set_canary_storage(storage)

    registry = CanaryTokenRegistry(settings.canary_db_path)
    await registry.init()
    set_token_registry(registry)

    pruned = await storage.prune_old_hits(settings.canary_hit_retention_days)
    if pruned and settings.debug:
        import logging

        logging.getLogger(__name__).info("pruned %s stale canary hits", pruned)

    yield


def create_app() -> FastAPI:
    settings = get_settings()
    production = not settings.debug

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Lightweight self-hosted phishing email investigative toolkit.",
        debug=settings.debug,
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.debug else [],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    app.add_middleware(
        MaxBodySizeMiddleware,
        max_bytes=settings.max_request_body_bytes,
    )

    if production and settings.allowed_hosts:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.allowed_hosts,
        )

    app.include_router(analyze.router)
    app.include_router(osint.router)
    app.include_router(canary.router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        # OpSec: no version string — reduces fingerprinting after canary discovery
        return {"status": "ok"}

    return app


app = create_app()
