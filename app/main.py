"""FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.config import get_settings
from app.core.cache import osint_cache
from app.routers import analyze, canary, osint
from app.routers.canary import set_canary_storage
from app.services.canary.storage import build_canary_storage


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    osint_cache._ttl = settings.osint_cache_ttl  # noqa: SLF001 — startup wiring

    storage = build_canary_storage(settings)
    await storage.init()
    set_canary_storage(storage)

    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Lightweight self-hosted phishing email investigative toolkit.",
        debug=settings.debug,
        lifespan=lifespan,
        # OpSec: disable public OpenAPI on production deployments if desired
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # OpSec: restrict CORS on isolated VPS — tighten origins in production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.debug else [],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.include_router(analyze.router)
    app.include_router(osint.router)
    app.include_router(canary.router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
