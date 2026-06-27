"""Authentication and request hardening for investigative endpoints."""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, status

from app.config import Settings, get_settings


def require_investigator(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> None:
    """
    Protect /analyze and /osint from public abuse.

    Canary pixels stay unauthenticated — mail clients cannot send API keys.
    When INVESTIGATOR_API_KEY is unset, debug mode allows open access for local dev.
    """
    if not settings.investigator_api_key:
        if settings.debug:
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable",
        )

    provided = request.headers.get("x-api-key", "")
    if not provided or not secrets.compare_digest(provided, settings.investigator_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )
