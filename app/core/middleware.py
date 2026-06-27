"""ASGI middleware for request size limits."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies before they reach route handlers."""

    def __init__(self, app, max_bytes: int) -> None:
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in {"POST", "PUT", "PATCH"}:
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > self._max_bytes:
                        return JSONResponse(
                            status_code=413,
                            content={"detail": "Request entity too large"},
                        )
                except ValueError:
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length"},
                    )
        return await call_next(request)
