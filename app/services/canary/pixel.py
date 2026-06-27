"""1x1 transparent PNG pixel (RFC 2397 data URI decoded to bytes)."""

import base64

# Minimal valid 1x1 transparent PNG
_TRANSPARENT_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
    "/x8AAwMCAO+X2ZkAAAAASUVORK5CYII="
)

TRANSPARENT_PNG: bytes = base64.b64decode(_TRANSPARENT_PNG_B64)
