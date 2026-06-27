"""Shared validation limits for attacker-controlled input."""

from __future__ import annotations

import re

# token_urlsafe(32) ≈ 43 chars; cap rejects path-traversal / padding floods
CANARY_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

# Headers worth keeping for investigation; ignore the rest to limit log poisoning
CANARY_LOG_HEADERS = frozenset(
    {
        "user-agent",
        "referer",
        "accept",
        "accept-language",
        "accept-encoding",
    }
)
