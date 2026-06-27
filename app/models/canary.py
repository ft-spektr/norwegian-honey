from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CanaryHitRecord(BaseModel):
    token: str
    client_ip: str
    user_agent: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    timestamp: datetime
    referer: str | None = None
    method: str = "GET"
    trap: str = "images"  # images | portfolio


class CanaryHitResponse(BaseModel):
    id: int | str
    token: str
    client_ip: str
    timestamp: datetime


class CanaryTokenInfo(BaseModel):
    token: str
    embed_url: str
    html_snippet: str
    trap: str = "images"
    link_url: str | None = None
