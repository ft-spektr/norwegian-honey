from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class OSINTQueryRequest(BaseModel):
    ips: list[str] = Field(default_factory=list, max_length=10)
    domains: list[str] = Field(default_factory=list, max_length=10)
    emails: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("ips", "domains", "emails")
    @classmethod
    def _cap_entity_length(cls, values: list[str]) -> list[str]:
        return [v[:253] for v in values if v][:10]


class IPIntelResult(BaseModel):
    ip: str
    source: str
    cached: bool = False
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class DomainIntelResult(BaseModel):
    domain: str
    source: str
    cached: bool = False
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class EmailIntelResult(BaseModel):
    email: str
    domain: str
    source: str
    cached: bool = False
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class OSINTQueryResponse(BaseModel):
    ips: list[IPIntelResult] = Field(default_factory=list)
    domains: list[DomainIntelResult] = Field(default_factory=list)
    emails: list[EmailIntelResult] = Field(default_factory=list)
