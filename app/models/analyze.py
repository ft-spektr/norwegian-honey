from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AuthResultStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NEUTRAL = "neutral"
    SOFTFAIL = "softfail"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class ReceivedHop(BaseModel):
    index: int
    raw: str
    from_host: str | None = None
    by_host: str | None = None
    with_protocol: str | None = None
    timestamp: str | None = None
    source_ip: str | None = None


class AuthCheckResult(BaseModel):
    mechanism: str  # spf | dkim | dmarc
    status: AuthResultStatus
    domain: str | None = None
    selector: str | None = None
    detail: str | None = None
    dns_record_found: bool | None = None


class AnomalySeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Anomaly(BaseModel):
    code: str
    severity: AnomalySeverity
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class HeaderAnalysisRequest(BaseModel):
    """Analyze raw RFC 822 headers (body optional)."""

    raw_headers: str | None = None
    raw_email: str | None = None


class HeaderAnalysisResponse(BaseModel):
    message_id: str | None = None
    from_address: str | None = None
    from_domain: str | None = None
    reply_to: str | None = None
    reply_to_domain: str | None = None
    return_path: str | None = None
    return_path_domain: str | None = None
    subject: str | None = None
    date: str | None = None
    x_originating_ip: str | None = None
    received_hops: list[ReceivedHop] = Field(default_factory=list)
    authentication: list[AuthCheckResult] = Field(default_factory=list)
    extracted_ips: list[str] = Field(default_factory=list)
    extracted_domains: list[str] = Field(default_factory=list)
    extracted_emails: list[str] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)
