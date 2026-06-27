"""Canary trap investigation export models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.analyze import HeaderAnalysisResponse
from app.models.canary import StoredCanaryHit
from app.models.osint import OSINTQueryResponse
from app.models.report import ThreatScoreReport


class IPProfile(BaseModel):
    ip: str
    hit_ids: list[int] = Field(default_factory=list)
    hit_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    user_agents: list[str] = Field(default_factory=list)
    traps: list[str] = Field(default_factory=list)
    role: str
    notes: list[str] = Field(default_factory=list)
    osint: dict[str, Any] = Field(default_factory=dict)


class CanaryInvestigationReport(BaseModel):
    exported_at: datetime
    token: str | None = None
    trap: str | None = None
    hit_count: int = 0
    unique_ip_count: int = 0
    summary: str
    timeline: list[StoredCanaryHit] = Field(default_factory=list)
    ip_profiles: list[IPProfile] = Field(default_factory=list)
    osint: OSINTQueryResponse | None = None
    analysis: HeaderAnalysisResponse | None = None
    threat_report: ThreatScoreReport | None = None


class CanaryInvestigationRequest(BaseModel):
    token: str | None = None
    trap: str | None = None
    run_osint: bool = True
    osint: OSINTQueryResponse | None = None
    analysis: HeaderAnalysisResponse | None = None
    threat_report: ThreatScoreReport | None = None
