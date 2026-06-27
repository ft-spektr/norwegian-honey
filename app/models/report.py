"""Threat score report models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.models.analyze import HeaderAnalysisResponse
from app.models.osint import OSINTQueryResponse


class ScoreFinding(BaseModel):
    category: str
    code: str
    severity: str
    points: int
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class CategoryScore(BaseModel):
    name: str
    score: int = Field(ge=0, le=100)
    weight: float
    findings: list[ScoreFinding] = Field(default_factory=list)


class ThreatScoreReport(BaseModel):
    overall_score: int = Field(ge=0, le=100)
    verdict: str
    summary: str
    from_address: str | None = None
    from_domain: str | None = None
    subject: str | None = None
    categories: list[CategoryScore] = Field(default_factory=list)
    findings: list[ScoreFinding] = Field(default_factory=list)
    analysis: HeaderAnalysisResponse | None = None
    osint: OSINTQueryResponse | None = None


class ThreatScoreRequest(BaseModel):
    analysis: HeaderAnalysisResponse
    osint: OSINTQueryResponse | None = None
    include_source: bool = False
