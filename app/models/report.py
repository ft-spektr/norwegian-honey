"""Threat score report models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

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
    investigation: CanaryInvestigationReport | None = None


class ThreatScoreRequest(BaseModel):
    analysis: HeaderAnalysisResponse
    osint: OSINTQueryResponse | None = None
    investigation: CanaryInvestigationReport | None = None
    include_source: bool = False


class ReportFromAnalysisRequest(BaseModel):
    """Analysis JSON plus optional canary investigation export."""

    analysis: HeaderAnalysisResponse
    investigation: CanaryInvestigationReport | None = None
    include_source: bool = True

    @model_validator(mode="before")
    @classmethod
    def accept_legacy_analysis_body(cls, data: object) -> object:
        """Allow POST body to be a bare HeaderAnalysisResponse for backward compatibility."""
        if isinstance(data, dict) and "analysis" not in data and "from_domain" in data:
            return {"analysis": data, "include_source": True}
        return data


def _rebuild_report_models() -> None:
    from app.models.canary_investigation import CanaryInvestigationReport

    types_namespace = {
        "CanaryInvestigationReport": CanaryInvestigationReport,
        "ThreatScoreReport": ThreatScoreReport,
    }
    ThreatScoreReport.model_rebuild(_types_namespace=types_namespace)
    ThreatScoreRequest.model_rebuild(_types_namespace=types_namespace)
    ReportFromAnalysisRequest.model_rebuild(_types_namespace=types_namespace)
    CanaryInvestigationReport.model_rebuild(_types_namespace=types_namespace)


_rebuild_report_models()
