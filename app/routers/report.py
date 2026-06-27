"""Threat score report router."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.config import Settings, get_settings
from app.core.security import require_investigator
from app.models.analyze import HeaderAnalysisResponse
from app.models.osint import OSINTQueryRequest
from app.models.report import ThreatScoreReport, ThreatScoreRequest
from app.services.osint.aggregator import aggregate_osint
from app.services.threat_scorer import build_threat_report

router = APIRouter(
    prefix="/report",
    tags=["report"],
    dependencies=[Depends(require_investigator)],
)


@router.post("/score", response_model=ThreatScoreReport)
async def report_score(payload: ThreatScoreRequest) -> ThreatScoreReport:
    """Build a phishing/spam threat score from analysis and optional OSINT results."""
    return build_threat_report(
        payload.analysis,
        payload.osint,
        include_source=payload.include_source,
    )


@router.post("/from-analysis", response_model=ThreatScoreReport)
async def report_from_analysis(
    analysis: HeaderAnalysisResponse,
    settings: Settings = Depends(get_settings),
) -> ThreatScoreReport:
    """Run OSINT on analysis entities, then produce a threat score report."""
    osint_request = OSINTQueryRequest(
        ips=analysis.extracted_ips[: settings.osint_max_entities_per_type],
        domains=analysis.extracted_domains[: settings.osint_max_entities_per_type],
        emails=analysis.extracted_emails[: settings.osint_max_entities_per_type],
    )
    osint = await aggregate_osint(osint_request, settings)
    return build_threat_report(analysis, osint, include_source=True)
