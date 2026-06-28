"""Threat score report router."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.config import Settings, get_settings
from app.core.security import require_investigator
from app.models.osint import OSINTQueryRequest
from app.models.canary_investigation import CanaryInvestigationReport, CanaryInvestigationRequest
from app.models.report import ReportFromAnalysisRequest, ThreatScoreReport, ThreatScoreRequest
from app.routers.canary import get_canary_storage
from app.services.canary_investigation import build_canary_investigation
from app.services.osint.aggregator import aggregate_osint
from app.services.threat_scorer import build_threat_report, merge_osint

router = APIRouter(
    prefix="/report",
    tags=["report"],
    dependencies=[Depends(require_investigator)],
)


@router.post("/score", response_model=ThreatScoreReport)
async def report_score(payload: ThreatScoreRequest) -> ThreatScoreReport:
    """Build a phishing/spam threat score from analysis and optional OSINT results."""
    osint = merge_osint(payload.osint, payload.investigation.osint if payload.investigation else None)
    return build_threat_report(
        payload.analysis,
        osint,
        investigation=payload.investigation,
        include_source=payload.include_source,
    )


@router.post("/from-analysis", response_model=ThreatScoreReport)
async def report_from_analysis(
    payload: ReportFromAnalysisRequest,
    settings: Settings = Depends(get_settings),
) -> ThreatScoreReport:
    """Run OSINT on analysis entities, optionally merge canary investigation, then score."""
    analysis = payload.analysis
    osint_request = OSINTQueryRequest(
        ips=analysis.extracted_ips[: settings.osint_max_entities_per_type],
        domains=analysis.extracted_domains[: settings.osint_max_entities_per_type],
        emails=analysis.extracted_emails[: settings.osint_max_entities_per_type],
    )
    osint = await aggregate_osint(osint_request, settings)
    if payload.investigation and payload.investigation.osint:
        osint = merge_osint(osint, payload.investigation.osint)
    return build_threat_report(
        analysis,
        osint,
        investigation=payload.investigation,
        include_source=payload.include_source,
    )


@router.post("/canary-investigation", response_model=CanaryInvestigationReport)
async def report_canary_investigation(
    payload: CanaryInvestigationRequest,
    settings: Settings = Depends(get_settings),
    storage=Depends(get_canary_storage),
) -> CanaryInvestigationReport:
    """Export canary hits with IP profiles, optional OSINT, analysis, and threat report."""
    hits = await storage.list_hits(token=payload.token, trap=payload.trap)
    osint = payload.osint
    if osint is None and payload.run_osint:
        ips = list(dict.fromkeys(hit.client_ip for hit in hits))
        if ips:
            osint = await aggregate_osint(
                OSINTQueryRequest(ips=ips[: settings.osint_max_entities_per_type]),
                settings,
            )

    return build_canary_investigation(
        hits,
        token=payload.token,
        trap=payload.trap,
        osint=osint,
        analysis=payload.analysis,
        threat_report=payload.threat_report,
    )
