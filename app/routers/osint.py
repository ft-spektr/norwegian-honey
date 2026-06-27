"""OSINT enrichment router."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.config import Settings, get_settings
from app.models.analyze import HeaderAnalysisResponse
from app.models.osint import OSINTQueryRequest, OSINTQueryResponse
from app.services.osint.aggregator import aggregate_osint

router = APIRouter(prefix="/osint", tags=["osint"])


@router.post("/query", response_model=OSINTQueryResponse)
async def osint_query(
    request: OSINTQueryRequest,
    settings: Settings = Depends(get_settings),
) -> OSINTQueryResponse:
    """Query public OSINT sources for IPs, domains, and email addresses."""
    return await aggregate_osint(request, settings)


@router.post("/from-analysis", response_model=OSINTQueryResponse)
async def osint_from_analysis(
    analysis: HeaderAnalysisResponse,
    settings: Settings = Depends(get_settings),
) -> OSINTQueryResponse:
    """Convenience endpoint: run OSINT on entities extracted by /analyze."""
    request = OSINTQueryRequest(
        ips=analysis.extracted_ips,
        domains=analysis.extracted_domains,
        emails=analysis.extracted_emails,
    )
    return await aggregate_osint(request, settings)
