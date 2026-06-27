"""Routers for email header analysis."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.config import Settings, get_settings
from app.core.security import require_investigator
from app.models.analyze import HeaderAnalysisRequest, HeaderAnalysisResponse
from app.services.header_evaluator import (
    parse_headers_only,
    parse_raw_email,
)

router = APIRouter(
    prefix="/analyze",
    tags=["analyze"],
    dependencies=[Depends(require_investigator)],
)


def _check_input_size(text: str, settings: Settings) -> None:
    if len(text) > settings.max_analyze_input_chars:
        raise HTTPException(status_code=413, detail="Input too large")


@router.post("/headers", response_model=HeaderAnalysisResponse)
async def analyze_headers(
    payload: HeaderAnalysisRequest,
    settings: Settings = Depends(get_settings),
) -> HeaderAnalysisResponse:
    """Analyze raw email headers or a full raw message."""
    if payload.raw_email:
        _check_input_size(payload.raw_email, settings)
        return parse_raw_email(payload.raw_email)
    if payload.raw_headers:
        _check_input_size(payload.raw_headers, settings)
        return parse_headers_only(payload.raw_headers)
    raise HTTPException(status_code=400, detail="Provide raw_headers or raw_email")


@router.post("/eml", response_model=HeaderAnalysisResponse)
async def analyze_eml_upload(
    file: UploadFile = File(...),
    settings: Settings = Depends(get_settings),
) -> HeaderAnalysisResponse:
    """Upload an .eml file for header analysis."""
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Expected a .eml file upload")

    content = await file.read(settings.max_eml_upload_bytes + 1)
    if len(content) > settings.max_eml_upload_bytes:
        raise HTTPException(status_code=413, detail="File too large")

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1", errors="replace")

    _check_input_size(text, settings)
    return parse_raw_email(text)
