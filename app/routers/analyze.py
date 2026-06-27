"""Routers for email header analysis."""

from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.models.analyze import HeaderAnalysisRequest, HeaderAnalysisResponse
from app.services.header_evaluator import (
    parse_eml_file,
    parse_headers_only,
    parse_raw_email,
)

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post("/headers", response_model=HeaderAnalysisResponse)
async def analyze_headers(payload: HeaderAnalysisRequest) -> HeaderAnalysisResponse:
    """Analyze raw email headers or a full raw message."""
    if payload.raw_email:
        return parse_raw_email(payload.raw_email)
    if payload.raw_headers:
        return parse_headers_only(payload.raw_headers)
    raise HTTPException(status_code=400, detail="Provide raw_headers or raw_email")


@router.post("/eml", response_model=HeaderAnalysisResponse)
async def analyze_eml_upload(file: UploadFile = File(...)) -> HeaderAnalysisResponse:
    """Upload an .eml file for header analysis."""
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Expected a .eml file upload")

    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1", errors="replace")

    return parse_raw_email(text)
