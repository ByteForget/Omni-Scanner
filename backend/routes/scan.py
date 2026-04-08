from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from backend.services.scanner_service import perform_scan, perform_scan_background
from backend.services.scan_manager import scan_manager


router = APIRouter()


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target URL, IPv4, or host to analyze.")
    modules: Optional[list[str]] = Field(default=None, description="Module names to run; default runs all.")
    cookies: Optional[str] = Field(default=None, description="Cookie string e.g. 'PHPSESSID=12345; security=low'.")
    deep: bool = Field(default=False, description="Enable deep scan behavior.")
    dvwa: bool = Field(default=False, description="Attempt DVWA auto-login (admin:password).")
    workers: int = Field(default=5, ge=1, le=50, description="Concurrent scan workers.")


    write_reports: bool = Field(default=False, description="Whether to also write JSON/HTML/PDF to disk.")
    output_base: str = Field(default="scan_report", description="Base name for report files when writing reports.")
    reports_dir: str = Field(default="reports", description="Reports output directory.")
    generate_html: bool = Field(default=True, description="When write_reports is true, generate HTML.")
    generate_pdf: bool = Field(default=True, description="When write_reports is true, generate PDF (requires reportlab).")


@router.post("/scan")
def scan(req: ScanRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:

    background_tasks.add_task(perform_scan_background, req.model_dump())
    return {"status": "started", "message": "Scan initiated in background."}

@router.get("/scan/status")
def get_scan_status():
    return scan_manager.get_status()

@router.post("/api/scan/stop")
def stop_scan():
    scan_manager.cancel_scan()
    return {"status": "stopping", "message": "Scan termination signal sent."}

