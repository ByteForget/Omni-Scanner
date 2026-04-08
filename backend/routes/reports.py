from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from utils.ai_analyzer import summarize_vulnerability
from utils.reporter import Reporter
from backend.services.scan_manager import scan_manager


router = APIRouter()


def _safe_report_name(name: str) -> str:

    if not name or name != os.path.basename(name):
        raise ValueError("Invalid report name.")
    if "/" in name or "\\" in name:
        raise ValueError("Invalid report name.")
    allowed_exts = (".json", ".pdf", ".html")
    if not name.lower().endswith(allowed_exts):
        raise ValueError(f"Only {', '.join(allowed_exts)} reports are supported.")
    return name


def _count_findings(payload: dict[str, Any]) -> int:
    results = payload.get("results", {}) if isinstance(payload, dict) else {}
    total = 0
    for mod_name, mod_data in results.items():
        if mod_name == "crawler":
            continue
        if not isinstance(mod_data, dict):
            continue
        for _, u_res in mod_data.items():
            if isinstance(u_res, dict) and u_res.get("vulnerabilities_found"):
                details = u_res.get("details", [])
                if isinstance(details, list):
                    total += len(details)
    return total


def _get_latest_report_for_url(url: str) -> dict[str, Any] | None:
    """
    Finds the most recent JSON report for a target URL by modification time.
    """
    report_dir = "reports"
    if not os.path.isdir(report_dir):
        return None


    files = []
    for f in os.listdir(report_dir):
        if f.lower().endswith(".json"):
            path = os.path.join(report_dir, f)
            files.append((f, os.path.getmtime(path)))


    files.sort(key=lambda x: x[1], reverse=True)


    norm_url = url.rstrip('/')

    for filename, _ in files:
        path = os.path.join(report_dir, filename)
        try:
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            target = data.get("target", "").rstrip('/')
            if target == norm_url:
                return data
        except Exception:
            continue

    return None


@router.get("/reports")
def list_reports() -> JSONResponse:
    report_dir = "reports"
    if not os.path.isdir(report_dir):
        return JSONResponse({"reports": []})

    files = [f for f in os.listdir(report_dir) if f.lower().endswith(".json")]
    files.sort(reverse=True)

    reports: list[dict[str, Any]] = []
    for f in files:
        path = os.path.join(report_dir, f)
        scan_date = None
        findings = 0
        try:
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            scan_date = data.get("scan_date")
            findings = _count_findings(data)
        except Exception:

            try:
                scan_date = datetime.fromtimestamp(os.path.getctime(path)).isoformat()
            except Exception:
                scan_date = None

        reports.append(
            {
                "name": f,
                "scan_date": scan_date,
                "findings": findings,
            }
        )

    return JSONResponse({"reports": reports})


@router.get("/reports/{name}")
def get_report(name: str) -> JSONResponse:
    try:
        safe = _safe_report_name(name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    path = os.path.join("reports", safe)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not found.")

    if safe.lower().endswith(".json"):
        try:
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            return JSONResponse(data)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read report: {e}") from e
    else:

        media_type = "application/pdf" if safe.lower().endswith(".pdf") else "text/html"
        return FileResponse(path, media_type=media_type, filename=safe)


@router.get("/api/ai-analyze")
def ai_analyze_report(url: str, api_key: str = None, skip_pdf: bool = False) -> JSONResponse:
    """
    Finds the most recent scan report for the provided URL and passes it to the AI Integration pipeline.
    """

    target_report = _get_latest_report_for_url(url)

    if not target_report:
        raise HTTPException(status_code=404, detail=f"No scan report found for '{url}'. Please ensure an Omni Scan has successfully completed for this specific target before requesting AI analysis.")


    ai_result = summarize_vulnerability(target_report, api_key=api_key)

    from utils.reporter import Reporter
    rep = Reporter()

    if isinstance(ai_result, str):

        pdf_path = None
        if not skip_pdf:
            pdf_path = rep.generate_ai_pdf(ai_result, url)

        pdf_filename = os.path.basename(pdf_path) if pdf_path else None

        return JSONResponse({
            "status": "success",
            "security_score": 0,
            "risk_level": "UNKNOWN",
            "summary": "Full markdown report generated.",
            "findings": [],
            "pdf_url": f"/reports/{pdf_filename}" if pdf_filename else None,
            "finds_count": 0,
            "scan_date": target_report.get("scan_date", "Recently Completed")
        })

    if isinstance(ai_result, dict):
        if "error" in ai_result:
            raise HTTPException(status_code=500, detail=ai_result["error"])


        pdf_path = None
        if not skip_pdf:
            pdf_source = ai_result.get("report_markdown", ai_result)
            pdf_path = rep.generate_ai_pdf(pdf_source, url)

        pdf_filename = os.path.basename(pdf_path) if pdf_path else None


        ai_result["status"] = "success"
        ai_result["pdf_url"] = f"/reports/{pdf_filename}" if pdf_filename else None
        ai_result["finds_count"] = len(ai_result.get("findings", []))
        ai_result["scan_date"] = target_report.get("scan_date", "Recently Completed")

        return JSONResponse(ai_result)

    raise HTTPException(status_code=500, detail="Unexpected AI Analysis result format.")


@router.get("/api/generate-ai-pdf")
def generate_ai_pdf_report(url: str, api_key: str = None) -> FileResponse:
    """
    Generates a professional AI Threat Report PDF on demand.
    """
    report_dir = "reports"
    if not os.path.isdir(report_dir):
        raise HTTPException(status_code=404, detail="No scan reports exist yet.")


    current_status = scan_manager.get_status()
    if current_status["status"] == "running" and current_status["target"] == url:
        raise HTTPException(
            status_code=400,
            detail="Scan is currently in progress for this target. Please wait for completion before generating the AI report."
        )


    target_report = _get_latest_report_for_url(url)

    if not target_report:
        raise HTTPException(status_code=404, detail=f"No scan report found for '{url}'.")


    ai_result = summarize_vulnerability(target_report, api_key=api_key)

    if isinstance(ai_result, dict) and "error" in ai_result:
        raise HTTPException(status_code=500, detail=ai_result["error"])


    reporter = Reporter(output_dir=report_dir)
    pdf_path = reporter.generate_ai_pdf(ai_result, url)

    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Failed to generate AI PDF report.")

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=os.path.basename(pdf_path)
    )


@router.get("/api/generate-manual-pdf")
def generate_manual_pdf_report_api(url: str) -> FileResponse:
    """
    Generates or regenerates a professional high-fidelity VAPT PDF report on demand.
    """
    report_dir = "reports"
    if not os.path.isdir(report_dir):
        raise HTTPException(status_code=404, detail="No scan reports exist yet.")


    current_status = scan_manager.get_status()
    if current_status["status"] == "running" and current_status["target"] == url:
        raise HTTPException(
            status_code=400,
            detail="Scan is currently in progress for this target. Please wait for completion before generating the PDF report."
        )


    target_report = _get_latest_report_for_url(url)

    if not target_report:
        raise HTTPException(status_code=404, detail=f"No scan report found for '{url}'.")


    reporter = Reporter(output_dir=report_dir)


    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.path).split(':')[0].rstrip('/')
    if '.' in domain:
        sitename = '.'.join(domain.split('.')[:-1])
    else:
        sitename = domain
    if not sitename: sitename = "Target"

    filename = f"Omni_VAPT_Result {sitename}.pdf"


    actual_path = reporter.generate_pdf(target_report, filename=filename)

    if not actual_path or not os.path.exists(actual_path):
        raise HTTPException(status_code=500, detail="Failed to generate high-fidelity PDF report.")

    return FileResponse(
        actual_path,
        media_type="application/pdf",
        filename=os.path.basename(actual_path)
    )


@router.get("/api/generate-manual-ai-report")
def generate_manual_ai_report_api(url: str, api_key: str = None) -> FileResponse:
    """
    Generates a professional AI-driven Manual Pentest Report PDF for the Dashboard.
    """
    from utils.manual_report import generate_manual_ai_report_pdf

    report_dir = "reports"
    if not os.path.isdir(report_dir):
        raise HTTPException(status_code=404, detail="No scan reports exist yet.")


    target_report = _get_latest_report_for_url(url)

    if not target_report:
        raise HTTPException(status_code=404, detail=f"No scan report found for '{url}'.")


    pdf_path = generate_manual_ai_report_pdf(url, target_report, api_key=api_key)

    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail=f"Failed to generate Manual AI PDF report for {url}. This project requires a valid GEMINI_API_KEY for intelligence synthesis.")

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=os.path.basename(pdf_path)
    )

