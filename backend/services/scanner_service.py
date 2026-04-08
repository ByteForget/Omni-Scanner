from __future__ import annotations

from typing import Any

from scanner_core import run_full_scan


from backend.services.scan_manager import scan_manager

def perform_scan_background(request: dict[str, Any]):
    """
    Wrapper for run_full_scan to be run in a background thread.
    Updates the global scan_manager state.
    """
    target = request.get("target")
    mods = request.get("modules", [])
    scan_type = "recon" if mods == ["port_scanner"] else "web"
    scan_manager.start_scan(target, scan_type=scan_type)

    try:
        def on_progress(pct, label, log):
            scan_manager.update_progress(pct, label, log)

        results = run_full_scan(
            target,
            modules=request.get("modules"),
            cookies=request.get("cookies"),
            deep=request.get("deep", False),
            dvwa=request.get("dvwa", False),
            workers=request.get("workers", 5),
            write_reports=request.get("write_reports", False),
            output_base=request.get("output_base", "scan_report"),
            reports_dir=request.get("reports_dir", "reports"),
            generate_html=request.get("generate_html", True),
            generate_pdf=request.get("generate_pdf", True),
            on_progress=on_progress,
            is_cancelled=scan_manager.is_cancelled
        )
        scan_manager.complete_scan(results)
    except Exception as e:
        import traceback
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        scan_manager.fail_scan(error_msg)

def perform_scan(request: dict[str, Any]) -> dict[str, Any]:
    """
    Service layer for scan requests (synchronous).
    Kept for backward compatibility if needed, but primary use will be background.
    """
    return run_full_scan(**request)
