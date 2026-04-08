"""
Scanner core: orchestrates module execution and returns structured JSON.

This module intentionally contains no UI/framework code so it can be reused by
CLI entrypoints and the FastAPI backend.
"""

from __future__ import annotations

import concurrent.futures
import inspect
import time
from datetime import datetime
from typing import Any, Callable
from urllib.parse import urlparse

import os
import requests
from bs4 import BeautifulSoup

from modules import get_available_modules
from utils.logger import logger
from utils.reporter import Reporter


def _parse_cookie_string(cookies: str) -> dict[str, str]:
    cookies_dict: dict[str, str] = {}
    for cookie in cookies.split(";"):
        if "=" in cookie:
            k, v = cookie.strip().split("=", 1)
            cookies_dict[k] = v
    return cookies_dict


def _auto_login_dvwa(session: requests.Session, target: str) -> None:
    parsed_target = urlparse(target)
    if not parsed_target.scheme or not parsed_target.netloc:
        raise ValueError("DVWA login requires a full URL with scheme and host.")

    base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
    login_url = f"{base_url}/login.php"


    if "vulnerabilities" in parsed_target.path:
        login_url = f"{base_url}{parsed_target.path.split('vulnerabilities')[0]}login.php"

    logger.info(f"[*] Attempting automatic DVWA login at {login_url}...")
    r = session.get(login_url, timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})

    if not token_input:
        raise RuntimeError("Could not find 'user_token' on DVWA login page (not DVWA?).")

    token = token_input.get("value")
    data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token,
    }
    session.post(login_url, data=data, timeout=10)
    session.cookies.set("security", "low")
    logger.info("[+] Successfully authenticated to DVWA. Session seeded.")


def _should_pass_forms(execute_func: Callable[..., Any]) -> bool:
    try:
        params = inspect.signature(execute_func).parameters
        return "forms" in params
    except (TypeError, ValueError):

        return hasattr(execute_func, "__code__") and "forms" in execute_func.__code__.co_varnames


def run_full_scan(
    target: str,
    *,
    modules: list[str] | None = None,
    cookies: str | None = None,
    deep: bool = False,
    dvwa: bool = False,
    workers: int = 5,
    write_reports: bool = False,
    output_base: str = "scan_report",
    reports_dir: str = "reports",
    generate_html: bool = True,
    generate_pdf: bool = True,
    on_progress: Callable[[int, str, str | None], None] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """
    Run a full vulnerability scan and return structured JSON results.

    Args:
        target: Initial URL, IPv4, or host identifier to analyze.
        modules: Optional list of module names to execute. Use ["all"] (default)
                 to run every discovered module.
        cookies: Optional "k=v; k2=v2" cookie string for authenticated scanning.
        deep: Enable deep scanning behavior (e.g., smart parameter fuzzing).
        dvwa: Attempt DVWA auto-login (admin:password).
        workers: Thread pool size for URL scanning concurrency.
        write_reports: If True, also emit JSON/HTML/PDF report files into `reports_dir`.
        output_base: Base filename for the non-timestamped scan artifacts.
        reports_dir: Output directory for report artifacts.
        generate_html: If write_reports is True, generate HTML report too.
        generate_pdf: If write_reports is True, generate PDF report too.

    Returns:
        Structured scan payload (JSON-serializable).
    """

    modules = modules or ["all"]

    available_modules = get_available_modules()
    if not available_modules:
        raise RuntimeError("No valid modules found! Please insert them into the 'modules' folder.")

    if on_progress: on_progress(5, "Detecting modules...", f"Detected modules: {', '.join(available_modules.keys())}")
    logger.info(f"Detected modules: {', '.join(available_modules.keys())}")

    modules_to_run: dict[str, Callable[..., Any]] = {}
    if "all" in modules:
        modules_to_run = dict(available_modules)
    else:
        for mod in modules:
            if mod in available_modules:
                modules_to_run[mod] = available_modules[mod]
            else:
                logger.warning(f"Requested module '{mod}' is not recognized. Check spelling.")

    if not modules_to_run:
        raise ValueError("No executable modules selected. Aborting safely.")

    session = requests.Session()
    if cookies:
        cookies_dict = _parse_cookie_string(cookies)
        session.cookies.update(cookies_dict)
        logger.info(f"[+] Authenticated scanning enabled. Injected {len(cookies_dict)} cookies.")

    if dvwa:
        _auto_login_dvwa(session=session, target=target)

    scan_mode_str = "Deep Scan (Smart Fuzzer)" if deep else "Normal Mode"
    scan_payload: dict[str, Any] = {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "scan_mode": scan_mode_str,
        "discovered_urls": [target],
        "results": {},
    }


    urls_to_scan = [target]
    discovered_forms: list[dict[str, Any]] = []

    if "crawler" in modules_to_run:
        logger.info("[*] Executing module: crawler (Phase 1/2: Discovery)...")
        crawler_func = modules_to_run.pop("crawler")
        try:
            crawler_result = crawler_func(target, session=session, deep_scan=deep)
            scan_payload["results"]["crawler"] = crawler_result

            discovered = crawler_result.get("urls", []) if isinstance(crawler_result, dict) else []
            if discovered:
                urls_to_scan.extend(discovered)
                urls_to_scan = sorted(set(urls_to_scan))
                scan_payload["discovered_urls"] = urls_to_scan

            discovered_forms = (
                crawler_result.get("forms", []) if isinstance(crawler_result, dict) else []
            )

            if on_progress: on_progress(25, "Discovery Complete", f"Crawler finished. Total URLs to scan: {len(urls_to_scan)}")
            logger.info(f"[+] Crawler finished. Total URLs to scan: {len(urls_to_scan)}")
        except Exception as e:
            logger.error(f"[-] Execution crashed in 'crawler': {e}")
            scan_payload["results"]["crawler"] = {"fatal_error": str(e)}


    mod_count = len(modules_to_run)
    for i, (mod_name, execute_func) in enumerate(modules_to_run.items()):
        if is_cancelled and is_cancelled():
            logger.info("[!] Scan cancellation detected. Aborting at module start.")
            break

        current_pct = 25 + int((i / mod_count) * 65)
        if on_progress: on_progress(current_pct, f"Executing: {mod_name}", f"Starting module: {mod_name}")
        logger.info(f"[*] Executing module: {mod_name} (Phase 2/2: Exploitation)...")
        scan_payload["results"][mod_name] = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_url = {}

            def scan_url(url_to_test: str):
                if is_cancelled and is_cancelled():
                    return url_to_test, {"cancelled": True}

                logger.info(f"   -> [{mod_name}] Scanning target string: {url_to_test}")
                try:
                    forms_for_this_url = [
                        f
                        for f in discovered_forms
                        if f.get("action", "").startswith(url_to_test)
                    ]

                    if _should_pass_forms(execute_func):
                        return url_to_test, execute_func(
                            url_to_test, forms=forms_for_this_url, session=session
                        )

                    return url_to_test, execute_func(url_to_test, session=session)
                except Exception as e:
                    logger.error(f"   [-] Crash on {url_to_test}: {e}")
                    return url_to_test, {"fatal_error": str(e)}

            for u in urls_to_scan:
                future_to_url[executor.submit(scan_url, u)] = u

            import concurrent.futures as _cf

            for future in _cf.as_completed(future_to_url):
                u_completed = future_to_url[future]
                try:
                    res_url, mod_res = future.result()
                    if isinstance(mod_res, dict) and mod_res.get("cancelled"):
                        continue
                    scan_payload["results"][mod_name][res_url] = mod_res
                except Exception as exc:
                    logger.error(f"   [-] Thread exception on {u_completed}: {exc}")
                    scan_payload["results"][mod_name][u_completed] = {"fatal_error": str(exc)}

        logger.info(f"[+] Module '{mod_name}' finished on all targets.")

    report_paths: dict[str, str] = {}
    if write_reports:
        reporter = Reporter(output_dir=reports_dir)

        parsed_netloc = urlparse(target).netloc
        safe_target = parsed_netloc.replace(":", "_").replace(".", "_") if parsed_netloc else "target"
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        history_base = f"scan_{safe_target}_{timestamp}"


        report_paths["history_json"] = os.path.join(reports_dir, f"{history_base}.json").replace("\\", "/")
        report_paths["history_html"] = os.path.join(reports_dir, f"{history_base}.html").replace("\\", "/")
        report_paths["history_pdf"] = os.path.join(reports_dir, f"{history_base}.pdf").replace("\\", "/")

        report_paths["json"] = os.path.join(reports_dir, f"{output_base}.json").replace("\\", "/")
        if generate_html:
            report_paths["html"] = os.path.join(reports_dir, f"{output_base}.html").replace("\\", "/")
        if generate_pdf:
            report_paths["pdf"] = os.path.join(reports_dir, f"{output_base}.pdf").replace("\\", "/")

        scan_payload["report_paths"] = report_paths


        reporter.generate_json(scan_payload, filename=f"{history_base}.json")
        reporter.generate_html(scan_payload, filename=f"{history_base}.html")
        reporter.generate_pdf(scan_payload, filename=f"{history_base}.pdf")

        reporter.generate_json(scan_payload, filename=f"{output_base}.json")
        if generate_html:
            reporter.generate_html(scan_payload, filename=f"{output_base}.html")
        if generate_pdf:
            reporter.generate_pdf(scan_payload, filename=f"{output_base}.pdf")

        if on_progress: on_progress(100, "Scan Complete", "Reports generated successfully.")

    return scan_payload

