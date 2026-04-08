import requests
from typing import Dict, Any, Optional, List

from utils.logger import logger

def execute(target: str, forms: Optional[List[Dict[str, Any]]] = None, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Execute checks for missing or misconfigured security headers.

    Args:
        target (str): The target URL to scan.
        forms (list): Ignored for header scans.
        session (requests.Session): The optional authenticated session context.

    Returns:
        Dict[str, Any]: A dictionary containing the scan results.
    """
    logger.info(f"Starting Security Headers scan on target: {target}")
    req_client = session if session else requests

    results: Dict[str, Any] = {
        "vulnerabilities_found": False,
        "details": []
    }

    headers_to_check = {
        "Content-Security-Policy": (
            "Missing Content-Security-Policy (CSP)",
            "Medium",
            "CSP helps prevent a wide range of attacks, including Cross-Site Scripting (XSS) and other cross-site injections. Ensure a strict CSP is implemented restricting inline scripts and unauthorized domains."
        ),
        "X-Frame-Options": (
            "Missing X-Frame-Options",
            "Low",
            "Protects the web application against Clickjacking attacks. Set the header to DENY or SAMEORIGIN."
        ),
        "Strict-Transport-Security": (
            "Missing HTTP Strict Transport Security (HSTS)",
            "Medium",
            "Ensures the browser only communicates over HTTPS. Set the Strict-Transport-Security header with an appropriate max-age."
        ),
        "X-Content-Type-Options": (
            "Missing X-Content-Type-Options",
            "Low",
            "Prevents MIME-sniffing attacks by forcing the browser to stick to the declared content type. Set the value to 'nosniff'."
        )
    }

    try:
        resp = req_client.get(target, timeout=10, allow_redirects=True)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        for expected_header, metadata in headers_to_check.items():
            vuln_name, severity, remediation = metadata


            if expected_header.lower() not in resp_headers:
                logger.warning(f"[!] {vuln_name} detected on {target}")
                results["vulnerabilities_found"] = True
                results["details"].append({
                    "type": "Security Misconfiguration",
                    "severity": severity,
                    "parameter": "HTTP Response Header",
                    "cwe": "CWE-1021",
                    "payload": f"Missing: {expected_header}",
                    "url": target,
                    "evidence": f"The '{expected_header}' protective header was not found in the server's HTTP response.",
                    "remediation": remediation
                })

    except requests.RequestException as e:
        logger.error(f"Execution crashed during Headers Scan on {target}: {e}")

    return results
