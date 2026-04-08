"""
Cross-Site Scripting (XSS) Vulnerability Scanner Module for Vuln_Scanner_AG.
Sends common XSS payloads to a target URL parameters and forms.
Checks responses to see if the payload is reflected without proper escaping/sanitization.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from typing import Dict, Any, Optional, List

from utils.logger import logger

def execute(target: str, forms: Optional[List[Dict[str, Any]]] = None, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Execute XSS checks against the target URL and forms.

    Args:
        target (str): The target URL to scan.
        forms (list): Optional list of forms discovered on the target (from crawler).
        session (requests.Session): The optional authenticated session context.

    Returns:
        Dict[str, Any]: A dictionary containing the scan results.
    """
    logger.info(f"Starting XSS scan on target: {target}")
    forms = forms or []
    req_client = session if session else requests

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
    ]

    results: Dict[str, Any] = {
        "vulnerabilities_found": False,
        "details": []
    }


    def check_for_reflection(response: requests.Response, payload: str, test_url: str, type_str: str, param_name: str = ""):
        if response.status_code in [403, 406]:
            logger.info(f"[WAF Block] XSS Payload intercepted or denied: {test_url} -> HTTP {response.status_code}")
            return False

        if payload in response.text:
            results["vulnerabilities_found"] = True
            results["details"].append({
                "payload_used": payload,
                "test_url": test_url,
                "type": type_str,
                "severity": "High",
                "vulnerable_parameter": param_name,
                "evidence": f"Unfiltered payload reflected in the response.",
                "remediation": "Implement strict context-aware output encoding. Sanitize all user-supplied data before rendering it in the browser. Use a robust Content Security Policy (CSP)."
            })
            logger.warning(f"[{type_str}] Vulnerability Found! Unfiltered reflection for parameter '{param_name}' with payload: {payload}")
            return True
        return False


    parsed_url = urlparse(target)
    query_params = parse_qsl(parsed_url.query)

    if query_params:
        logger.debug("Testing Query Parameters for Reflected XSS...")
        for i, (param_name, param_value) in enumerate(query_params):
            for payload in xss_payloads:
                test_params = query_params.copy()
                test_params[i] = (param_name, payload)
                new_query = urlencode(test_params)
                test_url = urlunparse(parsed_url._replace(query=new_query))

                try:
                    resp = req_client.get(test_url, timeout=10)
                    check_for_reflection(resp, payload, test_url, "Reflected XSS (GET)", param_name)
                except requests.RequestException:
                    pass


    if forms:
        logger.debug(f"Testing {len(forms)} Forms for XSS...")
        for form in forms:
            action = form.get("action", target)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            if not inputs:
                continue

            for payload in xss_payloads:
                data_payload = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        data_payload[name] = payload

                try:
                    if method == "POST":
                        resp = req_client.post(action, data=data_payload, timeout=10)
                    else:
                        resp = req_client.get(action, params=data_payload, timeout=10)

                    check_for_reflection(resp, payload, action, f"Stored/Reflected XSS (Form {method})", "Multiple Form Inputs")
                except requests.RequestException:
                    pass

    if not results["vulnerabilities_found"]:
        logger.info("No XSS vulnerabilities detected.")

    return results
