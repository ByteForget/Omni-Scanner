"""
Server-Side Request Forgery (SSRF) Scanner Module for Vuln_Scanner_AG.
Sends payloads attempting to make the server fetch internal or external resources.
"""
import requests
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from typing import Dict, Any, Optional, List

from utils.logger import logger

def execute(target: str, forms: Optional[List[Dict[str, Any]]] = None, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Execute SSRF checks against the target URL and forms.

    Args:
        target (str): The target URL to scan.
        forms (list): Optional list of forms discovered on the target (from crawler).
        session (requests.Session): The optional authenticated session context.

    Returns:
        Dict[str, Any]: A dictionary containing the scan results.
    """
    logger.info(f"Starting SSRF scan on target: {target}")
    forms = forms or []
    req_client = session if session else requests


    ssrf_payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://example.com"
    ]

    results: Dict[str, Any] = {
        "vulnerabilities_found": False,
        "details": []
    }

    def check_for_ssrf(response: requests.Response, payload: str, test_url: str, type_str: str, param_name: str = ""):
        if response.status_code in [403, 406]:
            logger.info(f"[WAF Block] SSRF Payload intercepted or denied: {test_url} -> HTTP {response.status_code}")
            return False


        evidence = None
        if "Example Domain" in response.text and "example.com" in payload:
            evidence = "Server fetched and returned content from external domain (example.com)."
        elif "root:x:0:0:" in response.text and "file://" in payload:
            evidence = "Server fetched and returned local file content (/etc/passwd)."

        if evidence:
            results["vulnerabilities_found"] = True
            results["details"].append({
                "payload_used": payload,
                "test_url": test_url,
                "type": type_str,
                "vulnerable_parameter": param_name,
                "evidence": evidence,
                "severity": "Critical",
                "remediation": "Validate and sanitize all URLs passed to the server. Use a strict allowlist of permitted domains/IPs. Disable unused URL schemas (like file://, dict://). Do not blindly follow redirects."
            })
            logger.warning(f"[{type_str}] Vulnerability Found! Evidence of SSRF for parameter '{param_name}' with payload: {payload}")
            return True
        return False


    parsed_url = urlparse(target)
    query_params = parse_qsl(parsed_url.query)

    if query_params:
        logger.debug("Testing Query Parameters for SSRF...")
        for i, (param_name, param_value) in enumerate(query_params):

            if any(keyword in param_name.lower() for keyword in ['url', 'uri', 'path', 'dest', 'redirect', 'file', 'domain']):
                for payload in ssrf_payloads:
                    test_params = query_params.copy()
                    test_params[i] = (param_name, payload)
                    new_query = urlencode(test_params)
                    test_url = urlunparse(parsed_url._replace(query=new_query))

                    try:
                        resp = req_client.get(test_url, timeout=10)
                        check_for_ssrf(resp, payload, test_url, "Server-Side Request Forgery (GET)", param_name)
                    except requests.RequestException:
                        pass


    if forms:
        logger.debug(f"Testing {len(forms)} Forms for SSRF...")
        for form in forms:
            action = form.get("action", target)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            if not inputs:
                continue

            for payload in ssrf_payloads:
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

                    check_for_ssrf(resp, payload, action, f"Server-Side Request Forgery (Form {method})", "Multiple Form Inputs")
                except requests.RequestException:
                    pass

    if not results["vulnerabilities_found"]:
        logger.info("No SSRF vulnerabilities detected (heuristically).")

    return results
