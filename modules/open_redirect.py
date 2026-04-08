"""
Open Redirect Scanner Module for Vuln_Scanner_AG.
Checks if URL parameters can be manipulated to redirect the user to an arbitrary external domain.
"""
import requests
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from typing import Dict, Any, Optional, List

from utils.logger import logger

def execute(target: str, forms: Optional[List[Dict[str, Any]]] = None, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Execute Open Redirect checks against the target URL.

    Args:
        target (str): The target URL to scan.
        forms (list): Optional list of forms discovered on the target (from crawler).
        session (requests.Session): The optional authenticated session context.

    Returns:
        Dict[str, Any]: A dictionary containing the scan results.
    """
    logger.info(f"Starting Open Redirect scan on target: {target}")
    forms = forms or []
    req_client = session if session else requests

    redirect_payloads = [
        "http://example.com",
        "https://example.com",
        "//example.com",
        "\\/\\/example.com",
        "/%09/example.com",
        "/%5cexample.com"
    ]

    results: Dict[str, Any] = {
        "vulnerabilities_found": False,
        "details": []
    }

    def check_for_redirect(response: requests.Response, payload: str, test_url: str, type_str: str, param_name: str = ""):


        if response.status_code in [403, 406]:
            return False


        redirected_to_external = False
        final_url = response.url

        if "example.com" in final_url:
            redirected_to_external = True

        for resp in response.history:
            if "example.com" in resp.headers.get('Location', ''):
                redirected_to_external = True
                break

        if redirected_to_external:
            results["vulnerabilities_found"] = True
            results["details"].append({
                "payload_used": payload,
                "test_url": test_url,
                "type": type_str,
                "vulnerable_parameter": param_name,
                "evidence": f"Successfully redirected to: {final_url}",
                "severity": "Medium",
                "remediation": "Do not allow user input to directly control redirect destinations. Validate URLs against a strict allowlist. Use relative paths where possible."
            })
            logger.warning(f"[{type_str}] Vulnerability Found! Open Redirect possible on parameter '{param_name}' with payload: {payload}")
            return True
        return False


    parsed_url = urlparse(target)
    query_params = parse_qsl(parsed_url.query)

    if query_params:
        logger.debug("Testing Query Parameters for Open Redirect...")
        for i, (param_name, param_value) in enumerate(query_params):
            if any(keyword in param_name.lower() for keyword in ['url', 'next', 'redirect', 'target', 'return', 'uri', 'path', 'dest']):
                for payload in redirect_payloads:
                    test_params = query_params.copy()
                    test_params[i] = (param_name, payload)
                    new_query = urlencode(test_params)
                    test_url = urlunparse(parsed_url._replace(query=new_query))

                    try:
                        resp = req_client.get(test_url, timeout=10, allow_redirects=True)
                        check_for_redirect(resp, payload, test_url, "Open Redirect (GET)", param_name)
                    except requests.RequestException:
                        pass

    if not results["vulnerabilities_found"]:
        logger.info("No Open Redirect vulnerabilities detected.")

    return results
