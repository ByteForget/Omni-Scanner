"""
SQL Injection Vulnerability Scanner Module for Vuln_Scanner_AG.
Sends common SQLi payloads to a target URL parameters, forms, or path.
Checks responses for reflections, database errors, or boolean differences.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from typing import Dict, Any, Optional, List

from utils.logger import logger

def execute(target: str, forms: Optional[List[Dict[str, Any]]] = None, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Execute SQL Injection checks against the target URL and forms.

    Args:
        target (str): The target URL to scan.
        forms (list): Optional list of forms discovered on the target (from crawler).
        session (requests.Session): The optional authenticated session context.

    Returns:
        Dict[str, Any]: A dictionary containing the scan results.
    """
    logger.info(f"Starting SQL Injection scan on target: {target}")
    forms = forms or []
    req_client = session if session else requests

    error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sql syntax error",
        "ora-01756",
        "microsoft sql server native client",
        "mysql_fetch_array()",
        "database error",
        "syntax error",
        "pg_query()"
    ]

    results: Dict[str, Any] = {
        "vulnerabilities_found": False,
        "details": []
    }


    try:
        baseline_resp = req_client.get(target, timeout=10)
        baseline_length = len(baseline_resp.text)
    except requests.RequestException as e:
        logger.error(f"Cannot baseline target {target}: {e}")
        return results


    def check_for_errors(response: requests.Response, payload: str, test_url: str, type_str: str):

        if response.status_code in [403, 406]:
            results["details"].append({
                "payload_used": payload,
                "test_url": test_url,
                "type": f"Potential WAF Block ({response.status_code})",
                "severity": "Low",
                "evidence": "Access Denied or Not Acceptable HTTP Code",
                "remediation": "The WAF successfully blocked the SQLi payload. Regularly audit WAF rules to ensure they provide adequate protection against evolving injection techniques."
            })
            logger.info(f"[WAF Block] Payload intercepted or denied: {test_url} -> HTTP {response.status_code}")
            return False


        if "sleep" in payload.lower() or "waitfor" in payload.lower() or "delay" in payload.lower():
            if response.elapsed.total_seconds() > 5.0:
                results["vulnerabilities_found"] = True
                results["details"].append({
                    "payload_used": payload,
                    "test_url": test_url,
                    "type": "Time-Based SQLi",
                    "severity": "High",
                    "evidence": f"Request delayed by {response.elapsed.total_seconds():.2f} seconds",
                    "remediation": "Use parameterized queries (Prepared Statements) for all database access. Avoid concatenating user input directly into SQL strings. Validate and sanitize all input."
                })
                logger.warning(f"[Time-Based SQLi] Successful 5+ second delay detected!")
                return True


        page_text = response.text.lower()
        for signature in error_signatures:
            if signature in page_text:
                results["vulnerabilities_found"] = True
                results["details"].append({
                    "payload_used": payload,
                    "test_url": test_url,
                    "type": type_str,
                    "severity": "High",
                    "evidence": f"Found signature: '{signature}'",
                    "remediation": "Use parameterized queries (Prepared Statements) for all database access. Avoid concatenating user input directly into SQL strings. Validate and sanitize all input."
                })
                logger.warning(f"[{type_str}] Error Signature Found! Payload: {payload}")
                return True
        return False


    parsed_url = urlparse(target)
    query_params = parse_qsl(parsed_url.query)


    import os
    error_payloads = []
    payloads_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "utils", "sqli_payloads.txt")
    try:
        with open(payloads_file_path, 'r', encoding='utf-8') as f:
            error_payloads = [line.strip() for line in f if line.strip()]
        logger.debug(f"Successfully loaded {len(error_payloads)} SQLi payloads from {payloads_file_path}.")
    except FileNotFoundError:
        logger.error(f"Payload file not found at {payloads_file_path}. Using fallback payloads.")
        error_payloads = ["'", "''", "\"", "\\", "1' Waitfor Delay '0:0:5'--"]
    except Exception as e:
        logger.error(f"Error reading payloads from {payloads_file_path}: {e}")
        error_payloads = ["'", "''", "\"", "\\", "1' Waitfor Delay '0:0:5'--"]


    bool_true = "' OR 1=1--"
    bool_false = "' OR 1=2--"

    if query_params:
        logger.debug("Testing Query Parameters...")
        for i, (param_name, param_value) in enumerate(query_params):

            for payload in error_payloads:
                test_params = query_params.copy()
                test_params[i] = (param_name, f"{param_value}{payload}")
                new_query = urlencode(test_params)
                test_url = urlunparse(parsed_url._replace(query=new_query))

                try:
                    resp = req_client.get(test_url, timeout=10)
                    check_for_errors(resp, payload, test_url, "Error-Based SQLi (GET)")
                except requests.RequestException:
                    pass


            test_params_true = query_params.copy()
            test_params_true[i] = (param_name, f"{param_value}{bool_true}")
            url_true = urlunparse(parsed_url._replace(query=urlencode(test_params_true)))

            test_params_false = query_params.copy()
            test_params_false[i] = (param_name, f"{param_value}{bool_false}")
            url_false = urlunparse(parsed_url._replace(query=urlencode(test_params_false)))

            try:
                resp_true = req_client.get(url_true, timeout=10)
                resp_false = req_client.get(url_false, timeout=10)


                diff = abs(len(resp_true.text) - len(resp_false.text))
                if diff > 50:
                    results["vulnerabilities_found"] = True
                    finding: Dict[str, str] = {
                        "payload_used": f"True: {bool_true} | False: {bool_false}",
                        "test_url": url_true,
                        "type": "Boolean-Based SQLi (GET)",
                        "severity": "High",
                        "evidence": f"Length difference: {diff} bytes",
                        "remediation": "Use parameterized queries (Prepared Statements) for all database access. Avoid concatenating user input directly into SQL strings. Validate and sanitize all input."
                    }
                    results["details"].append(finding)
                    logger.warning(f"[Boolean-Based SQLi (GET)] Inference successful on param '{param_name}'")
            except requests.RequestException:
                pass
    else:


        logger.debug("No queries found. Testing Path Append...")
        for payload in error_payloads:
            test_url = f"{target}{payload}"
            try:
                resp = req_client.get(test_url, timeout=10)
                check_for_errors(resp, payload, str(test_url), "Error-Based SQLi (Path)")
            except requests.RequestException:
                pass


    if forms:
        logger.debug(f"Testing {len(forms)} Forms...")
        for form in forms:
            action = form.get("action", target)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            if not inputs:
                continue

            for payload in error_payloads + [bool_true]:
                data_payload = {}
                for inp in inputs:

                    name = inp.get("name")
                    if name:
                        data_payload[name] = f"test{payload}"

                try:
                    if method == "POST":
                        resp = req_client.post(action, data=data_payload, timeout=10)
                    else:
                        resp = req_client.get(action, params=data_payload, timeout=10)

                    check_for_errors(resp, payload, action, f"Error-Based SQLi (Form {method})")
                except requests.RequestException:
                    pass

    if not results["vulnerabilities_found"]:
        logger.info("No SQL Injection vulnerabilities detected.")

    return results
