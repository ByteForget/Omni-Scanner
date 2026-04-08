import os
import requests
from typing import Dict, Any, Optional, List

from utils.logger import logger

def execute(target: str, forms: Optional[List[Dict[str, Any]]] = None, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Execute Brute Force checks against discovered login forms.

    Args:
        target (str): The target URL to scan.
        forms (list): Optional list of forms on the target.
        session (requests.Session): The optional authenticated session context.

    Returns:
        Dict[str, Any]: A dictionary containing the scan results.
    """
    logger.info(f"Starting Brute Force scan on target: {target}")
    forms = forms or []
    req_client = session if session else requests

    usernames = ["admin", "user", "test", "guest"]
    passwords = ["password", "admin", "123456", "password123"]

    if os.path.exists("utils/usernames.txt"):
        with open("utils/usernames.txt", "r", encoding="utf-8") as f:
            usernames = [line.strip() for line in f if line.strip()]

    if os.path.exists("utils/passwords.txt"):
        with open("utils/passwords.txt", "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]

    results: Dict[str, Any] = {
        "vulnerabilities_found": False,
        "details": []
    }


    login_forms = []
    for form in forms:
        inputs = form.get("inputs", [])
        has_password = any(inp.get("type", "").lower() == "password" for inp in inputs)
        if has_password:
            login_forms.append(form)

    if not login_forms:
        logger.info(f"No authentication forms detected on {target}. Skipping Brute Force.")
        return results

    logger.info(f"Identified {len(login_forms)} potential login boundaries on {target}.")


    for form in login_forms:
        action = form.get("action", target)
        method = form.get("method", "get").upper()
        inputs = form.get("inputs", [])


        user_param = None
        pass_param = None

        for inp in inputs:
            itype = inp.get("type", "").lower()
            iname = inp.get("name", "").lower()

            if itype == "password" or "pass" in iname:
                pass_param = inp.get("name")
            elif itype == "text" and ("user" in iname or "login" in iname or "email" in iname):
                user_param = inp.get("name")


        if not user_param and len(inputs) >= 2:

            for inp in inputs:
                if inp.get("name") != pass_param:
                    user_param = inp.get("name")
                    break

        if not user_param or not pass_param:
            logger.warning(f"Could not decisively identify credential fields on form: {action}. Skipping.")
            continue

        successful_login = False

        for user in usernames:
            if successful_login:
                break

            for passwd in passwords:
                if successful_login:
                    break

                data_payload = {}
                for inp in inputs:
                    name = inp.get("name")
                    if not name: continue
                    if name == user_param:
                        data_payload[name] = user
                    elif name == pass_param:
                        data_payload[name] = passwd
                    else:
                        data_payload[name] = "Login"

                try:

                    current_url = action

                    if method == "POST":

                        csrf_keys = [k for k in data_payload.keys() if "token" in k.lower() or "csrf" in k.lower()]
                        if csrf_keys:
                            from bs4 import BeautifulSoup
                            get_resp = req_client.get(action, timeout=10)
                            soup = BeautifulSoup(get_resp.text, 'html.parser')
                            for c_key in csrf_keys:
                                token_input = soup.find('input', {'name': c_key})
                                if token_input:
                                    data_payload[c_key] = token_input.get('value', data_payload[c_key])

                        resp = req_client.post(action, data=data_payload, timeout=10, allow_redirects=True)
                    else:
                        resp = req_client.get(action, params=data_payload, timeout=10, allow_redirects=True)


                    resp_text = resp.text.lower()
                    redirected = resp.url != current_url

                    found_success_string = any(kw in resp_text for kw in ["welcome", "logout", "dashboard", "password protected area"])
                    found_failure_string = any(kw in resp_text for kw in ["login failed", "incorrect", "invalid", "username and/or password incorrect"])

                    is_success = False
                    if redirected and not found_failure_string:
                        is_success = True
                    elif found_success_string and not found_failure_string:
                        is_success = True

                    if is_success:
                        successful_login = True
                        logger.warning(f"[!] Weak Credentials Found over {action} - {user}:{passwd}")
                        results["vulnerabilities_found"] = True
                        results["details"].append({
                            "type": "Weak Default Credentials",
                            "severity": "Critical",
                            "parameter": f"{user_param} / {pass_param}",
                            "payload_used": f"Username: {user} | Password: {passwd}",
                            "url": action,
                            "evidence": f"Successfully authenticated using weak credentials. System redirected to {resp.url} or displayed internal dashboard keys.",
                            "remediation": "Enforce strong password policies. Disable default accounts and implement account lockouts/rate limiting to prevent automated brute-forcing."
                        })

                except requests.RequestException as e:
                    logger.error(f"Execution crashed during Brute-Force on {action}: {e}")

    return results
