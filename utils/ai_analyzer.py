import os
import json
import requests
from typing import Dict, Any

from utils.logger import logger

def summarize_vulnerability(vuln_data: Dict[str, Any], api_key: str = None) -> str | Dict[str, Any]:
    """
    Analyzes aggregated scanner vulnerabilities and calls an AI API (like OpenAI)
    to provide a Security Researcher's perspective on risk and chained attack vectors.
    """


    try:
        from dotenv import load_dotenv
        load_dotenv(override=True)
    except ImportError:
        pass

    final_api_key = api_key or os.environ.get("GEMINI_API_KEY")
    if not final_api_key:
        logger.info("GEMINI_API_KEY environment variable not found. Skipping Gemini Insights generation.")
        return {"error": "AI Insights are disabled. Please enter your Gemini API Key in the Settings panel."}

    logger.info("Initializing AI Intelligence Layer. Generating insights...")


    threat_context = []

    results = vuln_data.get("results", {})
    for mod_name, mod_data in results.items():
        if mod_name == "crawler":
            continue

        for url, result in mod_data.items():
            if isinstance(result, dict) and result.get("vulnerabilities_found"):
                for detail in result.get("details", []):
                    threat_context.append({
                        "module": mod_name,
                        "vulnerability_type": detail.get("type", "Unknown"),
                        "severity": detail.get("severity", "Medium"),
                        "url": detail.get("url", url),
                        "parameter": detail.get("parameter", "N/A"),
                        "payload": detail.get("payload_used", detail.get("payload", "N/A"))
                    })

    target_url = vuln_data.get("target", "Unknown Target")


    system_prompt = (
        "You are a Senior Lead Penetration Tester and Cyber Threat Intelligence Analyst. "
        "Your task is to analyze raw JSON vulnerability scan data from Omni Scanner.\n\n"
        "Technical Depth: Explain exactly why a payload worked based on the evidence provided. Detail remediation steps.\n"
        "Formatting: You MUST return your findings in the following EXACT JSON format (respond with JSON only, no markdown markdown blocks):\n"
        "{\n"
        '  "risk_level": "HIGH",\n'
        '  "security_score": 40,\n'
        '  "summary": "2-3 sentence executive summary...",\n'
        '  "score_breakdown": {"critical_pct": 30, "medium_pct": 50, "info_pct": 10, "passed_pct": 10},\n'
        '  "findings": [{'
        '    "name": "Finding Name",\n'
        '    "severity": "HIGH",\n'
        '    "description": "Detailed explanation...",\n'
        '    "url": "Specific endpoint affected",\n'
        '    "evidence": "Server reflection or PoC...",\n'
        '    "remediation": "Exact fix steps",\n'
        '    "tags": ["CWE-79"]\n'
        '  }]\n'
        "}\n\n"
        "If there are no vulnerabilities, return the same JSON structure but with a HIGH security score (e.g. 95), risk_level SAFE, and an empty findings list."
    )

    try:
        if not threat_context:
            final_prompt = f"{system_prompt}\n\nThe scan against {target_url} returned 0 vulnerabilities. Generate the requested JSON."
        else:
            final_prompt = f"{system_prompt}\n\nTarget Assessed: {target_url}\nJSON Results Data:\n{json.dumps(threat_context, indent=2)}"

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={final_api_key}"
        headers = {'Content-Type': 'application/json'}
        payload = {
            "contents": [{"parts": [{"text": final_prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "response_mime_type": "application/json"
            }
        }
        import time
        max_retries = 3

        for attempt in range(max_retries):
            try:

                timeout_val = 150 if attempt == 0 else 200
                response = requests.post(url, headers=headers, json=payload, timeout=timeout_val)

                if response.status_code in [429, 503]:
                    if attempt < max_retries - 1:
                        sleep_time = (attempt + 1) * 8
                        logger.warning(f"Gemini API returned {response.status_code}. Retrying in {sleep_time}s... (Attempt {attempt+1}/{max_retries})")
                        time.sleep(sleep_time)
                        continue
                    else:
                        err_json = response.json() if response.text else {}
                        msg = err_json.get("error", {}).get("message", f"HTTP {response.status_code}")
                        return {"error": f"AI Analysis failed after {max_retries} attempts. Google servers are currently overloaded ({response.status_code}): {msg}"}

                if response.status_code != 200:
                    err_json = response.json() if response.text else {}
                    msg = err_json.get("error", {}).get("message", f"HTTP {response.status_code}")
                    return {"error": f"AI Analysis failed: {msg}"}


                break

            except requests.exceptions.ReadTimeout as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Gemini AI API read timed out. Retrying... (Attempt {attempt+1}/{max_retries})")
                    continue
                else:
                    logger.error(f"Gemini API timed out after {max_retries} attempts: {e}")
                    return {"error": "AI Analysis failed: Target has too much data or API is overloaded (ReadTimeout). Please try again or download a manual report."}
        res_data = response.json()
        if "candidates" in res_data and res_data["candidates"]:
            text = res_data["candidates"][0]["content"]["parts"][0]["text"]
            logger.info("Successfully generated Gemini AI Insights.")
            try:
                return json.loads(text.strip())
            except json.JSONDecodeError:
                cleaned = text.replace("```json", "").replace("```", "").strip()
                return json.loads(cleaned)
        else:
            return {"error": "AI Analysis failed: Empty response format received from Gemini."}

    except Exception as e:
        logger.error(f"Gemini AI API integration failure: {e}")
        return {"error": f"AI Analysis failed due to network or authentication error: {e}"}
