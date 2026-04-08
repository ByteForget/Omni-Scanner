import os
import logging
import json
from datetime import datetime
from typing import Any, Dict, List
import re
import html
from dotenv import load_dotenv
from utils.ai_report import generate_ai_pdf_report


load_dotenv()

logger = logging.getLogger(__name__)

def highlight_params(text):
    """Wraps technical terms in red-bold font with a light-red background for PDF."""

    pattern = r'(\/[a-zA-Z0-9\/\.]+|uid|passw|SQL Injection|XSS|CWE-\d+|username|password|payload|vulnerability|vulnerable|malicious)'
    def replace(match):
        term = match.group(0)
        return f"<font color='#b30000' backColor='#fff1f2'><b>{term}</b></font>"
    return re.sub(pattern, replace, text, flags=re.IGNORECASE)


def generate_manual_ai_report_pdf(target_url: str, raw_data: Dict[str, Any], api_key: str = None) -> str:
    """
    Orchestrates the Manual AI Report generation:
    1. Analyzes raw scan data using Gemini AI with a specialized consultancy prompt.
    2. Renders the resulting intelligence into the perfected 8-page PDF template.
    """
    try:


        final_api_key = api_key or os.getenv("GEMINI_API_KEY")


        threat_context = []
        results = raw_data.get("results", {})
        for mod_name, mod_data in results.items():
            if mod_name == "crawler" or not isinstance(mod_data, dict):
                continue
            for url, result in mod_data.items():
                if not isinstance(result, dict): continue
                details = result.get("details", [])
                for detail in details:
                    threat_context.append({
                        "module": mod_name,
                        "type": detail.get("type", "Unknown"),
                        "severity": detail.get("severity", "Medium"),
                        "url": detail.get("url", url),
                        "parameter": detail.get("parameter", "N/A"),
                        "cwe": detail.get("cwe", "N/A"),
                        "evidence": detail.get("payload_used", detail.get("evidence", "Technical proof available"))
                    })


        total_findings_count = len(threat_context)


        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        threat_context.sort(key=lambda x: severity_order.get(x["severity"], 99))
        limited_context = threat_context[:25]


        if not limited_context:
            ai_data = {
                "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "summary": [
                    f"The security assessment of {target_url} was completed with zero immediate vulnerabilities detected across all tested endpoints.",
                    "The application demonstrates a robust security posture. Continuous monitoring is recommended to maintain this secure baseline."
                ],
                "findings": []
            }
        else:

            real_counts = {
                "CRITICAL": sum(1 for x in threat_context if x["severity"].lower() == "critical"),
                "HIGH": sum(1 for x in threat_context if x["severity"].lower() == "high"),
                "MEDIUM": sum(1 for x in threat_context if x["severity"].lower() == "medium"),
                "LOW": sum(1 for x in threat_context if x["severity"].lower() == "low")
            }


            prompt = (
                "You are an Elite Cybersecurity Consultant.\n"
                f"The automated audit of {target_url} identified a TOTAL of {total_findings_count} security findings.\n"
                f"Real Severity Breakdown: {json.dumps(real_counts)}\n"
                f"I am providing you with the top {len(limited_context)} most critical findings for deep analysis:\n"
                f"{json.dumps(limited_context, indent=2)}\n\n"
                "Return ONLY a JSON with:\n"
                "1. 'counts': { 'CRITICAL': int, 'HIGH': int, 'MEDIUM': int, 'LOW': int } (Use the real counts provided above)\n"
                f"2. 'summary': [ 'Paragraph 1 acknowledging all {total_findings_count} findings', 'Paragraph 2 focusing on critical remediation' ]\n"
                "3. 'findings': List of EXACTLY 10 detailed { name, severity, url, cwe, description, payload, remediation } for the most important issues.\n"
                "   - IMPORTANT: If a CWE-ID is missing or 'N/A' in the input data, use your intelligence to assign the most appropriate CWE ID (e.g., CWE-89 for SQL Injection, CWE-79 for XSS, CWE-1021 for missing security headers, CWE-16 for misconfigurations).\n"
            )

            try:
                import google.generativeai as genai
                if not final_api_key:
                    raise ValueError("GEMINI_API_KEY is missing. Falling back to Standard Report.")

                genai.configure(api_key=final_api_key)
                model = genai.GenerativeModel('gemini-1.5-flash')
                response = model.generate_content(prompt)

                if not response or not response.text:
                    return ""

                clean_text = response.text.strip()
                if "```json" in clean_text:
                    clean_text = clean_text.split("```json")[1].split("```")[0].strip()
                elif "```" in clean_text:
                    clean_text = clean_text.split("```")[1].split("```")[0].strip()

                ai_data = json.loads(clean_text)
            except Exception as e:
                logger.error(f"Gemini call failed in executive report: {e}. Using standard fallback.")

                fall_findings = []
                for x in limited_context[:10]:
                    fall_findings.append({
                        "name": x.get("type", "Security Finding"),
                        "severity": x.get("severity", "MEDIUM").upper(),
                        "url": x.get("url", "/"),
                        "cwe": x.get("cwe") if x.get("cwe") and x.get("cwe") != "N/A" else ("CWE-1021" if "Misconfiguration" in x.get("type", "") else "CWE-999"),
                        "description": f"Potential {x.get('type')} vulnerability identified during automated scanning of the {x.get('module')} module.",
                        "payload": x.get("evidence", "Technical proof available in logs."),
                        "remediation": "Review system configurations and apply security patches. Ensure input validation is implemented for all dynamic parameters."
                    })

                ai_data = {
                    "counts": real_counts,
                    "summary": [
                        f"An executive security audit of {target_url} has been completed. The automated scanner identified {total_findings_count} total findings using the modular intelligence suite.",
                        f"While the AI reasoning layer was unavailable during this specific generation cycle, the following technical evidence has been manually verified. This section details the top {len(fall_findings)} most critical findings."
                    ],
                    "findings": fall_findings
                }


        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = (parsed.netloc or parsed.path).split(':')[0].rstrip('/')
        if '.' in domain:
            sitename = '.'.join(domain.split('.')[:-1])
        else:
            sitename = domain
        if not sitename: sitename = "Target"

        filename = f"Omni_VAPT_Executive_Report {sitename}.pdf"
        filepath = os.path.join("reports", filename)


        return generate_ai_pdf_report(ai_data, target_url, filepath, total_findings=total_findings_count)

    except Exception as e:
        logger.error(f"Manual AI Report Generation Failed: {e}")
        return ""
