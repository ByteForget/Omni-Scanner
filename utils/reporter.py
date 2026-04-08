"""
Reporter utility for Vuln_Scanner_AG.
Handles exporting vulnerability scan results to structured JSON and viewable HTML formats.
"""
import json
import os
from datetime import datetime
from typing import Dict, Any

from utils.logger import logger
from utils.manual_pdf import generate_manual_pdf_report
from utils.ai_report import generate_ai_pdf_report
from utils.vuln_utils import get_vuln_info

class Reporter:
    """Handles parsing resulting vulnerabilities and generating reports."""

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the Reporter object.

        Args:
           output_dir (str): Relative or absolute directory path to save reports.
        """
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logger.debug(f"Created reports directory at {self.output_dir}")

    def generate_json(self, data: Dict[str, Any], filename: str = "report.json") -> str:
        """
        Export scan data to a JSON file.

        Args:
            data (Dict[str, Any]): The aggregated results payload.
            filename (str): Desired output file name.

        Returns:
            str: Path to the generated JSON file upon success, otherwise an empty string.
        """
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=4)
            logger.info(f"JSON report successfully generated: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return ""


    def generate_html(self, data: Dict[str, Any], filename: str = "report.html") -> str:
        """
        Export scan data to an HTML visual report with dashboards, tables, and remediation advice.
        """
        filepath = os.path.join(self.output_dir, filename)


        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        results = data.get('results', {})

        for mod_name, mod_data in results.items():
            if mod_name == 'crawler':
                continue
            for url, result in mod_data.items():
                if isinstance(result, dict) and result.get('vulnerabilities_found'):
                    for detail in result.get('details', []):
                        provided_sev = detail.get('severity')
                        if provided_sev:
                            sev = provided_sev.capitalize()
                            if sev == 'Critical':
                                sev = 'High'
                        else:
                            sev, _ = get_vuln_info(detail.get('type', ''))

                        if sev in severity_counts:
                            severity_counts[sev] += 1
                        else:
                            severity_counts['Medium'] += 1


        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vuln_Scanner_AG Report</title>
    <style>
        :root {{
            --bg-color: #f4f7f6;
            --text-color: #333;
            --card-bg: #fff;
            --high-color: #e74c3c;
            --medium-color: #f39c12;
            --low-color: #3498db;
            --safe-color: #2ecc71;
            --border-radius: 8px;
        }}
        body {{ font-family: 'Inter', 'Segoe UI', sans-serif; margin: 0; padding: 20px; background-color: var(--bg-color); color: var(--text-color); }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .header-info {{ background: var(--card-bg); padding: 20px; border-radius: var(--border-radius); box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 25px; }}
        .header-info h1 {{ margin-top: 0; border-bottom: 2px solid #eee; padding-bottom: 15px; }}

        .dashboard {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ flex: 1; background: var(--card-bg); padding: 20px; border-radius: var(--border-radius); box-shadow: 0 2px 10px rgba(0,0,0,0.05); text-align: center; border-bottom: 4px solid #ddd; }}
        .stat-card.high {{ border-bottom-color: var(--high-color); }}
        .stat-card.medium {{ border-bottom-color: var(--medium-color); }}
        .stat-card.low {{ border-bottom-color: var(--low-color); }}
        .stat-card h3 {{ margin: 0 0 10px 0; font-size: 1.2rem; color: #7f8c8d; }}
        .stat-card .value {{ font-size: 2.5rem; font-weight: bold; margin: 0; }}
        .stat-card.high .value {{ color: var(--high-color); }}
        .stat-card.medium .value {{ color: var(--medium-color); }}
        .stat-card.low .value {{ color: var(--low-color); }}

        .module-section {{ background: var(--card-bg); padding: 25px; border-radius: var(--border-radius); margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }}
        .module-title {{ margin-top: 0; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #eee; padding-bottom: 15px; margin-bottom: 20px; }}
        .badge {{ padding: 5px 12px; border-radius: 20px; font-size: 0.9rem; font-weight: 600; color: white; }}
        .badge.safe {{ background: var(--safe-color); }}
        .badge.vuln {{ background: var(--high-color); }}

        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.95rem; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background-color: #f8f9fa; font-weight: 600; color: #2c3e50; text-transform: uppercase; font-size: 0.85rem; letter-spacing: 0.5px; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover {{ background-color: #fcfcfc; }}

        .severity-high {{ color: var(--high-color); font-weight: bold; }}
        .severity-medium {{ color: var(--medium-color); font-weight: bold; }}
        .severity-low {{ color: var(--low-color); font-weight: bold; }}

        .rem-box {{ background-color: #f8f9fa; border-left: 4px solid #34495e; padding: 10px 15px; margin-top: 8px; font-size: 0.9rem; color: #555; border-radius: 0 4px 4px 0; }}
        .code-snippet {{ background: #2c3e50; color: #ecf0f1; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 0.85rem; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="header-info">
        <h1>Vuln_Scanner_AG Executive Report</h1>
        <p><strong>Target:</strong> <a href="{data.get('target', '#')}">{data.get('target', 'Unknown')}</a></p>
        <p><strong>Scan Timestamp:</strong> {data.get('scan_date', datetime.now().isoformat())}</p>
    </div>

    <div class="dashboard">
        <div class="stat-card high">
            <h3>High Severity</h3>
            <p class="value">{severity_counts['High']}</p>
        </div>
        <div class="stat-card medium">
            <h3>Medium Severity</h3>
            <p class="value">{severity_counts['Medium']}</p>
        </div>
        <div class="stat-card low">
            <h3>Low / Info</h3>
            <p class="value">{severity_counts['Low']}</p>
        </div>
    </div>
"""

        from utils.ai_analyzer import summarize_vulnerability
        ai_summary = summarize_vulnerability(data)

        if isinstance(ai_summary, dict):
            if "error" in ai_summary:
                formatted_summary = f"AI Error: {ai_summary['error']}"
            else:
                formatted_summary = ai_summary.get("summary", "No summary provided by AI.")
        else:
            formatted_summary = str(ai_summary).replace('\n', '<br>')

        html_content += f"""
    <div class="module-section" style="border-left: 5px solid #8e44ad;">
        <h2 class="module-title" style="color: #8e44ad;">
            <span>🧠 AI Security Researcher Insights</span>
        </h2>
        <div style="font-size: 0.95rem; line-height: 1.6; color: #34495e;">
            <p>{formatted_summary}</p>
        </div>
    </div>
"""
        if not results:
            html_content += "<div class='module-section'><p>No modules were executed or no results were collected.</p></div>"
        else:
            for mod_name, mod_data in results.items():
                if mod_name == 'crawler':
                    continue

                total_vulns_in_mod = 0
                rows_html = ""

                for url, result in mod_data.items():
                    if isinstance(result, dict) and result.get('vulnerabilities_found'):
                        for detail in result.get('details', []):
                            total_vulns_in_mod += 1
                            v_type = detail.get('type', 'Unknown')

                            provided_sev = detail.get('severity')
                            if provided_sev:
                                sev = provided_sev.capitalize()
                                provided_rem = detail.get('remediation')
                                if provided_rem:
                                    rem = provided_rem
                                else:
                                    _, rem = get_vuln_info(v_type)
                            else:
                                sev, rem = get_vuln_info(v_type)

                            css_sev = 'high' if sev == 'Critical' else sev.lower()
                            sev_class = f"severity-{css_sev}"

                            import html
                            payload = html.escape(str(detail.get('payload_used', detail.get('payload', 'N/A'))))
                            evidence = html.escape(str(detail.get('evidence', 'N/A')))
                            param = html.escape(str(detail.get('vulnerable_parameter', detail.get('parameter', 'N/A'))))
                            test_url = html.escape(str(detail.get('test_url', detail.get('url', url))))
                            v_type = html.escape(str(v_type))
                            rem = html.escape(str(rem))

                            rows_html += f"""
                            <tr>
                                <td><a href="{test_url}" target="_blank">Link</a></td>
                                <td>{param}</td>
                                <td><span class="{sev_class}">{v_type}</span></td>
                                <td><span class="code-snippet">{payload}</span></td>
                                <td>
                                    {evidence}
                                    <div class="rem-box"><strong>Remediation:</strong> {rem}</div>
                                </td>
                            </tr>
                            """

                badge_class = "vuln" if total_vulns_in_mod > 0 else "safe"
                badge_text = f"{total_vulns_in_mod} Vulnerabilities" if total_vulns_in_mod > 0 else "Secure"

                html_content += f"""
    <div class="module-section">
        <h2 class="module-title">
            <span>Module: {mod_name.upper()}</span>
            <span class="badge {badge_class}">{badge_text}</span>
        </h2>
"""
                if total_vulns_in_mod > 0:
                    html_content += f"""
        <table>
            <thead>
                <tr>
                    <th style="width: 10%;">Test URL</th>
                    <th style="width: 15%;">Parameter</th>
                    <th style="width: 15%;">Type</th>
                    <th style="width: 25%;">Payload Used</th>
                    <th style="width: 35%;">Evidence & Remediation</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
"""
                else:
                    html_content += "<p style='color: var(--safe-color); font-weight: 500;'>No vulnerabilities detected by this module.</p>"

                html_content += "    </div>\n"

        html_content += """
</body>
</html>
"""
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(html_content)
            logger.info(f"HTML report successfully generated: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return ""

    def generate_pdf(self, data: Dict[str, Any], filename: str = "report.pdf") -> str:
        """
        Export scan data to a formatted professional VAPT PDF report.
        Delegates to manual_pdf.py.
        """
        filepath = os.path.join(self.output_dir, filename)
        return generate_manual_pdf_report(data, filepath)

    def generate_ai_pdf(self, ai_data: Dict[str, Any], target_url: str) -> str:
        """
        Takes structured Gemini AI output and generates a high-fidelity
        Professional Executive Pentest Report (V2).
        Delegates to ai_report.py (formerly report_pdf).
        """
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = (parsed.netloc or parsed.path).split(':')[0].rstrip('/')
        if '.' in domain:
            sitename = '.'.join(domain.split('.')[:-1])
        else:
            sitename = domain
        if not sitename: sitename = "Target"

        filename = f"Omni Ai_Report {sitename}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        return generate_ai_pdf_report(ai_data, target_url, filepath)
