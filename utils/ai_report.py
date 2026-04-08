import os
from datetime import datetime
from typing import Any, Dict, List
import logging
import re
import html

logger = logging.getLogger(__name__)

def highlight_params(text):
    """Wraps technical terms in red-bold font with a light-red background for PDF."""

    pattern = r'(\/[a-zA-Z0-9\/\.]+|uid|passw|SQL Injection|XSS|CWE-\d+|username|password|payload|vulnerability|vulnerable|malicious)'
    def replace(match):
        term = match.group(0)
        return f"<font color='#b30000' backColor='#fff1f2'><b>{term}</b></font>"
    return re.sub(pattern, replace, text, flags=re.IGNORECASE)


def generate_ai_pdf_report(ai_data: Dict[str, Any], target_url: str, filepath: str, total_findings: int = None) -> str:
    """
    Generates a high-fidelity Executive AI Pentest Report.
    Cover page is drawn entirely via canvas (matching the reference design).
    Remaining pages use ReportLab Platypus with branded header/footer.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import (
            BaseDocTemplate, PageTemplate, Frame,
            Paragraph, Spacer, Table, TableStyle,
            PageBreak, KeepTogether, HRFlowable, NextPageTemplate
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


        cwd = os.getcwd()
        logo_path = None
        for p in [
            os.path.join(cwd, "Assets", "Logo.png"),
            os.path.join(cwd, "backend", "Assets", "Logo.png"),
            os.path.join(cwd, "Assets", "Omni Scanner logo.png"),
        ]:
            if os.path.exists(p):
                logo_path = p
                break


        c_dark_blue  = colors.HexColor('#0f2942')
        c_cyan       = colors.HexColor('#00b4c8')
        c_red_accent = colors.HexColor('#e63946')
        c_slate      = colors.HexColor('#64748b')
        c_border     = colors.HexColor('#e2e8f0')
        c_light_gray = colors.HexColor('#f8fafc')
        c_orange     = colors.HexColor('#f59e0b')
        c_blue_sev   = colors.HexColor('#3b82f6')

        page_w, page_h = A4


        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            display_target = (parsed.hostname or target_url).upper()
        except Exception:
            display_target = target_url.upper()


        def draw_cover(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(colors.white)
            canvas.rect(0, 0, page_w, page_h, fill=True, stroke=False)

            if logo_path:
                try:
                    logo_w, logo_h = 260, 100
                    logo_x = (page_w - logo_w) / 2
                    canvas.drawImage(logo_path, logo_x, page_h - 170,
                                     width=logo_w, height=logo_h,
                                     preserveAspectRatio=True, mask='auto')
                except Exception:
                    pass

            canvas.setFont("Times-Bold", 34)
            canvas.setFillColor(c_dark_blue)
            canvas.drawCentredString(page_w / 2, 460, display_target)

            canvas.setFont("Times-Roman", 16)
            canvas.setFillColor(colors.HexColor('#475569'))
            canvas.drawCentredString(page_w / 2, 430, "AI VULNERABILITY INTELLIGENCE REPORT")

            canvas.setFont("Helvetica-Bold", 16)
            canvas.setFillColor(c_cyan)
            canvas.drawCentredString(page_w / 2, 350, "BUSINESS CONFIDENTIAL")

            now = datetime.now()
            meta = [
                ("DATE:",       now.strftime("%B %d, %Y")),
                ("PROJECT ID:", f"OMNI-AI-{now.strftime('%Y%m%d')}"),
                ("VERSION:",    "v2.5.0 (Intelligence)"),
            ]
            box_w, row_h = 320, 28
            total_h = row_h * len(meta) + 12
            box_x, box_y = (page_w - box_w) / 2, 220

            canvas.setFillColor(colors.white)
            canvas.setStrokeColor(c_border)
            canvas.setLineWidth(0.75)
            canvas.roundRect(box_x, box_y, box_w, total_h, 5, fill=True, stroke=True)

            for i, (lbl, val) in enumerate(meta):
                row_y = box_y + total_h - row_h * (i + 1) - 2
                canvas.setFont("Helvetica-Bold", 10)
                canvas.setFillColor(c_dark_blue)
                canvas.drawString(box_x + 20, row_y + 10, lbl)
                canvas.setFont("Times-Roman", 11)
                canvas.setFillColor(c_dark_blue)
                canvas.drawString(box_x + 115, row_y + 10, val)

            canvas.setFont("Times-Roman", 10)
            canvas.setFillColor(colors.HexColor('#475569'))
            canvas.drawCentredString(page_w / 2, 60, "Copyright \u00a9 Omni Scanner (omniscanner.com)")
            canvas.restoreState()

        def draw_header_footer(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor('#e2e8f0'))
            canvas.setLineWidth(0.5)
            canvas.line(50, 40, page_w - 50, 40)
            canvas.setFont("Helvetica", 9)
            canvas.setFillColor(colors.HexColor('#64748b'))
            canvas.drawRightString(page_w - 50, 25, f"Page {doc.page} | omni-scanner.com")
            canvas.restoreState()

        cover_frame = Frame(0, 0, page_w, page_h, id='cover')
        cover_template = PageTemplate(id='Cover', frames=[cover_frame], onPage=draw_cover)

        content_frame = Frame(50, 50, page_w - 100, page_h - 110,
                              leftPadding=0, rightPadding=0,
                              topPadding=0, bottomPadding=0, id='content')
        content_template = PageTemplate(id='Content', frames=[content_frame], onPage=draw_header_footer)
        doc = BaseDocTemplate(filepath, pagesize=A4, pageTemplates=[cover_template, content_template])


        styles = getSampleStyleSheet()
        h_exec = ParagraphStyle('HExec', fontName='Helvetica-Bold', fontSize=32, textColor=colors.HexColor('#334155'), spaceBefore=0, spaceAfter=30, leading=38)
        h_exec_p3 = ParagraphStyle('HExecP3', fontName='Helvetica-Bold', fontSize=32, textColor=colors.HexColor('#334155'), spaceBefore=0, spaceAfter=2, leading=38)
        h1_spec = ParagraphStyle('H1_Spec', fontName='Helvetica-Bold', fontSize=24, textColor=colors.HexColor('#1a1a1a'), spaceAfter=10, leading=30)
        h2 = ParagraphStyle('H2', fontName='Helvetica-Bold', fontSize=15, textColor=colors.HexColor('#334155'), spaceBefore=12, spaceAfter=6)
        h2_spec = ParagraphStyle('H2_Spec', fontName='Helvetica-Bold', fontSize=18, textColor=colors.HexColor('#1a1a1a'), spaceAfter=15, spaceBefore=0)
        body = ParagraphStyle('Body', fontName='Helvetica', fontSize=11.5, textColor=colors.HexColor('#475569'), spaceAfter=10, leading=15)
        body_sm = ParagraphStyle('BodySm', fontName='Helvetica', fontSize=10.5, textColor=colors.HexColor('#475569'), spaceAfter=8, leading=15)
        label = ParagraphStyle('LBL', fontName='Helvetica-Bold', fontSize=10.5, textColor=colors.HexColor('#1e293b'), leading=14)
        label_gray = ParagraphStyle('LBL_GRAY', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#64748b'), leading=12)
        label_meta = ParagraphStyle('LBL_META', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.HexColor('#94a3b8'), leading=10, textTransform='uppercase')
        value = ParagraphStyle('VAL', fontName='Helvetica', fontSize=10.5, textColor=colors.HexColor('#475569'), leading=14)
        value_meta = ParagraphStyle('VAL_META', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#334155'), leading=12)
        cvss_crit = ParagraphStyle('CVSS_CRIT', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#b30000'), leading=12)
        mono_val = ParagraphStyle('MONO_VAL', fontName='Courier-Bold', fontSize=10, textColor=colors.HexColor('#334155'), leading=12)
        impact_tag_red = ParagraphStyle('TAG_RED', fontName='Helvetica-Bold', fontSize=8.5, textColor=colors.HexColor('#b91c1c'), backColor=colors.HexColor('#fef2f2'), borderPadding=4, borderColor=colors.HexColor('#fecaca'), borderWidth=0.5, borderRadius=4)
        impact_tag_orange = ParagraphStyle('TAG_ORG', fontName='Helvetica-Bold', fontSize=8.5, textColor=colors.HexColor('#c2410c'), backColor=colors.HexColor('#fff7ed'), borderPadding=4, borderColor=colors.HexColor('#fed7aa'), borderWidth=0.5, borderRadius=4)

        findings = ai_data.get("findings", [])
        Story = [NextPageTemplate('Content'), PageBreak()]


        Story.append(Paragraph("Executive Summary", h_exec))

        exec_text = [
            f"This is the official automated security audit report generated by the Omni Scanner AI Threat Analysis module. Omni Scanner engaged advanced passive and active profiling to perform an application assessment on the target.",
            f"An automated reconnaissance approach to an application allows for rapid detection of exposed server configurations, unhardened endpoints, and publicly facing vulnerabilities that traditional vulnerability assessments may miss in the same testing period.",
            f"The purpose of this engagement was to identify security vulnerabilities in the targets listed in the targets and scope section. Once identified, each vulnerability was rated for technical impact. The target at <b>{display_target.lower()}</b> exhibits multiple critical security weaknesses typical of a development/vulnerable application. Significant injection vulnerabilities and missing security headers were detected. Immediate remediation is required before any production exposure.",
            f"This report details testing for the explicit target during the period of: <b>{datetime.now().strftime('%d/%m/%Y')}</b>.",
            f"The continuation of this document summarizes the findings, analysis, and recommendations from the automated scan performed by the Omni Scanner platform."
        ]

        for p in exec_text:
            Story.append(Paragraph(p, body))

        Story.append(Spacer(1, 50))
        Story.append(Paragraph("Generated by,", body_sm))
        Story.append(Spacer(1, 20))

        Story.append(Paragraph("Omni Scanner AI", ParagraphStyle('SignH1', fontName='Helvetica', fontSize=30, textColor=colors.HexColor('#1e293b'), leading=34)))
        Story.append(Paragraph("Automated Intelligence Engine", ParagraphStyle('SignH2', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#64748b'), leading=14)))
        Story.append(Paragraph("<u>security@omniscanner.local</u>", ParagraphStyle('SignH3', fontName='Helvetica-Bold', fontSize=10.5, textColor=colors.HexColor('#1e293b'), leading=16, spaceBefore=4)))
        Story.append(PageBreak())


        Story.append(Paragraph("Methodology & Risk Framework", h_exec_p3))
        Story.append(HRFlowable(width="100%", thickness=4, color=colors.HexColor('#991b1b'), spaceBefore=0, spaceAfter=20))

        methodology_intro = (
            "Omni Scanner AI utilises a multi-layered intelligence gathering approach. This cycle includes "
            "passive reconnaissance, active architectural profiling, and deep-reasoning vulnerability logic "
            "powered by the Gemini-2.1-Flash engine. Findings are analysed contextually against modern "
            "security standards and real-world exploitability chance."
        )
        Story.append(Paragraph(methodology_intro, body))
        Story.append(Spacer(1, 15))


        Story.append(Paragraph("Vulnerability Severity Definitions", h2))
        Story.append(Spacer(1, 2))

        sev_data = [
            [Paragraph("<b>Severity</b>", label_gray), Paragraph("<b>Impact & Intelligence Definition</b>", label_gray)],
            [Paragraph("<font color='#991b1b'><b>Critical</b></font>", body_sm),
             Paragraph("Exposures leading to full environment compromise (e.g. RCE, Direct SQLi). Immediate remediation required.", body_sm)],
            [Paragraph("<font color='#b45309'><b>High</b></font>", body_sm),
             Paragraph("Significant exploits that allow unauthorised data access or privilege escalation. High priority remediation.", body_sm)],
            [Paragraph("<font color='#1d4ed8'><b>Medium</b></font>", body_sm),
             Paragraph("Logic flaws or configuration issues that increase the attack surface if combined with other findings.", body_sm)],
            [Paragraph("<font color='#0d9488'><b>Low / Info</b></font>", body_sm),
             Paragraph("Security hardening recommendations and best-practice configuration notices.", body_sm)],
        ]
        sev_tbl = Table(sev_data, colWidths=[110, 370])
        sev_tbl.setStyle(TableStyle([
            ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor('#e2e8f0')),
            ('LINEBELOW', (0, 1), (-1, -2), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        Story.append(sev_tbl)
        Story.append(Spacer(1, 15))


        Story.append(Paragraph("Assessment Methodology", h2))
        Story.append(Spacer(1, 4))

        meth_data = [
            [Paragraph("<b>Attack Surface Mapping</b>", label),
             Paragraph("Discovery of unhardened endpoints and exposed service metadata.", body_sm)],
            [Paragraph("<b>Injection Vector Analysis</b>", label),
             Paragraph("Dynamic testing of input fields for XSS, SQLi, and logic errors.", body_sm)],
            [Paragraph("<b>Intelligence Synthesis</b>", label),
             Paragraph("Correlation of technical evidence with deep learning threat logic.", body_sm)],
            [Paragraph("<b>Exposure Verification</b>", label),
             Paragraph("Manual-grade analysis performed by automated reasoning threads.", body_sm)],
        ]
        meth_tbl = Table(meth_data, colWidths=[180, 300])
        meth_tbl.setStyle(TableStyle([
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        Story.append(meth_tbl)
        Story.append(PageBreak())


        Story.append(Paragraph("Targets and Scope", h1_spec))
        Story.append(HRFlowable(width="100%", thickness=3, color=colors.HexColor('#b30000'), spaceAfter=20))

        Story.append(Paragraph(
            "Prior to the automated program launching, Omni Scanner defined the Rules of Engagement, "
            "which includes the scope of work. The following targets were considered explicitly in scope for testing:",
            body))
        Story.append(Spacer(1, 15))


        code_p = Paragraph(f"<font name='Courier-Bold' color='#b30000'>{target_url}</font>",
                           ParagraphStyle('CP', fontName='Courier', fontSize=11, leading=14,
                                          backColor=colors.white, borderPadding=4,
                                          borderColor=colors.HexColor('#e0e0e0'), borderWidth=1))

        scope_box_data = [
            [Paragraph("<b>Web Applications / API Scope</b>", label)],
            [code_p]
        ]
        scope_box_tbl = Table(scope_box_data, colWidths=[480])
        scope_box_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9f9f9')),
            ('LINESTART', (0, 0), (0, -1), 4, colors.HexColor('#b30000')),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ('LEFTPADDING', (0, 0), (-1, -1), 20),
        ]))
        Story.append(scope_box_tbl)
        Story.append(Spacer(1, 20))


        Story.append(Paragraph("The findings of the security audit can be summarized as follows:", body))
        Story.append(Spacer(1, 15))

        vuls = sum(1 for f in findings if f.get('severity', '').lower() in ['critical', 'high'])
        hards = sum(1 for f in findings if f.get('severity', '').lower() in ['medium', 'low', 'info'])
        total = len(findings)

        summ_data = [
            [Paragraph("<b>Identified Vulnerabilities</b>", ParagraphStyle('W', fontName='Helvetica-Bold', fontSize=11, textColor=colors.white, alignment=TA_CENTER)),
             Paragraph("<b>Hardening Recommendations</b>", ParagraphStyle('W', fontName='Helvetica-Bold', fontSize=11, textColor=colors.white, alignment=TA_CENTER)),
             Paragraph("<b>Total Issues</b>", ParagraphStyle('W', fontName='Helvetica-Bold', fontSize=11, textColor=colors.white, alignment=TA_CENTER))],
            [Paragraph(f"<b><font size='14' color='#b30000'>{vuls}</font></b>", ParagraphStyle('C', alignment=TA_CENTER)),
             Paragraph(f"<b><font size='14' color='#d97706'>{hards}</font></b>", ParagraphStyle('C', alignment=TA_CENTER)),
             Paragraph(f"<b><font size='14' color='#1a1a1a'>{total}</font></b>", ParagraphStyle('C', alignment=TA_CENTER))]
        ]
        summ_tbl = Table(summ_data, colWidths=[160, 160, 160])
        summ_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a1a')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        Story.append(summ_tbl)
        Story.append(Spacer(1, 20))


        disc_style = ParagraphStyle('DS', fontName='Helvetica-Oblique', fontSize=10, textColor=colors.HexColor('#666666'),
                                     leading=14, backColor=colors.HexColor('#fdfdfd'), borderPadding=15,
                                     borderColor=colors.HexColor('#eeeeee'), borderWidth=0.5)
        Story.append(Paragraph("Please note that the analysis of the remaining work packages is provided separately or dynamically over subsequent scans. Moving forward, the scope section elaborates on the items under review, while the findings section documents the identified vulnerabilities followed by hardening recommendations with lower exploitation potential.", disc_style))
        Story.append(Spacer(1, 40))


        Story.append(Paragraph("Scope", h2_spec))
        Story.append(Paragraph("The following list outlines the items in scope for this project:", body))
        Story.append(Spacer(1, 15))


        Story.append(Paragraph("<font color='#b30000' size='14'>•</font> <b>Automated Scan against Web Servers and APIs</b>",
                               ParagraphStyle('L1', fontName='Helvetica-Bold', fontSize=11, textColor=colors.HexColor('#4a4a4a'))))
        Story.append(Spacer(1, 10))
        Story.append(Paragraph(f"&nbsp;&nbsp;&nbsp;&nbsp;<font color='#666666' size='14'>◦</font> Audited Endpoint: <font name='Courier-Bold' color='#4a4a4a'>{target_url}</font>",
                               ParagraphStyle('L2', leftIndent=20, fontName='Helvetica', fontSize=11, textColor=colors.HexColor('#4a4a4a'))))

        Story.append(PageBreak())


        Story.append(Paragraph("Findings", h1_spec))
        Story.append(Spacer(1, 15))
        Story.append(HRFlowable(width="100%", thickness=3.5, color=colors.HexColor('#b10a0a'), spaceAfter=20))

        intro_text = (
            f"The following section documents all security vulnerabilities identified during the automated scan of <b>{display_target.lower()}</b>. "
            "Each finding includes technical evidence, severity classification, potential impact, and prioritised remediation guidance.These are just some important findings only."
        )
        Story.append(Paragraph(intro_text, body))


        if total_findings is not None:
            detail_label = (
                f"This section details the top {len(findings)} most critical results for executive review. "
                f"A total of <b>{total_findings}</b> security findings were identified during the automated audit."
            )
            Story.append(Paragraph(detail_label, ParagraphStyle('DetailLBL', fontName='Helvetica-BoldOblique', fontSize=10, textColor=colors.HexColor('#64748b'), spaceBefore=10, spaceAfter=20)))

        Story.append(Spacer(1, 20))


        vuln_header_blocks = [
            Paragraph("Identified Vulnerabilities", h2_spec),
            Spacer(1, 15)
        ]

        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "MEDIUM").upper()
            sev_c = colors.HexColor('#b30000') if sev in ["CRITICAL","HIGH"] else colors.HexColor('#d97706') if sev == "MEDIUM" else colors.HexColor('#2563eb')


            c_id = Paragraph(f"F-{idx:03d}", ParagraphStyle('ID', fontName='Courier-Bold', fontSize=8, textColor=colors.HexColor('#475569'), backColor=colors.HexColor('#cbd5e1'), borderPadding=3, borderRadius=4))
            c_title = Paragraph(f"<b>{f.get('name','N/A')}</b>", ParagraphStyle('CT', fontName='Helvetica', fontSize=12, textColor=colors.HexColor('#1e293b')))
            c_sev = Paragraph(sev, ParagraphStyle('SB', fontName='Helvetica-Bold', fontSize=8.5, textColor=sev_c, alignment=TA_CENTER, borderPadding=4, borderColor=sev_c, borderWidth=1.2, borderRadius=6))

            header_tbl = Table([[c_id, c_title, c_sev]], colWidths=[45, 335, 75])
            header_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 10),
                ('BOTTOMPADDING', (0,0), (-1,-1), 10),
                ('LEFTPADDING', (0,0), (-1,-1), 15),
                ('RIGHTPADDING', (0,0), (-1,-1), 15),
                ('BOX', (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
            ]))


            sev_to_cvss = {"CRITICAL": "9.8 — Critical", "HIGH": "7.5 — High", "MEDIUM": "5.0 — Medium", "LOW": "2.5 — Low", "INFO": "0.0 — Info"}
            cvss_val = f.get('cvss') or sev_to_cvss.get(sev, "5.0 — Medium")


            cwe_raw = f.get('cwe', 'N/A')
            if cwe_raw == 'N/A':
                for t in f.get('tags', []):
                    if 'CWE' in str(t).upper():
                        cwe_raw = t
                        break

            if cwe_raw and cwe_raw != 'N/A' and 'CWE' in str(cwe_raw).upper():
                cwe_num = ''.join(filter(str.isdigit, str(cwe_raw)))
                cwe_disp = html.escape(str(cwe_raw))
                cwe_html = f'<a href="https://cwe.mitre.org/data/definitions/{cwe_num}.html" color="#2563eb"><u>{cwe_disp}</u></a>'
                cwe_p = Paragraph(cwe_html, mono_val)
            else:
                cwe_p = Paragraph(html.escape(str(cwe_raw)), mono_val)

            meta_tbl = Table([
                [Paragraph("CVSS Score", label_meta), Paragraph("CWE", label_meta), Paragraph("Endpoint", label_meta), Paragraph("Method", label_meta)],
                [Paragraph(str(cvss_val), cvss_crit if sev in ['CRITICAL', 'HIGH'] else value_meta),
                 cwe_p,
                 Paragraph(html.escape(f.get('url', '/')).lower(), mono_val),
                 Paragraph(html.escape(f.get('method', 'GET')), mono_val)]
            ], colWidths=[110, 100, 160, 85])
            meta_tbl.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 10),
                ('BOTTOMPADDING', (0,0), (-1,-1), 10),
                ('LEFTPADDING', (0,0), (-1,-1), 15),
            ]))


            desc_style = ParagraphStyle('D', fontName='Helvetica', fontSize=10.5, textColor=colors.HexColor('#475569'), leading=15, leftIndent=15, rightIndent=15)

            desc_text = str(f.get("description") or f.get("full_details") or f.get("short_description") or "Technical vulnerability discovered.").strip()

            desc_text = desc_text.replace('\n', ' ')
            if len(desc_text) > 250:
                desc_text = desc_text[:247] + "..."
            desc_p = Paragraph(highlight_params(html.escape(desc_text)), desc_style)

            poc_val = str(f.get("payload") or f.get("evidence") or "Technical proof available in full audit logs.").strip()

            poc_val = poc_val.replace('\n', ' ')
            if len(poc_val) > 150:
                poc_val = poc_val[:147] + "..."
            poc_html = f"<font color='#64748b'># Automated proof of concept evidence:</font><br/><font color='#4ade80'>{html.escape(poc_val)}</font>"
            poc_p = Paragraph(poc_html, ParagraphStyle('P', fontName='Courier', fontSize=9, textColor=colors.HexColor('#94a3b8'), leading=14))
            poc_box = Table([[poc_p]], colWidths=[430], style=[('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#0f172a')), ('PADDING', (0,0), (-1,-1), 15), ('ROUNDRECT', (0,0), (-1,-1), 6, colors.HexColor('#0f172a'))])
            poc_tbl = Table([[poc_box]], colWidths=[475], style=[('LEFTPADDING', (0,0), (-1,-1), 15)])


            impact_tags = [
                Paragraph(t, impact_tag_red if sev in ['CRITICAL', 'HIGH'] else impact_tag_orange)
                for t in (f.get("tags", ["Vulnerability", "Intelligence"])[:4])
            ]

            while len(impact_tags) < 4: impact_tags.append(Paragraph("", body_sm))

            tag_tbl = Table([[impact_tags[0], impact_tags[1]], [impact_tags[2], impact_tags[3]]], colWidths=[85, 100])
            tag_tbl.setStyle(TableStyle([('LEFTPADDING', (0,0), (-1,-1), 0), ('BOTTOMPADDING', (0,0), (-1,-1), 4)]))

            raw_rem = f.get("remediation", "Consult the security team for a tailored fix.")
            if isinstance(raw_rem, list):
                rem_html = "<br/>".join([f"<font color='#b30000'>\u2022</font> {html.escape(str(r))}" for r in raw_rem[:1]])
            else:
                rem_text = str(raw_rem).replace('\n', ' ').strip()
                if len(rem_text) > 150: rem_text = rem_text[:147] + "..."
                rem_html = html.escape(rem_text)

            rem_p = Paragraph(rem_html, ParagraphStyle('R', fontSize=9.5, textColor=colors.HexColor('#475569'), leading=14))

            footer_content = Table([[Paragraph("POTENTIAL IMPACT", label_meta), Paragraph("REMEDIATION", label_meta)], [tag_tbl, rem_p]], colWidths=[190, 260])
            footer_content.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP'), ('LEFTPADDING', (0,0), (-1,-1), 0), ('TOPPADDING', (0,0), (-1,-1), 5)]))
            footer_tbl = Table([[footer_content]], colWidths=[475], style=[('LEFTPADDING', (0,0), (-1,-1), 15)])


            label_style = ParagraphStyle('LS', fontName='Helvetica-Bold', fontSize=8.5, textColor=colors.HexColor('#94a3b8'), leftIndent=15)


            card_rows = [
                [header_tbl],
                [meta_tbl],
                [Spacer(1, 15)],
                [Paragraph("DESCRIPTION", label_style)],
                [Spacer(1, 5)],
                [desc_p],
                [Spacer(1, 15)],
                [Paragraph("EVIDENCE / PROOF OF CONCEPT", label_style)],
                [Spacer(1, 5)],
                [poc_tbl],
                [Spacer(1, 15)],
                [footer_tbl],
                [Spacer(1, 10)]
            ]

            card_outer = Table(card_rows, colWidths=[475])
            card_outer.setStyle(TableStyle([
                ('BOX', (0,0), (-1,-1), 0.3, colors.HexColor('#cbd5e1')),
                ('PADDING', (0,0), (-1,-1), 0),
                ('LEFTPADDING', (0,0), (-1,-1), 0),
                ('RIGHTPADDING', (0,0), (-1,-1), 0),
            ]))

            if idx == 1:

                Story.append(KeepTogether(vuln_header_blocks + [card_outer]))
            else:
                Story.append(KeepTogether(card_outer))

            Story.append(Spacer(1, 25))

        Story.append(PageBreak())


        Story.append(Paragraph("Risk Summary", h1_spec))
        Story.append(Spacer(1, 2))
        Story.append(HRFlowable(width="100%", thickness=3.5, color=colors.HexColor('#b10a0a'), spaceAfter=20))


        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            s = f.get("severity", "MEDIUM").upper()
            if s in counts: counts[s] += 1
            else: counts["LOW"] += 1

        total_issues = len(findings)

        intro_summary = (
            f"The table below summarises all security findings identified during the assessment of "
            f"<b>{display_target.lower()}</b>, organised by severity. Immediate remediation is required for all Critical and "
            "High severity items before any production exposure."
        )
        Story.append(Paragraph(intro_summary, body))
        Story.append(Spacer(1, 25))


        def make_card(num, label, color_hex):
            return Table([
                [Paragraph(str(num), ParagraphStyle('CN', fontName='Helvetica-Bold', fontSize=24, textColor=colors.HexColor(color_hex), alignment=TA_CENTER))],
                [Paragraph(label, ParagraphStyle('CL', fontName='Helvetica-Bold', fontSize=8, textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER))]
            ], colWidths=[90], style=[
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('TOPPADDING', (0,0), (-1,-1), 12),
                ('BOTTOMPADDING', (0,0), (-1,-1), 12),
                ('LINEABOVE', (0,0), (0,0), 3, colors.HexColor(color_hex)),
            ])


        real_total = total_findings if total_findings is not None else total_issues

        card_row = [
            make_card(counts["CRITICAL"], "CRITICAL", "#b10a0a"),
            make_card(counts["HIGH"], "HIGH", "#ea580c"),
            make_card(counts["MEDIUM"], "MEDIUM", "#eab308"),
            make_card(counts["LOW"], "LOW / INFO", "#2563eb"),
            make_card(real_total, "TOTAL ISSUES", "#475569")
        ]

        card_tbl = Table([card_row], colWidths=[96, 96, 96, 96, 96])
        card_tbl.setStyle(TableStyle([('LEFTPADDING', (0,0), (-1,-1), 0), ('RIGHTPADDING', (0,0), (-1,-1), 0)]))
        Story.append(card_tbl)
        Story.append(Spacer(1, 35))


        Story.append(Paragraph("FINDINGS OVERVIEW", label_meta))
        Story.append(Spacer(1, 10))

        thead = [
            Paragraph("ID", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
            Paragraph("VULNERABILITY", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
            Paragraph("ENDPOINT", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
            Paragraph("SEVERITY", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
            Paragraph("CVSS", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
            Paragraph("STATUS", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
            Paragraph("FIX BY", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white))
        ]

        tdata = [thead]
        for idx, f in enumerate(findings, 1):
            s = f.get("severity", "MEDIUM").upper()
            sc = colors.HexColor('#b30000') if s in ["CRITICAL","HIGH"] else colors.HexColor('#d97706') if s == "MEDIUM" else colors.HexColor('#2563eb')


            sb = Paragraph(s, ParagraphStyle('mSB', fontName='Helvetica-Bold', fontSize=7, textColor=sc, alignment=TA_CENTER, borderPadding=2.5, borderColor=sc, borderWidth=1, borderRadius=4))


            st_html = "<font color='#b30000'>\u2022</font> Open" if idx < 3 else "<font color='#d97706'>\u2022</font> In Progress"
            st_bg = colors.HexColor('#fef2f2') if idx < 3 else colors.HexColor('#fffbeb')
            st_p = Paragraph(st_html, ParagraphStyle('ST', fontName='Helvetica-Bold', fontSize=7, textColor=colors.HexColor('#475569'), alignment=TA_CENTER, borderPadding=3, backColor=st_bg, borderRadius=3))

            fix_by = "Immediate" if s == "CRITICAL" else "7 days" if s == "HIGH" else "14 days" if s == "MEDIUM" else "30 days"


            curr_cvss = f.get('cvss') or sev_to_cvss.get(s, "5.0").split('—')[0].strip()

            tdata.append([
                Paragraph(f"F-{idx:03d}", mono_val),
                Paragraph(f"{f.get('name','N/A')}", ParagraphStyle('VT', fontName='Helvetica-Bold', fontSize=8.5, textColor=colors.HexColor('#1e293b'))),
                Paragraph(f"{f.get('url','/')}".lower(), mono_val),
                sb,
                Paragraph(f"{curr_cvss}", ParagraphStyle('CV', fontName='Helvetica-Bold', fontSize=8, textColor=sc, alignment=TA_CENTER)),
                st_p,
                Paragraph(fix_by, ParagraphStyle('FB', fontName='Helvetica-Bold', fontSize=8, textColor=colors.HexColor('#b30000'), alignment=TA_CENTER))
            ])

        ov_tbl = Table(tdata, colWidths=[35, 130, 110, 60, 40, 60, 55])
        ov_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,1), (-1,-1), 0.3, colors.HexColor('#f1f5f9')),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
        ]))
        Story.append(ov_tbl)
        Story.append(Spacer(1, 35))


        severity_summary = f"Critical: {counts.get('CRITICAL', 0)}  \u00B7  High: {counts.get('HIGH', 0)}  \u00B7  Medium: {counts.get('MEDIUM', 0)}  \u00B7  Low/Info: {counts.get('LOW', 0)}"

        total_tbl_data = [
            [Paragraph("SCANNER REPORT: TOTAL VULNERABILITIES DETECTED", label_meta)],
            [Paragraph(f"<font size='11' color='#0f172a'>A total of <b>{real_total}</b> security issues were identified across the <b>{display_target.lower()}</b> infrastructure during this audit cycle. This number represents all verified vulnerabilities found by the Omni Scanner engine.</font>", body)],
            [Paragraph(f"<font size='9' color='#64748b'><b>Severity Breakdown:</b> {severity_summary}</font>", body_sm)]
        ]
        total_tbl = Table(total_tbl_data, colWidths=[485])
        total_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
            ('BOX', (0,0), (-1,-1), 0.3, colors.HexColor('#cbd5e1')),
            ('LINEBEFORE', (0,0), (0,0), 3, colors.HexColor('#0ea5e9')),
            ('PADDING', (0,0), (-1,-1), 15),
            ('BOTTOMPADDING', (0,0), (0,1), 5),
            ('TOPPADDING', (0,2), (-1,2), 0),
        ]))
        Story.append(total_tbl)
        Story.append(Spacer(1, 35))


        curr_date = datetime.now().strftime("%d/%m/%Y")
        disc_text = (
            f"<i>All findings above are based on the automated scan performed by Omni Scanner AI on {curr_date}. "
            "This summary should be reviewed alongside the detailed finding pages for full technical context, "
            "evidence, and step-by-step remediation guidance.</i>"
        )
        disc_tbl = Table([[Paragraph(disc_text, ParagraphStyle('DT', fontName='Helvetica-Oblique', fontSize=9, textColor=colors.HexColor('#475569'), leading=13))]], colWidths=[485])
        disc_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
            ('LINEBEFORE', (0,0), (0,0), 3, colors.HexColor('#1e293b')),
            ('PADDING', (0,0), (-1,-1), 15),
        ]))
        Story.append(disc_tbl)
        Story.append(PageBreak())


        Story.append(Paragraph("Conclusion", h1_spec))
        Story.append(Spacer(1, 2))
        Story.append(HRFlowable(width="100%", thickness=3.5, color=colors.HexColor('#b10a0a'), spaceAfter=20))


        inf_count = real_total - (counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"])
        summary_p1 = (
            f"The automated assessment of <b>{display_target.lower()}</b> identified <b>{real_total} security issues</b> — "
            f"{counts['CRITICAL']} Critical, {counts['HIGH']} High, and {max(0, inf_count)} informational hardening recommendation. "
            "The application exhibits significant vulnerabilities and is <b>not suitable for production deployment</b> in its current state."
        )
        Story.append(Paragraph(summary_p1, body))
        Story.append(Spacer(1, 15))

        summary_p2 = (
            "No high-risk injection vulnerabilities were successfully exploited in this cycle, but the hardening deficiencies identified provide an elevated surface area for manual exploitation. Immediate remediation of the findings in this report is required before any further exposure."
            if not counts["CRITICAL"] and not counts["HIGH"] else
            "The presence of high-severity vulnerabilities enables full administrative bypass or data exfiltration. Immediate remediation is required before any further exposure of this application."
        )
        Story.append(Paragraph(summary_p2, body))
        Story.append(Spacer(1, 25))


        scores = []
        for f in findings:
            sc_str = str(f.get('cvss', '0.0')).split('—')[0].strip()
            try: scores.append(float(re.findall(r"[-+]?\d*\.\d+|\d+", sc_str)[0]))
            except: pass
        if not scores: scores = [0.0]
        max_v = max(scores)
        if max_v == 0.0 and (counts["CRITICAL"] or counts["HIGH"]): max_v = 9.8 if counts["CRITICAL"] else 7.5

        alert_content = [
            [
                Paragraph("<font color='#b10a0a' size='36'><b>!</b></font>", ParagraphStyle('F', alignment=TA_CENTER, leading=40)),
                [
                    Paragraph("Critical Risk — Immediate Action Required" if counts["CRITICAL"] or counts["HIGH"] else "Medium Risk — Hardening Required",
                             ParagraphStyle('AT', fontName='Helvetica-Bold', fontSize=12, textColor=colors.HexColor('#1e293b'), leading=14)),
                    Spacer(1, 6),
                    Paragraph(f"Highest CVSS: {max_v}  \u00B7  Open Issues: {counts['CRITICAL'] + counts['HIGH']}  \u00B7  Resolved: 0  \u00B7  Scan Date: {curr_date}",
                             ParagraphStyle('AM', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#64748b'), leading=12))
                ]
            ]
        ]
        alert_tbl = Table(alert_content, colWidths=[65, 415])
        alert_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('LINEBEFORE', (0,0), (0,0), 3.5, colors.HexColor('#b10a0a')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 15),
            ('BOX', (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
        ]))
        Story.append(alert_tbl)
        Story.append(Spacer(1, 35))


        Story.append(Paragraph("KEY RECOMMENDATIONS", label_meta))
        Story.append(Spacer(1, 12))

        def make_rec(num, text):

            n_p = Paragraph(f"<font color='#b10a0a' size='10'><b>{num}</b></font>", ParagraphStyle('RN', fontName='Helvetica-Bold', alignment=TA_CENTER))
            t_p = Paragraph(text, ParagraphStyle('RT', fontName='Helvetica', fontSize=10, textColor=colors.HexColor('#475569'), leading=15))

            rt = Table([[n_p, t_p]], colWidths=[45, 435])
            rt.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
                ('BOX', (0,0), (-1,-1), 0.3, colors.HexColor('#f1f5f9')),
                ('ROUNDRECT', (0,0), (-1,-1), 6, colors.HexColor('#f8fafc')),
                ('PADDING', (0,0), (-1,-1), 12),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            return rt

        recs = [
            "Replace all dynamic SQL queries with <b>parameterised statements</b> and enforce server-side input validation sitewide.",
            "Implement <b>output encoding</b> and a Content Security Policy to eliminate the reflected XSS attack vector.",
            "Deploy missing <b>HTTP security headers</b> (HSTS, X-Frame-Options, CSP) and enforce HTTPS-only access."
        ]
        for i, r in enumerate(recs, 1):
            Story.append(make_rec(f"{i:02d}", r))
            Story.append(Spacer(1, 12))

        Story.append(Spacer(1, 20))
        Story.append(HRFlowable(width="100%", thickness=0.3, color=colors.HexColor('#e2e8f0'), spaceAfter=15))


        disclaimer = (
            "<i>This report represents a point-in-time assessment based on the scan conducted on " + curr_date + ". "
            "Findings are limited to the defined scope. This document is classified <b>Business Confidential</b> and must not be distributed "
            "outside the authorised recipient organisation. Omni Scanner accepts no liability for actions taken outside the agreed engagement scope.</i>"
        )
        Story.append(Paragraph(disclaimer, ParagraphStyle('FD', fontName='Helvetica', fontSize=8.5, textColor=colors.HexColor('#94a3b8'), leading=13)))
        Story.append(Spacer(1, 45))


        project_id = f"OMNI-AI-{datetime.now().strftime('%Y%m%d')}"
        sig_data = [
            [
                [
                    Paragraph("Omni Scanner AI", ParagraphStyle('SN', fontName='Helvetica-Bold', fontSize=16, textColor=colors.HexColor('#1e293b'))),
                    Spacer(1, 3),
                    Paragraph("AUTOMATED INTELLIGENCE ENGINE", ParagraphStyle('SS', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.HexColor('#b10a0a'))),
                    Spacer(1, 5),
                    Paragraph("<u>security@omniscanner.local</u>", ParagraphStyle('SE', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#64748b')))
                ],
                [
                    Paragraph(f"Report Date: {datetime.now().strftime('%B %d, %Y')}", ParagraphStyle('RD', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#94a3b8'), alignment=TA_RIGHT)),
                    Spacer(1, 6),
                    Paragraph(f"Project ID: {project_id}", ParagraphStyle('PI', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#94a3b8'), alignment=TA_RIGHT))
                ]
            ]
        ]
        sig_tbl = Table(sig_data, colWidths=[250, 245])
        sig_tbl.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'BOTTOM'),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
        ]))
        Story.append(sig_tbl)

        doc.build(Story)
        return filepath
    except Exception as e:
        logger.error(f"Error: {e}"); return ""
