import os
from datetime import datetime
from typing import Any, Dict, List
import logging
import html
from utils.vuln_utils import get_vuln_info

logger = logging.getLogger(__name__)

def generate_manual_pdf_report(data: Dict[str, Any], filepath: str, logo_path: str = None) -> str:
    """
    Constructs a high-fidelity professional VAPT PDF report.
    Finalized v5: Perfect Cover + New Findings Layout.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


        cwd = os.getcwd()
        if not logo_path:
            paths = [
                os.path.join(cwd, "Assets", "Logo.png"),
                os.path.join(cwd, "backend", "Assets", "Logo.png"),
                os.path.join(cwd, "Assets", "Omni Scanner logo.png")
            ]
            for p in paths:
                if os.path.exists(p):
                    logo_path = p
                    break

        if logo_path and not os.path.exists(logo_path):
            logger.warning(f"Logo not found at {logo_path}")
            logo_path = None

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=45, leftMargin=45, topMargin=95, bottomMargin=50
        )


        c_dark_blue = colors.HexColor('#143154')
        c_cyan = colors.HexColor('#00a9ba')
        c_light_gray = colors.HexColor('#f4f6f9')
        c_text_gray = colors.HexColor('#9ba4b5')
        c_red = colors.HexColor('#d62c2c')
        c_orange = colors.HexColor('#d67a00')
        c_blue = colors.HexColor('#1a66cc')


        title_style = ParagraphStyle('TitleStyle', fontName='Helvetica-Bold', fontSize=34, textColor=c_dark_blue, spaceAfter=4, leading=38)
        subtitle_top = ParagraphStyle('SubtitleTop', fontName='Helvetica-Bold', fontSize=8, textColor=colors.HexColor('#929aab'), letterSpacing=0.8, spaceAfter=4)
        subtitle_bottom = ParagraphStyle('SubtitleBot', fontName='Helvetica', fontSize=13, textColor=c_cyan, spaceAfter=18)
        section_label = ParagraphStyle('SectionLabel', fontName='Helvetica-Bold', fontSize=9, textColor=c_text_gray, spaceBefore=18, spaceAfter=6, textTransform='uppercase')
        body_style = ParagraphStyle('BodyStyle', fontName='Helvetica', fontSize=10, textColor=colors.HexColor('#4a5568'), leading=13)


        f_section_title = ParagraphStyle('FSectionTitle', fontName='Helvetica-Bold', fontSize=24, textColor=colors.HexColor('#153359'), leading=28, spaceAfter=30)
        f_header_style = ParagraphStyle('FHeaderStyle', fontName='Helvetica-Bold', fontSize=12, textColor=colors.whitesmoke, leading=14)

        label_style = ParagraphStyle('LabelStyle', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#153359'), leading=12)
        value_style = ParagraphStyle('ValueStyle', fontName='Helvetica', fontSize=10, textColor=colors.HexColor('#4a5568'), leading=12)

        block_label_style = ParagraphStyle('BlockLabelStyle', fontName='Helvetica-Bold', fontSize=8.5, textColor=c_text_gray, spaceBefore=10, spaceAfter=4, textTransform='uppercase')

        poc_style = ParagraphStyle('POCStyle', fontName='Courier-Bold', fontSize=9, textColor=colors.HexColor('#f8fafc'), leading=11, leftIndent=10)
        context_style = ParagraphStyle('ContextStyle', fontName='Helvetica', fontSize=9.5, textColor=colors.HexColor('#4a5568'), leading=12, leftIndent=10)
        rem_style = ParagraphStyle('RemStyle', fontName='Helvetica', fontSize=9.5, textColor=colors.HexColor('#0c4a6e'), leading=12, leftIndent=10)


        target = data.get('target', 'Unknown Target')
        scan_date = data.get('scan_date', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        scan_mode = data.get('scan_mode', 'Normal Mode')
        workers = data.get('workers', 5)
        results = data.get('results', {})

        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        findings_list = []

        for mod_name, mod_data in results.items():
            if mod_name == 'crawler': continue
            for url, result in mod_data.items():
                if isinstance(result, dict) and result.get('vulnerabilities_found'):
                    for detail in result.get('details', []):
                        v_type = detail.get('type', 'Unknown Vulnerability')
                        provided_sev = detail.get('severity')
                        if provided_sev:
                            sev = provided_sev.capitalize()
                            rem = detail.get('remediation', 'Implement explicit validation rules.')
                        else:
                            sev, rem = get_vuln_info(v_type)

                        if sev == 'Critical': counts['Critical'] += 1
                        elif sev == 'High': counts['High'] += 1
                        elif sev in ['Low', 'Info']: counts['Low'] += 1
                        else: counts['Medium'] += 1

                        findings_list.append({
                            'type': v_type, 'severity': sev, 'url': url,
                            'parameter': detail.get('parameter', 'N/A'),
                            'payload': detail.get('payload_used', 'N/A'),
                            'evidence': detail.get('evidence', 'N/A'),
                            'remediation': rem
                        })


        sev_priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Information": 4}
        findings_list.sort(key=lambda x: sev_priority.get(x['severity'], 99))

        total_vulns = len(findings_list)
        if counts['Critical'] > 0:
            risk_level = "CRITICAL RISK"
            risk_color = c_red
        elif counts['High'] > 0:
            risk_level = "HIGH RISK"
            risk_color = c_red
        elif counts['Medium'] > 0:
            risk_level = "MEDIUM RISK"
            risk_color = c_orange
        else:
            risk_level = "LOW RISK"
            risk_color = c_blue

        def add_header_footer(canvas, doc):
            canvas.saveState()
            page_w, page_h = A4
            head_h = 85
            canvas.setFillColor(c_dark_blue)
            canvas.rect(0, page_h - head_h, page_w, head_h, fill=True, stroke=False)
            canvas.setStrokeColor(c_cyan)
            canvas.setLineWidth(5)
            canvas.line(0, page_h - 2.5, page_w, page_h - 2.5)
            canvas.setLineWidth(1.5)
            canvas.line(0, page_h - head_h, page_w, page_h - head_h)
            if logo_path:
                try: canvas.drawImage(logo_path, 45, page_h - 75, width=150, height=60, preserveAspectRatio=True, mask='auto')
                except: pass
            canvas.setFont("Helvetica-Bold", 10)
            canvas.setFillColor(c_cyan)
            canvas.drawRightString(page_w - 45, page_h - 50, "OmniScanner.com")
            foot_h = 45
            canvas.setFillColor(c_dark_blue)
            canvas.rect(0, 0, page_w, foot_h, fill=True, stroke=False)
            canvas.setStrokeColor(c_cyan)
            canvas.setLineWidth(5)
            canvas.line(0, 2.5, page_w, 2.5)
            canvas.setFont("Helvetica", 9)
            canvas.setFillColor(colors.HexColor('#7b8e9f'))
            canvas.drawString(45, 18, "CONFIDENTIAL — Authorized use only")
            canvas.drawRightString(page_w - 45, 18, f"Page {doc.page} | omni-scanner-report.pdf")
            canvas.restoreState()

        Story = []


        Story.append(Paragraph("<font color='#929aab'><b>■</b> SECURITY ASSESSMENT REPORT · CONFIDENTIAL</font>", subtitle_top))
        Story.append(Paragraph("Pentest Report", title_style))
        Story.append(Paragraph("AI-Powered Automated Vulnerability Assessment", subtitle_bottom))
        Story.append(HRFlowable(width="100%", thickness=2, color=c_cyan, spaceBefore=-12, spaceAfter=20))

        Story.append(Paragraph("TARGET INFRASTRUCTURE", section_label))
        target_tb = Table([[Paragraph(f"<b>{target}</b>", ParagraphStyle('TgtURL', fontName='Helvetica-Bold', fontSize=20, textColor=colors.HexColor('#1a66cc')))]], colWidths=[505])
        target_tb.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), c_light_gray), ('LINESTART', (0,0), (0,0), 4, c_cyan), ('LEFTPADDING', (0,0), (-1,-1), 22), ('TOPPADDING', (0,0), (-1,-1), 16), ('BOTTOMPADDING', (0,0), (-1,-1), 16)]))
        Story.append(target_tb)
        Story.append(Paragraph(f"Automated Scan · {scan_mode} · {workers} Workers", ParagraphStyle('TgtMeta', fontSize=10, textColor=colors.HexColor('#8c98a4'), spaceBefore=5)))

        Story.append(Paragraph("OVERALL INFRASTRUCTURE RISK LEVEL", section_label))
        risk_tb = Table([[Paragraph(risk_level, ParagraphStyle('RL', fontName='Helvetica-Bold', fontSize=15, textColor=risk_color, alignment=TA_CENTER))]], colWidths=[190])
        risk_tb.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fffaf0')), ('BOX', (0,0), (-1,-1), 2, colors.HexColor('#f6b553')), ('ROUNDEDCORNERS', [5,5,5,5]), ('TOPPADDING', (0,0), (-1,-1), 10), ('BOTTOMPADDING', (0,0), (-1,-1), 10)]))
        Story.append(risk_tb)

        Story.append(Paragraph("FINDINGS SUMMARY", section_label))
        def make_sum_card(val, label, bg, border, txt):
            p_val = Paragraph(f"<b>{val}</b>", ParagraphStyle('CV', fontSize=30, textColor=txt, alignment=TA_CENTER)); p_lbl = Paragraph(label, ParagraphStyle('CL', fontSize=9, textColor=txt, alignment=TA_CENTER, fontName='Helvetica-Bold'))
            return Table([[p_val], [p_lbl]], colWidths=[120], style=TableStyle([('BACKGROUND', (0,0), (-1,-1), bg), ('BOX', (0,0), (-1,-1), 1, border), ('ROUNDEDCORNERS', [5,5,5,5]), ('TOPPADDING', (0,0), (-1,-1), 12), ('BOTTOMPADDING', (0,0), (-1,-1), 12)]))
        sums_tb = Table([[make_sum_card(counts['Critical'] + counts['High'], "CRITICAL / HIGH", colors.HexColor('#fff3f3'), colors.HexColor('#f9d8d8'), c_red), make_sum_card(counts['Medium'], "MEDIUM", colors.HexColor('#fff9ef'), colors.HexColor('#fce4ba'), c_orange), make_sum_card(counts['Low'], "LOW / INFO", colors.HexColor('#f1f6ff'), colors.HexColor('#c9defc'), c_blue), make_sum_card(total_vulns, "TOTAL FINDINGS", c_light_gray, colors.HexColor('#dce1e7'), c_dark_blue)]], colWidths=[126, 126, 126, 126], hAlign='LEFT')
        Story.append(sums_tb)

        Story.append(Paragraph("SCAN DETAILS", section_label))
        details_tb = Table([[Paragraph("<b>Execution Timestamp</b>", body_style), Paragraph(scan_date, body_style)], [Paragraph("<b>Execution Architecture</b>", body_style), Paragraph(scan_mode, body_style)], [Paragraph("<b>Attack Surface</b>", body_style), Paragraph(f"{len(results.get('crawler', {}))} Endpoints", body_style)], [Paragraph("<b>Active Modules</b>", body_style), Paragraph(", ".join(results.keys()), body_style)], [Paragraph("<b>Report File</b>", body_style), Paragraph("scan_report.json", body_style)]], colWidths=[170, 335])
        details_tb.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.7, colors.HexColor('#eaedf1')), ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#fbfcfd')), ('PADDING', (0,0), (-1,-1), 10), ('VALIGN', (0,0), (-1,-1), 'MIDDLE')]))
        Story.append(details_tb)
        Story.append(Spacer(1, 30))
        Story.append(Paragraph("GENERATED BY", section_label))
        gen_tb = Table([[Paragraph("<b>Omni Scanner AI</b><br/><font color='#8c98a4' size='9'>Automated Intelligence Engine</font>", body_style), Paragraph(f"Report Date: {datetime.now().strftime('%B %d, %Y')}<br/>Version 1.0", ParagraphStyle('GenRight', fontSize=10, textColor=colors.HexColor('#8c98a4'), alignment=TA_RIGHT))]], colWidths=[250, 255])
        gen_tb.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'BOTTOM')]))
        Story.append(gen_tb)


        Story.append(PageBreak())


        Story.append(Paragraph("2. Detailed Technical Findings", f_section_title))
        Story.append(HRFlowable(width="100%", thickness=2, color=c_cyan, spaceBefore=-25, spaceAfter=25))

        if not findings_list:
            Story.append(Paragraph("No vulnerabilities detected.", body_style))
        else:
            for idx, finding in enumerate(findings_list, start=1):
                sev = finding['severity']

                if sev in ['Critical', 'High']:
                    bg_color = c_red; text_color_class = 'text-critical'
                elif sev == 'Medium':
                    bg_color = c_orange; text_color_class = 'text-medium'
                else:
                    bg_color = c_blue; text_color_class = 'text-low'


                header_p = Paragraph(f"Finding #{idx}: {finding['type']}", f_header_style)


                info_table_data = [
                    [Paragraph("Severity:", label_style), Paragraph(f"<font color='{bg_color.hexval()}'>{sev}</font>", label_style)],
                    [Paragraph("Affected Endpoint:", label_style), Paragraph(html.escape(finding['url']), value_style)],
                    [Paragraph("Vulnerable Parameter:", label_style), Paragraph(html.escape(finding['parameter']), value_style)],
                ]
                info_table = Table(info_table_data, colWidths=[150, 315])
                info_table.setStyle(TableStyle([('LEFTPADDING', (0,0), (-1,-1), 0), ('TOPPADDING', (0,0), (-1,-1), 2), ('BOTTOMPADDING', (0,0), (-1,-1), 2)]))

                card_content = []
                card_content.append(info_table)


                card_content.append(Paragraph("Proof of Concept (Payload injected):", block_label_style))
                poc_box = Table([[Paragraph(html.escape(finding['payload']), poc_style)]], colWidths=[465])
                poc_box.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), c_dark_blue), ('ROUNDEDCORNERS', [4,4,4,4]), ('TOPPADDING', (0,0), (-1,-1), 10), ('BOTTOMPADDING', (0,0), (-1,-1), 10)]))
                card_content.append(poc_box)


                card_content.append(Paragraph("Server Output Context:", block_label_style))
                context_box = Table([[Paragraph(html.escape(finding['evidence']), context_style)]], colWidths=[465])
                context_box.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), c_light_gray), ('LINESTART', (0,0), (0,0), 3, colors.HexColor('#9ba4b5')), ('TOPPADDING', (0,0), (-1,-1), 10), ('BOTTOMPADDING', (0,0), (-1,-1), 10)]))
                card_content.append(context_box)


                card_content.append(Paragraph("Remediation Action Required:", block_label_style))
                rem_box = Table([[Paragraph(html.escape(finding['remediation']), rem_style)]], colWidths=[465])
                rem_box.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f0f7ff')), ('LINESTART', (0,0), (0,0), 3, c_cyan), ('TOPPADDING', (0,0), (-1,-1), 10), ('BOTTOMPADDING', (0,0), (-1,-1), 10)]))
                card_content.append(rem_box)


                full_card_data = [
                    [header_p],
                    [card_content]
                ]

                final_card = Table(full_card_data, colWidths=[495])
                final_card.setStyle(TableStyle([
                    ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#eaedf1')),
                    ('BACKGROUND', (0,0), (0,0), bg_color),
                    ('TOPPADDING', (0,1), (0,1), 15),
                    ('BOTTOMPADDING', (0,1), (0,1), 15),
                    ('LEFTPADDING', (0,1), (0,1), 15),
                    ('RIGHTPADDING', (0,1), (0,1), 15),

                ]))

                Story.append(KeepTogether(final_card))
                Story.append(Spacer(1, 25))

        doc.build(Story, onFirstPage=add_header_footer, onLaterPages=add_header_footer)
        return filepath
    except Exception as e:
        logger.error(f"Failed to generate manual PDF: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return ""
