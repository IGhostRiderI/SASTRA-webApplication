from io import BytesIO
from textwrap import shorten
from typing import Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


def _severity_rank(severity: str) -> int:
    ranks = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}
    return ranks.get(severity, 0)


def _severity_color(severity: str):
    palette = {
        "Critical": colors.HexColor("#B42318"),
        "High":     colors.HexColor("#E8590C"),
        "Medium":   colors.HexColor("#D39E00"),
        "Low":      colors.HexColor("#2B8A3E"),
    }
    return palette.get(severity, colors.HexColor("#4F5B62"))


def _text(text: str, width: int = 145) -> str:
    return shorten(str(text), width=width, placeholder=" ...")


def _normalized(value: str) -> str:
    return " ".join((value or "").lower().split())


def _show_rule_fix(ml_fix: str, rule_fix: str) -> bool:
    ml_n = _normalized(ml_fix)
    rule_n = _normalized(rule_fix)
    if not rule_n:
        return False
    if not ml_n:
        return True
    return rule_n not in ml_n


def build_pdf_report(scan_payload: Dict[str, object]) -> bytes:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    margin_x = 14 * mm
    content_width = width - (2 * margin_x)

    summary = scan_payload["summary"]
    findings = sorted(
        scan_payload.get("findings", []),
        key=lambda f: (_severity_rank(f["severity"]), -f["line_number"]),
        reverse=True,
    )

    # Header band
    header_h = 22 * mm
    c.setFillColor(colors.HexColor("#0F766E"))
    c.rect(0, height - header_h, width, header_h, fill=1, stroke=0)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 15)
    c.drawString(margin_x, height - 12 * mm, "SAST Scan Report")
    c.setFont("Helvetica", 9)
    c.drawString(margin_x, height - 17 * mm, "CWE + OWASP mapped vulnerability summary")

    y = height - header_h - 7 * mm

    # Metadata
    c.setFillColor(colors.HexColor("#1F2B2F"))
    c.setFont("Helvetica", 10)
    c.drawString(margin_x, y, f"File: {_text(scan_payload['filename'], 90)}")
    y -= 5 * mm
    c.drawString(margin_x, y, f"Language: {scan_payload['language']}")
    y -= 5 * mm
    c.drawString(margin_x, y, f"Files Scanned: {summary.get('files_scanned', 1)}")
    y -= 5 * mm
    c.drawString(margin_x, y, f"Scan ID: {scan_payload['scan_id']}   Scanned At (UTC): {_text(scan_payload['scanned_at'], 80)}")
    y -= 8 * mm

    # Summary card
    c.setFillColor(colors.HexColor("#F2F7F6"))
    c.setStrokeColor(colors.HexColor("#D7E4E1"))
    c.roundRect(margin_x, y - 20 * mm, content_width, 20 * mm, 4, fill=1, stroke=1)

    c.setFillColor(colors.HexColor("#1F2B2F"))
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin_x + 4 * mm, y - 6 * mm, "Summary")
    c.setFont("Helvetica", 10)
    c.drawString(
        margin_x + 4 * mm,
        y - 11 * mm,
        f"Total Findings: {summary['total_findings']}   Risk Score: {summary['risk_score']}",
    )

    severity = summary["severity"]
    chips_y = y - 17 * mm
    x_cursor = margin_x + 4 * mm
    for level in ["Critical", "High", "Medium", "Low"]:
        count = severity.get(level, 0)
        chip_color = _severity_color(level)
        chip_w = 27 * mm
        c.setFillColor(chip_color)
        c.roundRect(x_cursor, chips_y, chip_w, 4.5 * mm, 2.2, fill=1, stroke=0)
        c.setFillColor(colors.white if level != "Medium" else colors.HexColor("#2F2F2F"))
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(x_cursor + chip_w / 2, chips_y + 1.35 * mm, f"{level}: {count}")
        x_cursor += chip_w + 2.2 * mm

    y -= 26 * mm

    c.setFillColor(colors.HexColor("#1F2B2F"))
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin_x, y, "Findings")
    y -= 5 * mm

    for index, finding in enumerate(findings, start=1):
        llm_fix = (finding.get("llm_fix") or "").strip()
        card_h = 34 * mm if llm_fix else 30 * mm
        if y - card_h < 16 * mm:
            c.showPage()
            c.setFillColor(colors.HexColor("#0F766E"))
            c.rect(0, height - 14 * mm, width, 14 * mm, fill=1, stroke=0)
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 11)
            c.drawString(margin_x, height - 9.3 * mm, "SAST Scan Report - Findings Continued")
            y = height - 22 * mm

        severity_label = finding["severity"]
        sev_color = _severity_color(severity_label)

        c.setFillColor(colors.HexColor("#FBFCFC"))
        c.setStrokeColor(colors.HexColor("#DDE7E5"))
        c.roundRect(margin_x, y - card_h, content_width, card_h, 3.5, fill=1, stroke=1)

        c.setFillColor(sev_color)
        c.roundRect(margin_x + 1.2 * mm, y - card_h + 1.2 * mm, 3.5 * mm, card_h - 2.4 * mm, 1.5, fill=1, stroke=0)

        text_x = margin_x + 6.6 * mm
        text_y = y - 5 * mm

        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(colors.HexColor("#1F2B2F"))
        c.drawString(
            text_x,
            text_y,
            _text(
                f"{index}. [{severity_label}] {finding['title']} | {finding['cwe_id']} | Line {finding['line_number']}:{finding['column_number']}",
            ),
        )

        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#37474F"))
        c.drawString(text_x, text_y - 4 * mm, _text(f"File: {finding.get('source_path', scan_payload['filename'])}", 128))
        c.drawString(text_x, text_y - 8 * mm, _text(f"OWASP: {finding['owasp_category']}"))
        c.drawString(text_x, text_y - 12 * mm, _text(f"Code: {finding['snippet']}", 128))

        # ML confidence for this finding, displayed as a dedicated line.
        ml_sev = finding.get("ml_severity", "")
        ml_conf = finding.get("ml_confidence", finding.get("ml_severity_confidence", 0.0))
        try:
            ml_conf = float(ml_conf)
        except (TypeError, ValueError):
            ml_conf = 0.0
        ml_conf_percent = (ml_conf * 100.0) if ml_conf <= 1 else ml_conf
        ml_conf_percent = max(0.0, min(100.0, ml_conf_percent))
        if ml_sev:
            ml_line = f"ML Confidence: {ml_conf_percent:.0f}% (Severity: {ml_sev})"
        else:
            ml_line = f"ML Confidence: {ml_conf_percent:.0f}%"
        c.drawString(text_x, text_y - 16 * mm, _text(ml_line, 128))

        # Rule-based recommendation + FP flag
        rule_fix = finding.get("recommendation", "")
        fp_flag  = bool(finding.get("fp_flag", False))
        fp_label = finding.get("fp_label", "")
        suffix   = f"  ⚠ {fp_label}" if fp_flag and fp_label else ("  ⚠ Potential false positive" if fp_flag else "")
        c.drawString(text_x, text_y - 20 * mm, _text(f"Fix: {rule_fix}{suffix}", 128))

        # LLM-generated fix
        if llm_fix:
            c.setFillColor(colors.HexColor("#1B4F72"))
            c.drawString(text_x, text_y - 24 * mm, _text(f"AI Fix: {llm_fix}", 128))
            c.setFillColor(colors.HexColor("#37474F"))

        y -= card_h + 3 * mm

    c.save()
    buffer.seek(0)
    return buffer.read()
