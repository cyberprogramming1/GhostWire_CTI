

from __future__ import annotations

import io
import re
from typing import Optional, Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.units     import mm
from reportlab.lib.colors    import HexColor, white, black
from reportlab.lib.styles    import ParagraphStyle
from reportlab.lib.enums     import TA_LEFT, TA_CENTER
from reportlab.platypus      import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
# Native ReportLab charting — no Plotly dependency, renders inline in PDF
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line
from reportlab.graphics        import renderPDF
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.piecharts import Pie

import logging
logger = logging.getLogger(__name__)


# ── Colour palette (matches GhostWire dark UI) ───────────────────────────────
C_BG      = HexColor("#060a10")
C_SURFACE = HexColor("#0a1520")
C_BORDER  = HexColor("#1a2a3a")
C_TEXT    = HexColor("#c0d4e8")
C_MUTED   = HexColor("#4a6a8a")
C_GREEN   = HexColor("#00ffb4")
C_CYAN    = HexColor("#00c8ff")
C_YELLOW  = HexColor("#ffd060")
C_ORANGE  = HexColor("#ff9a3c")
C_RED     = HexColor("#ff2d55")
C_PURPLE  = HexColor("#c47aff")

LEVEL_COLORS = {
    "SAFE":     HexColor("#00ffb4"),
    "LOW":      HexColor("#78d97a"),
    "MEDIUM":   HexColor("#ffd060"),
    "HIGH":     HexColor("#ff6b35"),
    "CRITICAL": HexColor("#ff2d55"),
}
LEVEL_BG = {
    "SAFE":     HexColor("#051810"),
    "LOW":      HexColor("#0a1f0a"),
    "MEDIUM":   HexColor("#1f1a05"),
    "HIGH":     HexColor("#1f0f05"),
    "CRITICAL": HexColor("#1f050a"),
}

_VERDICT_HA_COLORS = {
    "malicious":          HexColor("#ff2d55"),
    "suspicious":         HexColor("#ffd060"),
    "no specific threat": HexColor("#78d97a"),
    "whitelisted":        HexColor("#00ffb4"),
    "no verdict":         HexColor("#4a6a8a"),
}

# ── Security: input sanitisation ─────────────────────────────────────────────

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _safe_str(val: Any, max_len: int = 200) -> str:
    """
    Sanitise any value for safe embedding in a ReportLab PDF.
    Strips control characters, null bytes, truncates to max_len.
    Prevents PDF injection and encoding errors.
    """
    if val is None:
        return "N/A"
    s = str(val)
    s = _CTRL_RE.sub("", s)
    s = s.replace("\x00", "")
    return s[:max_len] or "N/A"


def _clamp(v: Any, lo: int = 0, hi: int = 100) -> int:
    """Clamp score to valid range to prevent bar-chart overflow/underflow."""
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return 0


def _classify_score(score: int) -> tuple[str, str, str]:
    """Return (threat_level, colour_hex, bg_hex) for a raw 0-100 score."""
    s = _clamp(score)
    if s >= 85:
        return "CRITICAL", "#ff2d55", "rgba(255,45,85,0.08)"
    if s >= 65:
        return "HIGH",     "#ff6b35", "rgba(255,107,53,0.08)"
    if s >= 40:
        return "MEDIUM",   "#ffd060", "rgba(255,208,96,0.06)"
    if s >= 20:
        return "LOW",      "#78d97a", "rgba(120,217,122,0.06)"
    return "SAFE", "#00ffb4", "rgba(0,255,180,0.06)"


# ── Styles ────────────────────────────────────────────────────────────────────

def _build_styles() -> dict:
    return {
        "title": ParagraphStyle(
            "title", fontName="Courier-Bold", fontSize=20,
            textColor=C_CYAN, alignment=TA_CENTER, spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontName="Courier", fontSize=9,
            textColor=HexColor("#2a6a5a"), alignment=TA_CENTER, spaceAfter=2,
        ),
        "h1": ParagraphStyle(
            "h1", fontName="Courier-Bold", fontSize=12,
            textColor=C_CYAN, spaceBefore=12, spaceAfter=5,
        ),
        "h2": ParagraphStyle(
            "h2", fontName="Courier-Bold", fontSize=9.5,
            textColor=C_GREEN, spaceBefore=8, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", fontName="Courier", fontSize=8,
            textColor=C_TEXT, leading=13, spaceAfter=3,
        ),
        "mono": ParagraphStyle(
            "mono", fontName="Courier", fontSize=7.5,
            textColor=C_TEXT, leading=11, spaceAfter=2,
        ),
        "flag": ParagraphStyle(
            "flag", fontName="Courier", fontSize=7.5,
            textColor=HexColor("#8aaac8"), leading=12, leftIndent=8, spaceAfter=1,
        ),
        "ioc": ParagraphStyle(
            "ioc", fontName="Courier-Bold", fontSize=7.5,
            textColor=C_RED, leading=11, spaceAfter=1,
        ),
        "caption": ParagraphStyle(
            "caption", fontName="Courier", fontSize=6.5,
            textColor=HexColor("#2a5a4a"), alignment=TA_CENTER,
        ),
        "warning": ParagraphStyle(
            "warning", fontName="Courier-Bold", fontSize=8,
            textColor=C_RED, backColor=HexColor("#1a0005"),
            borderPad=4, spaceAfter=3,
        ),
        "mit_step": ParagraphStyle(
            "mit_step", fontName="Courier", fontSize=8,
            textColor=C_TEXT, leading=13, leftIndent=10, spaceAfter=2,
        ),
        "action": ParagraphStyle(
            "action", fontName="Courier", fontSize=8,
            textColor=HexColor("#8aaac8"), leading=13, leftIndent=12, spaceAfter=2,
        ),
    }


# ── Page template ─────────────────────────────────────────────────────────────

def _on_page(canvas, doc, target: str, timestamp: str, pipeline: str = "URL") -> None:
    W, H = A4
    canvas.saveState()

    # ── Full dark background ─────────────────────────────────────────
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)

    # ── Scan-line overlay effect (subtle horizontal lines) ───────────
    canvas.setStrokeColor(HexColor("#0d1525"))
    canvas.setLineWidth(0.3)
    for y in range(0, int(H), 4):
        canvas.line(0, y, W, y)

    # ── Header bar ───────────────────────────────────────────────────
    canvas.setFillColor(HexColor("#0a1828"))
    canvas.rect(0, H - 20*mm, W, 20*mm, fill=1, stroke=0)

    # Cyan accent line top
    canvas.setStrokeColor(C_CYAN)
    canvas.setLineWidth(1.5)
    canvas.line(0, H - 20*mm, W, H - 20*mm)

    # Left side: GhostWire branding
    canvas.setFillColor(C_CYAN)
    canvas.setFont("Courier-Bold", 9)
    canvas.drawString(12*mm, H - 10*mm, "GHOSTWIRE CTI v6")
    canvas.setFillColor(C_MUTED)
    canvas.setFont("Courier", 7)
    canvas.drawString(12*mm, H - 15*mm, "CYBER THREAT INTELLIGENCE PLATFORM")

    # Pipeline badge
    pip_color = {
        "URL": C_CYAN, "IP": HexColor("#c47aff"),
        "FILE": HexColor("#ff9a3c"), "HASH": HexColor("#ff9a3c"),
        "EMAIL": HexColor("#ffd060"), "SANDBOX": HexColor("#ff2d55"),
    }.get(pipeline.upper(), C_CYAN)

    badge_x = W - 80*mm
    canvas.setFillColor(HexColor("#0d1525"))
    canvas.roundRect(badge_x, H - 16*mm, 35*mm, 8*mm, 2, fill=1, stroke=0)
    canvas.setStrokeColor(pip_color)
    canvas.setLineWidth(0.5)
    canvas.roundRect(badge_x, H - 16*mm, 35*mm, 8*mm, 2, fill=0, stroke=1)
    canvas.setFillColor(pip_color)
    canvas.setFont("Courier-Bold", 7)
    canvas.drawCentredString(badge_x + 17.5*mm, H - 11*mm, f"PIPELINE: {pipeline.upper()}")

    # TLP badge
    tlp_x = W - 42*mm
    canvas.setFillColor(HexColor("#1a0a00"))
    canvas.roundRect(tlp_x, H - 16*mm, 28*mm, 8*mm, 2, fill=1, stroke=0)
    canvas.setStrokeColor(HexColor("#ff9a3c"))
    canvas.setLineWidth(0.5)
    canvas.roundRect(tlp_x, H - 16*mm, 28*mm, 8*mm, 2, fill=0, stroke=1)
    canvas.setFillColor(HexColor("#ff9a3c"))
    canvas.setFont("Courier-Bold", 7)
    canvas.drawCentredString(tlp_x + 14*mm, H - 11*mm, "TLP:AMBER")

    # Timestamp
    canvas.setFillColor(C_MUTED)
    canvas.setFont("Courier", 6.5)
    canvas.drawRightString(W - 12*mm, H - 6*mm, _safe_str(timestamp, 40))

    # ── Footer bar ───────────────────────────────────────────────────
    canvas.setFillColor(HexColor("#0a1828"))
    canvas.rect(0, 0, W, 13*mm, fill=1, stroke=0)

    # Cyan accent top of footer
    canvas.setStrokeColor(C_CYAN)
    canvas.setLineWidth(0.5)
    canvas.line(0, 13*mm, W, 13*mm)

    # Vertical separator
    canvas.setStrokeColor(HexColor("#1a2a3a"))
    canvas.setLineWidth(0.5)
    canvas.line(W/2, 2*mm, W/2, 11*mm)

    canvas.setFillColor(HexColor("#2a6a5a"))
    canvas.setFont("Courier", 6.5)
    canvas.drawString(12*mm, 8*mm, "TARGET:")
    canvas.setFillColor(C_TEXT)
    canvas.setFont("Courier-Bold", 6.5)
    canvas.drawString(30*mm, 8*mm, _safe_str(target, 55))

    canvas.setFillColor(HexColor("#2a6a5a"))
    canvas.setFont("Courier", 6.5)
    canvas.drawString(12*mm, 3.5*mm, "GENERATED BY GhostWire CTI  |  CONFIDENTIAL")

    canvas.setFillColor(C_MUTED)
    canvas.setFont("Courier", 6.5)
    canvas.drawRightString(W - 12*mm, 8*mm, f"PAGE {doc.page}")
    canvas.setFillColor(HexColor("#2a5a7a"))
    canvas.setFont("Courier", 6)
    canvas.drawRightString(W - 12*mm, 3.5*mm, "ghostwire-cti-v6 | abuse.ch | MITRE ATT&CK")

    # ── Left accent stripe ────────────────────────────────────────────
    canvas.setFillColor(C_CYAN)
    canvas.rect(0, 13*mm, 1.5, H - 33*mm, fill=1, stroke=0)

    canvas.restoreState()


# ── Reusable layout helpers ───────────────────────────────────────────────────

def _section_bar(story: list, styles: dict, title: str) -> None:
    story.append(Spacer(1, 5 * mm))
    # Hacker-style: left-glow border + dark surface + cyan monospace text
    sec_data = [[Paragraph(
        f'<font color="#00ffb4">▸</font> <font color="#00ffb4">{_safe_str(title, 80).upper()}</font>',
        ParagraphStyle(
            "sec", fontName="Courier-Bold", fontSize=8.5,
            textColor=C_CYAN, leftIndent=4,
        ),
    )]]
    sec_t = Table(sec_data, colWidths=[165 * mm], rowHeights=[9 * mm])
    sec_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#060f1a")),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("LINEAFTER",     (0, 0), (0, -1), 0, C_BG),
        ("LINEBEFORE",    (0, 0), (0, -1), 3, C_CYAN),
        ("BOX",           (0, 0), (-1, -1), 0.3, HexColor("#0a2030")),
    ]))
    story.append(sec_t)
    story.append(Spacer(1, 2 * mm))


def _score_bar_table(label: str, score: int, max_s: int, color: HexColor) -> Table:
    """Mini horizontal score bar rendered as a table row."""
    score  = _clamp(score, 0, max_s)
    pct    = max(2, int(score / max_s * 100)) if max_s else 2
    bar_w  = 60
    filled = max(1, bar_w * pct // 100)
    empty  = max(1, bar_w - filled)

    data = [[
        Paragraph(_safe_str(label, 30), ParagraphStyle(
            "sl", fontName="Courier", fontSize=7, textColor=C_MUTED)),
        "", "",
        Paragraph(f"{score}/{max_s}", ParagraphStyle(
            "sv", fontName="Courier-Bold", fontSize=7, textColor=color)),
    ]]
    t = Table(data,
              colWidths=[45 * mm, filled * mm, empty * mm, 14 * mm],
              rowHeights=5 * mm)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (1, 0), (1, 0), color),
        ("BACKGROUND",    (2, 0), (2, 0), C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("LEFTPADDING",   (0, 0), (-1, -1), 2),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 2),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def _kv_table(rows: list[tuple[str, str]],
              col_widths: tuple[int, int] = (50, 110)) -> Table:
    """Two-column key-value table — terminal / hacker style."""
    data = [[_safe_str(k, 40), _safe_str(v, 150)] for k, v in rows]
    t = Table(data,
              colWidths=[col_widths[0] * mm, col_widths[1] * mm],
              rowHeights=6.5 * mm)
    t.setStyle(TableStyle([
        ("FONT",          (0, 0), (0, -1), "Courier-Bold", 7),
        ("FONT",          (1, 0), (1, -1), "Courier", 7),
        ("TEXTCOLOR",     (0, 0), (0, -1), HexColor("#2a7a6a")),   # muted green for keys
        ("TEXTCOLOR",     (1, 0), (1, -1), C_TEXT),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [HexColor("#0a1520"), HexColor("#080e18")]),
        ("BOX",           (0, 0), (-1, -1), 0.3, HexColor("#0a2030")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.2, HexColor("#0d1a28")),
        ("LINEBEFORE",    (0, 0), (0, -1), 2, HexColor("#0a3040")),  # left accent
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (0, -1), 6),
        ("LEFTPADDING",   (1, 0), (1, -1), 4),
    ]))
    return t


def _score_gauge_drawing(score: int, threat_level: str) -> Drawing:
    """
    Render a native ReportLab score gauge (pie donut + score text).
    Embeds directly in PDF — no Plotly/external image needed.
    Returns a Drawing object usable as a Flowable.
    """
    score  = _clamp(score)
    level_color = LEVEL_COLORS.get(threat_level, C_CYAN)

    W, H = 120, 120
    d = Drawing(W, H)

    # Outer circle background
    d.add(Circle(60, 55, 48, fillColor=HexColor("#0a1520"), strokeColor=HexColor("#1a2a3a"), strokeWidth=1))

    # Donut segments: filled arc (score%) + empty arc (remainder%)
    # ReportLab Pie used as donut via innerRadiusFraction
    pie = Pie()
    pie.x           = 12
    pie.y           = 7
    pie.width       = 96
    pie.height      = 96
    pie.startAngle  = 90   # start at top

    filled_pct  = max(1, score)
    empty_pct   = max(1, 100 - score)
    pie.data    = [filled_pct, empty_pct]

    pie.slices[0].fillColor    = level_color
    pie.slices[0].strokeColor  = HexColor("#0a1520")
    pie.slices[0].strokeWidth  = 1
    pie.slices[1].fillColor    = HexColor("#1a2a3a")
    pie.slices[1].strokeColor  = HexColor("#0a1520")
    pie.slices[1].strokeWidth  = 1

    pie.innerRadiusFraction = 0.65   # donut hole
    pie.simpleLabels = 1
    pie.labels       = ["", ""]
    d.add(pie)

    # Centre: score number
    d.add(String(60, 48, str(score),
                 fontName="Helvetica-Bold", fontSize=22,
                 fillColor=level_color, textAnchor="middle"))
    d.add(String(60, 36, "/100",
                 fontName="Helvetica", fontSize=8,
                 fillColor=HexColor("#4a6a8a"), textAnchor="middle"))
    d.add(String(60, 24, threat_level,
                 fontName="Courier-Bold", fontSize=8,
                 fillColor=level_color, textAnchor="middle"))
    d.add(String(60, 109, "RISK SCORE",
                 fontName="Courier-Bold", fontSize=7,
                 fillColor=HexColor("#4a6a8a"), textAnchor="middle"))
    return d


def _engine_barchart_drawing(engines: list[tuple[str, int, int]]) -> Drawing:
    """
    Native ReportLab horizontal bar chart for engine score breakdown.
    engines: list of (label, score, max_score)
    Returns Drawing — embeds directly in PDF.
    """
    n      = len(engines)
    bar_h  = 9
    gap    = 3
    H      = n * (bar_h + gap) + 30
    W      = 400

    d = Drawing(W, H)

    # Background
    d.add(Rect(0, 0, W, H, fillColor=HexColor("#0a1520"),
               strokeColor=HexColor("#1a2a3a"), strokeWidth=0.5))

    label_w  = 110
    score_w  = 28
    bar_area = W - label_w - score_w - 12

    COLOURS = [
        HexColor("#00c8ff"), HexColor("#ff9a3c"), HexColor("#c47aff"),
        HexColor("#ff2d55"), HexColor("#ffd060"), HexColor("#00ffb4"),
        HexColor("#00c8ff"), HexColor("#c47aff"),
    ]

    for i, (label, score, max_s) in enumerate(engines):
        y = H - 22 - i * (bar_h + gap)
        pct = max(0.02, score / max_s) if max_s else 0.02
        col = COLOURS[i % len(COLOURS)]

        # Empty track
        d.add(Rect(label_w, y, bar_area, bar_h,
                   fillColor=HexColor("#1a2a3a"), strokeColor=None))
        # Filled portion
        d.add(Rect(label_w, y, int(bar_area * pct), bar_h,
                   fillColor=col, strokeColor=None))
        # Label
        d.add(String(label_w - 4, y + 1.5, label[:20],
                     fontName="Courier", fontSize=6.5,
                     fillColor=HexColor("#8aaac8"), textAnchor="end"))
        # Score value
        d.add(String(label_w + bar_area + 4, y + 1.5, f"{score}/{max_s}",
                     fontName="Courier-Bold", fontSize=6.5,
                     fillColor=col, textAnchor="start"))

    # Title
    d.add(String(W // 2, H - 10, "ENGINE SCORE BREAKDOWN",
                 fontName="Courier-Bold", fontSize=7.5,
                 fillColor=HexColor("#00ffb4"), textAnchor="middle"))
    return d


def _chart_row(gauge: Drawing, barchart: Drawing) -> Table:
    """
    Place gauge + barchart side-by-side in a PDF table row.
    Both are native ReportLab Drawings — render inline without any image files.
    """
    from reportlab.platypus import Flowable

    class _DrawingFlowable(Flowable):
        """Wraps a ReportLab Drawing as a Platypus Flowable."""
        def __init__(self, drawing: Drawing):
            super().__init__()
            self._d = drawing
            self.width  = drawing.width
            self.height = drawing.height

        def draw(self):
            renderPDF.draw(self._d, self.canv, 0, 0)

    g_flow = _DrawingFlowable(gauge)
    b_flow = _DrawingFlowable(barchart)

    t = Table([[g_flow, b_flow]],
              colWidths=[130 * mm, 35 * mm],
              rowHeights=[max(gauge.height, barchart.height)])
    t.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 2),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 2),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#060a10")),
    ]))
    return t


def _header_table(rows: list[list[str]], col_widths: list[int],
                  header_color: HexColor = None) -> Table:
    """Table with colored header row, repeating on new pages."""
    if header_color is None:
        header_color = C_CYAN
    t = Table(rows, colWidths=[w * mm for w in col_widths], repeatRows=1)
    t.setStyle(TableStyle([
        ("FONT",          (0, 0), (-1, 0), "Courier-Bold", 7.5),
        ("FONT",          (0, 1), (-1, -1), "Courier", 7),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_BG),
        ("BACKGROUND",    (0, 0), (-1, 0), header_color),
        ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_SURFACE, C_BG]),
        ("BOX",           (0, 0), (-1, -1), 0.3, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.2, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
    ]))
    return t


def _cover_page(
    story: list,
    styles: dict,
    target: str,
    score: int,
    threat_level: str,
    confidence: int,
    timestamp: str,
    duration: float,
    ioc_count: int,
    pipeline_label: str,
    one_line: str = "",
    extra_meta: Optional[list[tuple[str, str]]] = None,
) -> None:
    """Shared cover page builder — hacker terminal aesthetic."""
    level_color = LEVEL_COLORS.get(threat_level, C_CYAN)
    level_bg    = LEVEL_BG.get(threat_level, C_SURFACE)

    story.append(Spacer(1, 6 * mm))

    # ── ASCII-art style logo block ─────────────────────────────────────
    logo_lines = [
        " ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗    ██╗██╗██████╗ ███████╗",
        "██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║    ██║██║██╔══██╗██╔════╝",
        "██║  ███╗███████║██║   ██║███████╗   ██║   ██║ █╗ ██║██║██████╔╝█████╗  ",
        "██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║███╗██║██║██╔══██╗██╔══╝  ",
        "╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚███╔███╔╝██║██║  ██║███████╗",
        " ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝",
        "                  C  T  I     P  L  A  T  F  O  R  M     v  6             ",
    ]
    logo_data = [
        [Paragraph(line, ParagraphStyle(
            "logo", fontName="Courier", fontSize=4.8,
            textColor=HexColor("#1a4a3a"), alignment=TA_CENTER,
        ))]
        for line in logo_lines
    ]
    logo_t = Table(logo_data, colWidths=[165 * mm])
    logo_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#040810")),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("LINEAFTER",     (0, 0), (0, -1), 0, C_BG),
        ("LINEBEFORE",    (0, 0), (0, -1), 1, HexColor("#0a3040")),
        ("LINEAFTER",     (0, 0), (-1, -1), 1, HexColor("#0a3040")),
    ]))
    story.append(logo_t)
    story.append(Spacer(1, 3 * mm))

    # ── Classification stripe ──────────────────────────────────────────
    stripe_data = [[Paragraph(
        f"[ TLP:AMBER ]  ·  CONFIDENTIAL  ·  {_safe_str(pipeline_label, 45).upper()}  ·  GHOSTWIRE CTI v6",
        ParagraphStyle("stripe", fontName="Courier-Bold", fontSize=7,
                       textColor=HexColor("#040810"), alignment=TA_CENTER),
    )]]
    stripe_t = Table(stripe_data, colWidths=[165 * mm], rowHeights=[7 * mm])
    stripe_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#00c8aa")),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(stripe_t)
    story.append(Spacer(1, 5 * mm))

    # ── Target box — terminal-style ───────────────────────────────────
    td = [
        [Paragraph("[ ANALYSIS TARGET ]", ParagraphStyle(
            "tl", fontName="Courier-Bold", fontSize=7,
            textColor=HexColor("#2a6a5a"), alignment=TA_CENTER))],
        [Paragraph(_safe_str(target, 90), ParagraphStyle(
            "tv", fontName="Courier-Bold", fontSize=10,
            textColor=C_CYAN, alignment=TA_CENTER))],
    ]
    target_t = Table(td, colWidths=[165 * mm], rowHeights=[6 * mm, 10 * mm])
    target_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#060f1a")),
        ("BOX",           (0, 0), (-1, -1), 1.5, C_CYAN),
        ("LINEBEFORE",    (0, 0), (0, -1), 4, C_CYAN),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(target_t)
    story.append(Spacer(1, 5 * mm))

    # ── Threat metrics row ────────────────────────────────────────────
    def _metric_cell(label: str, value: str, color: HexColor, bg: HexColor) -> Table:
        d = [
            [Paragraph(f"[ {label} ]", ParagraphStyle(
                "ml", fontName="Courier-Bold", fontSize=6.5,
                textColor=HexColor("#2a5a4a"), alignment=TA_CENTER))],
            [Paragraph(value, ParagraphStyle(
                "mv", fontName="Courier-Bold", fontSize=18,
                textColor=color, alignment=TA_CENTER))],
        ]
        t = Table(d, colWidths=[51 * mm], rowHeights=[7 * mm, 16 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg),
            ("BOX",           (0, 0), (-1, -1), 1.5, color),
            ("LINEBEFORE",    (0, 0), (0, -1), 3, color),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return t

    metrics_row = [[
        _metric_cell("THREAT LEVEL",  _safe_str(threat_level, 10), level_color, level_bg),
        Spacer(3 * mm, 1),
        _metric_cell("RISK SCORE",    f"{_clamp(score)}/100",       level_color, level_bg),
        Spacer(3 * mm, 1),
        _metric_cell("CONFIDENCE",    f"{_clamp(confidence)}%",     C_CYAN,      C_SURFACE),
    ]]
    metrics_t = Table(metrics_row, colWidths=[51*mm, 3*mm, 51*mm, 3*mm, 51*mm],
                      rowHeights=[23 * mm])
    metrics_t.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(metrics_t)
    story.append(Spacer(1, 5 * mm))

    # ── One-line verdict ──────────────────────────────────────────────
    if one_line:
        verdict_box_data = [[Paragraph(
            f"▸ {_safe_str(one_line, 180)}",
            ParagraphStyle("verdict_line", fontName="Courier-Bold", fontSize=9,
                           textColor=level_color, alignment=TA_LEFT,
                           spaceBefore=2, spaceAfter=2),
        )]]
        verdict_box_t = Table(verdict_box_data, colWidths=[165 * mm])
        verdict_box_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), level_bg),
            ("BOX",           (0, 0), (-1, -1), 0.5, level_color),
            ("LINEBEFORE",    (0, 0), (0, -1), 4, level_color),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(verdict_box_t)
        story.append(Spacer(1, 4 * mm))

    # ── Metadata grid ─────────────────────────────────────────────────
    meta = [
        ("TIMESTAMP UTC",      _safe_str(timestamp, 40)),
        ("PIPELINE",           _safe_str(pipeline_label, 60)),
        ("IOCs IDENTIFIED",    str(ioc_count)),
        ("ANALYSIS DURATION",  f"{duration:.1f}s" if duration else "N/A"),
    ]
    if extra_meta:
        for k, v in extra_meta:
            meta.append((_safe_str(k, 30).upper(), _safe_str(v, 110)))

    meta_data = [[_safe_str(k, 35), _safe_str(v, 120)] for k, v in meta]
    meta_t = Table(meta_data,
                   colWidths=[50 * mm, 115 * mm],
                   rowHeights=6.5 * mm)
    meta_t.setStyle(TableStyle([
        ("FONT",          (0, 0), (0, -1), "Courier-Bold", 7),
        ("FONT",          (1, 0), (1, -1), "Courier", 7),
        ("TEXTCOLOR",     (0, 0), (0, -1), HexColor("#2a7a6a")),
        ("TEXTCOLOR",     (1, 0), (1, -1), C_TEXT),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [HexColor("#0a1520"), HexColor("#080e18")]),
        ("BOX",           (0, 0), (-1, -1), 0.3, HexColor("#0a2030")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.2, HexColor("#0d1a28")),
        ("LINEBEFORE",    (0, 0), (0, -1), 2, HexColor("#0a3040")),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (0, -1), 6),
        ("LEFTPADDING",   (1, 0), (1, -1), 4),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 5 * mm))

    # ── Disclaimer ────────────────────────────────────────────────────
    disc_data = [[Paragraph(
        "This report is generated automatically by GhostWire CTI v6. "
        "Results should be reviewed by a qualified security analyst. "
        "IOC data sourced from VirusTotal, AbuseIPDB, Shodan, GreyNoise, URLhaus, OTX, Hybrid Analysis.",
        ParagraphStyle("disc", fontName="Courier", fontSize=6.5,
                       textColor=HexColor("#2a4a3a"), alignment=TA_CENTER),
    )]]
    disc_t = Table(disc_data, colWidths=[165 * mm])
    disc_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#060f1a")),
        ("BOX",           (0, 0), (-1, -1), 0.3, HexColor("#0a2030")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(disc_t)
    story.append(Spacer(1, 1 * mm))
    story.append(Paragraph(
        f"Generated: {_safe_str(timestamp, 40)}  |  GhostWire CTI v6  |  stay ghost.",
        styles["caption"],
    ))

    story.append(PageBreak())


def _disclaimer_footer(story: list, styles: dict, timestamp: str) -> None:
    story.append(Spacer(1, 8 * mm))
    # Hacker-style footer separator
    sep_data = [[Paragraph(
        "─" * 80,
        ParagraphStyle("sep", fontName="Courier", fontSize=6,
                       textColor=HexColor("#0a2030"), alignment=TA_CENTER),
    )]]
    sep_t = Table(sep_data, colWidths=[165 * mm])
    sep_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#040810")),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(sep_t)
    story.append(Spacer(1, 2 * mm))

    disc_data = [[Paragraph(
        "[ TLP:AMBER ]  CONFIDENTIAL  ·  FOR INTERNAL USE ONLY  ·  "
        "Results must be validated by a qualified security analyst before action.  "
        "AI inference performed locally — no data transmitted to external AI services.",
        ParagraphStyle("disc", fontName="Courier", fontSize=6.5,
                       textColor=HexColor("#2a4a3a"), alignment=TA_CENTER),
    )]]
    disc_t = Table(disc_data, colWidths=[165 * mm])
    disc_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#060f1a")),
        ("BOX",           (0, 0), (-1, -1), 0.3, HexColor("#0a2030")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(disc_t)
    story.append(Spacer(1, 1 * mm))
    story.append(Paragraph(
        f"Generated: {_safe_str(timestamp, 40)}  |  GhostWire CTI v6  |  stay ghost.",
        styles["caption"],
    ))


def _doc_build(story: list, target: str,
               timestamp: str, pipeline: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=28 * mm, bottomMargin=18 * mm,
    )
    doc.build(
        story,
        onFirstPage  = lambda c, d: _on_page(c, d, target, timestamp, pipeline),
        onLaterPages = lambda c, d: _on_page(c, d, target, timestamp, pipeline),
    )
    buf.seek(0)
    return buf.read()


# =============================================================================
# Pipeline A — URL / Domain Analysis
# =============================================================================

def generate_cti_report(
    target:       str,
    verdict,
    sig,
    h_res,
    w_res,
    ai_res,
    rep_res,
    dec_res,
    sb_res,
    ssl_res,
    pdns_res,
    all_iocs:     list[str],
    duration:     float,
    timestamp:    str,
    shodan_res    = None,
    greynoise_res = None,
    urlhaus_res   = None,   # FIX v7: added missing param — pipeline passes this, caused TypeError crash
    otx_res       = None,   # FIX v7: added missing param — pipeline passes this, caused TypeError crash
    extra_flags:  Optional[list] = None,
) -> bytes:
    """Generate URL/Domain pipeline CTI PDF. Returns raw bytes."""
    styles = _build_styles()
    story: list[Any] = []
    extra_flags = extra_flags or []

    _cover_page(
        story, styles,
        target         = target,
        score          = verdict.score,
        threat_level   = verdict.threat_level,
        confidence     = getattr(sig, "overall_confidence", 50),
        timestamp      = timestamp,
        duration       = duration,
        ioc_count      = len(all_iocs),
        pipeline_label = "URL / Domain Analysis",
        one_line       = getattr(verdict, "one_line", ""),
        extra_meta     = [
            ("Engines Run",   "10 detection engines"),
            ("IP Address",    getattr(rep_res, "ip_address", None) or "N/A"),
            ("VT Detections", f"{getattr(rep_res,'vt_malicious',0)}/{getattr(rep_res,'vt_total_engines',0)}"),
        ],
    )

    # ── Score Gauge + Engine Bar Chart (native PDF graphics) ─────────
    _gauge = _score_gauge_drawing(
        score=verdict.score,
        threat_level=verdict.threat_level,
    )
    _engines_for_chart = [
        ("URL Heuristics",      getattr(h_res,    "score", 0), 30),
        ("WHOIS / Domain Age",  getattr(w_res,    "score", 0), 40),
        ("AI NLP (Ollama)",     getattr(ai_res,   "score", 0), 30),
        ("Infrastructure Rep",  getattr(rep_res,  "score", 0), 40),
        ("Tech Deception",      getattr(dec_res,  "score", 0), 30),
        ("Sandbox Simulation",  getattr(sb_res,   "score", 0), 30),
        ("SSL/TLS Certificate", getattr(ssl_res,  "score", 0), 50),
        ("Passive DNS / IP",    getattr(pdns_res, "score", 0), 30),
    ]
    _barchart = _engine_barchart_drawing(_engines_for_chart)
    story.append(_chart_row(_barchart, _gauge))
    story.append(Spacer(1, 4 * mm))

    # Override banners
    if getattr(sig, "infrastructure_override", False):
        story.append(Paragraph(
            "INFRASTRUCTURE OVERRIDE ACTIVE — VT returned >8 malicious detections. "
            "Score locked to CRITICAL.",
            styles["warning"],
        ))
    if getattr(sig, "brand_squatting", False):
        story.append(Paragraph(
            "BRAND SQUATTING DETECTED — High-value brand keywords in domain. +35 penalty.",
            ParagraphStyle("squat", fontName="Courier-Bold", fontSize=8,
                           textColor=C_YELLOW, backColor=HexColor("#1a1500"),
                           borderPad=4, spaceAfter=3),
        ))

    # 1. Executive Summary
    _section_bar(story, styles, "1. Executive Summary")
    story.append(Paragraph(_safe_str(getattr(verdict, "one_line", ""), 200), styles["h2"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(_safe_str(getattr(verdict, "full_verdict", ""), 800), styles["body"]))

    if getattr(ai_res, "summary", "") and not getattr(ai_res, "error", None):
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph("AI Assessment (Ollama — local inference):", styles["h2"]))
        story.append(Paragraph(_safe_str(ai_res.summary, 400), styles["body"]))

    # 2. Engine Score Breakdown
    _section_bar(story, styles, "2. Engine Score Breakdown")
    engines = [
        ("URL Heuristics",      getattr(h_res,    "score", 0), 30,  C_CYAN),
        ("WHOIS / Domain Age",  getattr(w_res,    "score", 0), 40,  C_ORANGE),
        ("AI NLP (Ollama)",     getattr(ai_res,   "score", 0), 30,  C_PURPLE),
        ("Infrastructure Rep",  getattr(rep_res,  "score", 0), 40,  C_RED),
        ("Tech Deception",      getattr(dec_res,  "score", 0), 30,  C_YELLOW),
        ("Sandbox Simulation",  getattr(sb_res,   "score", 0), 30,  C_GREEN),
        ("SSL/TLS Certificate", getattr(ssl_res,  "score", 0), 50,  C_CYAN),
        ("Passive DNS / IP",    getattr(pdns_res, "score", 0), 30,  C_PURPLE),
    ]
    for eng_label, eng_score, eng_max, eng_color in engines:
        story.append(_score_bar_table(eng_label, eng_score, eng_max, eng_color))
    story.append(Spacer(1, 3 * mm))

    if extra_flags:
        story.append(Paragraph("Scoring Override Rules Applied:", styles["h2"]))
        for flag in extra_flags[:10]:
            story.append(Paragraph(f"> {_safe_str(flag, 120)}", styles["flag"]))

    # 3. Source Intelligence
    _section_bar(story, styles, "3. Source Intelligence")
    src_rows = [
        ["Source", "Result", "Impact"],
        ["VirusTotal Engines",
         f"{getattr(rep_res,'vt_malicious',0)}/{getattr(rep_res,'vt_total_engines',0)} malicious",
         "Primary"],
        ["VT Community",
         f"{getattr(rep_res,'vt_community_malicious_votes',0)} malicious votes",
         "Supplemental"],
        ["VT Related Files",
         f"{getattr(rep_res,'vt_malicious_files_related',0)} malicious",
         "Supplemental"],
        ["AbuseIPDB",
         f"{getattr(rep_res,'abuse_confidence',0)}% confidence, "
         f"{getattr(rep_res,'abuse_reports',0)} reports",
         "Primary"],
        ["SPF Record",   "Valid"   if getattr(rep_res, "spf_valid", False)  else "Missing", "Auth"],
        ["DMARC Record", "Found"   if getattr(rep_res, "dmarc_found", False) else "Missing", "Auth"],
    ]
    if shodan_res and getattr(shodan_res, "available", False):
        src_rows.append([
            "Shodan",
            f"{len(getattr(shodan_res,'open_ports',[]))} open ports, "
            f"{getattr(shodan_res,'vuln_count',0)} CVEs",
            "Supplemental",
        ])
    if greynoise_res and getattr(greynoise_res, "available", False):
        src_rows.append([
            "GreyNoise",
            f"noise={getattr(greynoise_res,'noise','?')}, "
            f"class={getattr(greynoise_res,'classification','?')}",
            "Context",
        ])
    story.append(_header_table(
        [[_safe_str(c, 80) for c in row] for row in src_rows],
        [50, 80, 30],
    ))

    # 4. IOCs
    _section_bar(story, styles, "4. Indicators of Compromise (IOCs)")
    if all_iocs:
        for ioc in all_iocs[:40]:
            story.append(Paragraph(f"* {_safe_str(ioc, 120)}", styles["ioc"]))
    else:
        story.append(Paragraph("No IOCs identified.", styles["body"]))

    # 5. Detection Signals
    _section_bar(story, styles, "5. Detection Signals by Engine")
    engine_flags = [
        ("URL Heuristics",     getattr(h_res,    "flags", []), C_CYAN),
        ("WHOIS / Domain Age", getattr(w_res,    "flags", []), C_ORANGE),
        ("AI NLP",             getattr(ai_res,   "flags", []), C_PURPLE),
        ("Infrastructure",     getattr(rep_res,  "flags", []), C_RED),
        ("Tech Deception",     getattr(dec_res,  "flags", []), C_YELLOW),
        ("Sandbox Simulation", getattr(sb_res,   "flags", []), C_GREEN),
        ("SSL/TLS",            getattr(ssl_res,  "flags", []), C_CYAN),
        ("Passive DNS / IP",   getattr(pdns_res, "flags", []), C_PURPLE),
    ]
    if shodan_res:
        engine_flags.append(("Shodan",     getattr(shodan_res,    "flags", []), C_ORANGE))
    if greynoise_res:
        engine_flags.append(("GreyNoise",  getattr(greynoise_res, "flags", []), C_CYAN))
    # FIX v8: URLhaus and OTX now included in PDF report
    if urlhaus_res and getattr(urlhaus_res, "available", False):
        engine_flags.append(("URLhaus (abuse.ch)", getattr(urlhaus_res, "flags", []), C_RED))
    if otx_res and getattr(otx_res, "available", False):
        engine_flags.append(("OTX AlienVault",    getattr(otx_res,     "flags", []), C_PURPLE))

    for eng_name, flags, eng_color in engine_flags:
        if not flags:
            continue
        story.append(KeepTogether([
            Paragraph(_safe_str(eng_name, 30), ParagraphStyle(
                "eng", fontName="Courier-Bold", fontSize=8,
                textColor=eng_color, spaceBefore=5, spaceAfter=2)),
            *[Paragraph(f"  > {_safe_str(f, 120)}", styles["flag"]) for f in flags[:8]],
        ]))

    # 6. MITRE ATT&CK
    mitre_tuples = getattr(pdns_res, "mitre_tactics", [])
    if mitre_tuples:
        _section_bar(story, styles, "6. MITRE ATT&CK Tactics")
        mitre_rows = [["Tactic ID", "Technique", "Description"]]
        for entry in mitre_tuples[:12]:
            if isinstance(entry, (list, tuple)) and len(entry) >= 3:
                mitre_rows.append([
                    _safe_str(entry[0], 15),
                    _safe_str(entry[1], 15),
                    _safe_str(entry[2], 80),
                ])
        story.append(_header_table(mitre_rows, [22, 24, 114], C_PURPLE))

    # 7. Behavioral Signals
    _section_bar(story, styles, "7. Behavioral Signal Summary")
    signal_items = [
        ("Urgency Language",        getattr(sig, "urgency",                False)),
        ("Financial Threat",        getattr(sig, "financial_threat",       False)),
        ("Manipulation Tactics",    getattr(sig, "manipulation",           False)),
        ("Credential Harvesting",   getattr(sig, "credential_harvest",     False)),
        ("Fake Login Page",         getattr(sig, "fake_login_page",        False)),
        ("Malware Dropper",         getattr(sig, "malware_dropper",        False)),
        ("Crypto Drainer",          getattr(sig, "crypto_drainer",         False)),
        ("Tor Exit Node",           getattr(sig, "tor_exit_node",          False)),
        ("VPN / Proxy",             getattr(sig, "vpn_detected",           False)),
        ("Brand Squatting",         getattr(sig, "brand_squatting",        False)),
        ("Infrastructure Override", getattr(sig, "infrastructure_override", False)),
        ("Subdomain Trap",          getattr(sig, "subdomain_trap_active",  False)),
    ]
    sig_rows = [["Signal", "Status"]] + [
        [_safe_str(n, 40), "DETECTED" if a else "Not detected"]
        for n, a in signal_items
    ]
    sig_t = Table(sig_rows, colWidths=[90 * mm, 70 * mm], repeatRows=1)
    sig_t.setStyle(TableStyle([
        ("FONT",          (0, 0), (-1, 0), "Courier-Bold", 7.5),
        ("FONT",          (0, 1), (-1, -1), "Courier", 7),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_BG),
        ("BACKGROUND",    (0, 0), (-1, 0), C_PURPLE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_SURFACE, C_BG]),
        ("TEXTCOLOR",     (0, 1), (0, -1), C_TEXT),
        *[
            ("TEXTCOLOR", (1, i + 1), (1, i + 1),
             C_RED if signal_items[i][1] else C_MUTED)
            for i in range(len(signal_items))
        ],
        ("BOX",           (0, 0), (-1, -1), 0.3, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.2, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
    ]))
    story.append(sig_t)

    # 8. Mitigation
    _section_bar(story, styles, "8. Recommended Mitigation Steps")
    for i, step in enumerate(getattr(verdict, "mitigation", [])[:15], 1):
        story.append(Paragraph(f"{i}. {_safe_str(step, 200)}", styles["mit_step"]))

    _disclaimer_footer(story, styles, timestamp)
    return _doc_build(story, target, timestamp, "URL/Domain")


# =============================================================================
# Pipeline B — File / Hash Forensics
# =============================================================================

def generate_hash_cti_report(
    h_res,
    timestamp: str,
    duration:  float = 0.0,
    urlhaus_res = None,   # FIX v8
    otx_res     = None,   # FIX v8
) -> bytes:
    """Generate File/Hash forensics CTI PDF. Returns raw bytes."""
    styles = _build_styles()
    story: list[Any] = []

    level, _, _ = _classify_score(h_res.score)

    _cover_page(
        story, styles,
        target         = h_res.sha256 or "Hash Analysis",
        score          = h_res.score,
        threat_level   = level,
        confidence     = 80,
        timestamp      = timestamp,
        duration       = duration,
        ioc_count      = len(getattr(h_res, "iocs", [])),
        pipeline_label = "File / Hash Forensics",
        extra_meta     = [
            ("File Type",     h_res.file_type or "N/A"),
            ("File Size",     f"{h_res.file_size:,} B" if h_res.file_size else "N/A"),
            ("VT Detections", f"{h_res.vt_malicious}/{h_res.vt_total}"),
            ("Malware Family",h_res.vt_family or "None identified"),
        ],
    )

    _section_bar(story, styles, "1. File Intelligence")
    story.append(_kv_table([
        ("SHA-256",       _safe_str(h_res.sha256, 64)),
        ("MD5",           _safe_str(h_res.md5,    32)),
        ("SHA-1",         _safe_str(h_res.sha1,   40)),
        ("File Type",     h_res.file_type or "N/A"),
        ("File Size",     f"{h_res.file_size:,} B" if h_res.file_size else "N/A"),
        ("Author",        h_res.author or "N/A"),
        ("Creator Tool",  h_res.creator_tool or "N/A"),
        ("Created",       h_res.creation_date or "N/A"),
        ("Last Modified", h_res.last_modified or "N/A"),
        ("Page Count",    str(h_res.page_count) if h_res.page_count else "N/A"),
    ]))

    _section_bar(story, styles, "2. VirusTotal Scan")
    story.append(Paragraph(
        f"Detections: {h_res.vt_malicious} malicious / {h_res.vt_suspicious} suspicious "
        f"/ {h_res.vt_harmless} harmless  (Total: {h_res.vt_total} engines)",
        styles["body"],
    ))
    if h_res.vt_family:
        story.append(Paragraph(
            f"Malware Family: {_safe_str(h_res.vt_family, 60)}",
            ParagraphStyle("fam", fontName="Courier-Bold", fontSize=9, textColor=C_RED),
        ))
    if h_res.vt_tags:
        story.append(Paragraph(
            "Tags: " + ", ".join(_safe_str(t, 30) for t in h_res.vt_tags[:12]),
            styles["mono"],
        ))

    _section_bar(story, styles, "3. Weaponization Indicators")
    weapons = []
    if h_res.has_macros:
        weapons.append("VBA Macros present in document")
    if h_res.has_auto_open:
        weapons.append("Auto-execute macro (AutoOpen / Document_Open)")
    if h_res.has_embedded_objects:
        weapons.append("Embedded objects detected (OLE / ActiveX)")
    if h_res.high_entropy_sections:
        weapons.append(f"High-entropy sections: {', '.join(h_res.high_entropy_sections[:5])}")
    if h_res.suspicious_imports:
        weapons.append(f"Suspicious PE imports: {', '.join(h_res.suspicious_imports[:6])}")

    if weapons:
        for w in weapons:
            story.append(Paragraph(f"* {_safe_str(w, 150)}", styles["ioc"]))
    else:
        story.append(Paragraph("No weaponization indicators found.", styles["body"]))

    _section_bar(story, styles, "4. Detection Flags")
    for flag in getattr(h_res, "flags", [])[:20]:
        story.append(Paragraph(f"> {_safe_str(flag, 150)}", styles["flag"]))

    # FIX v8: URLhaus hash section
    if urlhaus_res and getattr(urlhaus_res, "available", False):
        _section_bar(story, styles, "4b. URLhaus Malware Database")
        for flag in getattr(urlhaus_res, "flags", [])[:10]:
            story.append(Paragraph(f"> {_safe_str(flag, 150)}", styles["flag"]))
        if getattr(urlhaus_res, "signature", None):
            story.append(Paragraph(
                f"Malware Family: {_safe_str(urlhaus_res.signature, 60)}",
                ParagraphStyle("uh_fam", fontName="Courier-Bold", fontSize=9, textColor=C_RED),
            ))

    # FIX v8: OTX hash section
    if otx_res and getattr(otx_res, "available", False):
        _section_bar(story, styles, "4c. OTX AlienVault Threat Intel")
        story.append(Paragraph(
            f"Threat Pulses: {getattr(otx_res, 'pulse_count', 0)} | "            f"ATT&CK: {', '.join(getattr(otx_res, 'attack_ids', [])[:4]) or 'N/A'}",
            styles["body"],
        ))
        for flag in getattr(otx_res, "flags", [])[:8]:
            story.append(Paragraph(f"> {_safe_str(flag, 150)}", styles["flag"]))

    _section_bar(story, styles, "5. Indicators of Compromise")
    for ioc in getattr(h_res, "iocs", [])[:30]:
        story.append(Paragraph(f"* {_safe_str(ioc, 120)}", styles["ioc"]))

    _section_bar(story, styles, "6. Recommended Actions")
    for i, action in enumerate(_file_mitigation(
            h_res.score, h_res.vt_malicious, h_res.has_macros), 1):
        story.append(Paragraph(f"{i}. {action}", styles["mit_step"]))

    _disclaimer_footer(story, styles, timestamp)
    return _doc_build(story, h_res.sha256 or "hash_analysis", timestamp, "File/Hash")


def _file_mitigation(score: int, vt_malicious: int, has_macros: bool) -> list[str]:
    steps = [
        "Quarantine the file immediately — do not execute on any production system.",
        "Submit to additional sandboxes (Any.Run, JoeSandbox) for dynamic analysis.",
        "Block the file hash (SHA-256, MD5, SHA-1) across EDR and email gateway.",
        "Search SIEM / EDR telemetry for this hash across the entire environment.",
    ]
    if vt_malicious >= 10:
        steps.append("Escalate to IR — high AV detection rate indicates confirmed malware.")
    if has_macros:
        steps.append("Enforce Group Policy to block Office macro execution environment-wide.")
    steps.append("Reset credentials if the file was opened on any endpoint.")
    steps.append("Document findings and push IOCs to threat intelligence feeds.")
    return steps


# =============================================================================
# Pipeline C — Email / SMS Forensics
# =============================================================================

def generate_email_cti_report(
    em_res,
    timestamp: str,
    duration:  float = 0.0,
) -> bytes:
    """Generate Email/SMS forensics CTI PDF. Returns raw bytes."""
    styles = _build_styles()
    story: list[Any] = []

    level, _, _ = _classify_score(em_res.score)
    target = _safe_str(em_res.sender_address or em_res.subject or "Email Analysis", 80)

    _cover_page(
        story, styles,
        target         = target,
        score          = em_res.score,
        threat_level   = level,
        confidence     = 75,
        timestamp      = timestamp,
        duration       = duration,
        ioc_count      = len(getattr(em_res, "iocs", [])),
        pipeline_label = "Email / SMS Forensics",
        extra_meta     = [
            ("Sender",       em_res.sender_address or "N/A"),
            ("Subject",      em_res.subject or "N/A"),
            ("Auth Failed",  "YES" if em_res.auth_failed else "No"),
            ("SPF",          em_res.spf_result  or "N/A"),
            ("DKIM",         em_res.dkim_result or "N/A"),
            ("DMARC",        em_res.dmarc_result or "N/A"),
        ],
    )

    _section_bar(story, styles, "1. Email Header Intelligence")
    story.append(_kv_table([
        ("Sender Address", em_res.sender_address  or "N/A"),
        ("Display Name",   em_res.display_name    or "N/A"),
        ("Reply-To",       em_res.reply_to        or "N/A"),
        ("Return-Path",    em_res.return_path     or "N/A"),
        ("Message-ID",     em_res.message_id      or "N/A"),
        ("Subject",        em_res.subject         or "N/A"),
        ("Sender Domain",  em_res.sender_domain   or "N/A"),
    ]))

    _section_bar(story, styles, "2. Authentication Analysis")
    story.append(_kv_table([
        ("SPF Result",   em_res.spf_result   or "Not found"),
        ("DKIM Result",  em_res.dkim_result  or "Not found"),
        ("DMARC Result", em_res.dmarc_result or "Not found"),
        ("Auth Failed",  "YES — SPOOFING RISK" if em_res.auth_failed else "No"),
        ("Display Name Spoofing",
         "DETECTED" if getattr(em_res, "display_name_spoofing", False) else "Not detected"),
    ]))
    if em_res.auth_failed:
        story.append(Paragraph(
            "AUTHENTICATION FAILURE — SPF/DKIM/DMARC checks failed. "
            "High probability of email spoofing or phishing campaign.",
            styles["warning"],
        ))

    _section_bar(story, styles, "3. AI Content Analysis")
    ai_em = getattr(em_res, "ai_analysis", None)
    if ai_em and getattr(ai_em, "summary", ""):
        signals = []
        if getattr(ai_em, "urgency_detected",    False): signals.append("Urgency")
        if getattr(ai_em, "financial_threat",    False): signals.append("Financial threat")
        if getattr(ai_em, "manipulation_detected",False): signals.append("Manipulation")
        if getattr(ai_em, "impersonation_signal",False): signals.append("Impersonation")
        if getattr(ai_em, "social_engineering",  False): signals.append("Social engineering")
        if getattr(ai_em, "visual_deception",    False): signals.append("Visual deception")
        story.append(Paragraph(_safe_str(ai_em.summary, 400), styles["body"]))
        if signals:
            story.append(Paragraph(
                "Signals Detected: " + ", ".join(signals), styles["mono"]))
    else:
        story.append(Paragraph("AI analysis not available.", styles["body"]))

    if getattr(em_res, "all_emails_found", []):
        _section_bar(story, styles, "4. Extracted Email Addresses")
        for addr in em_res.all_emails_found[:15]:
            story.append(Paragraph(f"* {_safe_str(addr, 80)}", styles["mono"]))

    _section_bar(story, styles, "5. Detection Flags")
    for flag in getattr(em_res, "flags", [])[:20]:
        story.append(Paragraph(f"> {_safe_str(flag, 150)}", styles["flag"]))

    _section_bar(story, styles, "6. Indicators of Compromise")
    for ioc in getattr(em_res, "iocs", [])[:30]:
        story.append(Paragraph(f"* {_safe_str(ioc, 120)}", styles["ioc"]))

    _section_bar(story, styles, "7. Recommended Actions")
    for i, action in enumerate(_email_mitigation(
            em_res.score, em_res.auth_failed,
            getattr(em_res, "display_name_spoofing", False)), 1):
        story.append(Paragraph(f"{i}. {action}", styles["mit_step"]))

    _disclaimer_footer(story, styles, timestamp)
    return _doc_build(story, target, timestamp, "Email/SMS")


def _email_mitigation(score: int, auth_failed: bool, spoofing: bool) -> list[str]:
    steps = [
        "Do not click any links or open attachments from this email.",
        "Report the email to the security team / SOC immediately.",
        "Block sender address and domain at the email gateway.",
    ]
    if auth_failed:
        steps.append("Implement or verify SPF, DKIM, and DMARC records for your domain.")
    if spoofing:
        steps.append("Alert users about spoofed display name — train to verify raw sender.")
    if score >= 65:
        steps.append("Run phishing simulation awareness training across the organisation.")
    steps.append("Search email logs for all recipients of this message and quarantine copies.")
    steps.append("Extract and block all URLs, domains, and IPs found in the email body.")
    return steps


# =============================================================================
# Pipeline D — Standalone IP Intelligence
# =============================================================================

def generate_ip_cti_report(
    ip_res,
    ip_address: str,
    timestamp:  str,
    duration:   float = 0.0,
    shodan_res    = None,
    greynoise_res = None,
    urlhaus_res   = None,   # FIX v8
    otx_res       = None,   # FIX v8
) -> bytes:
    """Generate IP Intelligence CTI PDF. Returns raw bytes."""
    styles = _build_styles()
    story: list[Any] = []

    level, _, _ = _classify_score(ip_res.score)

    _cover_page(
        story, styles,
        target         = ip_address,
        score          = ip_res.score,
        threat_level   = level,
        confidence     = 80,
        timestamp      = timestamp,
        duration       = duration,
        ioc_count      = len(getattr(ip_res, "iocs", [])),
        pipeline_label = "IP Intelligence",
        extra_meta     = [
            ("Country",          ip_res.country or "N/A"),
            ("ASN",              ip_res.asn     or "N/A"),
            ("ISP",              ip_res.isp     or "N/A"),
            ("Abuse Confidence", f"{ip_res.abuse_confidence}%"),
            ("Is Tor",           "YES" if ip_res.is_tor else "No"),
            ("Is VPN/Proxy",     "YES" if (ip_res.is_vpn or ip_res.is_proxy) else "No"),
        ],
    )

    _section_bar(story, styles, "1. Geolocation & Identity")
    story.append(_kv_table([
        ("IP Address",    ip_address),
        ("IP Version",    ip_res.ip_version or "IPv4"),
        ("Reverse DNS",   ip_res.rdns or "N/A"),
        ("Country",       ip_res.country or "N/A"),
        ("Country Code",  ip_res.country_code or "N/A"),
        ("City / Region", f"{ip_res.city or 'N/A'} / {ip_res.region or 'N/A'}"),
        ("Timezone",      ip_res.timezone or "N/A"),
        ("Coordinates",   f"{ip_res.latitude}, {ip_res.longitude}"
                          if ip_res.latitude and ip_res.longitude else "N/A"),
    ]))

    _section_bar(story, styles, "2. ASN / Network Infrastructure")
    story.append(_kv_table([
        ("ASN",          ip_res.asn     or "N/A"),
        ("ASN Org",      ip_res.asn_org or "N/A"),
        ("ISP",          ip_res.isp     or "N/A"),
        ("Datacenter",   "YES" if ip_res.is_datacenter  else "No"),
        ("Bulletproof",  "YES — HIGH RISK" if ip_res.is_bulletproof else "No"),
        ("Mobile",       "Yes" if ip_res.is_mobile else "No"),
    ]))

    _section_bar(story, styles, "3. Threat Intelligence")
    story.append(_kv_table([
        ("Tor Exit Node",    "CONFIRMED" if ip_res.is_tor                          else "No"),
        ("VPN / Proxy",      "CONFIRMED" if (ip_res.is_vpn or ip_res.is_proxy)     else "No"),
        ("AbuseIPDB Score",  f"{ip_res.abuse_confidence}% confidence"),
        ("Abuse Reports",    str(ip_res.abuse_reports)),
        ("Last Reported",    ip_res.last_reported or "N/A"),
        ("VT Malicious",     str(ip_res.vt_malicious)),
    ]))
    if ip_res.abuse_categories:
        story.append(Paragraph(
            "Abuse Categories: " +
            ", ".join(_safe_str(c, 40) for c in ip_res.abuse_categories[:8]),
            styles["mono"],
        ))

    if shodan_res and getattr(shodan_res, "available", False):
        _section_bar(story, styles, "4. Shodan Intelligence")
        story.append(_kv_table([
            ("Open Ports", ", ".join(str(p) for p in getattr(shodan_res,"open_ports",[])[:15]) or "N/A"),
            ("CVEs Found", str(getattr(shodan_res, "vuln_count", 0))),
            ("OS",         getattr(shodan_res, "os", "N/A") or "N/A"),
            ("Banners",    str(len(getattr(shodan_res, "banners", [])))),
        ]))
        for flag in getattr(shodan_res, "flags", [])[:6]:
            story.append(Paragraph(f"> {_safe_str(flag, 120)}", styles["flag"]))

    if greynoise_res and getattr(greynoise_res, "available", False):
        _section_bar(story, styles, "5. GreyNoise Context")
        story.append(_kv_table([
            ("Classification", getattr(greynoise_res, "classification", "N/A") or "N/A"),
            ("Noise",          "YES" if getattr(greynoise_res, "noise", False) else "No"),
            ("RIOT",           "YES" if getattr(greynoise_res, "riot",  False) else "No"),
            ("Name",           getattr(greynoise_res, "name", "N/A") or "N/A"),
        ]))

    _section_bar(story, styles, "6. Detection Flags")
    for flag in getattr(ip_res, "flags", [])[:20]:
        story.append(Paragraph(f"> {_safe_str(flag, 150)}", styles["flag"]))

    # FIX v8: URLhaus and OTX in IP PDF
    if urlhaus_res and getattr(urlhaus_res, "available", False):
        _section_bar(story, styles, "6b. URLhaus Host Intelligence")
        for flag in getattr(urlhaus_res, "flags", [])[:10]:
            story.append(Paragraph(f"> {_safe_str(flag, 150)}", styles["flag"]))
    if otx_res and getattr(otx_res, "available", False) and getattr(otx_res, "pulse_count", 0) > 0:
        _section_bar(story, styles, "6c. OTX AlienVault Threat Intel")
        story.append(Paragraph(
            f"Threat Pulses: {getattr(otx_res, 'pulse_count', 0)} | "            f"ATT&CK: {', '.join(getattr(otx_res, 'attack_ids', [])[:4]) or 'N/A'}",
            styles["body"],
        ))
        for flag in getattr(otx_res, "flags", [])[:8]:
            story.append(Paragraph(f"> {_safe_str(flag, 150)}", styles["flag"]))

    _section_bar(story, styles, "7. Indicators of Compromise")
    for ioc in getattr(ip_res, "iocs", [])[:30]:
        story.append(Paragraph(f"* {_safe_str(ioc, 120)}", styles["ioc"]))

    _section_bar(story, styles, "8. Recommended Actions")
    for i, action in enumerate(_ip_mitigation(
            ip_res.score, ip_res.is_tor,
            ip_res.is_vpn or ip_res.is_proxy, ip_res.abuse_confidence), 1):
        story.append(Paragraph(f"{i}. {action}", styles["mit_step"]))

    _disclaimer_footer(story, styles, timestamp)
    return _doc_build(story, ip_address, timestamp, "IP Intelligence")


def _ip_mitigation(score: int, is_tor: bool, is_vpn: bool, abuse: int) -> list[str]:
    steps = [
        "Block this IP at perimeter firewall, WAF, and email gateway.",
        "Search SIEM logs for all historical connections from this IP.",
        "Identify and investigate all internal systems that communicated with this IP.",
    ]
    if is_tor:
        steps.append("Implement a Tor exit node blocklist (e.g. DanMeUK list) on the firewall.")
    if is_vpn:
        steps.append("Review VPN/proxy IP blocks that are not business-justified.")
    if abuse >= 80:
        steps.append("Report to AbuseIPDB to contribute to community threat intelligence.")
    steps.append("Add to threat intelligence feeds and update SIEM detection rules.")
    steps.append("Review and harden network egress filtering policies.")
    return steps


# =============================================================================
# Pipeline E — Hybrid Analysis Sandbox
# =============================================================================

def generate_ha_cti_report(
    ha_res,
    input_type:  str,
    target:      str,
    timestamp:   str,
    duration:    float = 0.0,
    ai_summary   = None,
) -> bytes:
    """Generate Hybrid Analysis Sandbox CTI PDF. Returns raw bytes."""
    styles = _build_styles()
    story: list[Any] = []

    _ha_to_level = {
        "malicious":          "CRITICAL",
        "suspicious":         "HIGH",
        "no specific threat": "LOW",
        "whitelisted":        "SAFE",
        "no verdict":         "MEDIUM",
    }
    threat_level = _ha_to_level.get(ha_res.verdict, "MEDIUM")

    _cover_page(
        story, styles,
        target         = target,
        score          = ha_res.verdict_score,
        threat_level   = threat_level,
        confidence     = 85 if ha_res.completed else 40,
        timestamp      = timestamp,
        duration       = duration,
        ioc_count      = len(ha_res.iocs),
        pipeline_label = f"Hybrid Analysis Sandbox ({_safe_str(input_type, 10).upper()})",
        extra_meta     = [
            ("HA Verdict",     ha_res.verdict.upper()),
            ("Threat Score",   f"{ha_res.threat_score}/100"
                               if ha_res.threat_score is not None else "N/A"),
            ("AV Detection",   f"{ha_res.av_detect}%"),
            ("Malware Family", ha_res.vx_family or "None identified"),
            ("Environment",    ha_res.environment),
            ("Job ID",         (ha_res.job_id or "N/A")[:24]),
            ("SHA-256",        ((ha_res.sha256 or "N/A")[:32] + "...")
                               if ha_res.sha256 else "N/A"),
        ],
    )

    # ── HA Score Gauge ────────────────────────────────────────────────
    _ha_level = (
        "CRITICAL" if ha_res.verdict_score >= 85 else
        "HIGH"     if ha_res.verdict_score >= 65 else
        "MEDIUM"   if ha_res.verdict_score >= 40 else
        "LOW"      if ha_res.verdict_score >= 20 else "SAFE"
    )
    _ha_gauge = _score_gauge_drawing(ha_res.verdict_score, _ha_level)
    # For HA: show gauge alone (no engine breakdown available)
    from reportlab.platypus import Flowable as _FLowable
    class _DFlowable(_FLowable):
        def __init__(self, drw):
            super().__init__(); self._d = drw
            self.width = drw.width; self.height = drw.height
        def draw(self): renderPDF.draw(self._d, self.canv, 0, 0)
    story.append(_DFlowable(_ha_gauge))
    story.append(Spacer(1, 4 * mm))

    # 1. Sandbox Verdict
    _section_bar(story, styles, "1. Sandbox Verdict")
    if ha_res.verdict == "malicious":
        story.append(Paragraph(
            f"HYBRID ANALYSIS CONFIRMED MALICIOUS — "
            f"Threat Score: {ha_res.threat_score or 'N/A'}/100 | "
            f"AV: {ha_res.av_detect}% | "
            f"Family: {ha_res.vx_family or 'Unknown'}",
            styles["warning"],
        ))
    story.append(_kv_table([
        ("HA Verdict",     ha_res.verdict.upper()),
        ("Threat Score",   f"{ha_res.threat_score}/100"
                           if ha_res.threat_score is not None else "N/A"),
        ("AV Detection %", f"{ha_res.av_detect}%"),
        ("Malware Family", ha_res.vx_family or "None identified"),
        ("Environment",    ha_res.environment),
        ("Analysis Start", ha_res.analysis_start or "N/A"),
        ("Report Status",  ha_res.status.upper()),
    ]))
    if ha_res.submit_url:
        story.append(Paragraph(
            f"Full Report URL: {_safe_str(ha_res.submit_url, 100)}",
            styles["mono"],
        ))

    # 2. AI Summary
    if ai_summary and getattr(ai_summary, "summary", ""):
        _section_bar(story, styles, "2. AI Threat Intelligence Summary")
        story.append(Paragraph(
            f"Confidence: {_safe_str(getattr(ai_summary,'confidence','N/A'),10).upper()}  "
            "(Ollama — local inference, no external data sent)",
            ParagraphStyle("conf", fontName="Courier-Bold", fontSize=8,
                           textColor=C_GREEN, spaceAfter=4),
        ))
        story.append(Paragraph(_safe_str(ai_summary.summary, 500), styles["body"]))
        if getattr(ai_summary, "threat_narrative", ""):
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph("Threat Narrative:", styles["h2"]))
            story.append(Paragraph(_safe_str(ai_summary.threat_narrative, 600), styles["body"]))
        if getattr(ai_summary, "recommended_actions", []):
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph("AI-Recommended Actions:", styles["h2"]))
            for i, action in enumerate(ai_summary.recommended_actions[:8], 1):
                story.append(Paragraph(f"{i}. {_safe_str(action, 200)}", styles["action"]))
    else:
        _section_bar(story, styles, "2. AI Analysis")
        story.append(Paragraph(
            "AI summary unavailable — ensure Ollama is running locally (ollama serve).",
            styles["body"],
        ))

    # 3. Network IOCs
    if any([ha_res.contacted_hosts, ha_res.dns_requests,
            ha_res.http_requests, ha_res.compromised_hosts]):
        _section_bar(story, styles, "3. Network Activity & IOCs")
        net_rows = [["Type", "Indicator"]]
        for h in ha_res.contacted_hosts[:10]:
            net_rows.append(["HOST", _safe_str(h, 80)])
        for d in ha_res.dns_requests[:10]:
            net_rows.append(["DNS",  _safe_str(d, 80)])
        for u in ha_res.http_requests[:8]:
            net_rows.append(["HTTP", _safe_str(u, 80)])
        for c in ha_res.compromised_hosts[:5]:
            net_rows.append(["C2",   _safe_str(c, 80)])
        if len(net_rows) > 1:
            story.append(_header_table(net_rows, [20, 140], C_ORANGE))

    # 4. Behavioral Analysis
    _section_bar(story, styles, "4. Behavioral Analysis")
    if ha_res.signatures:
        story.append(Paragraph("Behavioral Signatures:", styles["h2"]))
        for sig in ha_res.signatures[:12]:
            story.append(Paragraph(f"> {_safe_str(sig, 120)}", styles["flag"]))
    if ha_res.processes:
        story.append(Paragraph("Spawned Processes:", styles["h2"]))
        for proc in ha_res.processes[:10]:
            story.append(Paragraph(f"> {_safe_str(proc, 100)}", styles["mono"]))
    if ha_res.registry_keys:
        story.append(Paragraph("Registry Activity:", styles["h2"]))
        for reg in ha_res.registry_keys[:8]:
            story.append(Paragraph(f"> {_safe_str(reg, 120)}", styles["mono"]))
    if ha_res.mutexes:
        story.append(Paragraph("Mutexes:", styles["h2"]))
        for m in ha_res.mutexes[:8]:
            story.append(Paragraph(f"> {_safe_str(m, 80)}", styles["mono"]))
    if ha_res.extracted_files:
        story.append(Paragraph("Extracted / Dropped Files:", styles["h2"]))
        for f in ha_res.extracted_files[:8]:
            story.append(Paragraph(f"> {_safe_str(f, 80)}", styles["mono"]))

    # 5. MITRE ATT&CK
    if ha_res.mitre_attcks:
        _section_bar(story, styles, "5. MITRE ATT&CK Techniques")
        seen: set[str] = set()
        mitre_rows = [["Tactic", "Technique", "Name"]]
        for m in ha_res.mitre_attcks[:20]:
            key = f"{m.get('tactic')}-{m.get('technique')}"
            if key in seen:
                continue
            seen.add(key)
            mitre_rows.append([
                _safe_str(m.get("tactic",    ""), 15),
                _safe_str(m.get("technique", ""), 15),
                _safe_str(m.get("name",      ""), 80),
            ])
        story.append(_header_table(mitre_rows, [25, 25, 110], C_PURPLE))

    # 6. AV Detections
    if ha_res.av_detections:
        _section_bar(story, styles,
                     f"6. AV Detections ({len(ha_res.av_detections)} engines)")
        av_rows = [["Engine", "Detection"]]
        for det in ha_res.av_detections[:20]:
            av_rows.append([
                _safe_str(det.get("engine", "N/A"), 40),
                _safe_str(det.get("result", "N/A"), 80),
            ])
        av_t = Table(av_rows, colWidths=[55 * mm, 105 * mm], repeatRows=1)
        av_t.setStyle(TableStyle([
            ("FONT",          (0, 0), (-1, 0), "Courier-Bold", 7.5),
            ("FONT",          (0, 1), (-1, -1), "Courier", 7),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_BG),
            ("BACKGROUND",    (0, 0), (-1, 0), C_RED),
            ("TEXTCOLOR",     (0, 1), (0, -1), C_MUTED),
            ("TEXTCOLOR",     (1, 1), (1, -1), C_RED),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_SURFACE, C_BG]),
            ("BOX",           (0, 0), (-1, -1), 0.3, C_BORDER),
            ("INNERGRID",     (0, 0), (-1, -1), 0.2, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ]))
        story.append(av_t)

    # 7. Tags & Flags
    _section_bar(story, styles, "7. Analysis Flags & Tags")
    if ha_res.tags:
        story.append(Paragraph(
            "Tags: " + ", ".join(_safe_str(t, 30) for t in ha_res.tags[:12]),
            styles["mono"],
        ))
    for flag in ha_res.flags[:15]:
        story.append(Paragraph(f"> {_safe_str(flag, 150)}", styles["flag"]))

    # 8. IOCs
    _section_bar(story, styles, "8. Indicators of Compromise")
    for ioc in ha_res.iocs[:30]:
        story.append(Paragraph(f"* {_safe_str(ioc, 120)}", styles["ioc"]))

    # 9. Mitigation
    _section_bar(story, styles, "9. Recommended Mitigation Steps")
    for i, action in enumerate(_ha_mitigation(
            ha_res.verdict, ha_res.av_detect,
            bool(ha_res.contacted_hosts),
            bool(ha_res.mitre_attcks)), 1):
        story.append(Paragraph(f"{i}. {action}", styles["mit_step"]))

    _disclaimer_footer(story, styles, timestamp)
    return _doc_build(story, target, timestamp, "Hybrid Analysis Sandbox")


def _ha_mitigation(verdict: str, av_detect: int,
                   network_activity: bool, mitre: bool) -> list[str]:
    steps = ["Isolate any system that executed or received this sample immediately."]
    if verdict == "malicious":
        steps.append("Escalate to Incident Response — sandbox confirmed malicious.")
        steps.append("Block all IOCs (hashes, hosts, IPs, domains) across SIEM, EDR, firewall.")
    else:
        steps.append("Monitor systems for suspicious behaviour matching detected signatures.")
        steps.append("Submit to additional sandboxes for deeper dynamic analysis.")
    if av_detect >= 30:
        steps.append(f"High AV detection ({av_detect}%) — push updated signatures to all endpoints.")
    if network_activity:
        steps.append("Block identified C2 hosts and DNS requests at firewall and DNS resolver.")
        steps.append("Hunt for beaconing behaviour in NetFlow / proxy logs.")
    if mitre:
        steps.append("Map MITRE ATT&CK techniques to your detection coverage gaps.")
        steps.append("Update SIEM correlation rules to detect the identified techniques.")
    steps.append("Document all findings, preserve forensic artefacts, update threat intel feeds.")
    return steps
