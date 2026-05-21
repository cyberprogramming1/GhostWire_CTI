"""
frontend/components.py
----------------------
Reusable UI components for GhostWire CTI v6.
"""

from __future__ import annotations
from typing import Optional
import streamlit as st
import plotly.graph_objects as go


# ── Gauge ─────────────────────────────────────────────────────────────────────

def make_gauge(score: int, colour: str) -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number={"suffix": "%", "font": {"size": 34, "family": "Space Mono, monospace", "color": colour}},
        gauge={
            "axis": {"range": [0, 100], "tickfont": {"size": 8, "color": "#2a4060", "family": "Space Mono"}, "nticks": 6},
            "bar":  {"color": colour, "thickness": 0.16},
            "bgcolor": "#0a1520", "borderwidth": 0,
            "steps": [
                {"range": [0,  20], "color": "rgba(0,255,180,0.04)"},
                {"range": [20, 40], "color": "rgba(120,217,122,0.04)"},
                {"range": [40, 65], "color": "rgba(255,208,96,0.04)"},
                {"range": [65, 85], "color": "rgba(255,107,53,0.04)"},
                {"range": [85, 100], "color": "rgba(255,45,85,0.05)"},
            ],
            "threshold": {"line": {"color": colour, "width": 3}, "thickness": 0.84, "value": score},
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=8, b=4, l=12, r=12), height=210, font={"color": "#c0d4e8"},
    )
    return fig


# ── Threat Banner ─────────────────────────────────────────────────────────────

def threat_banner(threat_level: str, score: int, colour: str, bg_colour: str) -> str:
    return (
        f'<div class="threat-banner" style="background:{bg_colour};border:1px solid {colour}44">'
        f'<div class="threat-label">Threat Level</div>'
        f'<div class="threat-value" style="color:{colour}">{threat_level}</div>'
        f'<div class="threat-score" style="color:{colour}">{score}/100</div>'
        f'</div>'
    )


# ── Engine Score Bars ─────────────────────────────────────────────────────────

def _single_ebar(label: str, score: int, max_s: int, colour: str) -> str:
    pct = max(3, int(score / max_s * 100)) if max_s else 0
    return (
        f'<div class="ebar">'
        f'<div class="ebar-label"><span>{label}</span>'
        f'<span style="color:{colour}">{score}/{max_s}</span></div>'
        f'<div class="ebar-track">'
        f'<div class="ebar-fill" style="width:{pct}%;background:{colour}"></div>'
        f'</div></div>'
    )


def engine_score_bars(engine_scores: list[tuple[str, int, int, str]]) -> str:
    """engine_scores: list of (label, score, max, colour)"""
    return "".join(_single_ebar(*b) for b in engine_scores)


# ── Flag List ─────────────────────────────────────────────────────────────────

import html as _html


def flag_list(flags: list[str]) -> str:
    """Render flags as HTML divs. All flag text is HTML-escaped to prevent XSS."""
    if not flags:
        return '<p style="color:#2a4a6a;font-size:0.68rem">No signals detected.</p>'
    return "".join(f'<div class="flag-item">{_html.escape(str(f))}</div>' for f in flags)


# ── IOC Chips ─────────────────────────────────────────────────────────────────

def ioc_chips(iocs: list[str]) -> str:
    """Render IOC badges as HTML spans. All IOC strings are HTML-escaped to prevent XSS."""
    if not iocs:
        return '<p style="color:#2a4a6a;font-size:0.68rem">None identified.</p>'
    return "".join(f'<span class="ioc-badge">{_html.escape(str(i))}</span>' for i in iocs)


# ── Behavioral Signal Pill ────────────────────────────────────────────────────

def signal_pill(name: str, active: bool, colour: str, icon: str) -> str:
    if active:
        r, g, b = int(colour[1:3], 16), int(colour[3:5], 16), int(colour[5:7], 16)
        bg = f"rgba({r},{g},{b},0.12)"
    else:
        bg = "transparent"
    brd = colour if active else "#1a2a3a"
    txt = colour if active else "#2a4a6a"
    return (
        f'<div class="sig-pill" style="background:{bg};border-color:{brd};color:{txt}">'
        f'<div class="si">{icon if active else "○"}</div>'
        f'<div class="sn">{name}</div></div>'
    )


def signal_row(items: list[tuple[str, bool, str, str]]) -> None:
    """Render a row of behavioral signal pills."""
    cols = st.columns(len(items))
    for col, (name, active, colour, icon) in zip(cols, items):
        with col:
            st.markdown(signal_pill(name, active, colour, icon), unsafe_allow_html=True)
    st.markdown("")


# ── Key-Value Row ─────────────────────────────────────────────────────────────

def kv_row(key: str, val: str, danger: bool = False) -> str:
    vc = "#ff6b8a" if danger else "#c0d4e8"
    return (
        f'<div class="cert-row">'
        f'<span class="cert-key">{_html.escape(str(key))}</span>'
        f'<span class="cert-val" style="color:{vc}">{_html.escape(str(val))}</span></div>'
    )


# ── SSL Cert Table ────────────────────────────────────────────────────────────

def cert_table(rows: list[tuple[str, str, bool]]) -> str:
    return "".join(kv_row(k, v, d) for k, v, d in rows)


# ── MITRE ATT&CK Card (v5 redesign) ──────────────────────────────────────────

# Tactic phase metadata for richer display
TACTIC_PHASES: dict[str, str] = {
    "TA0001": "INITIAL ACCESS",
    "TA0002": "EXECUTION",
    "TA0003": "PERSISTENCE",
    "TA0004": "PRIVILEGE ESC",
    "TA0005": "DEFENSE EVASION",
    "TA0006": "CREDENTIAL ACCESS",
    "TA0007": "DISCOVERY",
    "TA0008": "LATERAL MOVEMENT",
    "TA0009": "COLLECTION",
    "TA0010": "EXFILTRATION",
    "TA0011": "C2",
    "TA0040": "IMPACT",
    "TA0042": "RESOURCE DEV",
    "TA0043": "RECONNAISSANCE",
}

TACTIC_DESCRIPTIONS: dict[str, str] = {
    "TA0001": "Adversary trying to get into your network",
    "TA0002": "Adversary running malicious code",
    "TA0003": "Adversary maintaining presence",
    "TA0005": "Adversary avoiding detection",
    "TA0009": "Gathering data of interest",
    "TA0010": "Stealing data from your network",
    "TA0011": "Communicating with compromised systems",
    "TA0040": "Manipulating, interrupting, or destroying systems",
    "TA0042": "Establishing resources to support operations",
    "TA0043": "Gathering information to plan future operations",
}


def mitre_card(tac_id: str, tech_id: str, description: str) -> str:
    """
    v5 redesign: full card with tactic phase, technique ID,
    description, and gradient left border.
    """
    parts      = description.split(" — ") if " — " in description else [description, ""]
    tac_name   = parts[0]
    tech_desc  = parts[1] if len(parts) > 1 else ""
    phase      = TACTIC_PHASES.get(tac_id, "UNKNOWN")
    tac_detail = TACTIC_DESCRIPTIONS.get(tac_id, "")

    url = f"https://attack.mitre.org/tactics/{tac_id}/"

    return (
        f'<div class="mitre-card">'
        f'<div class="mitre-phase">{phase}</div>'
        f'<div style="display:flex;align-items:center;gap:0.4rem;flex-wrap:wrap">'
        f'<span class="mitre-tac-id">{tac_id}</span>'
        f'<span class="mitre-tech-id">{tech_id}</span>'
        f'</div>'
        f'<div class="mitre-tac-name">{tac_name}</div>'
        f'<div class="mitre-desc">{tech_desc or tac_detail}</div>'
        f'<div style="margin-top:0.4rem">'
        f'<a href="{url}" target="_blank" style="font-family:Space Mono,monospace;'
        f'font-size:0.58rem;color:rgba(0,200,255,0.5);text-decoration:none">'
        f'→ MITRE ATT&CK Reference</a>'
        f'</div>'
        f'</div>'
    )


def mitre_section(tactics: list[tuple[str, str, str]], title: str = "⚔️ MITRE ATT&CK") -> None:
    """Render a full MITRE section with all tactic cards."""
    st.markdown(f'<p class="slabel">{_html.escape(str(title))}</p>', unsafe_allow_html=True)
    if not tactics:
        st.markdown(
            '<p style="color:#2a4a6a;font-family:Space Mono,monospace;font-size:0.68rem">'
            'No MITRE tactics mapped for this target.</p>',
            unsafe_allow_html=True,
        )
        return

    seen = set()
    for tac_id, tech_id, desc in tactics[:6]:
        key = f"{tac_id}-{tech_id}"
        if key not in seen:
            seen.add(key)
            st.markdown(mitre_card(tac_id, tech_id, desc), unsafe_allow_html=True)


# ── Confidence Panel ──────────────────────────────────────────────────────────

def confidence_panel(overall: int, factors: list[tuple[str, int, str]]) -> str:
    """
    Displays overall score confidence + individual factor bars.
    factors: list of (label, value_0_100, colour)
    """
    bars = ""
    for label, val, colour in factors:
        val = max(0, min(val, 100))
        bars += (
            f'<div class="cfac-row"><span>{label.upper()}</span>'
            f'<span style="color:{colour}">{val}</span></div>'
            f'<div class="cfac-bar">'
            f'<div class="cfac-fill" style="width:{val}%;background:{colour}"></div>'
            f'</div>'
        )

    return (
        f'<div class="conf-meter">'
        f'<div class="conf-label">Score Confidence</div>'
        f'<div class="conf-value">{overall}%</div>'
        f'<div class="conf-bar-track">'
        f'<div class="conf-bar-fill" style="width:{overall}%"></div>'
        f'</div>'
        f'</div>'
        f'{bars}'
    )


# ── Source Badges ─────────────────────────────────────────────────────────────

def source_badge(label: str, value: str, colour: str) -> str:
    import html as _hs
    safe_lbl = _hs.escape(str(label))
    safe_val = _hs.escape(str(value))
    safe_clr = _hs.escape(str(colour)) if str(colour).startswith("#") else "#c0d4e8"
    return (
        f'<div class="source-badge">'
        f'<span class="sb-label">{safe_lbl}</span>'
        f'<span class="sb-val" style="color:{safe_clr}">{safe_val}</span>'
        f'</div>'
    )


# ── Override Banner ───────────────────────────────────────────────────────────

def override_banner(message: str, level: str = "critical") -> str:
    import html as _ho
    safe_msg = _ho.escape(str(message))
    if level == "critical":
        return f'<div class="override-banner">🚨 {safe_msg}</div>'
    return f'<div class="rule-banner">⚠ {safe_msg}</div>'


# ── Verdict Box ───────────────────────────────────────────────────────────────

def verdict_box(text: str, colour: str) -> str:
    import html as _hv
    safe_c = _hv.escape(str(colour)) if str(colour).startswith("#") else "#00ffb4"
    return (
        f'<div class="verdict-box" style="border-left-color:{safe_c}">'
        + _hv.escape(str(text)) +
        '</div>'
    )


# ── Mitigation List ───────────────────────────────────────────────────────────

def mitigation_list(steps: list[str]) -> str:
    import html as _hm
    return '<div class="card">' + "".join(
        f'<div class="mit-step">{_hm.escape(str(s))}</div>' for s in steps
    ) + '</div>'


# ── Engine Card (Detection Signals) ──────────────────────────────────────────

def engine_card(title: str, flags: list[str], caption: str = "") -> None:
    """Render a per-engine signal card (used in the signals grid)."""
    st.markdown(f'<div class="card"><b>{_html.escape(str(title))}</b><br>', unsafe_allow_html=True)
    st.markdown(flag_list(flags), unsafe_allow_html=True)
    if caption:
        st.caption(f"ℹ {caption}")
    st.markdown("</div>", unsafe_allow_html=True)


# ── Section Label ─────────────────────────────────────────────────────────────

def section_label(text: str) -> None:
    st.markdown(f'<p class="slabel">{_html.escape(str(text))}</p>', unsafe_allow_html=True)


# ── Footer ────────────────────────────────────────────────────────────────────

def footer(timestamp: str, mode: str = "10-ENGINE") -> None:
    st.markdown(
        f'<div style="text-align:center;margin-top:2.5rem;padding-bottom:2rem;'
        f'font-family:Space Mono,monospace;font-size:0.6rem;color:#1a2a3a;'
        f'letter-spacing:0.1em">GHOSTWIRE CTI v6  ·  {mode}  ·  '
        f'ALL PROCESSING ON-DEVICE  ·  {timestamp}</div>',
        unsafe_allow_html=True,
    )


# ── MITRE ATT&CK Interactive Heatmap ─────────────────────────────────────────

# Full ATT&CK tactic ordering (Enterprise)
TACTIC_ORDER = [
    ("TA0043", "RECON"),
    ("TA0042", "RESOURCE DEV"),
    ("TA0001", "INITIAL ACCESS"),
    ("TA0002", "EXECUTION"),
    ("TA0003", "PERSISTENCE"),
    ("TA0004", "PRIV ESC"),
    ("TA0005", "DEF EVASION"),
    ("TA0006", "CRED ACCESS"),
    ("TA0007", "DISCOVERY"),
    ("TA0008", "LATERAL MOV"),
    ("TA0009", "COLLECTION"),
    ("TA0011", "C2"),
    ("TA0010", "EXFILTRATION"),
    ("TA0040", "IMPACT"),
]

# Colour gradient for hit count: 0=empty, 1=low, 2+=high
_HEAT_COLOURS = {
    0: "#0a1520",   # empty
    1: "#1a3a6a",   # single hit
    2: "#1a5a8a",
    3: "#0078aa",
    4: "#005faa",
    5: "#c47aff",   # 5+ = purple (high)
}


def render_mitre_heatmap(
    tactics: list[tuple[str, str, str]],
    title:   str = "⚔️ MITRE ATT&CK Coverage Heatmap",
) -> None:
    """
    Render an interactive Plotly MITRE ATT&CK heatmap.
    X-axis = tactic phases, Y-axis = technique IDs.
    Colour intensity = hit count.
    Replaces the static card list for a more professional view.

    tactics: list of (tactic_id, technique_id, description)
    """
    import plotly.graph_objects as go

    st.markdown(f'<p class="slabel">{_html.escape(title)}</p>', unsafe_allow_html=True)

    if not tactics:
        st.markdown(
            '<p style="color:#2a4a6a;font-family:Space Mono,monospace;font-size:0.68rem">'
            'No MITRE techniques mapped.</p>',
            unsafe_allow_html=True,
        )
        return

    # Build hit count matrix: tactic_id → {technique_id: count}
    from collections import defaultdict
    tac_hits: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    tech_names: dict[str, str] = {}

    for tac_id, tech_id, desc in tactics:
        tac_hits[tac_id][tech_id] += 1
        tech_names[tech_id] = desc[:40]

    # Collect all unique techniques across all tactics
    all_techs = sorted({tech for hits in tac_hits.values() for tech in hits})
    if not all_techs:
        return

    # Filter to only tactics that have hits
    active_tactics = [(tid, tname) for tid, tname in TACTIC_ORDER if tid in tac_hits]
    if not active_tactics:
        # Fallback: show any tactic IDs found
        active_tactics = [(tid, tid) for tid in tac_hits]

    tac_labels = [tname for _, tname in active_tactics]
    tac_ids    = [tid   for tid, _   in active_tactics]

    # Build Z matrix (techniques × tactics)
    z_matrix   = []
    hover_text = []
    y_labels   = []

    for tech in all_techs:
        row   = []
        hover = []
        for tac_id in tac_ids:
            count = tac_hits[tac_id].get(tech, 0)
            row.append(count)
            desc = tech_names.get(tech, "")
            hover.append(
                f"Tactic: {tac_id}<br>"
                f"Technique: {tech}<br>"
                f"Name: {desc}<br>"
                f"Hits: {count}"
            )
        z_matrix.append(row)
        hover_text.append(hover)
        y_labels.append(tech)

    # Custom colour scale: 0=dark, >0=gradient
    colorscale = [
        [0.0,  "#0a1520"],
        [0.01, "#1a3a6a"],
        [0.3,  "#0078aa"],
        [0.6,  "#c47aff"],
        [1.0,  "#ff2d55"],
    ]

    fig = go.Figure(data=go.Heatmap(
        z=z_matrix,
        x=tac_labels,
        y=y_labels,
        text=hover_text,
        hovertemplate="%{text}<extra></extra>",
        colorscale=colorscale,
        showscale=True,
        colorbar=dict(
            title=dict(text="Hits", font=dict(color="#4a6a8a", size=8,
                                              family="Space Mono")),
            tickfont=dict(color="#4a6a8a", size=7, family="Space Mono"),
            thickness=10,
            len=0.8,
        ),
        xgap=2,
        ygap=2,
    ))

    cell_h = max(20, min(40, 400 // max(len(all_techs), 1)))
    h = max(200, len(all_techs) * cell_h + 80)

    fig.update_layout(
        paper_bgcolor = "rgba(0,0,0,0)",
        plot_bgcolor  = "rgba(0,0,0,0)",
        height        = h,
        margin        = dict(t=10, b=60, l=80, r=40),
        xaxis=dict(
            showgrid=False,
            tickfont=dict(family="Space Mono", size=8, color="#00ffb4"),
            side="bottom",
        ),
        yaxis=dict(
            showgrid=False,
            tickfont=dict(family="Space Mono", size=8, color="#8aaac8"),
            autorange="reversed",
        ),
        hoverlabel=dict(
            bgcolor="#0a1520",
            bordercolor="#1a2a3a",
            font=dict(family="Space Mono", size=10, color="#c0d4e8"),
        ),
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    # Legend caption
    st.caption(
        f"🎯 {len(set(t for t,_,_ in tactics))} tactic(s)  ·  "
        f"{len(all_techs)} technique(s)  ·  "
        f"Cell colour = detection frequency"
    )

    # Clickable detail cards below heatmap (collapsed)
    with st.expander(f"📋 Technique Details ({len(tactics)} entries)", expanded=False):
        seen = set()
        for tac_id, tech_id, desc in tactics[:20]:
            key = f"{tac_id}-{tech_id}"
            if key not in seen:
                seen.add(key)
                st.markdown(mitre_card(tac_id, tech_id, desc), unsafe_allow_html=True)
