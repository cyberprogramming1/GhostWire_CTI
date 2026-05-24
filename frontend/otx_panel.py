"""
frontend/otx_panel.py
----------------------
GhostWire CTI v7 — AlienVault OTX UI Panel Renderer.
"""

from __future__ import annotations

import html as _html
import streamlit as st

from frontend.components import section_label, flag_list


# Pulse count → colour
def _pulse_colour(count: int) -> tuple[str, str]:
    if count >= 20:
        return "#ff2d55", "rgba(255,45,85,0.15)"
    elif count >= 10:
        return "#ff6b00", "rgba(255,107,0,0.13)"
    elif count >= 3:
        return "#ffd060", "rgba(255,208,96,0.12)"
    elif count >= 1:
        return "#8aaac8", "rgba(138,170,200,0.08)"
    return "#2a4a6a", "transparent"


# MITRE tactic → colour
_TACTIC_COLOUR: dict[str, str] = {
    "Phishing":        "#ff2d55",
    "Ransomware":      "#ff2d55",
    "Injection":       "#ff6b00",
    "C2 Protocol":     "#ff6b00",
    "Execution":       "#ffd060",
    "Obfuscation":     "#ffd060",
    "Lateral Movement":"#ffd060",
    "Ingress Transfer":"#c47aff",
    "System Discovery":"#8aaac8",
    "File Discovery":  "#8aaac8",
}


def render_otx_panel(otx_res, mode: str = "url") -> None:
    """
    Render AlienVault OTX threat intelligence panel.

    Parameters
    ----------
    otx_res : OTXResult
        Result from backend.otx_engine
    mode : str
        "url" | "hash" | "ip"  (same panel, minor label differences)
    """
    section_label("🛸 OTX Threat Intelligence")

    # ── API key missing ────────────────────────────────────────────────
    if not otx_res.available and any("OTX_API_KEY" in e for e in otx_res.errors):
        st.markdown(
            '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
            'color:#2a4a6a">OTX: API key not configured — add OTX_API_KEY to .env '
            '(free at <a href="https://otx.alienvault.com/settings" target="_blank" '
            'style="color:#00b4ff">otx.alienvault.com</a>)</div>',
            unsafe_allow_html=True,
        )
        return

    # ── Other errors ───────────────────────────────────────────────────
    if not otx_res.available:
        for e in otx_res.errors:
            e_str = str(e).lower()
            if "timeout" in e_str:
                colour, msg = "#ffd060", "⚠ OTX request timed out — retry later"
            elif "rate_limit" in e_str:
                colour, msg = "#ffd060", "⚠ OTX rate limit reached — retry in a moment"
            elif "unauthorized" in e_str or "invalid" in e_str:
                colour, msg = "#ff5f87", f"⚠ {_html.escape(str(e))}"
            else:
                colour, msg = "#4a6a8a", f"⚠ OTX: {_html.escape(str(e))}"
            st.markdown(
                f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                f'color:{colour}">{msg}</div>',
                unsafe_allow_html=True,
            )
        return

    # ── Main content ───────────────────────────────────────────────────
    pulse_col, mitre_col = st.columns([1, 1], gap="medium")

    # ── Pulse count badge ─────────────────────────────────────────────
    with pulse_col:
        p_colour, p_bg = _pulse_colour(otx_res.pulse_count)
        pulse_label_text = {
            "hash": "MALWARE HASH IN PULSES",
            "ip":   "HOST IN THREAT PULSES",
        }.get(mode, "INDICATOR IN PULSES")

        if otx_res.pulse_count > 0:
            st.markdown(
                f'<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                f'color:#00ffb4;letter-spacing:0.2em">{pulse_label_text}</p>'
                f'<div style="background:{p_bg};border:1px solid {p_colour}44;'
                f'border-radius:8px;padding:0.5rem 0.8rem;display:inline-block">'
                f'<span style="font-family:Space Mono,monospace;font-size:1.8rem;'
                f'font-weight:700;color:{p_colour}">{otx_res.pulse_count}</span>'
                f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
                f'color:#4a6a8a;margin-left:0.4rem">pulses</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                f'color:#00ffb4;letter-spacing:0.2em">{pulse_label_text}</p>'
                f'<div style="font-family:Space Mono,monospace;font-size:0.72rem;'
                f'color:#2a4a6a;margin-top:0.3rem">✅ Not found in any OTX pulse</div>',
                unsafe_allow_html=True,
            )

        # Threat actor attribution
        if otx_res.adversaries:
            for adv in otx_res.adversaries[:3]:
                is_hp = any(
                    hp in adv.lower()
                    for hp in {"lazarus","apt28","apt29","fin7","darkside","revil",
                               "lockbit","conti","emotet","cobalt","turla","hafnium"}
                )
                adv_col = "#ff2d55" if is_hp else "#ffd060"
                adv_bg  = "rgba(255,45,85,0.12)" if is_hp else "rgba(255,208,96,0.08)"
                st.markdown(
                    f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                    f'background:{adv_bg};border:1px solid {adv_col}44;'
                    f'border-radius:4px;padding:0.25rem 0.6rem;'
                    f'margin-top:0.4rem;display:inline-block">'
                    f'🕵️ <span style="color:{adv_col}">{_html.escape(adv)}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    # ── MITRE ATT&CK pills ────────────────────────────────────────────
    with mitre_col:
        if otx_res.attack_ids:
            st.markdown(
                '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                'color:#00ffb4;letter-spacing:0.2em">MITRE ATT&CK</p>',
                unsafe_allow_html=True,
            )
            pills_html = ""
            for tid in otx_res.attack_ids[:8]:
                from backend.otx_engine import _MITRE_TACTIC_MAP
                base   = tid[:5]
                tactic = _MITRE_TACTIC_MAP.get(base, "")
                colour = _TACTIC_COLOUR.get(tactic, "#8aaac8")
                label  = f"{tid}" + (f" · {tactic}" if tactic else "")
                pills_html += (
                    f'<span style="font-family:Space Mono,monospace;font-size:0.62rem;'
                    f'background:rgba({_hex_to_rgb(colour)},0.12);'
                    f'border:1px solid {colour}44;color:{colour};'
                    f'border-radius:4px;padding:0.18rem 0.5rem;'
                    f'margin:0.15rem;display:inline-block">'
                    f'{_html.escape(label)}</span>'
                )
            st.markdown(pills_html, unsafe_allow_html=True)
        else:
            st.markdown(
                '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                'color:#00ffb4;letter-spacing:0.2em">MITRE ATT&CK</p>'
                '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                'color:#2a4a6a">No ATT&CK techniques mapped</div>',
                unsafe_allow_html=True,
            )

        # OTX reputation score
        if otx_res.reputation is not None:
            rep_val  = otx_res.reputation
            rep_col  = "#ff2d55" if rep_val < -50 else ("#ffd060" if rep_val < 0 else "#00ffb4")
            rep_text = "Malicious" if rep_val < -50 else ("Suspicious" if rep_val < 0 else "Clean")
            st.markdown(
                f'<div style="font-family:Space Mono,monospace;font-size:0.65rem;'
                f'color:{rep_col};margin-top:0.5rem">'
                f'Reputation: {rep_val} ({rep_text})</div>',
                unsafe_allow_html=True,
            )

    # ── Top pulse names (campaign context) ───────────────────────────
    if otx_res.pulse_names:
        st.markdown(
            '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
            'color:#00ffb4;letter-spacing:0.2em;margin-top:0.7rem">RECENT PULSE NAMES</p>',
            unsafe_allow_html=True,
        )
        for name in otx_res.pulse_names[:5]:
            st.markdown(
                f'<div style="font-family:Space Mono,monospace;font-size:0.65rem;'
                f'color:#8aaac8;padding:0.15rem 0;'
                f'border-bottom:1px solid rgba(42,58,74,0.4)">'
                f'› {_html.escape(str(name)[:80])}</div>',
                unsafe_allow_html=True,
            )

    # ── Targeted countries / industries ───────────────────────────────
    if otx_res.targeted_countries or otx_res.targeted_industries:
        t_col_a, t_col_b = st.columns(2, gap="small")

        with t_col_a:
            if otx_res.targeted_countries:
                st.markdown(
                    '<p style="font-family:Space Mono,monospace;font-size:0.58rem;'
                    'color:#4a6a8a;letter-spacing:0.15em;margin-top:0.5rem">TARGETED COUNTRIES</p>',
                    unsafe_allow_html=True,
                )
                st.markdown(
                    " ".join(
                        f'<span style="font-family:Space Mono,monospace;font-size:0.62rem;'
                        f'color:#8aaac8;background:rgba(255,255,255,0.04);'
                        f'border:1px solid #1a2a3a;border-radius:3px;padding:0.12rem 0.35rem;'
                        f'margin:0.1rem;display:inline-block">{_html.escape(c)}</span>'
                        for c in otx_res.targeted_countries[:6]
                    ),
                    unsafe_allow_html=True,
                )

        with t_col_b:
            if otx_res.targeted_industries:
                st.markdown(
                    '<p style="font-family:Space Mono,monospace;font-size:0.58rem;'
                    'color:#4a6a8a;letter-spacing:0.15em;margin-top:0.5rem">TARGETED SECTORS</p>',
                    unsafe_allow_html=True,
                )
                st.markdown(
                    " ".join(
                        f'<span style="font-family:Space Mono,monospace;font-size:0.62rem;'
                        f'color:#8aaac8;background:rgba(255,255,255,0.04);'
                        f'border:1px solid #1a2a3a;border-radius:3px;padding:0.12rem 0.35rem;'
                        f'margin:0.1rem;display:inline-block">{_html.escape(i)}</span>'
                        for i in otx_res.targeted_industries[:6]
                    ),
                    unsafe_allow_html=True,
                )

    # ── Flags ─────────────────────────────────────────────────────────
    st.markdown(flag_list(otx_res.flags), unsafe_allow_html=True)

    for e in otx_res.errors:
        st.caption(f"⚠ OTX: {e}")


# ── Colour helper ─────────────────────────────────────────────────────────────

def _hex_to_rgb(hex_colour: str) -> str:
    """Convert #rrggbb to 'r,g,b' string for rgba() CSS."""
    h = hex_colour.lstrip("#")
    if len(h) == 6:
        r = int(h[0:2], 16)
        g = int(h[2:4], 16)
        b = int(h[4:6], 16)
        return f"{r},{g},{b}"
    return "138,170,200"   # fallback: #8aaac8
