"""
frontend/extra_widgets.py
--------------------------
Extra UI Widgets — GhostWire CTI v6
"""

from __future__ import annotations

import html as _html
from typing import Optional
import streamlit as st

from frontend.components import section_label, flag_list, ioc_chips, kv_row


# ── WHOIS Timeline ────────────────────────────────────────────────────────────

def render_whois_timeline(timeline_res) -> None:
    """
    Render an interactive Plotly timeline of WHOIS + cert events.
    Color-coded by severity: info=cyan, warning=yellow, critical=red.
    """
    import plotly.graph_objects as go

    section_label("📅 WHOIS & Certificate Timeline")

    if not timeline_res.events:
        st.caption("No timeline data available.")
        return

    sev_colors = {
        "info":     "#00c8ff",
        "warning":  "#ffd060",
        "critical": "#ff2d55",
    }
    cat_symbols = {
        "registration": "circle",
        "expiry":       "diamond",
        "cert":         "square",
        "dns":          "triangle-up",
        "risk":         "star",
    }

    dates   = [e.date       for e in timeline_res.events]
    labels  = [e.label      for e in timeline_res.events]
    descs   = [e.description for e in timeline_res.events]
    colors  = [sev_colors.get(e.severity, "#00c8ff") for e in timeline_res.events]
    symbols = [cat_symbols.get(e.category, "circle") for e in timeline_res.events]

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=dates, y=[0] * len(dates),
        mode="lines",
        line=dict(color="#1a2a3a", width=2),
        hoverinfo="skip",
        showlegend=False,
    ))

    fig.add_trace(go.Scatter(
        x=dates,
        y=[0] * len(dates),
        mode="markers+text",
        marker=dict(
            size=14,
            color=colors,
            symbol=symbols,
            line=dict(color="#060a10", width=1.5),
        ),
        text=labels,
        textposition="top center",
        textfont=dict(family="Space Mono", size=9, color="#c0d4e8"),
        customdata=descs,
        hovertemplate="<b>%{text}</b><br>%{x}<br><br>%{customdata}<extra></extra>",
        showlegend=False,
    ))

    meta_parts = []
    if timeline_res.domain_age_days is not None:
        meta_parts.append(f"Age: {timeline_res.domain_age_days}d")
    if timeline_res.registrar:
        meta_parts.append(f"Registrar: {timeline_res.registrar[:30]}")
    if timeline_res.cert_count:
        meta_parts.append(f"Certs in CT: {timeline_res.cert_count}")
    if meta_parts:
        fig.add_annotation(
            x=dates[0] if dates else "2020-01-01",
            y=0.15, xref="x", yref="y",
            text=" · ".join(meta_parts),
            showarrow=False,
            font=dict(family="Space Mono", size=8, color="#4a6a8a"),
            align="left",
        )

    fig.update_layout(
        paper_bgcolor = "rgba(0,0,0,0)",
        plot_bgcolor  = "rgba(0,0,0,0)",
        height        = 200,
        margin        = dict(t=30, b=10, l=10, r=10),
        xaxis=dict(
            showgrid=False, zeroline=False,
            tickfont=dict(family="Space Mono", size=8, color="#4a6a8a"),
            type="date",
        ),
        yaxis=dict(
            showgrid=False, zeroline=False,
            showticklabels=False,
            range=[-0.3, 0.5],
        ),
        hovermode="x",
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    for e in (timeline_res.errors or [])[:3]:
        st.caption(f"⚠ {e}")


# ── Screenshot Preview ────────────────────────────────────────────────────────

def render_screenshot_preview(url: str) -> None:
    """
    Capture and display a Playwright screenshot of the target URL.
    Safe — browser is sandboxed, content not executed past render.
    """
    section_label("🖥 Site Screenshot Preview")

    with st.spinner("Capturing screenshot (Playwright Chromium)…"):
        try:
            from backend.screenshot_engine import capture_screenshot
            img_bytes = capture_screenshot(url, width=1280, height=700)

            if img_bytes:
                import base64
                b64 = base64.b64encode(img_bytes).decode()
                st.markdown(
                    f'<div style="border:1px solid rgba(0,255,180,0.15);border-radius:8px;'
                    f'overflow:hidden;margin-bottom:0.5rem">'
                    f'<img src="data:image/png;base64,{b64}" '
                    f'style="width:100%;display:block" alt="Site screenshot"/>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.caption(
                    "📷 Screenshot captured via Playwright Chromium  ·  "
                    "Viewport 1280×700  ·  No JS execution risk"
                )
            else:
                st.caption("⚠ Screenshot unavailable — site may be offline or blocking headless browsers.")
        except Exception as e:
            st.caption(f"⚠ Screenshot error: {e}")


# ── Threat Map ────────────────────────────────────────────────────────────────

def render_threat_map(
    latitude:  Optional[float],
    longitude: Optional[float],
    ip:        str,
    country:   Optional[str] = None,
    city:      Optional[str] = None,
) -> None:
    """
    Display an interactive map showing the IP's geolocation.

    v6.1: st.map (Streamlit native — Carto tile basemap).
    - MAPBOX_TOKEN opsionaldır — .env-də varsa daha yüksək zoom keyfiyyəti
    - Token yoxdursa Carto default tile-ları işləyir (pulsuz, tokensiz)
    - st.map Streamlit 1.45.0-da tam dəstəklənir
    - Plotly scatter_geo fallback — st.map uğursuz olsa işə düşür
    """
    import os
    import pandas as pd

    section_label("🗺 Threat Map — IP Geolocation")

    if latitude is None or longitude is None:
        st.caption("⚠ Geolocation data unavailable for this IP.")
        return

    loc_str = f"{city or ''} {country or ''}".strip() or ip

    # Koordinat + yer məlumatı başlıq
    st.markdown(
        f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
        f'color:#4a6a8a;margin-bottom:0.4rem">'
        f'📍  {_html.escape(ip)}  ·  {_html.escape(loc_str)}  ·  '
        f'{latitude:.4f}°N  {longitude:.4f}°E'
        f'</div>',
        unsafe_allow_html=True,
    )

    # DataFrame — st.map latitude/longitude sütunları tələb edir
    df = pd.DataFrame({
        "latitude":  [latitude],
        "longitude": [longitude],
    })

    try:
        # st.map — Streamlit 1.45.0 native map (Carto tile basemap)
        # MAPBOX_TOKEN .env-də varsa → .streamlit/config.toml [mapbox] token oxunur
        # Token yoxdursa → Carto default tile-ları (pulsuz, tokensiz) işləyir
        st.map(
            df,
            latitude="latitude",
            longitude="longitude",
            color="#ff2d55",      # GhostWire qırmızı marker
            size=200,             # Marker ölçüsü (metr — zoom-a görə görünür)
            zoom=6,               # Şəhər səviyyəsi zoom
            use_container_width=True,
        )

    except Exception as e:
        # Fallback — Plotly scatter_geo (offline, tokensiz)
        import plotly.graph_objects as go
        try:
            fig = go.Figure(go.Scattergeo(
                lat=[latitude],
                lon=[longitude],
                mode="markers+text",
                marker=dict(size=14, color="#ff2d55",
                            line=dict(color="#ff6b8a", width=2)),
                text=[f"  {_html.escape(ip)}"],
                textfont=dict(family="Space Mono, monospace", size=10, color="#ff6b8a"),
                textposition="middle right",
                showlegend=False,
            ))
            fig.update_geos(
                projection_type="natural earth",
                showland=True,      landcolor="#0d1e2e",
                showocean=True,     oceancolor="#060a10",
                showcoastlines=True, coastlinecolor="#1a2a3a",
                showcountries=True, countrycolor="#1a3a5a",
                bgcolor="#060a10",
                center=dict(lat=latitude, lon=longitude),
                lataxis_range=[max(-90, latitude-35), min(90, latitude+35)],
                lonaxis_range=[max(-180, longitude-55), min(180, longitude+55)],
            )
            fig.update_layout(
                height=350, margin=dict(l=0, r=0, t=0, b=0),
                paper_bgcolor="#060a10", plot_bgcolor="#060a10",
            )
            st.plotly_chart(fig, use_container_width=True,
                           config={"displayModeBar": False})
        except Exception:
            # Son fallback — sadə koordinat göstər
            st.markdown(
                f'<div style="font-family:Space Mono,monospace;font-size:0.72rem;'
                f'background:#0a1520;border:1px solid #1a2a3a;border-radius:8px;'
                f'padding:1rem;color:#4a6a8a;text-align:center">'
                f'📍 {_html.escape(ip)} · {_html.escape(loc_str)}<br>'
                f'<span style="font-size:0.6rem">{latitude:.4f}°N, {longitude:.4f}°E</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
        st.caption(f"⚠ st.map unavailable, fallback used: {e}")


# ── Shodan Panel ──────────────────────────────────────────────────────────────

def render_shodan_panel(shodan_res) -> None:
    """Display Shodan intelligence: ports, CVEs, tags, banners."""
    section_label("🔍 Shodan Intelligence")

    if not shodan_res.available:
        st.markdown(
            f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
            f'color:#4a6a8a">'
            f'{"".join(f"  › {_html.escape(str(f))}<br>" for f in shodan_res.flags)}'
            f'</div>',
            unsafe_allow_html=True,
        )
        return

    col_a, col_b = st.columns([1, 1], gap="medium")

    with col_a:
        if shodan_res.open_ports:
            st.markdown(
                '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                'color:#00ffb4;letter-spacing:0.2em">OPEN PORTS</p>',
                unsafe_allow_html=True,
            )
            SUSPICIOUS = {4444,4445,4446,1080,8080,3128,9001,9002,6667,6668,6669,31337,23}
            port_html = "".join(
                f'<span style="font-family:Space Mono,monospace;font-size:0.72rem;'
                f'background:{"rgba(255,45,85,0.15)" if p in SUSPICIOUS else "rgba(255,255,255,0.05)"};'
                f'border:1px solid {"#ff2d55" if p in SUSPICIOUS else "#2a3a4a"};'
                f'color:{"#ff6b8a" if p in SUSPICIOUS else "#8aaac8"};'
                f'border-radius:4px;padding:0.2rem 0.5rem;margin:0.15rem;'
                f'display:inline-block">:{p}</span>'
                for p in sorted(shodan_res.open_ports)[:20]
            )
            st.markdown(port_html, unsafe_allow_html=True)

        if shodan_res.services:
            st.markdown(
                '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                'color:#00ffb4;letter-spacing:0.2em;margin-top:0.6rem">SERVICES</p>',
                unsafe_allow_html=True,
            )
            for svc in shodan_res.services[:5]:
                prod = svc.get("product", "")
                ver  = svc.get("version", "")
                port = svc.get("port", "?")
                label = f":{port} — {prod} {ver}".strip() if prod else f":{port}"
                st.markdown(
                    f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                    f'color:#8aaac8;padding:0.15rem 0">› {_html.escape(str(label))}</div>',
                    unsafe_allow_html=True,
                )

    with col_b:
        if shodan_res.cves:
            st.markdown(
                '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                'color:#ff2d55;letter-spacing:0.2em">CVEs DETECTED</p>',
                unsafe_allow_html=True,
            )
            for cve in shodan_res.cves[:6]:
                st.markdown(
                    f'<span style="font-family:Space Mono,monospace;font-size:0.68rem;'
                    f'background:rgba(255,45,85,0.12);border:1px solid rgba(255,45,85,0.3);'
                    f'color:#ff6b8a;border-radius:4px;padding:0.18rem 0.45rem;'
                    f'margin:0.15rem;display:inline-block">{_html.escape(str(cve))}</span>',
                    unsafe_allow_html=True,
                )
            if shodan_res.vuln_count > 6:
                st.caption(f"… and {shodan_res.vuln_count - 6} more")

        if shodan_res.tags:
            st.markdown(
                '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                'color:#00ffb4;letter-spacing:0.2em;margin-top:0.5rem">SHODAN TAGS</p>',
                unsafe_allow_html=True,
            )
            RISK_TAGS = {"tor","vpn","scanner","botnet","malware","c2","phishing","spam","proxy"}
            tags_html = "".join(
                f'<span style="font-family:Space Mono,monospace;font-size:0.68rem;'
                f'background:{"rgba(255,45,85,0.12)" if t.lower() in RISK_TAGS else "rgba(255,255,255,0.05)"};'
                f'border:1px solid {"rgba(255,45,85,0.3)" if t.lower() in RISK_TAGS else "#2a3a4a"};'
                f'color:{"#ff6b8a" if t.lower() in RISK_TAGS else "#8aaac8"};'
                f'border-radius:4px;padding:0.18rem 0.45rem;margin:0.15rem;'
                f'display:inline-block">{_html.escape(str(t))}</span>'
                for t in shodan_res.tags[:8]
            )
            st.markdown(tags_html, unsafe_allow_html=True)

    if shodan_res.banners:
        with st.expander(f"📋 Shodan Service Banners ({len(shodan_res.banners)})"):
            for b in shodan_res.banners[:5]:
                st.code(b[:200], language=None)

    st.markdown(flag_list(shodan_res.flags), unsafe_allow_html=True)
    for e in shodan_res.errors:
        st.caption(f"⚠ {e}")


# ── GreyNoise Panel ───────────────────────────────────────────────────────────

def render_greynoise_panel(gn_res) -> None:
    """Display GreyNoise classification, intent, tags, CVE attempts."""
    section_label("👁 GreyNoise Context")

    cls = gn_res.classification or "unknown"
    cls_colors = {
        "malicious": ("#ff2d55", "rgba(255,45,85,0.15)"),
        "benign":    ("#00ffb4", "rgba(0,255,180,0.08)"),
        "unknown":   ("#4a6a8a", "rgba(255,255,255,0.05)"),
    }
    cls_color, cls_bg = cls_colors.get(cls, cls_colors["unknown"])

    riot_html = ""
    if gn_res.riot:
        riot_html = (
            '<span style="font-family:Space Mono,monospace;font-size:0.68rem;'
            'background:rgba(0,255,180,0.1);border:1px solid rgba(0,255,180,0.3);'
            'color:#00ffb4;border-radius:4px;padding:0.2rem 0.6rem;margin-left:0.5rem">'
            'RIOT ✓ Known Benign</span>'
        )

    noise_label = "NOISE" if gn_res.noise else "NOT NOISE"
    noise_desc  = "Mass internet scanner" if gn_res.noise else "Targeted/directed traffic"

    st.markdown(
        f'<div style="display:flex;align-items:center;gap:0.8rem;margin-bottom:0.8rem;'
        f'flex-wrap:wrap">'
        f'<div style="background:{cls_bg};border:1px solid {cls_color}44;'
        f'border-radius:8px;padding:0.5rem 1rem;text-align:center">'
        f'<div style="font-family:Space Mono,monospace;font-size:0.58rem;'
        f'color:#4a6a8a;letter-spacing:0.2em">CLASSIFICATION</div>'
        f'<div style="font-family:Space Mono,monospace;font-size:1.1rem;'
        f'font-weight:700;color:{cls_color}">{_html.escape(cls.upper())}</div>'
        f'</div>'
        f'<div style="background:rgba(255,255,255,0.04);border:1px solid #1a2a3a;'
        f'border-radius:8px;padding:0.5rem 1rem;text-align:center">'
        f'<div style="font-family:Space Mono,monospace;font-size:0.58rem;'
        f'color:#4a6a8a;letter-spacing:0.2em">NOISE</div>'
        f'<div style="font-family:Space Mono,monospace;font-size:0.9rem;'
        f'font-weight:700;color:#c0d4e8">{noise_label}</div>'
        f'<div style="font-family:Space Mono,monospace;font-size:0.58rem;color:#3a5a7a">'
        f'{noise_desc}</div>'
        f'</div>'
        f'{riot_html}'
        f'</div>',
        unsafe_allow_html=True,
    )

    if gn_res.name:
        st.markdown(
            f'<div style="font-family:Space Mono,monospace;font-size:0.72rem;'
            f'color:#ffd060;margin-bottom:0.4rem">Actor: {_html.escape(str(gn_res.name))}</div>',
            unsafe_allow_html=True,
        )

    if gn_res.tags:
        MAL_TAGS = {"scanner","brute_force","exploit","malware","trojan","bot","c2","phishing","spam"}
        tags_html = "".join(
            f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
            f'background:{"rgba(255,45,85,0.12)" if any(m in t.lower() for m in MAL_TAGS) else "rgba(255,255,255,0.05)"};'
            f'border:1px solid {"rgba(255,45,85,0.3)" if any(m in t.lower() for m in MAL_TAGS) else "#2a3a4a"};'
            f'color:{"#ff6b8a" if any(m in t.lower() for m in MAL_TAGS) else "#8aaac8"};'
            f'border-radius:4px;padding:0.18rem 0.45rem;margin:0.15rem;'
            f'display:inline-block">{_html.escape(str(t))}</span>'
            for t in gn_res.tags[:8]
        )
        st.markdown(tags_html, unsafe_allow_html=True)

    if gn_res.cve_attempts:
        st.markdown(
            '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
            'color:#ff2d55;margin-top:0.5rem;letter-spacing:0.15em">CVE EXPLOITATION ATTEMPTS</p>',
            unsafe_allow_html=True,
        )
        for cve in gn_res.cve_attempts[:5]:
            st.markdown(
                f'<span style="font-family:Space Mono,monospace;font-size:0.68rem;'
                f'background:rgba(255,45,85,0.12);border:1px solid rgba(255,45,85,0.3);'
                f'color:#ff6b8a;border-radius:4px;padding:0.18rem 0.45rem;margin:0.15rem;'
                f'display:inline-block">{_html.escape(str(cve))}</span>',
                unsafe_allow_html=True,
            )

        st.markdown(
            f'<div style="font-family:Space Mono,monospace;font-size:0.65rem;'
            f'color:#3a5a7a;margin-top:0.4rem">'
            f'First seen: {_html.escape(str(gn_res.first_seen or "?"))}  ·  Last seen: {_html.escape(str(gn_res.last_seen or "?"))}'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown(flag_list(gn_res.flags), unsafe_allow_html=True)
    for e in gn_res.errors:
        st.caption(f"⚠ {e}")


# ── URLhaus Panel ─────────────────────────────────────────────────────────────
# v6.1: URLhaus engine UI paneli — url/hash/ip mode-aware rendering
from frontend.urlhaus_panel import render_urlhaus_panel  # noqa: F401
