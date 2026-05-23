"""
frontend/stix_panel.py
-----------------------
GhostWire CTI v7 — STIX 2.1 / TAXII Export Panel.

Renders a download widget for STIX 2.1 bundle and CSV IOC export.
Called from url_renderer.py / other_renderers.py after analysis completes.
"""

from __future__ import annotations

import json
import streamlit as st
from frontend.components import section_label


def render_stix_export_panel(
    target_url: str,
    threat_level: str,
    score: int,
    iocs: list,
    flags: list,
    malware_family: str | None = None,
    threat_actors: list | None = None,
    ip_address: str | None = None,
    verdict_text: str = "",
    sha256_hash: str | None = None,
    md5_hash: str | None = None,
    mitre_ids: list | None = None,
) -> None:
    """
    Render STIX 2.1 export panel with download buttons.
    Only shows for MEDIUM+ threat levels to avoid IOC pollution.
    """
    section_label("📦 STIX 2.1 / TAXII Export")

    if score < 20:
        st.markdown(
            '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
            'color:#2a4a6a">STIX export available for MEDIUM+ threat indicators only</div>',
            unsafe_allow_html=True,
        )
        return

    try:
        from backend.stix_export import export_stix_bundle, export_csv_iocs

        stix_json = export_stix_bundle(
            target_url=target_url,
            threat_level=threat_level,
            score=score,
            iocs=iocs,
            flags=flags,
            malware_family=malware_family,
            threat_actors=threat_actors or [],
            ip_address=ip_address,
            verdict_text=verdict_text,
            sha256_hash=sha256_hash,
            md5_hash=md5_hash,
            mitre_ids=mitre_ids or [],
        )

        csv_iocs = export_csv_iocs(
            target_url=target_url,
            ip_address=ip_address,
            iocs=iocs,
            threat_level=threat_level,
            score=score,
            sha256_hash=sha256_hash,
            md5_hash=md5_hash,
            malware_family=malware_family,
        )

        # Parse bundle to show summary
        bundle = json.loads(stix_json)
        obj_count = len(bundle.get("objects", []))
        indicator_count = sum(1 for o in bundle.get("objects", []) if o.get("type") == "indicator")

        # Stats row
        st.markdown(
            f'<div style="display:flex;gap:0.8rem;margin-bottom:0.8rem">'
            f'<div style="background:rgba(0,255,180,0.05);border:1px solid rgba(0,255,180,0.15);'
            f'border-radius:6px;padding:0.4rem 0.8rem;font-family:Space Mono,monospace;font-size:0.62rem">'
            f'<span style="color:#3a6a5a">STIX OBJECTS</span><br>'
            f'<span style="color:#00ffb4;font-size:1rem;font-weight:700">{obj_count}</span></div>'
            f'<div style="background:rgba(0,200,255,0.05);border:1px solid rgba(0,200,255,0.15);'
            f'border-radius:6px;padding:0.4rem 0.8rem;font-family:Space Mono,monospace;font-size:0.62rem">'
            f'<span style="color:#2a5a7a">INDICATORS</span><br>'
            f'<span style="color:#00c8ff;font-size:1rem;font-weight:700">{indicator_count}</span></div>'
            f'<div style="background:rgba(255,208,96,0.05);border:1px solid rgba(255,208,96,0.15);'
            f'border-radius:6px;padding:0.4rem 0.8rem;font-family:Space Mono,monospace;font-size:0.62rem">'
            f'<span style="color:#6a5a2a">SPEC</span><br>'
            f'<span style="color:#ffd060;font-size:0.8rem;font-weight:700">STIX 2.1</span></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        col1, col2 = st.columns(2, gap="small")

        with col1:
            st.download_button(
                label="⬇ STIX 2.1 Bundle (JSON)",
                data=stix_json,
                file_name=f"ghostwire_stix_{threat_level.lower()}_{score}.json",
                mime="application/json",
                help="STIX 2.1 Bundle — import into MISP, OpenCTI, TheHive, TAXII server",
                use_container_width=True,
            )

        with col2:
            st.download_button(
                label="⬇ IOC Export (CSV)",
                data=csv_iocs,
                file_name=f"ghostwire_iocs_{threat_level.lower()}_{score}.csv",
                mime="text/csv",
                help="IOC CSV — import into Splunk, QRadar, Elastic SIEM, Microsoft Sentinel",
                use_container_width=True,
            )

        # TAXII info
        with st.expander("🔌 TAXII 2.1 Integration Guide"):
            st.markdown(
                '<div style="font-family:Space Mono,monospace;font-size:0.65rem;'
                'color:#4a7a6a;line-height:1.8">'
                '<b style="color:#00ffb4">POST to TAXII 2.1 endpoint:</b><br>'
                '<code style="color:#00c8ff;background:rgba(0,200,255,0.07);'
                'padding:0.2rem 0.4rem;border-radius:3px">'
                'POST /taxii2/{api_root}/collections/{id}/objects/</code><br><br>'
                '<b style="color:#00ffb4">Headers:</b><br>'
                'Content-Type: application/taxii+json;version=2.1<br>'
                'Authorization: Basic {your_token}<br><br>'
                '<b style="color:#00ffb4">Compatible platforms:</b><br>'
                '· MISP (import via STIX2 module)<br>'
                '· OpenCTI (native STIX 2.1 import)<br>'
                '· TheHive + Cortex (STIX analyzer)<br>'
                '· Anomali ThreatStream<br>'
                '· EclecticIQ Platform<br>'
                '· IBM QRadar (via TAXII feed)</div>',
                unsafe_allow_html=True,
            )

    except Exception as e:
        st.markdown(
            f'<div style="font-family:Space Mono,monospace;font-size:0.65rem;'
            f'color:#ff5f87">⚠ STIX export error: {str(e)[:100]}</div>',
            unsafe_allow_html=True,
        )
