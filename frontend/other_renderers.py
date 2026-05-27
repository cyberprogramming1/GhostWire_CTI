"""
frontend/other_renderers.py
---------------------------
"""

from __future__ import annotations

import streamlit as st

from frontend.components import (
    make_gauge, threat_banner, flag_list, ioc_chips, kv_row, cert_table,
    source_badge, override_banner, verdict_box, mitigation_list,
    engine_card, section_label, footer, mitre_section, confidence_panel,
)
from backend.verdict import _classify


# ── Pipeline B: Hash / File ───────────────────────────────────────────────────

def render_hash_results(h_res, timestamp: str) -> None:
    """Render file/hash forensic analysis results."""
    st.markdown("---")
    level, colour, bg = _classify(h_res.score)

    ca, cb = st.columns([1, 2], gap="large")

    with ca:
        st.markdown(threat_banner(level, h_res.score, colour, bg), unsafe_allow_html=True)
        st.plotly_chart(
            make_gauge(h_res.score, colour),
            use_container_width=True,
            config={"displayModeBar": False},
        )

        section_label("Hash Digests")
        rows = [
            ("SHA-256", (h_res.sha256 or "—")[:32] + "…", False),
            ("MD5",     h_res.md5  or "—",               False),
            ("SHA-1",   h_res.sha1 or "—",               False),
        ]
        st.markdown(
            '<div class="card">' + "".join(kv_row(k, v, d) for k, v, d in rows) + "</div>",
            unsafe_allow_html=True,
        )

    with cb:
        section_label("📁 File Intelligence")
        meta_rows = [
            ("File Type",    h_res.file_type or "Unknown",                              False),
            ("Size",         f"{h_res.file_size:,} B" if h_res.file_size else "—",     False),
            ("Author",       h_res.author    or "—",                                    False),
            ("Creator Tool", h_res.creator_tool or "—",                                 False),
            ("Created",      h_res.creation_date or "—",                               False),
            ("VT Detections",f"{h_res.vt_malicious}/{h_res.vt_total}",                 h_res.vt_malicious > 0),
            ("Malware Family",h_res.vt_family or "None",                               bool(h_res.vt_family)),
        ]
        st.markdown(
            '<div class="card">' + "".join(kv_row(k, v, d) for k, v, d in meta_rows) + "</div>",
            unsafe_allow_html=True,
        )

        weapons = []
        if h_res.has_macros:
            weapons.append("⚠ VBA Macros present")
        if h_res.has_auto_open:
            weapons.append("🚨 Auto-execute macro (AutoOpen/Document_Open)")
        if h_res.has_embedded_objects:
            weapons.append("⚠ Embedded objects detected")
        if h_res.high_entropy_sections:
            weapons.append(f"⚠ High-entropy sections: {', '.join(h_res.high_entropy_sections)}")
        if h_res.suspicious_imports:
            weapons.append(f"⚠ Suspicious PE imports: {', '.join(h_res.suspicious_imports[:4])}")

        if weapons:
            section_label("☠️ Weaponization Indicators")
            st.markdown(flag_list(weapons), unsafe_allow_html=True)

        section_label("Detection Signals")
        st.markdown(flag_list(h_res.flags), unsafe_allow_html=True)

        if h_res.iocs:
            section_label("🔴 IOCs")
            st.markdown(ioc_chips(h_res.iocs), unsafe_allow_html=True)

        for e in h_res.errors:
            st.caption(f"⚠ {e}")

    # ── STIX 2.1 / TAXII Export for Hash pipeline ─────────────────────
    try:
        from frontend.stix_panel import render_stix_export_panel
        level, _, _ = _classify(h_res.score)
        render_stix_export_panel(
            target_url     = h_res.sha256 or h_res.md5 or "unknown_hash",
            threat_level   = level,
            score          = h_res.score,
            iocs           = h_res.iocs,
            flags          = h_res.flags,
            sha256_hash    = h_res.sha256,
            md5_hash       = h_res.md5,
            malware_family = h_res.vt_family,
            verdict_text   = f"File/Hash forensic analysis. Type: {h_res.file_type}. VT: {h_res.vt_malicious}/{h_res.vt_total} detections.",
        )
    except Exception as _stix_err:
        st.caption(f"⚠ STIX export error: {_stix_err}")

    footer(timestamp, "FILE/HASH ENGINE")


# ── Pipeline C: Email / SMS ───────────────────────────────────────────────────

def render_email_results(em_res, timestamp: str) -> None:
    """Render email/SMS forensic analysis results."""
    st.markdown("---")
    level, colour, bg = _classify(em_res.score)

    ca, cb = st.columns([1, 2], gap="large")

    with ca:
        st.markdown(threat_banner(level, em_res.score, colour, bg), unsafe_allow_html=True)
        st.plotly_chart(
            make_gauge(em_res.score, colour),
            use_container_width=True,
            config={"displayModeBar": False},
        )

        section_label("Email Signals")
        for name, active, clr, icon in [
            ("Impersonation",  em_res.display_name_spoofing,  "#ff2d55", "🎭"),
            ("Reply-To Hijack",em_res.reply_to_hijack,        "#ff9a3c", "📤"),
            ("Auth Failed",    em_res.auth_failed,            "#ffd060", "🔓"),
            ("Urgency Lang",   bool(em_res.urgency_phrases),  "#c47aff", "⚡"),
            ("Authority",      bool(em_res.authority_phrases),"#00c8ff", "🏛"),
            ("OCR Used",       bool(em_res.ocr_text),         "#00ffb4", "👁"),
        ]:
            c_val = clr if active else "#2a4a6a"
            c_bg  = (
                f"rgba({int(clr[1:3],16)},{int(clr[3:5],16)},{int(clr[5:7],16)},0.09)"
                if active else "transparent"
            )
            st.markdown(
                f'<div style="display:flex;align-items:center;gap:0.55rem;'
                f'background:{c_bg};border:1px solid {c_val}44;border-radius:6px;'
                f'padding:0.3rem 0.65rem;margin-bottom:0.28rem">'
                f'<span>{icon if active else "○"}</span>'
                f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;color:{c_val}">'
                f'{name.upper()}</span></div>',
                unsafe_allow_html=True,
            )

    with cb:
        section_label("📧 Header Intelligence")
        hdr = [
            ("Display Name",  em_res.display_name    or "Not found", em_res.display_name_spoofing),
            ("Sender Address",em_res.sender_address  or "Not found", False),
            ("Sender Domain", em_res.sender_domain   or "Not found", em_res.display_name_spoofing),
            ("Reply-To",      em_res.reply_to        or "Not set",   em_res.reply_to_hijack),
            ("Return-Path",   em_res.return_path     or "Not set",   False),
            ("Subject",       em_res.subject         or "Not found", False),
            ("SPF",           em_res.spf_result      or "—",         em_res.spf_result in ("fail", "softfail")),
            ("DKIM",          em_res.dkim_result     or "—",         em_res.dkim_result == "fail"),
            ("DMARC",         em_res.dmarc_result    or "—",         em_res.dmarc_result == "fail"),
        ]
        st.markdown(
            '<div class="card">' + "".join(kv_row(k, v, d) for k, v, d in hdr) + "</div>",
            unsafe_allow_html=True,
        )

        if em_res.brand_impersonated:
            st.markdown(
                override_banner(
                    f"IMPERSONATION: Pretends to be <b>{em_res.brand_impersonated}</b> "
                    f"but sent from <b>{em_res.sender_domain}</b>"
                ),
                unsafe_allow_html=True,
            )

        section_label("Detection Signals")
        st.markdown(flag_list(em_res.flags), unsafe_allow_html=True)

        if em_res.extracted_urls:
            section_label("🔗 Extracted URLs")
            for u in em_res.extracted_urls[:8]:
                st.code(u, language=None)

        if em_res.iocs:
            section_label("IOCs")
            st.markdown(ioc_chips(em_res.iocs), unsafe_allow_html=True)

        if em_res.ocr_text:
            with st.expander(f"📄 OCR Text ({em_res.ocr_method})"):
                st.text(em_res.ocr_text[:2500])

        for e in em_res.errors:
            e_str = str(e).lower()
            # FIX v7: Ollama unavailability is NOT a real error — it's expected
            # when Ollama is not running locally. Show as info, not red error.
            if "all ollama models failed" in e_str or "heuristics only" in e_str:
                st.markdown(
                    '<div style="font-family:Space Mono,monospace;font-size:0.65rem;'
                    'color:#4a6a8a;margin-top:0.3rem">'
                    'ℹ️ AI (Ollama): Not available — heuristic analysis used instead. '
                    'Start Ollama locally for enhanced AI detection.</div>',
                    unsafe_allow_html=True,
                )
            elif "ollama not installed" in e_str:
                st.markdown(
                    '<div style="font-family:Space Mono,monospace;font-size:0.65rem;'
                    'color:#4a6a8a;margin-top:0.3rem">'
                    'ℹ️ Ollama library not installed — pip install ollama for AI analysis.</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.caption(f"⚠ {e}")

    footer(timestamp, "EMAIL/SMS FORENSICS")


# ── Pipeline D: Standalone IP Intelligence ───────────────────────────────────

def render_ip_results(ip_res, ip_raw: str, timestamp: str) -> None:
    """Render standalone IP intelligence results."""
    from frontend.components import signal_pill

    level, colour, bg = _classify(ip_res.score)
    st.markdown("---")

    # Override banners
    if ip_res.abuse_confidence >= 80:
        st.markdown(
            override_banner(
                f"HIGH ABUSE CONFIDENCE: AbuseIPDB reports {ip_res.abuse_confidence}% "
                f"confidence with {ip_res.abuse_reports} community reports."
            ),
            unsafe_allow_html=True,
        )
    if ip_res.is_tor:
        st.markdown(
            override_banner(
                "TOR EXIT NODE CONFIRMED — IP is in the Tor Project bulk exit list. "
                "All traffic through this IP is anonymised.",
                level="warning",
            ),
            unsafe_allow_html=True,
        )

    # Header: IP + badges
    badge_tor = (
        '<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
        'padding:0.2rem 0.6rem;border:1px solid #ff2d55;border-radius:4px;'
        'color:#ff2d55;background:rgba(255,45,85,0.1)">TOR EXIT</span>'
        if ip_res.is_tor else ""
    )
    badge_vpn = (
        '<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
        'padding:0.2rem 0.6rem;border:1px solid #ff9a3c;border-radius:4px;'
        'color:#ff9a3c;background:rgba(255,154,60,0.1)">VPN/PROXY</span>'
        if ip_res.is_vpn else ""
    )
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:0.8rem;margin-bottom:1rem">'
        f'<span style="font-family:Space Mono,monospace;font-size:1.4rem;font-weight:700;color:#c0d4e8">'
        f'{ip_raw}</span>'
        f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;padding:0.2rem 0.6rem;'
        f'border:1px solid #00ffb4;border-radius:4px;color:#00ffb4">{ip_res.ip_version}</span>'
        f'{badge_tor}{badge_vpn}'
        f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;padding:0.2rem 0.6rem;'
        f'border:1px solid {colour};border-radius:4px;color:{colour};background:{bg}">{level}</span>'
        f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;color:#3a5a7a;margin-left:auto">'
        f'{timestamp}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    col_left, col_mid, col_right = st.columns([1.1, 1.2, 1], gap="medium")

    # ── LEFT: Geo + ASN ──────────────────────────────────────────────
    with col_left:
        section_label("📍 Geolocation")
        geo_rows = [
            ("Country",  f"{ip_res.country or 'Unknown'} {ip_res.country_code or ''}", False),
            ("City",     ip_res.city   or "Unknown", False),
            ("Region",   ip_res.region or "Unknown", False),
            ("Timezone", ip_res.timezone or "Unknown", False),
            ("ISP",      ip_res.isp    or "Unknown", False),
            ("ASN",      ip_res.asn    or "Unknown", False),
            ("Org",      ip_res.asn_org or "Unknown", False),
            ("rDNS",     ip_res.rdns   or "—",       False),
        ]
        st.markdown(
            '<div class="card">' + "".join(kv_row(k, v, d) for k, v, d in geo_rows) + "</div>",
            unsafe_allow_html=True,
        )

        if ip_res.open_ports:
            section_label("🔌 Open Ports (inferred)")
            pills = "".join(
                f'<span style="font-family:Space Mono,monospace;font-size:0.7rem;'
                f'background:{"rgba(255,45,85,0.15)" if p in [":9001",":9002"] else "rgba(255,255,255,0.05)"};'
                f'border:1px solid {"#ff2d55" if p in [":9001",":9002"] else "#2a3a4a"};'
                f'color:{"#ff6b8a" if p in [":9001",":9002"] else "#8aaac8"};'
                f'border-radius:4px;padding:0.2rem 0.5rem;margin:0.15rem">{p}</span>'
                for p in ip_res.open_ports
            )
            st.markdown(pills, unsafe_allow_html=True)

        if ip_res.threat_categories:
            section_label("🏷 Threat Categories")
            cats = "".join(
                f'<span style="font-family:Space Mono,monospace;font-size:0.68rem;'
                f'background:rgba(255,45,85,0.1);border:1px solid rgba(255,45,85,0.3);'
                f'color:#ff8aaa;border-radius:4px;padding:0.2rem 0.5rem;margin:0.15rem;'
                f'display:inline-block">{c}</span>'
                for c in ip_res.threat_categories
            )
            st.markdown(cats, unsafe_allow_html=True)

    # ── MID: Risk score + breakdown ───────────────────────────────────
    with col_mid:
        # Score ring
        st.markdown(
            f'<div class="card" style="text-align:center;padding:1.2rem">'
            f'<div style="font-family:Space Mono,monospace;font-size:0.62rem;'
            f'letter-spacing:0.2em;color:#3a5a7a;text-transform:uppercase">Risk Score</div>'
            f'<div style="font-family:Space Mono,monospace;font-size:3rem;'
            f'font-weight:700;color:{colour};line-height:1.1;margin:0.4rem 0">{ip_res.score}</div>'
            f'<div style="font-family:Space Mono,monospace;font-size:0.7rem;color:{colour};opacity:0.7">'
            f'{level}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # Sources hit + confidence
        sources_hit = ip_res.sources_hit if hasattr(ip_res, "sources_hit") else sum([
            ip_res.abuse_reports > 0, ip_res.is_tor, ip_res.is_vpn,
            ip_res.is_bulletproof, bool(ip_res.threat_categories),
        ])
        st.markdown(
            f'<div style="display:flex;gap:1rem;margin-bottom:0.8rem">'
            f'<div class="card" style="flex:1;text-align:center;padding:0.7rem">'
            f'<div style="font-family:Space Mono,monospace;font-size:0.58rem;color:#3a5a7a;'
            f'text-transform:uppercase;letter-spacing:0.15em">Sources Hit</div>'
            f'<div style="font-family:Space Mono,monospace;font-size:1.6rem;color:{colour};'
            f'font-weight:700">{sources_hit}</div></div>'
            f'<div class="card" style="flex:1;text-align:center;padding:0.7rem">'
            f'<div style="font-family:Space Mono,monospace;font-size:0.58rem;color:#3a5a7a;'
            f'text-transform:uppercase;letter-spacing:0.15em">Confidence</div>'
            f'<div style="font-family:Space Mono,monospace;font-size:1.6rem;color:#00c8ff;'
            f'font-weight:700">{ip_res.overall_confidence}%</div></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # Multi-source badges
        section_label("Intelligence Sources")
        from frontend.components import source_badge

        # AbuseIPDB
        ab_color = "#ff2d55" if ip_res.abuse_confidence >= 70 else ("#ffd060" if ip_res.abuse_confidence >= 30 else "#78d97a")
        st.markdown(source_badge(
            "AbuseIPDB",
            f"{ip_res.abuse_confidence}% · {ip_res.abuse_reports} reports",
            ab_color,
        ), unsafe_allow_html=True)

        # VT engines
        vt_mal = getattr(ip_res, "vt_malicious", 0)
        vt_tot = getattr(ip_res, "vt_total_engines", 0)
        vt_color = "#ff2d55" if vt_mal >= 3 else ("#ffd060" if vt_mal >= 1 else "#78d97a")
        st.markdown(source_badge(
            "VirusTotal",
            f"{vt_mal}/{vt_tot} engines malicious" if vt_tot else "Not queried",
            vt_color,
        ), unsafe_allow_html=True)

        # VT community
        cv_mal  = getattr(ip_res, "vt_community_votes_mal", 0)
        cv_harm = getattr(ip_res, "vt_community_votes_harm", 0)
        cc_mal  = getattr(ip_res, "vt_community_comments_mal", 0)
        cv_color = "#ff2d55" if cv_mal >= 2 else ("#ffd060" if cv_mal >= 1 else "#4a6a8a")
        st.markdown(source_badge(
            "VT Community Votes",
            f"{cv_mal} malicious · {cv_harm} harmless",
            cv_color,
        ), unsafe_allow_html=True)

        cc_color = "#ff2d55" if cc_mal >= 2 else ("#ffd060" if cc_mal >= 1 else "#4a6a8a")
        st.markdown(source_badge(
            "VT Comments",
            f"{cc_mal} malicious comment(s)" if cc_mal else "No malicious comments",
            cc_color,
        ), unsafe_allow_html=True)

        # VT related files
        rel_files = getattr(ip_res, "vt_malicious_files", 0)
        rel_color = "#ff2d55" if rel_files >= 2 else ("#ffd060" if rel_files >= 1 else "#4a6a8a")
        st.markdown(source_badge(
            "VT Related Files",
            f"{rel_files} malicious file(s)" if rel_files else "None malicious",
            rel_color,
        ), unsafe_allow_html=True)

        # AbuseIPDB categories
        if getattr(ip_res, "abuse_categories", []):
            section_label("📋 AbuseIPDB Report Categories")
            cats_html = "".join(
                f'<span style="font-family:Space Mono,monospace;font-size:0.62rem;'
                f'background:rgba(255,45,85,0.1);border:1px solid rgba(255,45,85,0.3);'
                f'color:#ff8aaa;border-radius:4px;padding:0.18rem 0.5rem;'
                f'margin:0.15rem;display:inline-block">{c}</span>'
                for c in ip_res.abuse_categories[:8]
            )
            st.markdown(cats_html, unsafe_allow_html=True)

        # Confidence factors
        section_label("Confidence Factors")
        conf_factors = [
            ("Source Agreement",   ip_res.source_agreement,   "#00c8ff"),
            ("Source Quality",     ip_res.source_quality,     "#ffd060"),
            ("Scanner Consensus",  ip_res.scanner_consensus,  "#8aaac8"),
            ("Provider Agreement", ip_res.provider_agreement, "#00c8ff"),
        ]
        st.markdown(
            confidence_panel(ip_res.overall_confidence, conf_factors),
            unsafe_allow_html=True,
        )

    # ── RIGHT: MITRE ATT&CK (v5 prominent) ───────────────────────────
    with col_right:
        if ip_res.mitre_tactics:
            mitre_section(ip_res.mitre_tactics)

        section_label("🏗 Infrastructure")
        infra_pairs = [
            ("Tor exit node", "YES" if ip_res.is_tor         else "No", ip_res.is_tor),
            ("Proxy",         "YES" if ip_res.is_vpn         else "No", ip_res.is_vpn),
            ("Bulletproof",   "YES" if ip_res.is_bulletproof else "No", ip_res.is_bulletproof),
            ("Datacenter",    "YES" if ip_res.is_datacenter  else "No", ip_res.is_datacenter),
        ]
        st.markdown(
            '<div class="card" style="padding:0.7rem 0.9rem">'
            + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.6rem 1rem">'
            + "".join(
                f'<div><div style="font-family:Space Mono,monospace;font-size:0.6rem;'
                f'letter-spacing:0.1em;color:#3a5a7a;text-transform:uppercase">{k}</div>'
                f'<div style="font-family:Space Mono,monospace;font-size:0.85rem;'
                f'font-weight:700;color:{"#ff2d55" if d else "#78d97a"}">{v}</div></div>'
                for k, v, d in infra_pairs
            )
            + "</div></div>",
            unsafe_allow_html=True,
        )

        if ip_res.apt_groups:
            section_label("🕵️ Related Threat Groups")
            apt_html = "".join(
                f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
                f'background:#0d1520;border:1px solid #2a3a4a;'
                f'color:#8aaac8;border-radius:4px;padding:0.22rem 0.55rem;'
                f'margin:0.2rem;display:inline-block">{g}</span>'
                for g in ip_res.apt_groups
            )
            st.markdown(apt_html, unsafe_allow_html=True)

    st.markdown("---")
    bf1, bf2 = st.columns([1, 1], gap="large")
    with bf1:
        section_label("🔍 Detection Flags")
        st.markdown(
            flag_list(ip_res.flags) if ip_res.flags
            else '<p style="color:#2a4a6a;font-size:0.68rem">No flags.</p>',
            unsafe_allow_html=True,
        )
        if ip_res.historical_ips:
            section_label("🌐 Hosted Domains (passive DNS)")
            for d in ip_res.historical_ips[:6]:
                st.code(d, language=None)
    with bf2:
        if ip_res.iocs:
            section_label("🔴 IOCs")
            st.markdown(ioc_chips(ip_res.iocs), unsafe_allow_html=True)
        for e in ip_res.errors:
            st.caption(f"⚠ {e}")

    # ── STIX 2.1 / TAXII Export for IP pipeline ───────────────────────
    try:
        from frontend.stix_panel import render_stix_export_panel
        level, _, _ = _classify(ip_res.score)
        render_stix_export_panel(
            target_url    = ip_raw,
            threat_level  = level,
            score         = ip_res.score,
            iocs          = ip_res.iocs,
            flags         = ip_res.flags,
            ip_address    = ip_raw,
            verdict_text  = f"IP Intelligence analysis. Country: {getattr(ip_res, 'country', 'Unknown')}. ASN: {getattr(ip_res, 'asn', 'Unknown')}.",
        )
    except Exception as _stix_err:
        st.caption(f"⚠ STIX export error: {_stix_err}")

    footer(timestamp, "IP INTELLIGENCE")


# ── Pipeline B (v9): Deep Forensic Engine Results ─────────────────────────────

def render_forensic_results(forensic_res, timestamp: str) -> None:
    """
    Render ForensicReport from forensic_engine.deep_forensic_analysis().

    Called only when a file was uploaded (not hash-only mode).
    forensic_res can be:
      - ForensicReport dataclass  → render full panel
      - dict with "error" key     → show error
      - None                      → file upload was skipped
    """
    st.markdown("---")
    st.markdown(
        '<p class="slabel">🔬 Deep Forensic Analysis</p>',
        unsafe_allow_html=True,
    )

    # ── Error / unavailable states ────────────────────────────────────
    if forensic_res is None:
        st.caption("Forensic analysis skipped (no file uploaded).")
        return

    if isinstance(forensic_res, dict):
        err = forensic_res.get("error", "Unknown error")
        st.warning(f"⚠️ Forensic engine error: {err}")
        return

    fr = forensic_res  # ForensicReport

    # ── Threat level colour map ───────────────────────────────────────
    _level_colours = {
        "CRITICAL": "#ff2d55",
        "HIGH":     "#ff9a3c",
        "MEDIUM":   "#ffd060",
        "LOW":      "#00ffb4",
        "SAFE":     "#4a8a6a",
        "UNKNOWN":  "#2a4060",
    }
    tl_colour = _level_colours.get(fr.threat_level, "#2a4060")

    # ── Summary banner ────────────────────────────────────────────────
    st.markdown(
        f'<div style="background:rgba({int(tl_colour[1:3],16)},'
        f'{int(tl_colour[3:5],16)},{int(tl_colour[5:7],16)},0.10);'
        f'border:1px solid {tl_colour}44;border-radius:8px;'
        f'padding:0.8rem 1.1rem;margin-bottom:0.8rem">'
        f'<span style="font-family:Space Mono,monospace;font-size:0.72rem;color:{tl_colour}">'
        f'FORENSIC VERDICT: {fr.final_verdict} &nbsp;·&nbsp; '
        f'THREAT: {fr.threat_level} &nbsp;·&nbsp; '
        f'RISK SCORE: {fr.risk_score}/100 &nbsp;·&nbsp; '
        f'CONFIDENCE: {fr.confidence}%</span><br>'
        f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;color:#4a6a8a">'
        f'{fr.executive_summary}</span></div>',
        unsafe_allow_html=True,
    )

    col_a, col_b = st.columns(2, gap="medium")

    with col_a:
        # File identity
        section_label("📄 File Identity")
        id_rows = [
            ("Type",      fr.file_type or "Unknown"),
            ("MIME",      fr.mime_type  or "—"),
            ("Size",      f"{fr.file_size:,} B"),
            ("SHA-256",   (fr.sha256 or "—")[:32] + "…"),
            ("MD5",       fr.md5  or "—"),
            ("SHA-1",     fr.sha1 or "—"),
        ]
        st.markdown(
            '<div class="card">' +
            "".join(kv_row(k, v, False) for k, v in id_rows) +
            "</div>",
            unsafe_allow_html=True,
        )

        # Structural flags
        section_label("🧬 Structural Findings")
        struct_items = []
        if fr.mime_mismatch:       struct_items.append("🚨 MIME/Extension mismatch — masquerading file")
        if fr.is_polyglot:         struct_items.append("🚨 POLYGLOT FILE — valid as two formats simultaneously")
        if fr.has_overlay_data:    struct_items.append(f"🚨 Overlay data: {fr.overlay_size:,} B after EOF marker")
        if fr.is_zip_bomb:         struct_items.append("💣 ZIP BOMB — extraction would exhaust system resources")
        if fr.has_macros:          struct_items.append("⚠️ VBA macros present")
        if fr.has_auto_exec:       struct_items.append("🚨 Auto-execute trigger (runs on open)")
        if fr.has_javascript:      struct_items.append("⚠️ JavaScript detected")
        if fr.has_shellcode:       struct_items.append("🚨 Shellcode pattern detected")
        if fr.has_powershell:      struct_items.append("🚨 PowerShell execution pattern")
        if fr.has_embedded_files:  struct_items.append("⚠️ Embedded files / OLE objects")
        if fr.timestamp_anomaly:   struct_items.append("⚠️ Timestamp anomaly (stomping/manipulation)")
        if fr.has_dga_pattern:     struct_items.append("🚨 DGA pattern — algorithmically generated C2 domains")
        if fr.environment_keyed:   struct_items.append("⚠️ Environment keying (sandbox evasion)")
        if fr.is_dormant:          struct_items.append("ℹ️ Payload dormant — conditional activation")

        if struct_items:
            st.markdown(flag_list(struct_items), unsafe_allow_html=True)
        else:
            st.caption("No structural anomalies detected.")

    with col_b:
        # Evasion techniques
        if fr.evasion_techniques:
            section_label("🥷 Evasion Techniques")
            st.markdown(flag_list(fr.evasion_techniques), unsafe_allow_html=True)

        # Network indicators
        if fr.extracted_domains or fr.extracted_ips or fr.extracted_urls:
            section_label("🌐 Extracted Network Indicators")
            if fr.extracted_domains:
                st.caption(f"Domains ({len(fr.extracted_domains)}): " +
                           ", ".join(fr.extracted_domains[:8]))
            if fr.extracted_ips:
                st.caption(f"IPs ({len(fr.extracted_ips)}): " +
                           ", ".join(fr.extracted_ips[:5]))
            if fr.extracted_urls:
                for url in fr.extracted_urls[:4]:
                    st.code(url[:120], language=None)

        # AI NLP findings
        if fr.nlp_intent_label != "UNKNOWN" or fr.nlp_summary:
            section_label("🤖 AI NLP Analysis")
            nlp_colour = {"MALICIOUS": "#ff2d55", "SUSPICIOUS": "#ffd060", "BENIGN": "#00ffb4"}.get(
                fr.nlp_intent_label, "#4a6a8a"
            )
            st.markdown(
                f'<div class="card">'
                f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                f'color:{nlp_colour};margin-bottom:0.4rem">Intent: {fr.nlp_intent_label}'
                f'{" · Family: " + fr.nlp_malware_family if fr.nlp_malware_family else ""}'
                f'</div>'
                f'<div style="font-family:Space Mono,monospace;font-size:0.63rem;color:#4a6a8a">'
                f'{fr.nlp_summary or fr.nlp_execution_flow or "—"}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # ── VT Engine divergence ──────────────────────────────────────────
    if fr.engine_divergence_reason:
        with st.expander("🔍 Engine Divergence Analysis", expanded=False):
            st.markdown(
                f'<div class="card" style="font-family:Space Mono,monospace;'
                f'font-size:0.65rem;color:#4a8aaa;white-space:pre-wrap">'
                f'{fr.engine_divergence_reason}</div>',
                unsafe_allow_html=True,
            )

    # ── Container discrepancy explanation ─────────────────────────────
    if fr.discrepancy_reason:
        with st.expander("💡 Why Clean Container ≠ Clean Hash?", expanded=False):
            st.markdown(
                f'<div class="card" style="font-family:Space Mono,monospace;'
                f'font-size:0.65rem;color:#4a8aaa;white-space:pre-wrap">'
                f'{fr.discrepancy_reason}</div>',
                unsafe_allow_html=True,
            )

    # ── Metadata anomalies ────────────────────────────────────────────
    if fr.metadata_anomalies:
        with st.expander(f"⚠️ Metadata Anomalies ({len(fr.metadata_anomalies)})", expanded=False):
            for ma in fr.metadata_anomalies:
                sev_colours = {
                    "CRITICAL": "#ff2d55", "HIGH": "#ff9a3c",
                    "MEDIUM": "#ffd060",   "LOW": "#00c8ff"
                }
                c = sev_colours.get(ma.severity, "#4a6a8a")
                st.markdown(
                    f'<div style="border-left:3px solid {c};padding:0.3rem 0.6rem;'
                    f'margin-bottom:0.4rem;font-family:Space Mono,monospace;font-size:0.63rem">'
                    f'<span style="color:{c}">[{ma.severity}]</span> '
                    f'<span style="color:#6a9aba">{ma.field}:</span> '
                    f'<span style="color:#4a8a6a">{ma.value}</span><br>'
                    f'<span style="color:#3a5a7a">{ma.description}</span></div>',
                    unsafe_allow_html=True,
                )

    # ── Forensic IOCs ─────────────────────────────────────────────────
    if fr.iocs:
        section_label("🔴 Forensic IOCs")
        st.markdown(ioc_chips(fr.iocs), unsafe_allow_html=True)

    # ── Forensic flags ────────────────────────────────────────────────
    if fr.flags:
        with st.expander(f"🚩 All Forensic Flags ({len(fr.flags)})", expanded=False):
            st.markdown(flag_list(fr.flags), unsafe_allow_html=True)

    # ── Errors / warnings ────────────────────────────────────────────
    for e in fr.errors:
        st.caption(f"⚠️ {e}")

    footer(timestamp, "FORENSIC ENGINE v9")
