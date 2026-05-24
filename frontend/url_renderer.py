"""
frontend/url_renderer.py
------------------------
Renders the full URL/Domain/IP analysis results page.
"""

from __future__ import annotations

import streamlit as st
from datetime import datetime, timezone

from frontend.components import (
    render_mitre_heatmap,
    make_gauge, threat_banner, engine_score_bars, flag_list, ioc_chips,
    signal_row, cert_table, kv_row, confidence_panel,
    source_badge, override_banner, verdict_box, mitigation_list,
    engine_card, section_label, footer,
)


def render_url_results(
    target:      str,
    verdict,           # Verdict
    sig,               # BehavioralSignals
    extra_flags: list[str],
    h_res,             # HeuristicsResult
    w_res,             # WhoisResult
    ai_res,            # AIAnalysisResult
    rep_res,           # ReputationResult
    dec_res,           # DeceptionResult
    sb_res,            # SandboxResult
    ssl_res,           # SSLResult
    pdns_res,          # PassiveDNSResult
    all_iocs:    list[str],
    duration:    float,
    timestamp:   str,
    legitimacy   = None,   # DomainLegitimacyResult | None
    urlhaus_res  = None,   # URLhausResult | None
    otx_res      = None,   # OTXResult | None
) -> None:

    st.markdown("---")

    # ── Override & rule banners ───────────────────────────────────────
    if sig.infrastructure_override:
        st.markdown(
            override_banner(
                "INFRASTRUCTURE OVERRIDE ACTIVE — VirusTotal returned >8 malicious "
                "detections. Score locked to CRITICAL regardless of other engines."
            ),
            unsafe_allow_html=True,
        )

    # ── AI Legitimacy Banner ──────────────────────────────────────────
    # FIX v7: Only show GREEN legitimacy banner if:
    #   1. AI ran and declared legitimate
    #   2. No URLhaus malware IOCs in the IOC list
    #   3. No OTX threat pulse IOCs
    # This prevents the green banner appearing alongside URLHAUS_OFFLINE/ONLINE IOCs.
    _has_malware_iocs = any(
        ioc.startswith(("URLHAUS_", "OTX_PULSE", "ABUSIVE_IP"))
        for ioc in (all_iocs or [])
    )
    if legitimacy is not None and legitimacy.ran and legitimacy.is_legitimate and not _has_malware_iocs:
        import html as _html
        org      = _html.escape(legitimacy.organization or "a legitimate organization")
        reason   = _html.escape(legitimacy.reasoning or "")
        conf_clr = {"high": "#00ffb4", "medium": "#78d97a"}.get(legitimacy.confidence, "#ffd060")
        st.markdown(
            f'<div style="background:rgba(0,255,180,0.06);border:1px solid {conf_clr}55;'
            f'border-radius:8px;padding:0.65rem 1rem;margin-bottom:0.6rem">'
            f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;color:{conf_clr}">'
            f'✅ AI LEGITIMACY — {legitimacy.confidence.upper()} CONFIDENCE</span>'
            f'<div style="font-family:Space Mono,monospace;font-size:0.72rem;color:#c0d4e8;margin-top:0.3rem">'
            f'{org} — {reason}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    rule_badges = ""
    for rule, pts in sig.score_adjustments:
        prefix = "+" if pts > 0 else ""
        rule_badges += f'<span class="rule-badge">{prefix}{pts} {rule}</span>'
    if rule_badges:
        st.markdown(f"<div style='margin-bottom:0.5rem'>{rule_badges}</div>", unsafe_allow_html=True)

    # ── Row 1: Gauge + Score Breakdown ───────────────────────────────
    col_g, col_r = st.columns([1, 2], gap="large")

    with col_g:
        st.markdown(threat_banner(verdict.threat_level, verdict.score, verdict.colour, verdict.bg_colour), unsafe_allow_html=True)
        st.plotly_chart(make_gauge(verdict.score, verdict.colour), use_container_width=True, config={"displayModeBar": False})
        st.caption(f"⏱ {duration:.1f}s  ·  {timestamp}  ·  Confidence: {sig.overall_confidence}%")

        # Confidence panel
        conf_factors = [
            ("VT Agreement",  min(rep_res.vt_malicious * 10, 100), "#ff2d55"),
            ("AbuseIPDB",     rep_res.abuse_confidence,            "#ff9a3c"),
            ("Engine Corr.",  min(sig.overall_confidence, 100),    "#00c8ff"),
        ]
        st.markdown(confidence_panel(sig.overall_confidence, conf_factors), unsafe_allow_html=True)

    with col_r:
        section_label("Engine Score Breakdown")
        bars = [
            ("URL Heuristics",  h_res.score,    30,  "#00c8ff"),
            ("WHOIS / Age",     w_res.score,    40,  "#ff9a3c"),
            ("AI NLP",          ai_res.score,   30,  "#c47aff"),
            ("Infrastructure",  rep_res.score,  40,  "#ff2d55"),
            ("Tech Deception",  dec_res.score,  30,  "#ffd060"),
            ("Sandbox",         sb_res.score,   30,  "#00ffb4"),
            ("SSL/TLS",         ssl_res.score,  50,  "#00c8ff"),
            ("Passive DNS/IP",  pdns_res.score, 30,  "#c47aff"),
        ]
        st.markdown(engine_score_bars(bars), unsafe_allow_html=True)

        section_label("🔴 Indicators of Compromise")
        st.markdown(ioc_chips(all_iocs), unsafe_allow_html=True)

        # Source summary badges (community + relations included)
        section_label("Source Intelligence")

        # VT Engines
        vt_color = "#ff2d55" if rep_res.vt_malicious > 3 else ("#ffd060" if rep_res.vt_malicious > 0 else "#00ffb4")
        st.markdown(source_badge(
            "VT Engines",
            f"{rep_res.vt_malicious}/{rep_res.vt_total_engines} malicious",
            vt_color,
        ), unsafe_allow_html=True)

        # VT Community Votes
        cv_mal = rep_res.vt_community_malicious_votes
        cv_harm = rep_res.vt_community_harmless_votes
        cv_color = "#ff2d55" if cv_mal >= 3 else ("#ffd060" if cv_mal >= 1 else "#78d97a")
        cv_val = f"{cv_mal} malicious · {cv_harm} harmless votes"
        st.markdown(source_badge("VT Community Votes", cv_val, cv_color), unsafe_allow_html=True)

        # VT Community Comments
        cc_cnt = rep_res.vt_community_malicious_comments
        cc_color = "#ff2d55" if cc_cnt >= 2 else ("#ffd060" if cc_cnt >= 1 else "#4a6a8a")
        cc_val = f"{cc_cnt} malicious comment(s)" if cc_cnt else "No malicious comments"
        st.markdown(source_badge("VT Comments", cc_val, cc_color), unsafe_allow_html=True)

        # VT Relations
        rel_files = rep_res.vt_malicious_files_related
        rel_color = "#ff2d55" if rel_files >= 2 else ("#ffd060" if rel_files >= 1 else "#4a6a8a")
        rel_val = f"{rel_files} malicious related file(s)" if rel_files else "No malicious related files"
        st.markdown(source_badge("VT Relations", rel_val, rel_color), unsafe_allow_html=True)

        # AbuseIPDB
        ab_val   = f"{rep_res.abuse_confidence}% conf · {rep_res.abuse_reports} reports"
        ab_color = "#ff2d55" if rep_res.abuse_confidence >= 65 else ("#ffd060" if rep_res.abuse_confidence >= 30 else "#78d97a")
        st.markdown(source_badge("AbuseIPDB", ab_val, ab_color), unsafe_allow_html=True)

        # SPF / DMARC
        st.markdown(source_badge("SPF/DMARC",
            f"SPF {'✅' if rep_res.spf_valid else '❌'}  ·  DMARC {'✅' if rep_res.dmarc_found else '❌'}",
            "#00ffb4" if (rep_res.spf_valid and rep_res.dmarc_found) else "#ff9a3c",
        ), unsafe_allow_html=True)

    st.markdown("---")

    # ── Row 2: Verdict one-liner + AI Assessment + Behavioral Signals ─
    col_ai, col_sig = st.columns([2, 1], gap="large")

    with col_ai:
        st.markdown(
            f'<div class="ai-box">'
            f'<span style="color:#4a6a8a;font-size:0.6rem;letter-spacing:0.15em">VERDICT ONE-LINE</span>'
            f'<br>{verdict.one_line}'
            f'</div>',
            unsafe_allow_html=True,
        )
        if ai_res.summary and not ai_res.error:
            import html as _h_url
            section_label("🤖 AI Assessment (Ollama)")
            st.markdown(f'<div class="ai-box">{_h_url.escape(str(ai_res.summary))}</div>', unsafe_allow_html=True)
        section_label("📋 Analyst's Summary")
        st.markdown(verdict_box(verdict.full_verdict, verdict.colour), unsafe_allow_html=True)

    with col_sig:
        section_label("🎯 Behavioral Signals")
        signal_row([
            ("Urgency",     sig.urgency,           "#ff2d55", "🔴"),
            ("Financial",   sig.financial_threat,   "#ff9a3c", "💰"),
            ("Manipulate",  sig.manipulation,       "#c47aff", "🧠"),
        ])
        signal_row([
            ("Cred Harvest", sig.credential_harvest, "#ff2d55", "🔑"),
            ("Fake Login",   sig.fake_login_page,    "#ffd060", "🎭"),
            ("Malware",      sig.malware_dropper,    "#ff6b35", "☠️"),
        ])
        signal_row([
            ("Crypto",      sig.crypto_drainer,     "#00c8ff", "💎"),
            ("Tor Node",    sig.tor_exit_node,      "#ff9a3c", "🧅"),
            ("VPN/Proxy",   sig.vpn_detected,       "#c47aff", "🛡"),
        ])
        signal_row([
            ("Free CA+Age", sig.free_ca_young_domain, "#ffd060", "🔓"),
            ("Bad Cert",    sig.cert_invalid,          "#ff2d55", "⛔"),
            ("Brand Squat", sig.brand_squatting,       "#ff9a3c", "⚠"),
        ])
        signal_row([
            ("Infra OVR",   sig.infrastructure_override, "#ff2d55", "🚨"),
            ("Sub Trap",    sig.subdomain_trap_active,   "#ffd060", "🌐"),
            ("High Abuse",  sig.high_abuse_ip,           "#ff6b35", "🔥"),
        ])

    st.markdown("---")

    # ── Row 3: Detection Signals by Engine (3-col grid) ───────────────
    section_label("🔍 Detection Signals by Engine")
    c1, c2, c3 = st.columns(3, gap="medium")

    with c1:
        engine_card("🔵 URL Heuristics", h_res.flags)
        engine_card(
            "🟠 WHOIS / Domain Age", w_res.flags,
            caption=(
                f"Created: {w_res.creation_date or '?'}  ·  "
                f"Age: {w_res.domain_age_days or '?'}d  ·  "
                f"{w_res.registrar or ''}"
            ),
        )

    with c2:
        engine_card(
            "🟣 AI NLP Engine", ai_res.flags,
            caption=(f"⚠ {ai_res.error}" if ai_res.error else ""),
        )
        engine_card(
            "🔴 Infrastructure", rep_res.flags,
            caption=(
                f"IP: {rep_res.ip_address or '?'}  ·  "
                f"VT: {rep_res.vt_malicious}/{rep_res.vt_total_engines}  ·  "
                f"Abuse: {rep_res.abuse_confidence}%"
            ),
        )
        if extra_flags:
            engine_card("⚡ Override Rules", extra_flags)

    with c3:
        engine_card(
            "🟡 Technical Deception", dec_res.flags,
            caption=(
                f"Target: {dec_res.typosquat_target}  dist={dec_res.typosquat_distance}"
                if dec_res.typosquat_target else ""
            ),
        )
        engine_card(
            "🟢 Sandbox", sb_res.flags,
            caption=(
                f"Title: {(sb_res.page_title or '')[:50]}  "
                f"Redirects: {sb_res.redirect_count}"
            ),
        )
        # SSL card
        st.markdown('<div class="card"><b>🔒 SSL / TLS Certificate</b><br>', unsafe_allow_html=True)
        ssl_rows = [
            ("Issuer",      ssl_res.issuer_org or ssl_res.issuer_cn or "Unknown", False),
            ("Subject CN",  ssl_res.subject_cn or "—",                            False),
            ("Valid Until", ssl_res.not_after.strftime("%Y-%m-%d") if ssl_res.not_after else "—", False),
            ("Days Left",   str(ssl_res.days_remaining) if ssl_res.days_remaining is not None else "—", False),
            ("Free CA",     "YES ⚠" if ssl_res.is_free_ca else "No",             ssl_res.is_free_ca),
            ("Self-Signed", "YES 🚨" if ssl_res.is_self_signed else "No",        ssl_res.is_self_signed),
        ]
        st.markdown(cert_table(ssl_rows), unsafe_allow_html=True)
        st.markdown(flag_list(ssl_res.flags), unsafe_allow_html=True)
        for e in ssl_res.errors:
            st.caption(f"⚠ {e}")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")

    # ── Row 4: MITRE ATT&CK (v5 — full-width prominent section) ──────
    if hasattr(pdns_res, "mitre_tactics") and pdns_res.mitre_tactics:
        render_mitre_heatmap(pdns_res.mitre_tactics, title="⚔️ MITRE ATT&CK — Passive DNS")
        st.markdown("---")

    # ── Row 5: DNS Intelligence ───────────────────────────────────────
    if any([rep_res.a_records, rep_res.ns_records, rep_res.mx_records]):
        section_label("🌐 DNS Intelligence")
        dc1, dc2, dc3, dc4 = st.columns(4, gap="medium")
        with dc1:
            st.markdown("**A Records**")
            for r in rep_res.a_records[:4]:
                st.code(r, language=None)
        with dc2:
            st.markdown("**NS Records**")
            for r in rep_res.ns_records[:4]:
                st.code(r, language=None)
        with dc3:
            st.markdown("**MX Records**")
            for r in rep_res.mx_records[:4]:
                st.code(r, language=None)
        with dc4:
            st.markdown("**Email Auth**")
            st.markdown(f"SPF   {'✅' if rep_res.spf_valid   else '❌'}")
            st.markdown(f"DMARC {'✅' if rep_res.dmarc_found else '❌'}")
        st.markdown("---")

    # ── Row 6: Final Verdict + Mitigation ────────────────────────────
    vc1, vc2 = st.columns([1, 1], gap="large")
    with vc1:
        section_label("⚖️ Final Verdict & Logic")
        st.markdown(verdict_box(verdict.full_verdict, verdict.colour), unsafe_allow_html=True)
    with vc2:
        section_label("🛡 Mitigation Steps")
        st.markdown(mitigation_list(verdict.mitigation), unsafe_allow_html=True)

    # ── Row 7: STIX 2.1 / TAXII Export ───────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    try:
        from frontend.stix_panel import render_stix_export_panel

        # Gather context for STIX export
        _malware_family = None
        _sha256 = None
        _md5 = None
        _threat_actors: list[str] = []
        _mitre_ids: list[str] = []
        _ip_address = getattr(rep_res, "ip_address", None)

        # Try to get urlhaus malware family (urlhaus_res now passed as parameter)
        if urlhaus_res is not None:
            if getattr(urlhaus_res, "signature", None):
                _malware_family = urlhaus_res.signature
            if getattr(urlhaus_res, "sha256_hash", None):
                _sha256 = urlhaus_res.sha256_hash
            if getattr(urlhaus_res, "md5_hash", None):
                _md5 = urlhaus_res.md5_hash

        # OTX adversaries and MITRE IDs (otx_res now passed as parameter)
        if otx_res is not None:
            _threat_actors = getattr(otx_res, "adversaries", [])[:3]
            _mitre_ids = getattr(otx_res, "attack_ids", [])[:6]

        render_stix_export_panel(
            target_url=target,
            threat_level=verdict.threat_level,
            score=verdict.score,
            iocs=all_iocs,
            flags=extra_flags,
            malware_family=_malware_family,
            threat_actors=_threat_actors,
            ip_address=_ip_address,
            verdict_text=verdict.full_verdict,
            sha256_hash=_sha256,
            md5_hash=_md5,
            mitre_ids=_mitre_ids,
        )
    except Exception as _stix_err:
        st.caption(f"⚠ STIX export error: {_stix_err}")

    footer(timestamp, "10-ENGINE · URL/DOMAIN")
