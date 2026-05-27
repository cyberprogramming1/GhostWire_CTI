"""
frontend/ha_renderer.py
-----------------------
Hybrid Analysis Sandbox Results Renderer — GhostWire CTI v6
"""

from __future__ import annotations

import html as _html
import streamlit as st

from frontend.components import (
    render_mitre_heatmap,
    make_gauge, threat_banner, flag_list, ioc_chips,
    section_label, engine_card, kv_row, source_badge, footer, override_banner,
)
from backend.verdict import _classify


# ── Verdict → GhostWire colour mapping ───────────────────────────────────────

_HA_COLOURS = {
    "malicious":           "#ff2d55",
    "suspicious":          "#ffd060",
    "no specific threat":  "#78d97a",
    "whitelisted":         "#00ffb4",
    "no verdict":          "#4a6a8a",
}

_HA_BG = {
    "malicious":           "rgba(255,45,85,0.08)",
    "suspicious":          "rgba(255,208,96,0.06)",
    "no specific threat":  "rgba(120,217,122,0.06)",
    "whitelisted":         "rgba(0,255,180,0.06)",
    "no verdict":          "rgba(74,106,138,0.06)",
}


def _verdict_colour(verdict: str) -> tuple[str, str]:
    v = verdict.lower()
    return _HA_COLOURS.get(v, "#4a6a8a"), _HA_BG.get(v, "rgba(74,106,138,0.06)")


def _av_bar(engine: str, result_str: str) -> str:
    """Render one AV detection row."""
    safe_e = _html.escape(str(engine))
    safe_r = _html.escape(str(result_str))
    return (
        f'<div style="display:flex;justify-content:space-between;'
        f'padding:0.22rem 0;border-bottom:1px solid rgba(255,255,255,0.04);'
        f'font-family:Space Mono,monospace;font-size:0.62rem;">'
        f'<span style="color:#4a6a8a">{safe_e}</span>'
        f'<span style="color:#ff6b8a">{safe_r}</span>'
        f'</div>'
    )


def _network_chip(label: str, value: str, colour: str = "#00c8ff") -> str:
    safe_v = _html.escape(str(value)[:80])
    return (
        f'<span style="display:inline-block;background:rgba(0,200,255,0.07);'
        f'border:1px solid {colour}33;color:{colour};'
        f'font-family:Space Mono,monospace;font-size:0.6rem;'
        f'padding:0.15rem 0.4rem;border-radius:4px;margin:0.12rem;'
        f'word-break:break-all;">'
        f'<span style="opacity:0.5">{_html.escape(label)}: </span>{safe_v}'
        f'</span>'
    )


def _status_badge(status: str, submitted: bool, completed: bool) -> str:
    if not submitted:
        return '<span style="color:#4a6a8a;font-family:Space Mono,monospace;font-size:0.65rem">⏳ Not submitted</span>'
    if status == "running":
        return '<span style="color:#ffd060;font-family:Space Mono,monospace;font-size:0.65rem">⚙️ Sandbox running…</span>'
    if status == "timeout":
        return '<span style="color:#ff9a3c;font-family:Space Mono,monospace;font-size:0.65rem">⏱ Timed out — check HA portal</span>'
    if status == "error":
        return '<span style="color:#ff2d55;font-family:Space Mono,monospace;font-size:0.65rem">❌ Sandbox error</span>'
    if completed:
        return '<span style="color:#00ffb4;font-family:Space Mono,monospace;font-size:0.65rem">✅ Report complete</span>'
    return '<span style="color:#4a6a8a;font-family:Space Mono,monospace;font-size:0.65rem">⏳ Pending</span>'


def _mitre_from_ha(mitre_list: list[dict]) -> list[tuple[str, str, str]]:
    """Convert HA mitre_attcks list → format expected by render_mitre_heatmap()."""
    out = []
    seen = set()
    for m in mitre_list:
        tac  = str(m.get("tactic") or "")
        tech = str(m.get("technique") or "")
        name = str(m.get("name") or tech)
        key  = f"{tac}-{tech}"
        if key not in seen and (tac or tech):
            seen.add(key)
            out.append((tac, tech, name))
    return out[:30]


# ── Main render function ──────────────────────────────────────────────────────

def render_ha_results(
    ha_res,          # HAResult
    input_type: str, # "url" | "file" | "hash" | "domain" | "ip"
    target:     str,
    timestamp:  str,
    ollama_model: str = "phi3:mini",
    run_ai:      bool = True,   # FIX v8.1: skip Ollama when AI disabled
) -> None:
    """
    Render Hybrid Analysis sandbox results in GhostWire style.
    Called from app.py after sandbox analysis completes.
    """
    st.markdown("---")

    colour, bg_colour = _verdict_colour(ha_res.verdict)

    # ── Errors / warnings at top ──────────────────────────────────────
    # v6 FIX: Differentiate between input types for accurate status messages.
    # - URL/File: "submitted" means job was accepted; poll results come later.
    # - Hash/Domain/IP: these are lookups — "submitted=False" is normal if
    #   the sample wasn't found; it does NOT mean "initialising".
    # Filter out transient 404 / "resource not found" messages only for URL/File.
    _is_lookup_type = input_type in ("hash", "domain", "ip")
    _display_errors = [
        e for e in ha_res.errors
        if "404" not in e and "resource not found" not in e.lower()
    ]

    if _display_errors:
        for err in _display_errors:
            st.error(f"❌ {err}")

    # Show informational flags first (e.g. "No HA results for this IP")
    if not ha_res.submitted and ha_res.flags:
        for flag in ha_res.flags:
            st.info(flag)

    # For URL/File: submitted=True means job accepted, even if not completed yet.
    # For Hash/IP/Domain: submitted=False + completed=True means "looked up, not found".
    if not ha_res.submitted and not ha_res.completed:
        if not _display_errors:
            if _is_lookup_type:
                # Lookup type with no results and no errors = not in database
                st.info(
                    f"ℹ️ No Hybrid Analysis records found for this {input_type.upper()}. "
                    "The sample may not have been analyzed before, or the database "
                    "does not contain an entry for this indicator."
                )
            else:
                # URL/File submission failed before job_id was assigned.
                # Most common cause: HA free account "Restricted" auth level
                # does not support full URL/File sandbox detonation.
                st.warning(
                    "⚠️ Hybrid Analysis sandbox submission did not return a Job ID.\n\n"
                    "**Most likely cause:** Your HA account has **Restricted** auth level "
                    "which does not support full URL sandbox detonation.\n\n"
                    "**What to do:**\n"
                    "• **Hash tab** → paste a known file hash to look up existing HA reports\n"
                    "• **File tab** → upload a file directly (file detonation may work)\n"
                    "• Verify at: hybrid-analysis.com → Profile → API Key → Auth level\n"
                    "• If rate limited: wait 1 minute and retry (free tier: 5/hour)"
                )
        return

    # completed=True but submitted=False (domain/IP with aggregate results)
    if not ha_res.submitted and ha_res.completed:
        # Falls through to render aggregate results normally
        pass

    # ── CRITICAL banner if malicious ──────────────────────────────────
    if ha_res.verdict == "malicious":
        st.markdown(
            override_banner(
                f"HYBRID ANALYSIS CONFIRMED MALICIOUS — "
                f"Threat Score: {ha_res.threat_score or '—'}/100 · "
                f"AV Detection: {ha_res.av_detect}% · "
                f"Family: {ha_res.vx_family or 'Unknown'}"
            ),
            unsafe_allow_html=True,
        )

    # ── Row 1: Gauge + Meta ───────────────────────────────────────────
    col_gauge, col_meta = st.columns([1, 2], gap="large")

    with col_gauge:
        st.markdown(
            threat_banner(ha_res.verdict.upper(), ha_res.verdict_score, colour, bg_colour),
            unsafe_allow_html=True,
        )
        st.plotly_chart(
            make_gauge(ha_res.verdict_score, colour),
            use_container_width=True,
            config={"displayModeBar": False},
        )
        st.markdown(
            _status_badge(ha_res.status, ha_res.submitted, ha_res.completed),
            unsafe_allow_html=True,
        )
        st.caption(f"🧪 {ha_res.environment}  ·  {timestamp}")

    with col_meta:
        section_label("Submission Intelligence")

        meta_items = [
            ("Input Type",    input_type.upper(),                              False),
            ("Target",        str(target)[:80],                                False),
            ("Environment",   ha_res.environment,                              False),
            ("SHA-256",       (ha_res.sha256 or "—")[:32] + ("…" if ha_res.sha256 and len(ha_res.sha256) > 32 else ""), False),
            ("Job ID",        (ha_res.job_id or "—")[:24],                    False),
            ("Verdict",       ha_res.verdict.upper(),                          ha_res.verdict == "malicious"),
            ("HA Threat Score", f"{ha_res.threat_score}/100" if ha_res.threat_score is not None else "—", ha_res.threat_score is not None and ha_res.threat_score >= 70),
            ("AV Detection",  f"{ha_res.av_detect}%",                         ha_res.av_detect >= 30),
            ("Malware Family", ha_res.vx_family or "None identified",         bool(ha_res.vx_family)),
            ("Analysis Time", ha_res.analysis_start or "—",                   False),
        ]

        st.markdown(
            '<div class="card">' +
            "".join(kv_row(k, v, d) for k, v, d in meta_items) +
            '</div>',
            unsafe_allow_html=True,
        )

        if ha_res.submit_url:
            st.markdown(
                f'<a href="{_html.escape(ha_res.submit_url) if ha_res.submit_url and ha_res.submit_url.startswith(("http://", "https://")) else "#"}" target="_blank" '
                f'style="font-family:Space Mono,monospace;font-size:0.65rem;'
                f'color:#00c8ff;text-decoration:none;">'
                f'🔗 View full report on Hybrid Analysis ↗</a>',
                unsafe_allow_html=True,
            )

        # Source badges
        section_label("Detection Summary")
        av_colour = "#ff2d55" if ha_res.av_detect >= 50 else (
            "#ffd060" if ha_res.av_detect >= 20 else "#78d97a"
        )
        st.markdown(source_badge("AV Detection Rate", f"{ha_res.av_detect}%", av_colour), unsafe_allow_html=True)
        st.markdown(source_badge("Behavioral Signatures", f"{len(ha_res.signatures)}", "#c47aff" if ha_res.signatures else "#4a6a8a"), unsafe_allow_html=True)
        st.markdown(source_badge("Network Contacts", f"{len(ha_res.contacted_hosts)}", "#ff9a3c" if ha_res.contacted_hosts else "#4a6a8a"), unsafe_allow_html=True)
        st.markdown(source_badge("MITRE Techniques", f"{len(ha_res.mitre_attcks)}", "#00c8ff" if ha_res.mitre_attcks else "#4a6a8a"), unsafe_allow_html=True)
        st.markdown(source_badge("Compromised Hosts", f"{len(ha_res.compromised_hosts)}", "#ff2d55" if ha_res.compromised_hosts else "#4a6a8a"), unsafe_allow_html=True)

    st.markdown("---")

    # ── Row 2: Network IOCs ───────────────────────────────────────────
    if any([ha_res.contacted_hosts, ha_res.dns_requests,
            ha_res.http_requests, ha_res.compromised_hosts]):

        section_label("🌐 Network Activity & IOCs")
        nc1, nc2 = st.columns(2, gap="medium")

        with nc1:
            if ha_res.contacted_hosts:
                st.markdown("**Contacted Hosts / IPs**")
                chips = "".join(
                    _network_chip("HOST", h, "#ff9a3c")
                    for h in ha_res.contacted_hosts[:15]
                )
                st.markdown(f'<div style="margin-bottom:0.8rem">{chips}</div>', unsafe_allow_html=True)

            if ha_res.dns_requests:
                st.markdown("**DNS Requests**")
                chips = "".join(
                    _network_chip("DNS", d, "#00c8ff")
                    for d in ha_res.dns_requests[:15]
                )
                st.markdown(f'<div style="margin-bottom:0.8rem">{chips}</div>', unsafe_allow_html=True)

        with nc2:
            if ha_res.http_requests:
                st.markdown("**HTTP Requests**")
                chips = "".join(
                    _network_chip("URL", u, "#c47aff")
                    for u in ha_res.http_requests[:10]
                )
                st.markdown(f'<div style="margin-bottom:0.8rem">{chips}</div>', unsafe_allow_html=True)

            if ha_res.compromised_hosts:
                st.markdown("**⚠️ Compromised Hosts**")
                chips = "".join(
                    _network_chip("C2", h, "#ff2d55")
                    for h in ha_res.compromised_hosts[:10]
                )
                st.markdown(f'<div style="margin-bottom:0.8rem">{chips}</div>', unsafe_allow_html=True)

        st.markdown("---")

    # ── Row 3: Behavioral Analysis ────────────────────────────────────
    section_label("🔬 Behavioral Analysis")
    bc1, bc2, bc3 = st.columns(3, gap="medium")

    with bc1:
        engine_card(
            "⚡ Behavioral Signatures",
            ha_res.signatures[:15] if ha_res.signatures else ["No signatures matched"],
        )
        if ha_res.processes:
            engine_card(
                "⚙️ Spawned Processes",
                ha_res.processes[:10],
            )

    with bc2:
        if ha_res.registry_keys:
            engine_card(
                "🗝️ Registry Activity",
                ha_res.registry_keys[:10],
            )
        if ha_res.mutexes:
            engine_card(
                "🔒 Mutexes",
                ha_res.mutexes[:10],
            )
        if not ha_res.registry_keys and not ha_res.mutexes:
            engine_card("🗝️ Registry / Mutexes", ["No activity recorded"])

    with bc3:
        if ha_res.extracted_files:
            engine_card(
                "📁 Extracted / Dropped Files",
                ha_res.extracted_files[:10],
            )
        engine_card(
            "🏷️ Tags",
            ha_res.tags[:10] if ha_res.tags else ["No tags assigned"],
        )

    st.markdown("---")

    # ── Row 4: MITRE ATT&CK ───────────────────────────────────────────
    if ha_res.mitre_attcks:
        mitre_tuples = _mitre_from_ha(ha_res.mitre_attcks)
        if mitre_tuples:
            render_mitre_heatmap(mitre_tuples, title="⚔️ MITRE ATT&CK — Hybrid Analysis")
            st.markdown("---")

    # ── Row 5: AV Detection Breakdown ────────────────────────────────
    if ha_res.av_detections:
        section_label(f"🛡 AV Detections ({len(ha_res.av_detections)} engines)")
        av_col1, av_col2 = st.columns(2, gap="medium")
        mid = len(ha_res.av_detections) // 2 + 1

        with av_col1:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            for det in ha_res.av_detections[:mid]:
                st.markdown(_av_bar(det["engine"], det["result"]), unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with av_col2:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            for det in ha_res.av_detections[mid:]:
                st.markdown(_av_bar(det["engine"], det["result"]), unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("---")

    # ── Row 6: HA Flags + IOC chips ──────────────────────────────────
    fc1, fc2 = st.columns([1, 1], gap="large")

    with fc1:
        section_label("🔍 Analysis Flags")
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown(flag_list(ha_res.flags), unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with fc2:
        section_label("🔴 Indicators of Compromise")
        st.markdown(ioc_chips(ha_res.iocs), unsafe_allow_html=True)

    st.markdown("---")

    # ── Row 7: AI Threat Intelligence Summary ────────────────────────
    # FIX v8.1: Only call Ollama when AI is enabled in sidebar
    if run_ai:
        render_ha_ai_summary(ha_res, ollama_model)

    footer(timestamp, "HYBRID ANALYSIS SANDBOX")


def render_ha_ai_summary(ha_res, ollama_model: str = "phi3:mini") -> None:
    """
    Render AI-generated threat intelligence summary for sandbox results.
    Uses local Ollama — no data sent to external AI APIs.
    """
    from backend.ai_analyzer import generate_ha_ai_summary

    section_label("🤖 AI Threat Intelligence Summary")

    with st.spinner("Generating AI threat narrative — analysing sandbox telemetry…"):
        ai_sum = generate_ha_ai_summary(ha_res, model=ollama_model)

    if ai_sum.error and not ai_sum.summary:
        st.warning(
            f"⚠️ AI summary unavailable: {ai_sum.error}. "
            "Ensure Ollama is running locally (`ollama serve`)."
        )
        return

    # Confidence badge colour
    conf_colour = {
        "high":   "#00ffb4",
        "medium": "#ffd060",
        "low":    "#4a6a8a",
    }.get(ai_sum.confidence, "#4a6a8a")

    st.markdown(
        f'<div style="background:rgba(0,255,180,0.04);border:1px solid rgba(0,255,180,0.15);'
        f'border-radius:10px;padding:1.2rem 1.5rem;margin-bottom:1rem;">'
        f'<div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem;">'
        f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
        f'background:{conf_colour}22;border:1px solid {conf_colour}55;'
        f'color:{conf_colour};padding:0.15rem 0.5rem;border-radius:4px;">'
        f'AI CONFIDENCE: {ai_sum.confidence.upper()}</span>'
        f'<span style="font-family:Space Mono,monospace;font-size:0.6rem;color:#2a4060;">'
        f'Powered by Ollama (local) · No data sent externally</span>'
        f'</div>'
        f'<p style="font-family:Inter,sans-serif;font-size:0.9rem;color:#c8d8e8;'
        f'line-height:1.6;margin:0 0 0.75rem 0;">{_html.escape(ai_sum.summary)}</p>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if ai_sum.threat_narrative:
        st.markdown(
            f'<div style="background:rgba(10,20,35,0.8);border:1px solid rgba(196,122,255,0.2);'
            f'border-radius:8px;padding:1rem 1.25rem;margin-bottom:1rem;">'
            f'<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
            f'color:#c47aff;margin:0 0 0.5rem 0;letter-spacing:0.08em;">THREAT NARRATIVE</p>'
            f'<p style="font-family:Inter,sans-serif;font-size:0.82rem;color:#a0b8cc;'
            f'line-height:1.65;margin:0;">{_html.escape(ai_sum.threat_narrative)}</p>'
            f'</div>',
            unsafe_allow_html=True,
        )

    if ai_sum.recommended_actions:
        section_label("🛡 Recommended Actions")
        st.markdown('<div class="card">', unsafe_allow_html=True)
        for i, action in enumerate(ai_sum.recommended_actions, 1):
            st.markdown(
                f'<div style="display:flex;align-items:flex-start;gap:0.6rem;'
                f'padding:0.3rem 0;border-bottom:1px solid rgba(255,255,255,0.04);">'
                f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
                f'color:#00ffb4;min-width:1.4rem;">{i:02d}.</span>'
                f'<span style="font-family:Inter,sans-serif;font-size:0.8rem;color:#a0b8cc;">'
                f'{_html.escape(action)}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
        st.markdown('</div>', unsafe_allow_html=True)
