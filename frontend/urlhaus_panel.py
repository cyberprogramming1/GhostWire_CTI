"""
frontend/urlhaus_panel.py
--------------------------
GhostWire CTI v6.1 — URLhaus UI Panel Renderer.
"""

from __future__ import annotations

import html as _html
import streamlit as st

from frontend.components import section_label, flag_list


# Threat → colour mapping for URL status badge
_STATUS_COLOURS = {
    "online":  ("#ff2d55", "rgba(255,45,85,0.15)"),
    "offline": ("#ffd060", "rgba(255,208,96,0.12)"),
    "unknown": ("#8aaac8", "rgba(138,170,200,0.08)"),
}

# Tags considered high-risk — highlighted in red
_HIGH_RISK_TAGS = {
    "exe", "dll", "bat", "ps1", "vbs", "js",
    "ransomware", "trojan", "botnet", "miner",
    "emotet", "qbot", "trickbot", "cobalt",
    "c2", "c&c", "rat", "stealer", "dropper",
}


def render_urlhaus_panel(urlhaus_res, mode: str = "url") -> None:
    """
    Render URLhaus threat intelligence panel.

    Parameters
    ----------
    urlhaus_res : URLhausResult
        Result object from backend.urlhaus_engine
    mode : str
        "url"  → pipeline_url  (URL + host context)
        "hash" → pipeline_hash (payload / hash context)
        "ip"   → pipeline_ip   (host/IP context)
    """
    # ── Section Header ─────────────────────────────────────────────────
    section_label("☣️ URLhaus Intelligence")

    # ── No data / error state ─────────────────────────────────────────
    if not urlhaus_res.available:
        errors = getattr(urlhaus_res, "errors", [])
        if errors:
            for e in errors:
                e_str = str(e).lower()
                if "rate_limit" in e_str:
                    st.markdown(
                        '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                        'color:#ffd060">⚠ URLhaus rate limit — add URLHAUS_API_KEY to .env '
                        'for higher limits (free at auth.abuse.ch)</div>',
                        unsafe_allow_html=True,
                    )
                elif "timeout" in e_str:
                    st.markdown(
                        '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                        'color:#ffd060">⚠ URLhaus request timed out — service may be slow, retry later</div>',
                        unsafe_allow_html=True,
                    )
                elif "invalid" in e_str or "rejected" in e_str:
                    st.markdown(
                        f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                        f'color:#ffd060">⚠ {_html.escape(str(e))}</div>',
                        unsafe_allow_html=True,
                    )
                elif "disabled" in e_str:
                    st.markdown(
                        '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                        'color:#2a4060">URLhaus: disabled for this scan</div>',
                        unsafe_allow_html=True,
                    )
                elif "json_decode" in e_str or "expecting value" in e_str:
                    st.markdown(
                        '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                        'color:#ffd060">⚠ URLhaus returned an unexpected response — '
                        'abuse.ch may be under maintenance. Retry in a moment.</div>',
                        unsafe_allow_html=True,
                    )
                elif "non_json" in e_str:
                    st.markdown(
                        '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                        'color:#ffd060">⚠ URLhaus returned a non-JSON response — '
                        'service may be temporarily unavailable.</div>',
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                        f'color:#ff5f87">⚠ URLhaus error: {_html.escape(str(e))}</div>',
                        unsafe_allow_html=True,
                    )
        else:
            # available=False with no errors = unexpected empty result
            st.markdown(
                '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                'color:#ff5f87">⚠ URLhaus: No response received — check network or API availability</div>',
                unsafe_allow_html=True,
            )
        # Still show flags if any (graceful degradation message)
        if getattr(urlhaus_res, "flags", []):
            st.markdown(flag_list(urlhaus_res.flags), unsafe_allow_html=True)
        return

    # ── URL / Domain mode ─────────────────────────────────────────────
    if mode == "url":
        col_a, col_b = st.columns([1, 1], gap="medium")

        with col_a:
            # URL Status badge
            if urlhaus_res.url_status:
                colour, bg = _STATUS_COLOURS.get(
                    urlhaus_res.url_status, ("#8aaac8", "rgba(138,170,200,0.08)")
                )
                st.markdown(
                    f'<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                    f'color:#00ffb4;letter-spacing:0.2em">URL STATUS</p>'
                    f'<span style="font-family:Space Mono,monospace;font-size:0.82rem;'
                    f'background:{bg};border:1px solid {colour};color:{colour};'
                    f'border-radius:4px;padding:0.25rem 0.75rem;display:inline-block">'
                    f'{_html.escape(urlhaus_res.url_status.upper())}</span>',
                    unsafe_allow_html=True,
                )

            # Threat type
            if urlhaus_res.threat:
                st.markdown(
                    f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                    f'color:#ffd060;margin-top:0.5rem">'
                    f'Threat: {_html.escape(str(urlhaus_res.threat))}</div>',
                    unsafe_allow_html=True,
                )

        with col_b:
            # Host malware URL count
            if urlhaus_res.urls_found > 0:
                count_col = "#ff2d55" if urlhaus_res.urls_found >= 5 else "#ffd060"
                st.markdown(
                    f'<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                    f'color:#00ffb4;letter-spacing:0.2em">HOST MALWARE URLs</p>'
                    f'<span style="font-family:Space Mono,monospace;font-size:1.4rem;'
                    f'font-weight:700;color:{count_col}">{urlhaus_res.urls_found}</span>'
                    f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
                    f'color:#4a6a8a"> malicious URLs on this host</span>',
                    unsafe_allow_html=True,
                )

    # ── Hash mode ─────────────────────────────────────────────────────
    elif mode == "hash":
        col_a, col_b = st.columns([1, 1], gap="medium")

        with col_a:
            if urlhaus_res.signature:
                st.markdown(
                    f'<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                    f'color:#ff2d55;letter-spacing:0.2em">MALWARE FAMILY</p>'
                    f'<span style="font-family:Space Mono,monospace;font-size:0.92rem;'
                    f'font-weight:700;color:#ff6b8a">'
                    f'{_html.escape(str(urlhaus_res.signature))}</span>',
                    unsafe_allow_html=True,
                )
            elif urlhaus_res.sha256_hash or urlhaus_res.md5_hash:
                st.markdown(
                    '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                    'color:#ffd060;letter-spacing:0.2em">HASH STATUS</p>'
                    '<span style="font-family:Space Mono,monospace;font-size:0.82rem;'
                    'background:rgba(255,45,85,0.15);border:1px solid #ff2d55;color:#ff6b8a;'
                    'border-radius:4px;padding:0.25rem 0.75rem;display:inline-block">'
                    '⚠ FOUND IN MALWARE DB</span>',
                    unsafe_allow_html=True,
                )
            if urlhaus_res.file_type:
                st.markdown(
                    f'<div style="font-family:Space Mono,monospace;font-size:0.65rem;'
                    f'color:#8aaac8;margin-top:0.3rem">'
                    f'File type: {_html.escape(str(urlhaus_res.file_type))}'
                    + (f' · {urlhaus_res.file_size} bytes' if urlhaus_res.file_size else "")
                    + '</div>',
                    unsafe_allow_html=True,
                )
            if urlhaus_res.virustotal:
                st.markdown(
                    f'<a href="{_html.escape(str(urlhaus_res.virustotal))}" target="_blank" '
                    f'style="font-family:Space Mono,monospace;font-size:0.65rem;color:#00b4ff">'
                    f'🔗 View on VirusTotal</a>',
                    unsafe_allow_html=True,
                )

        with col_b:
            # Score contribution badge — FIX v7: always show when hash found
            if urlhaus_res.score_contribution > 0:
                score_col = "#ff2d55" if urlhaus_res.score_contribution >= 20 else "#ffd060"
                st.markdown(
                    f'<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                    f'color:#00ffb4;letter-spacing:0.2em">URLHAUS SCORE</p>'
                    f'<span style="font-family:Space Mono,monospace;font-size:1.4rem;'
                    f'font-weight:700;color:{score_col}">+{urlhaus_res.score_contribution}</span>'
                    f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
                    f'color:#4a6a8a"> pts added to threat score</span>',
                    unsafe_allow_html=True,
                )
            if urlhaus_res.urls_found > 0:
                count_col = "#ff2d55" if urlhaus_res.urls_found >= 5 else "#ffd060"
                st.markdown(
                    f'<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                    f'color:#00ffb4;letter-spacing:0.2em">DELIVERY URLs</p>'
                    f'<span style="font-family:Space Mono,monospace;font-size:1.4rem;'
                    f'font-weight:700;color:{count_col}">{urlhaus_res.urls_found}</span>'
                    f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
                    f'color:#4a6a8a"> URLs distributed this payload</span>',
                    unsafe_allow_html=True,
                )

    # ── IP / Host mode ────────────────────────────────────────────────
    elif mode == "ip":
        if urlhaus_res.urls_found > 0:
            count_col = "#ff2d55" if urlhaus_res.urls_found >= 10 else "#ffd060"
            st.markdown(
                f'<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
                f'color:#00ffb4;letter-spacing:0.2em">MALWARE URLs ON THIS HOST</p>'
                f'<span style="font-family:Space Mono,monospace;font-size:1.6rem;'
                f'font-weight:700;color:{count_col}">{urlhaus_res.urls_found}</span>'
                f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
                f'color:#4a6a8a"> malicious URLs tracked by URLhaus</span>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
                'color:#4a6a8a">✅ URLhaus: No malware URLs associated with this host</div>',
                unsafe_allow_html=True,
            )

    # ── Tags (all modes) ─────────────────────────────────────────────
    if urlhaus_res.tags:
        st.markdown(
            '<p style="font-family:Space Mono,monospace;font-size:0.62rem;'
            'color:#00ffb4;letter-spacing:0.2em;margin-top:0.7rem">URLHAUS TAGS</p>',
            unsafe_allow_html=True,
        )
        tags_html = "".join(
            f'<span style="font-family:Space Mono,monospace;font-size:0.65rem;'
            f'background:{"rgba(255,45,85,0.12)" if t.lower() in _HIGH_RISK_TAGS else "rgba(255,255,255,0.05)"};'
            f'border:1px solid {"rgba(255,45,85,0.3)" if t.lower() in _HIGH_RISK_TAGS else "#2a3a4a"};'
            f'color:{"#ff6b8a" if t.lower() in _HIGH_RISK_TAGS else "#8aaac8"};'
            f'border-radius:4px;padding:0.18rem 0.45rem;margin:0.15rem;'
            f'display:inline-block">{_html.escape(str(t))}</span>'
            for t in urlhaus_res.tags[:10]
        )
        st.markdown(tags_html, unsafe_allow_html=True)

    # ── Score contribution (all modes) — show when hash/URL found ────
    if urlhaus_res.score_contribution > 0 and mode != "hash":
        # Hash mode already shows its own score badge above; skip duplication
        score_col = "#ff2d55" if urlhaus_res.score_contribution >= 20 else "#ffd060"
        st.markdown(
            f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
            f'color:{score_col};margin-top:0.4rem">'
            f'📊 URLhaus score contribution: <strong>+{urlhaus_res.score_contribution} pts</strong></div>',
            unsafe_allow_html=True,
        )

    # ── Associated URLs / Database entries expander (all modes) ──────
    if urlhaus_res.associated_urls:
        expander_label = (
            f"📋 URLhaus Database Entries — {len(urlhaus_res.associated_urls)} records"
            f" (of {urlhaus_res.urls_found} total)"
            if mode == "hash"
            else f"🔗 Associated Malware URLs ({len(urlhaus_res.associated_urls)} shown of {urlhaus_res.urls_found})"
        )
        with st.expander(expander_label):
            for u in urlhaus_res.associated_urls:
                url_str    = str(u.get("url", ""))
                url_status = u.get("status", "")
                threat     = u.get("threat", "")
                date       = u.get("date", "")

                colour, _ = _STATUS_COLOURS.get(url_status, ("#8aaac8", ""))
                # Defang URL for safe display (replace http with hxxp)
                defanged = url_str.replace("http://", "hxxp://").replace("https://", "hxxps://")

                st.markdown(
                    f'<div style="font-family:Space Mono,monospace;font-size:0.64rem;'
                    f'padding:0.3rem 0;border-bottom:1px solid rgba(42,58,74,0.5)">'
                    f'<span style="color:{colour};margin-right:0.5rem">[{url_status.upper() or "?"}]</span>'
                    f'<span style="color:#5a8aaa">{_html.escape(defanged[:80])}</span>'
                    + (f' <span style="color:#ffd060">· {_html.escape(str(threat))}</span>' if threat else "")
                    + (f' <span style="color:#3a5a7a">· {_html.escape(str(date[:10]))}</span>' if date else "")
                    + '</div>',
                    unsafe_allow_html=True,
                )

    # ── Flags ─────────────────────────────────────────────────────────
    st.markdown(flag_list(urlhaus_res.flags), unsafe_allow_html=True)

    # ── Clean result indicator — shown when API confirmed no records ───
    # query_status "no_results" or "ok" both mean: not in malware database
    if (
        urlhaus_res.available
        and not urlhaus_res.flags
        and urlhaus_res.query_status in ("no_results", "ok", "")
    ):
        st.markdown(
            '<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
            'color:#4a6a8a;margin-top:0.3rem">'
            '✅ Not found in URLhaus malware payload database<br>'
            '<span style="font-size:0.60rem;color:#2a3a4a">'
            'URLhaus tracks malware file delivery URLs (EXE, DLL, scripts). '
            'Phishing, C2, and spam domains may not appear here even if malicious.</span>'
            '</div>',
            unsafe_allow_html=True,
        )

    for e in urlhaus_res.errors:
        st.caption(f"⚠ {e}")
