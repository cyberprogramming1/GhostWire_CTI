"""
pipelines/pipeline_ip.py
------------------------
GhostWire CTI v6 — Pipeline D: Standalone IP Intelligence.
"""
from __future__ import annotations
import re
import time
from datetime import datetime, timezone
import streamlit as st

from backend.ip_intel       import analyze_ip
from backend.external_intel import analyze_shodan, analyze_greynoise
from backend.async_runner   import run_ip_urlhaus_parallel
from backend.audit_log      import log_analysis
from backend.pdf_report     import generate_ip_cti_report
from frontend.other_renderers import render_ip_results
from frontend.extra_widgets   import (
    render_threat_map, render_shodan_panel,
    render_greynoise_panel, render_urlhaus_panel,
)
from frontend.otx_panel import render_otx_panel

_IP_RE = re.compile(r'^[\d.:a-fA-F]{2,45}$')


def run(
    *,
    ip_raw: str,
    abuse_key: str,
    vt_key: str,
    shodan_key: str,
    run_shodan: bool,
    run_greynoise: bool,
    run_urlhaus: bool = True,
    run_otx:     bool = True,
) -> None:
    if not ip_raw:
        st.warning("Please enter an IP address.")
        return
    if not _IP_RE.match(ip_raw):
        st.error("❌ Invalid IP address format.")
        return

    prog = st.progress(0, "Initialising IP intelligence…")
    prog.progress(20, "Reverse DNS + geolocation + URLhaus host check…")

    # ── Step 1: Run analyze_ip + URLhaus + OTX in parallel ───────────
    import concurrent.futures
    from backend.urlhaus_engine import URLhausResult as _URLhausResult

    ip_res      = None
    urlhaus_res: _URLhausResult = _URLhausResult()
    otx_res     = None

    def _run_ip():
        return analyze_ip(ip_raw, abuse_api_key=abuse_key, vt_api_key=vt_key)

    def _run_urlhaus_parallel():
        if run_urlhaus:
            parallel = run_ip_urlhaus_parallel(ip_raw, run_urlhaus=True)
            return parallel.get("urlhaus")
        return None

    def _run_otx_ip_parallel():
        if run_otx:
            from backend.otx_engine import query_ip as _otx_qi
            return _otx_qi(ip_raw, vt_malicious=0)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_ip      = pool.submit(_run_ip)
        f_urlhaus = pool.submit(_run_urlhaus_parallel)
        f_otx     = pool.submit(_run_otx_ip_parallel)
        ip_res = f_ip.result(timeout=60)
        try:
            _uh = f_urlhaus.result(timeout=30)
            if _uh is not None:
                urlhaus_res = _uh
        except Exception as _uh_exc:
            _msg = str(_uh_exc)
            if "timeout" in _msg.lower() or "TimeoutError" in type(_uh_exc).__name__:
                urlhaus_res.errors = ["timeout"]
            else:
                urlhaus_res.errors = [f"URLhaus lookup error: {_msg[:80]}"]
        try:
            otx_res = f_otx.result(timeout=30)
        except Exception:
            pass

    prog.progress(60, "Querying GreyNoise + Shodan…")

    # ── Step 2: Query GreyNoise + Shodan (sequential, show spinners) ─
    _ip_shodan = _ip_gn = None

    if run_shodan:
        with st.spinner("Querying Shodan…"):
            _ip_shodan = analyze_shodan(ip_raw, api_key=shodan_key)

    if run_greynoise:
        with st.spinner("Querying GreyNoise…"):
            _ip_gn = analyze_greynoise(ip_raw)

    prog.progress(100, "Done."); time.sleep(0.3); prog.empty()

    # ── Step 3: Integrate ALL scores BEFORE rendering ─────────────────
    # FIX v7: Previously render_ip_results() was called right after Step 1,
    # before GreyNoise was even queried. Score showed VT+AbuseIPDB only.
    # Now all sources are scored first, then rendered once with final score.

    _score_boosts: list[tuple[str, int]] = []

    # GreyNoise score contribution
    if _ip_gn and getattr(_ip_gn, "available", False):
        gn_contrib = getattr(_ip_gn, "score_contribution", 0)
        if gn_contrib > 0:
            _score_boosts.append(("GreyNoise", gn_contrib))
        elif gn_contrib < 0:
            # RIOT (known benign) → reduce score (false positive suppression)
            ip_res.score = max(ip_res.score + gn_contrib, 0)
            ip_res.flags.append(
                f"✅ GreyNoise RIOT: score reduced by {abs(gn_contrib)} pts "
                f"(known benign service — false positive suppressed)"
            )

    # URLhaus host score contribution
    if urlhaus_res and getattr(urlhaus_res, "score_contribution", 0) > 0:
        _score_boosts.append(("URLhaus", urlhaus_res.score_contribution))
        ip_res.iocs.extend(urlhaus_res.iocs)

    # OTX score contribution — re-score with real VT data
    if run_otx and otx_res and getattr(otx_res, "available", False):
        from backend.otx_engine import _score_result as _otx_rescore
        vt_mal = getattr(ip_res, "vt_malicious", 0)
        otx_res.flags.clear(); otx_res.iocs.clear(); otx_res.score_contribution = 0
        _otx_rescore(otx_res, vt_malicious=vt_mal)
        if otx_res.score_contribution > 0:
            _score_boosts.append(("OTX AlienVault", otx_res.score_contribution))

    # Apply all boosts
    for source, pts in _score_boosts:
        ip_res.score = min(ip_res.score + pts, 100)
        ip_res.flags.append(f"📡 {source}: +{pts} pts added to threat score")

    # ── Step 4: Render everything with final score ────────────────────
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    render_ip_results(ip_res, ip_raw, ts)

    if ip_res.latitude is not None and ip_res.longitude is not None:
        render_threat_map(ip_res.latitude, ip_res.longitude, ip_raw,
                          country=ip_res.country, city=ip_res.city)

    if run_shodan:
        render_shodan_panel(_ip_shodan)

    if run_greynoise:
        render_greynoise_panel(_ip_gn)

    if run_urlhaus:
        render_urlhaus_panel(urlhaus_res, mode="ip")

    if run_otx and otx_res and getattr(otx_res, "available", False):
        render_otx_panel(otx_res, mode="ip")

    log_analysis(
        pipeline     = "ip",
        target       = ip_raw,
        score        = ip_res.score,
        threat_level = (
            "CRITICAL" if ip_res.score >= 85 else
            "HIGH"     if ip_res.score >= 65 else
            "MEDIUM"   if ip_res.score >= 40 else
            "LOW"      if ip_res.score >= 20 else "SAFE"
        ),
        ioc_count    = len(ip_res.iocs),
    )

    st.markdown("---")
    st.markdown('<p class="slabel">Export CTI Report</p>', unsafe_allow_html=True)
    with st.spinner("Generating PDF report…"):
        try:
            pdf_bytes = generate_ip_cti_report(ip_res, ip_raw, ts,
                                                shodan_res=_ip_shodan,
                                                greynoise_res=_ip_gn)
            safe_name = ip_raw.replace(".","_").replace(":","_")[:40]
            st.download_button(
                label="Download CTI Report",
                data=pdf_bytes,
                file_name=f"GhostWire_CTI_IP_{safe_name}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation error: {e}")
