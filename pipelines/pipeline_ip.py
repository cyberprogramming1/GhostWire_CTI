"""
pipelines/pipeline_ip.py
------------------------
GhostWire CTI v6 — Pipeline D: Standalone IP Intelligence.

v6.1: URLhaus host lookup added via run_ip_urlhaus_parallel.
      Checks if IP has hosted malware delivery URLs in abuse.ch database.
      Runs concurrently alongside Shodan / GreyNoise queries.
"""
from __future__ import annotations
import re
import time
from datetime import datetime, timezone
import streamlit as st

from backend.ip_intel       import analyze_ip
from backend.external_intel import analyze_shodan, analyze_greynoise
from backend.async_runner   import run_ip_urlhaus_parallel   # NEW
from backend.audit_log      import log_analysis
from backend.pdf_report     import generate_ip_cti_report
from frontend.other_renderers import render_ip_results
from frontend.extra_widgets   import (
    render_threat_map, render_shodan_panel,
    render_greynoise_panel, render_urlhaus_panel,  # NEW
)
from frontend.otx_panel import render_otx_panel  # v7

_IP_RE = re.compile(r'^[\d.:a-fA-F]{2,45}$')


def run(
    *,
    ip_raw: str,
    abuse_key: str,
    vt_key: str,
    shodan_key: str,
    run_shodan: bool,
    run_greynoise: bool,
    run_urlhaus: bool = True,   # NEW — URLhaus host lookup toggle
    run_otx:     bool = True,   # v7  — OTX IP lookup
) -> None:
    if not ip_raw:
        st.warning("Please enter an IP address.")
        return
    if not _IP_RE.match(ip_raw):
        st.error("❌ Invalid IP address format.")
        return

    prog = st.progress(0, "Initialising IP intelligence…")
    prog.progress(20, "Reverse DNS + geolocation + URLhaus host check…")

    # ── Run analyze_ip + URLhaus in parallel ──────────────────────────
    import concurrent.futures

    ip_res      = None
    urlhaus_res = None
    otx_res     = None

    def _run_ip():
        return analyze_ip(ip_raw, abuse_api_key=abuse_key, vt_api_key=vt_key)

    def _run_urlhaus_parallel():
        if run_urlhaus:
            parallel = run_ip_urlhaus_parallel(ip_raw, run_urlhaus=True)
            return parallel.get("urlhaus")
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_ip      = pool.submit(_run_ip)
        f_urlhaus = pool.submit(_run_urlhaus_parallel)

        def _run_otx_ip_parallel():
            if run_otx:
                from backend.otx_engine import query_ip as _otx_qi
                return _otx_qi(ip_raw, vt_malicious=0)
            return None
        f_otx = pool.submit(_run_otx_ip_parallel)
        ip_res      = f_ip.result(timeout=60)
        try:
            urlhaus_res = f_urlhaus.result(timeout=30)
            otx_res     = f_otx.result(timeout=30)
        except Exception:
            pass   # URLhaus failure is non-fatal

    prog.progress(100, "Done."); time.sleep(0.3); prog.empty()

    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    render_ip_results(ip_res, ip_raw, ts)

    if ip_res.latitude is not None and ip_res.longitude is not None:
        render_threat_map(ip_res.latitude, ip_res.longitude, ip_raw,
                          country=ip_res.country, city=ip_res.city)

    _ip_shodan = _ip_gn = None
    if run_shodan:
        with st.spinner("Querying Shodan…"):
            _ip_shodan = analyze_shodan(ip_raw, api_key=shodan_key)
        render_shodan_panel(_ip_shodan)

    if run_greynoise:
        with st.spinner("Querying GreyNoise…"):
            _ip_gn = analyze_greynoise(ip_raw)
        render_greynoise_panel(_ip_gn)

    # NEW: Render URLhaus panel (shows malicious URL history for this IP)
    if run_urlhaus and urlhaus_res:
        render_urlhaus_panel(urlhaus_res, mode="ip")

    # v7: OTX IP lookup — re-score with VT data, then render
    if run_otx and otx_res and getattr(otx_res, "available", False):
        from backend.otx_engine import _score_result as _otx_rescore
        vt_mal = getattr(ip_res, "vt_malicious", 0)
        otx_res.flags.clear(); otx_res.iocs.clear(); otx_res.score_contribution = 0
        _otx_rescore(otx_res, vt_malicious=vt_mal)
        render_otx_panel(otx_res, mode="ip")

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
