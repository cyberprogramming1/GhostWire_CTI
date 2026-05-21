"""
pipelines/pipeline_url.py
--------------------------
GhostWire CTI v6 — Pipeline A: URL / Domain / IP analysis.

v6 improvements:
  - Extracted from monolithic app.py (Problem #2 fix)
  - Uses async_runner for parallel engine execution (Problem #3 fix)
    → 3-5x faster: VT + AbuseIPDB + Shodan + GreyNoise run concurrently
"""
from __future__ import annotations

import time
import urllib.parse as _urlparse
from datetime import datetime, timezone

import streamlit as st

from backend.ai_analyzer  import assess_domain_legitimacy
from backend.scoring      import compute_final_score
from backend.verdict      import calculate_verdict
from backend.whois_timeline import build_whois_timeline
from backend.audit_log    import log_analysis
from backend.pdf_report   import generate_cti_report
from backend.async_runner import run_engines_parallel

from frontend.url_renderer  import render_url_results
from frontend.extra_widgets import (
    render_whois_timeline, render_screenshot_preview,
    render_threat_map, render_shodan_panel, render_greynoise_panel,
)


def _collect_iocs(*engine_results) -> list[str]:
    seen: set[str] = set(); out: list[str] = []
    for res in engine_results:
        for ioc in getattr(res, "iocs", []):
            if ioc not in seen:
                seen.add(ioc); out.append(ioc)
    return out


def _engines_triggered(h, w, ai, rep, dec, sb, ssl_res, pdns_res) -> list[str]:
    triggered = []
    if getattr(h,       "score", 0) >= 15: triggered.append("URL Heuristics")
    if getattr(w,       "score", 0) >= 10: triggered.append("WHOIS/Domain Age")
    if getattr(ai,      "score", 0) >= 10: triggered.append("AI NLP")
    if getattr(rep,     "score", 0) >= 10: triggered.append("Infrastructure Rep.")
    if getattr(dec,     "score", 0) >= 10: triggered.append("Tech Deception")
    if getattr(sb,      "score", 0) >= 10: triggered.append("Sandbox")
    if getattr(ssl_res, "score", 0) >= 10: triggered.append("SSL/TLS")
    if getattr(pdns_res,"score", 0) >= 10: triggered.append("Passive DNS")
    return triggered


def run(
    target: str,
    *,
    vt_key: str,
    abuse_key: str,
    shodan_key: str,
    ollama_model: str,
    run_ai: bool,
    run_sandbox: bool,
    run_ssl: bool,
    run_pdns: bool,
    run_screenshot: bool,
    run_timeline: bool,
    run_shodan: bool,
    run_greynoise: bool,
) -> None:
    """Execute the full URL/Domain/IP CTI pipeline and render results."""

    t0   = time.time()
    prog = st.progress(0, "Initialising CTI pipeline (parallel engines)…")
    prog.progress(10, "Launching parallel engine pool…")

    # ── Parallel execution (Problem #3 fix) ──────────────────────────
    # All network-bound engines run concurrently in a ThreadPoolExecutor.
    # Wall-clock time ≈ slowest single engine, not sum of all engines.
    results = run_engines_parallel(
        target,
        vt_key        = vt_key,
        abuse_key     = abuse_key,
        shodan_key    = shodan_key,
        ollama_model  = ollama_model,
        run_ai        = run_ai,
        run_sandbox   = run_sandbox,
        run_ssl       = run_ssl,
        run_pdns      = run_pdns,
        run_shodan    = run_shodan,
        run_greynoise = run_greynoise,
    )

    h_res       = results["heuristics"]
    w_res       = results["whois"]
    ai_res      = results["ai"]
    rep_res     = results["reputation"]
    dec_res     = results["deception"]
    sb_res      = results["sandbox"]
    ssl_res     = results["ssl"]
    pdns_res    = results["pdns"]
    shodan_res  = results["shodan"]
    greynoise_res = results["greynoise"]

    prog.progress(80, "Engines complete — computing score…")

    # ── AI Domain Legitimacy Assessment ──────────────────────────────
    legitimacy_res = assess_domain_legitimacy(
        domain           = target,
        vt_malicious     = getattr(rep_res, "vt_malicious", 0),
        vt_total         = getattr(rep_res, "vt_total_engines", 0),
        vt_relations_mal = getattr(rep_res, "vt_malicious_files_related", 0),
        abuse_confidence = getattr(rep_res, "abuse_confidence", 0),
        domain_age_days  = getattr(w_res,   "domain_age_days", None),
        popularity_rank  = getattr(rep_res, "vt_popularity_rank", None),
        vt_categories    = getattr(rep_res, "vt_categories", []),
        model            = ollama_model,
    )

    final_score, sig, extra_flags = compute_final_score(
        target, h_res, w_res, ai_res, rep_res, dec_res, sb_res, ssl_res, pdns_res,
        legitimacy=legitimacy_res,
    )

    prog.progress(92, "Computing verdict…")
    all_iocs = _collect_iocs(rep_res, dec_res, sb_res, ssl_res, pdns_res)
    verdict  = calculate_verdict(
        score             = final_score,
        engines_triggered = _engines_triggered(h_res, w_res, ai_res, rep_res, dec_res, sb_res, ssl_res, pdns_res),
        all_iocs          = all_iocs,
        infra_override    = getattr(sig, "infrastructure_override", False),
        subdomain_trap    = getattr(sig, "subdomain_trap_active", False),
        brand_squatting   = getattr(sig, "brand_squatting", False),
        url               = target,
        vt_malicious      = getattr(rep_res, "vt_malicious", 0),
        abuse_confidence  = getattr(rep_res, "abuse_confidence", 0),
    )

    ts  = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    dur = time.time() - t0
    prog.progress(100, f"Done in {dur:.1f}s (parallel engines).")
    time.sleep(0.3); prog.empty()

    # ── WHOIS Timeline (sequential — uses domain string only) ────────
    timeline_res = None
    if run_timeline:
        import tldextract
        ext = tldextract.extract(target)
        tl_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else target
        with st.spinner("Building WHOIS timeline…"):
            from backend.whois_timeline import build_whois_timeline
            timeline_res = build_whois_timeline(tl_domain)

    # ── Render ──────────────────────────────────────────────────────
    render_url_results(
        target, verdict, sig, extra_flags,
        h_res, w_res, ai_res, rep_res, dec_res, sb_res,
        ssl_res, pdns_res, all_iocs, dur, ts,
        legitimacy=legitimacy_res,
    )

    if timeline_res:
        render_whois_timeline(timeline_res)
    if run_screenshot:
        render_screenshot_preview(target)
    if shodan_res and getattr(shodan_res, "available", False):
        render_shodan_panel(shodan_res)
    elif run_shodan and shodan_res:
        render_shodan_panel(shodan_res)  # show even if unavailable (shows error gracefully)
    if greynoise_res and run_greynoise:
        render_greynoise_panel(greynoise_res)

    if getattr(rep_res, "ip_address", None):
        try:
            from backend.ip_intel import IPIntelResult as _IPR, _fetch_ip_api
            _geo_result = _IPR()
            _fetch_ip_api(rep_res.ip_address, _geo_result)
            if _geo_result.latitude is not None and _geo_result.longitude is not None:
                render_threat_map(
                    _geo_result.latitude,
                    _geo_result.longitude,
                    rep_res.ip_address,
                    country=_geo_result.country,
                    city=_geo_result.city,
                )
        except Exception as _map_exc:
            import logging as _ml
            _ml.getLogger(__name__).warning("Threat map geo lookup failed: %s", _map_exc)

    log_analysis(
        pipeline          = "url",
        target            = target,
        score             = final_score,
        verdict           = verdict.threat_level,
        threat_level      = verdict.threat_level,
        engines_triggered = verdict.engines_triggered,
        ioc_count         = len(all_iocs),
        duration_secs     = dur,
    )

    # ── PDF Export ───────────────────────────────────────────────────
    st.markdown("---")
    st.markdown('<p class="slabel">Export CTI Report</p>', unsafe_allow_html=True)
    with st.spinner("Generating PDF report (with score gauge + engine charts)…"):
        try:
            pdf_bytes = generate_cti_report(
                target=target, verdict=verdict, sig=sig,
                h_res=h_res, w_res=w_res, ai_res=ai_res,
                rep_res=rep_res, dec_res=dec_res, sb_res=sb_res,
                ssl_res=ssl_res, pdns_res=pdns_res,
                all_iocs=all_iocs, duration=dur, timestamp=ts,
                shodan_res=shodan_res, greynoise_res=greynoise_res,
                extra_flags=extra_flags,
            )
            safe_name = target.replace("http://","").replace("https://","").replace("/","_")[:40]
            st.download_button(
                label="Download CTI Report (PDF + Charts)",
                data=pdf_bytes,
                file_name=f"GhostWire_CTI_{safe_name}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation error: {e}")
