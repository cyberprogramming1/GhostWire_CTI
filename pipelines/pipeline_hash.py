"""
pipelines/pipeline_hash.py
--------------------------
GhostWire CTI v6 — Pipeline B: File / Hash analysis.

v6.1: URLhaus hash lookup added via run_hash_engines_parallel.
      Checks if uploaded file hash exists in abuse.ch malware database.
      Runs in parallel with VirusTotal lookup (concurrent.futures).
"""
from __future__ import annotations
import time
from datetime import datetime, timezone
import streamlit as st

from backend.hash_engine  import analyze_hash
from backend.async_runner import run_hash_engines_parallel   # NEW
from backend.audit_log    import log_analysis
from backend.pdf_report   import generate_hash_cti_report
from frontend.other_renderers import render_hash_results
from frontend.extra_widgets   import render_urlhaus_panel    # NEW
from frontend.otx_panel       import render_otx_panel           # v7

_MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB


def run(
    *,
    hash_input: str,
    file_upload,
    vt_key: str,
    run_urlhaus: bool = True,   # NEW — URLhaus hash lookup toggle
    run_otx:     bool = True,   # v7  — OTX hash lookup
) -> None:
    if not hash_input and not file_upload:
        st.warning("Please provide a hash or upload a file.")
        return
    if not vt_key:
        st.warning("VirusTotal API key required.")
        return

    prog = st.progress(0, "Analysing file / hash…")
    prog.progress(20, "Computing hash & launching parallel lookups…")

    _file_bytes: bytes | None = None
    _file_name:  str | None   = None
    if file_upload:
        if file_upload.size > _MAX_FILE_BYTES:
            st.error(f"❌ File too large: {file_upload.size/1024/1024:.1f} MB (max 50 MB).")
            return
        _file_bytes = file_upload.read()
        _file_name  = file_upload.name

    # ── Determine hash string for URLhaus lookup ──────────────────────
    # If file upload: compute SHA256 first so URLhaus can start in parallel
    _hash_for_urlhaus = hash_input.strip() if hash_input else ""
    if _file_bytes and not _hash_for_urlhaus:
        import hashlib
        _hash_for_urlhaus = hashlib.sha256(_file_bytes).hexdigest()

    prog.progress(40, "VirusTotal lookup & URLhaus hash check (parallel)…")

    # ── Run VirusTotal + URLhaus in parallel ──────────────────────────
    import concurrent.futures

    def _run_vt():
        if _file_bytes:
            return analyze_hash(_file_bytes, vt_api_key=vt_key, filename=_file_name)
        else:
            return analyze_hash(hash_input.strip(), vt_api_key=vt_key)

    def _run_urlhaus_parallel():
        if run_urlhaus and _hash_for_urlhaus:
            parallel = run_hash_engines_parallel(
                _hash_for_urlhaus,
                vt_key=vt_key,
                run_urlhaus=True,
            )
            return parallel.get("urlhaus")
        return None

    h_res_f    = None
    urlhaus_res = None
    otx_res     = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_vt       = pool.submit(_run_vt)
        f_urlhaus  = pool.submit(_run_urlhaus_parallel)

        def _run_otx_parallel():
            if run_otx and _hash_for_urlhaus:
                from backend.otx_engine import query_hash as _otx_qh
                return _otx_qh(_hash_for_urlhaus, vt_malicious=0)
            return None
        f_otx = pool.submit(_run_otx_parallel)
        try:
            h_res_f    = f_vt.result(timeout=120)
        except Exception as e:
            st.error(f"VirusTotal analysis failed: {e}")
            return
        try:
            urlhaus_res = f_urlhaus.result(timeout=30)
            otx_res     = f_otx.result(timeout=30)
        except Exception:
            pass   # URLhaus failure is non-fatal

    prog.progress(100, "Done."); time.sleep(0.3); prog.empty()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Render VT / PE / hash results ────────────────────────────────
    render_hash_results(h_res_f, ts)

    # NEW: Render URLhaus panel below hash results
    if run_urlhaus and urlhaus_res:
        # Integrate URLhaus score into hash result score
        if getattr(urlhaus_res, "score_contribution", 0) > 0:
            uh_boost = urlhaus_res.score_contribution
            h_res_f.score = min(h_res_f.score + uh_boost, 100)
            h_res_f.flags.append(
                f"🦠 URLhaus: +{uh_boost} pts — hash found in malware database"
            )
            h_res_f.iocs.extend(urlhaus_res.iocs)
        render_urlhaus_panel(urlhaus_res, mode="hash")

    # v7: OTX hash lookup — re-score with VT data, then render
    if run_otx and otx_res and getattr(otx_res, "available", False):
        from backend.otx_engine import _score_result as _otx_rescore
        vt_mal = getattr(h_res_f, "vt_malicious", 0)
        otx_res.flags.clear(); otx_res.iocs.clear(); otx_res.score_contribution = 0
        _otx_rescore(otx_res, vt_malicious=vt_mal)
        if otx_res.score_contribution > 0:
            h_res_f.score = min(h_res_f.score + otx_res.score_contribution, 100)
            h_res_f.flags.append(
                f"🛸 OTX: +{otx_res.score_contribution} pts — "
                f"{otx_res.pulse_count} pulses corroborated with VT"
            )
        render_otx_panel(otx_res, mode="hash")

    log_analysis(
        pipeline     = "file" if _file_bytes else "hash",
        target       = _file_name or hash_input.strip(),
        score        = h_res_f.score,
        threat_level = (
            "CRITICAL" if h_res_f.score >= 85 else
            "HIGH"     if h_res_f.score >= 65 else
            "MEDIUM"   if h_res_f.score >= 40 else
            "LOW"      if h_res_f.score >= 20 else "SAFE"
        ),
        ioc_count    = len(h_res_f.iocs),
    )

    st.markdown("---")
    st.markdown('<p class="slabel">Export CTI Report</p>', unsafe_allow_html=True)
    with st.spinner("Generating PDF report…"):
        try:
            pdf_bytes = generate_hash_cti_report(h_res_f, ts)
            safe_name = (_file_name or hash_input.strip() or "hash")[:40].replace("/","_")
            st.download_button(
                label="Download CTI Report",
                data=pdf_bytes,
                file_name=f"GhostWire_CTI_Hash_{safe_name}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation error: {e}")
