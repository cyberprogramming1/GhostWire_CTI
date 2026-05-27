"""
pipelines/pipeline_hash.py
--------------------------
GhostWire CTI v6 — Pipeline B: File / Hash analysis.

FIX v9: forensic_engine.deep_forensic_analysis() is now called whenever a
file is uploaded.  It runs in parallel with the existing VT / URLhaus / OTX
lookups and its rich ForensicReport is rendered in a dedicated expander below
the main hash results panel.
"""
from __future__ import annotations
import time
import hashlib
import concurrent.futures
from datetime import datetime, timezone

import streamlit as st

from backend.hash_engine  import analyze_hash
from backend.async_runner import run_hash_engines_parallel
from backend.audit_log    import log_analysis
from backend.pdf_report   import generate_hash_cti_report
from frontend.other_renderers import render_hash_results, render_forensic_results
from frontend.extra_widgets   import render_urlhaus_panel
from frontend.otx_panel       import render_otx_panel

_MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB


def run(
    *,
    hash_input: str,
    file_upload,
    vt_key: str,
    run_urlhaus: bool = True,
    run_otx:     bool = True,
    ollama_model: str = "phi3:mini",
) -> None:
    if not hash_input and not file_upload:
        st.warning("Please provide a hash or upload a file.")
        return
    if not vt_key:
        st.warning("VirusTotal API key required.")
        return

    prog = st.progress(0, "Analysing file / hash…")
    prog.progress(10, "Reading file & computing hashes…")

    _file_bytes: bytes | None = None
    _file_name:  str | None   = None
    if file_upload:
        if file_upload.size > _MAX_FILE_BYTES:
            st.error(f"❌ File too large: {file_upload.size/1024/1024:.1f} MB (max 50 MB).")
            return
        _file_bytes = file_upload.read()
        _file_name  = file_upload.name

    # ── Determine hash string for parallel lookups ────────────────────
    _hash_for_lookups = hash_input.strip() if hash_input else ""
    if _file_bytes and not _hash_for_lookups:
        _hash_for_lookups = hashlib.sha256(_file_bytes).hexdigest()

    prog.progress(25, "Launching parallel analysis engines…")

    # ── Parallel execution: VT + URLhaus + OTX + Forensic ────────────
    def _run_vt():
        if _file_bytes:
            return analyze_hash(_file_bytes, vt_api_key=vt_key, filename=_file_name)
        else:
            return analyze_hash(hash_input.strip(), vt_api_key=vt_key)

    def _run_urlhaus_parallel():
        if run_urlhaus and _hash_for_lookups:
            parallel = run_hash_engines_parallel(
                _hash_for_lookups,
                vt_key=vt_key,
                run_urlhaus=True,
            )
            return parallel.get("urlhaus")
        return None

    def _run_otx_parallel():
        if run_otx and _hash_for_lookups:
            from backend.otx_engine import query_hash as _otx_qh
            return _otx_qh(_hash_for_lookups, vt_malicious=0)
        return None

    def _run_forensic():
        """
        Deep forensic analysis — only runs when a file is actually uploaded.
        Security note: vt_api_key passed so ForensicReport can cross-check
        against VT independently; ollama_model passed for NLP analysis.
        """
        if not _file_bytes:
            return None
        try:
            from backend.forensic_engine import deep_forensic_analysis
            return deep_forensic_analysis(
                data=_file_bytes,
                filename=_file_name or "unknown",
                vt_api_key=vt_key,
                ollama_model=ollama_model,
            )
        except Exception as _fe:
            return {"error": str(_fe)}

    from backend.urlhaus_engine import URLhausResult as _URLhausResult

    h_res_f      = None
    urlhaus_res  = _URLhausResult()
    otx_res      = None
    forensic_res = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        f_vt       = pool.submit(_run_vt)
        f_urlhaus  = pool.submit(_run_urlhaus_parallel)
        f_otx      = pool.submit(_run_otx_parallel)
        f_forensic = pool.submit(_run_forensic)

        prog.progress(50, "VirusTotal · URLhaus · OTX · Forensic Engine running…")

        try:
            h_res_f = f_vt.result(timeout=120)
        except concurrent.futures.TimeoutError:
            # FIX v7: TimeoutError.str() == "" → shows blank error message.
            # Probable cause: Ollama running inside analyze_hash thread hung for >120s.
            # Don't abort — create a minimal result and continue with URLhaus/OTX/Forensic.
            from backend.hash_engine import HashAnalysisResult as _HAR
            h_res_f = _HAR()
            h_res_f.errors.append(
                "VirusTotal analysis timed out (>120s). "
                "Possible cause: Ollama model taking too long or VT API unreachable. "
                "URLhaus / OTX / Forensic results below are still valid."
            )
            st.warning(
                "⚠️ VirusTotal analysis timed out — continuing with URLhaus, OTX and Forensic results."
            )
        except Exception as e:
            _err_msg = str(e).strip()
            if not _err_msg:
                # Empty exception message — determine likely cause from exception type
                _etype = type(e).__name__
                _err_msg = (
                    f"Unexpected error ({_etype}). "
                    "Check that your VirusTotal API key is valid and the network is reachable."
                )
            st.error(f"VirusTotal analysis failed: {_err_msg}")
            return

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

        try:
            forensic_res = f_forensic.result(timeout=90)
        except concurrent.futures.TimeoutError:
            forensic_res = {"error": "Forensic engine timed out (>90s) — file may be too complex or Ollama hung"}
        except Exception as _fex:
            _fmsg = str(_fex).strip() or type(_fex).__name__
            forensic_res = {"error": _fmsg}

    prog.progress(85, "Integrating scores…")

    # ── Score integration ─────────────────────────────────────────────
    if run_urlhaus:
        if getattr(urlhaus_res, "score_contribution", 0) > 0:
            uh_boost = urlhaus_res.score_contribution
            h_res_f.score = min(h_res_f.score + uh_boost, 100)
            h_res_f.flags.append(
                f"🦠 URLhaus: +{uh_boost} pts — hash found in malware database"
            )
            h_res_f.iocs.extend(urlhaus_res.iocs)

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

    # ── Boost main score from forensic findings ───────────────────────
    if forensic_res and not isinstance(forensic_res, dict):
        forensic_boost = max(0, forensic_res.risk_score - h_res_f.score)
        if forensic_boost > 0:
            h_res_f.score = min(h_res_f.score + forensic_boost // 2, 100)
            h_res_f.flags.append(
                f"🔬 Forensic Engine: +{forensic_boost//2} pts — "
                f"risk score {forensic_res.risk_score}/100 [{forensic_res.threat_level}]"
            )
        # Merge forensic IOCs into main IOC list
        for ioc in forensic_res.iocs[:10]:
            if ioc not in h_res_f.iocs:
                h_res_f.iocs.append(ioc)

    prog.progress(100, "Done.")
    time.sleep(0.3)
    prog.empty()

    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Render ────────────────────────────────────────────────────────
    render_hash_results(h_res_f, ts)

    if run_urlhaus:
        render_urlhaus_panel(urlhaus_res, mode="hash")

    if run_otx and otx_res and getattr(otx_res, "available", False):
        render_otx_panel(otx_res, mode="hash")

    # ── Forensic deep-dive panel ──────────────────────────────────────
    if _file_bytes:
        render_forensic_results(forensic_res, ts)

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
            pdf_bytes = generate_hash_cti_report(
                h_res_f, ts,
                urlhaus_res=urlhaus_res,
                otx_res=otx_res,
            )
            safe_name = (_file_name or hash_input.strip() or "hash")[:40].replace("/", "_")
            st.download_button(
                label="Download CTI Report",
                data=pdf_bytes,
                file_name=f"GhostWire_CTI_Hash_{safe_name}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation error: {e}")
