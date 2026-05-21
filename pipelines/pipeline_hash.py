"""
pipelines/pipeline_hash.py
--------------------------
GhostWire CTI v6 — Pipeline B: File / Hash analysis.
"""
from __future__ import annotations
import time
from datetime import datetime, timezone
import streamlit as st

from backend.hash_engine import analyze_hash
from backend.audit_log   import log_analysis
from backend.pdf_report  import generate_hash_cti_report
from frontend.other_renderers import render_hash_results

_MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB


def run(
    *,
    hash_input: str,
    file_upload,
    vt_key: str,
) -> None:
    if not hash_input and not file_upload:
        st.warning("Please provide a hash or upload a file.")
        return
    if not vt_key:
        st.warning("VirusTotal API key required.")
        return

    prog = st.progress(0, "Analysing file / hash…")
    prog.progress(40, "VirusTotal lookup & metadata extraction…")

    _file_bytes: bytes | None = None
    _file_name:  str | None   = None
    if file_upload:
        if file_upload.size > _MAX_FILE_BYTES:
            st.error(f"❌ File too large: {file_upload.size/1024/1024:.1f} MB (max 50 MB).")
            return
        _file_bytes = file_upload.read()
        _file_name  = file_upload.name

    h_res_f = (
        analyze_hash(_file_bytes, vt_api_key=vt_key, filename=_file_name)
        if _file_bytes
        else analyze_hash(hash_input.strip(), vt_api_key=vt_key)
    )

    prog.progress(100, "Done."); time.sleep(0.3); prog.empty()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    render_hash_results(h_res_f, ts)

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
