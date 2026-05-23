"""
pipelines/pipeline_email.py
----------------------------
GhostWire CTI v6 — Pipeline C: Email / SMS forensics.
"""
from __future__ import annotations
import time
from datetime import datetime, timezone
import streamlit as st

from backend.email_engine import analyze_email
from backend.audit_log    import log_analysis
from backend.pdf_report   import generate_email_cti_report
from frontend.other_renderers import render_email_results

_MAX_IMG_BYTES = 10 * 1024 * 1024


def run(*, email_input: str, email_img) -> None:
    # ── Normalize inputs ──────────────────────────────────────────────
    # Strip whitespace — empty text_area returns "" not None in Streamlit
    clean_text = (email_input or "").strip() or None

    # Read image bytes immediately — UploadedFile pointer moves after read()
    # so we capture bytes once here and pass the bytes object everywhere.
    img_bytes: bytes | None = None
    if email_img is not None:
        try:
            # Streamlit UploadedFile: .read() returns b"" if already consumed
            raw = email_img.read()
            if raw:
                img_bytes = raw
            else:
                st.warning("⚠ Image upload appears empty — try re-uploading the file.")
                return
        except Exception as read_err:
            st.error(f"❌ Could not read uploaded image: {read_err}")
            return

    # Guard: nothing provided at all
    if not clean_text and img_bytes is None:
        st.warning("Please paste email/SMS text or upload an email screenshot.")
        return

    # Guard: image too large (check on bytes, not .size which can be unreliable)
    if img_bytes and len(img_bytes) > _MAX_IMG_BYTES:
        st.error(f"❌ Image too large: {len(img_bytes)/1024/1024:.1f} MB (max 10 MB).")
        return

    prog = st.progress(0, "Analysing email / SMS…")
    prog.progress(50, "Forensic header & content analysis…")

    em_res = analyze_email(text=clean_text, image_bytes=img_bytes)

    prog.progress(100, "Done."); time.sleep(0.3); prog.empty()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    render_email_results(em_res, ts)

    log_analysis(
        pipeline     = "email",
        target       = (email_input or "screenshot")[:80],
        score        = em_res.score,
        threat_level = (
            "CRITICAL" if em_res.score >= 85 else
            "HIGH"     if em_res.score >= 65 else
            "MEDIUM"   if em_res.score >= 40 else
            "LOW"      if em_res.score >= 20 else "SAFE"
        ),
        ioc_count    = len(em_res.iocs),
    )

    st.markdown("---")
    st.markdown('<p class="slabel">Export CTI Report</p>', unsafe_allow_html=True)
    with st.spinner("Generating PDF report…"):
        try:
            pdf_bytes = generate_email_cti_report(em_res, ts)
            safe_name = (em_res.sender_domain or "email")[:40].replace("/","_")
            st.download_button(
                label="Download CTI Report",
                data=pdf_bytes,
                file_name=f"GhostWire_CTI_Email_{safe_name}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation error: {e}")
