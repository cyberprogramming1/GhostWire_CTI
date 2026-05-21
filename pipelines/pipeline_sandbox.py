"""
pipelines/pipeline_sandbox.py
------------------------------
GhostWire CTI v6 — Pipeline E: Hybrid Analysis Sandbox.
"""
from __future__ import annotations
import re
import time
from datetime import datetime, timezone
import streamlit as st

from backend.hybrid_analysis import (
    analyze_url_ha, analyze_file_ha, analyze_hash_ha,
    analyze_domain_ip_ha, HAResult, ENV_WIN10_64,
)
from backend.audit_log  import log_analysis
from backend.pdf_report import generate_ha_cti_report
from frontend.ha_renderer import render_ha_results

_RL_COOLDOWN = 60
_RL_KEY      = "ha_rate_limit"
_IP_RE       = re.compile(r'^[\d.:a-fA-F]{7,45}$')
_HASH_RE_MAP = {32: re.compile(r'^[0-9a-f]{32}$'),
                40: re.compile(r'^[0-9a-f]{40}$'),
                64: re.compile(r'^[0-9a-f]{64}$')}
_HA_MAX_FILE = 100 * 1024 * 1024


def _rl_check(target: str):
    import hashlib
    key   = hashlib.sha256(target.strip().lower().encode()).hexdigest()[:16]
    store = st.session_state.setdefault(_RL_KEY, {})
    last  = store.get(key, 0.0)
    elapsed   = time.monotonic() - last
    remaining = max(0, int(_RL_COOLDOWN - elapsed))
    return remaining == 0, remaining


def _rl_record(target: str):
    import hashlib
    key   = hashlib.sha256(target.strip().lower().encode()).hexdigest()[:16]
    store = st.session_state.setdefault(_RL_KEY, {})
    store[key] = time.monotonic()


def _normalise_url(raw: str) -> str:
    raw = raw.strip()
    return ("http://" + raw) if raw and not raw.startswith(("http://","https://")) else raw


def run(
    *,
    ha_input_type: str,
    ha_url_input: str,
    ha_file_up,
    ha_hash_inp: str,
    ha_ip_inp: str,
    ha_key: str,
    ha_env_id: int,
    run_ha: bool,
    ollama_model: str,
) -> None:
    if not ha_key:
        st.error("Hybrid Analysis API key not configured.")
        return

    prog      = st.progress(0, "Initialising Hybrid Analysis sandbox…")
    ts        = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ha_res    = None
    ha_target = ""
    ha_itype  = ""

    # ── URL / Domain ──────────────────────────────────────────────────
    if ha_input_type == "URL / Domain":
        raw_ha = ha_url_input.strip()
        if not raw_ha:
            prog.empty(); st.warning("Please enter a URL or domain."); return
        if len(raw_ha) > 2048:
            prog.empty(); st.error("Input too long (max 2048 chars)."); return
        ha_target = _normalise_url(raw_ha)
        ha_itype  = "url"

        _rl_ok, _rl_wait = _rl_check(ha_target)
        if not _rl_ok:
            prog.empty()
            st.warning(
                f"⏱ Rate limit: this URL was already submitted {_RL_COOLDOWN - _rl_wait}s ago. "
                f"Please wait **{_rl_wait}s** (HA free tier: 5 submissions/hour)."
            )
            return

        prog.progress(10, "Submitting URL to Hybrid Analysis sandbox…")
        with st.spinner("Detonating URL in sandbox — this may take up to 2 minutes…"):
            if run_ha:
                ha_res = analyze_url_ha(ha_target, ha_key, env_id=ha_env_id)
                _rl_record(ha_target)
            else:
                ha_res = HAResult(); ha_res.errors.append("HA toggle is off")

    # ── File ──────────────────────────────────────────────────────────
    elif ha_input_type == "File":
        if not ha_file_up:
            prog.empty(); st.warning("Please upload a file."); return
        if ha_file_up.size > _HA_MAX_FILE:
            prog.empty()
            st.error(f"File too large: {ha_file_up.size//1024//1024}MB (max 100MB)")
            return
        ha_target = ha_file_up.name
        ha_itype  = "file"
        prog.progress(10, "Uploading file to Hybrid Analysis…")
        _ha_bytes = ha_file_up.read()
        with st.spinner("File uploaded — sandbox detonation in progress…"):
            if run_ha:
                ha_res = analyze_file_ha(_ha_bytes, ha_file_up.name, ha_key, env_id=ha_env_id)
            else:
                ha_res = HAResult(); ha_res.errors.append("HA toggle is off")

    # ── Hash ──────────────────────────────────────────────────────────
    elif ha_input_type == "Hash":
        raw_hash = ha_hash_inp.strip().lower()
        if not raw_hash:
            prog.empty(); st.warning("Please enter a hash."); return
        pat = _HASH_RE_MAP.get(len(raw_hash))
        if pat is None or not pat.match(raw_hash):
            prog.empty()
            st.error("Invalid hash format — expected MD5/SHA-1/SHA-256 hex string.")
            return
        ha_target = raw_hash
        ha_itype  = "hash"
        prog.progress(20, "Looking up hash in Hybrid Analysis database…")
        with st.spinner("Querying Hybrid Analysis database…"):
            if run_ha:
                ha_res = analyze_hash_ha(raw_hash, ha_key)
            else:
                ha_res = HAResult(); ha_res.errors.append("HA toggle is off")

    # ── IP Address ────────────────────────────────────────────────────
    else:
        raw_ha_ip = ha_ip_inp.strip()
        if not raw_ha_ip:
            prog.empty(); st.warning("Please enter an IP address."); return
        if not _IP_RE.match(raw_ha_ip):
            prog.empty(); st.error("Invalid IP address format."); return
        ha_target = raw_ha_ip
        ha_itype  = "ip"
        prog.progress(20, "Searching Hybrid Analysis for IP associations…")
        with st.spinner("Querying Hybrid Analysis for associated samples…"):
            if run_ha:
                ha_res = analyze_domain_ip_ha(raw_ha_ip, ha_key)
            else:
                ha_res = HAResult(); ha_res.errors.append("HA toggle is off")

    prog.progress(90, "Parsing sandbox report…")
    time.sleep(0.2)
    prog.progress(100, "Done.")
    time.sleep(0.3)
    prog.empty()

    if ha_res is None:
        st.error("❌ Sandbox pipeline returned no result.")
        return

    render_ha_results(ha_res, ha_itype, ha_target, ts, ollama_model=ollama_model)

    log_analysis(
        pipeline     = f"sandbox_{ha_itype}",
        target       = str(ha_target)[:80],
        score        = ha_res.verdict_score,
        threat_level = ha_res.verdict.upper(),
        ioc_count    = len(ha_res.iocs),
    )

    st.markdown("---")
    st.markdown('<p class="slabel">Export CTI Report</p>', unsafe_allow_html=True)
    with st.spinner("Generating PDF report…"):
        try:
            from backend.ai_analyzer import generate_ha_ai_summary
            _ha_ai_sum = generate_ha_ai_summary(ha_res, model=ollama_model)
            pdf_bytes  = generate_ha_cti_report(
                ha_res, ha_itype, str(ha_target)[:80], ts, ai_summary=_ha_ai_sum
            )
            safe_name = str(ha_target)[:40].replace("http://","").replace("https://","").replace("/","_")
            st.download_button(
                label="Download CTI Report",
                data=pdf_bytes,
                file_name=f"GhostWire_CTI_Sandbox_{safe_name}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation error: {e}")
