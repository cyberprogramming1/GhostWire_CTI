"""
app.py — GhostWire CTI v6
--------------------------
Entry point only. All pipeline logic has been extracted to:
  pipelines/pipeline_url.py      (Problem #2 fix — modularisation)
  pipelines/pipeline_hash.py
  pipelines/pipeline_email.py
  pipelines/pipeline_ip.py
  pipelines/pipeline_sandbox.py

v6 changes vs v5:
  #1  Interactive MITRE ATT&CK heatmap (Plotly, clickable)
  #2  app.py refactored — pipelines extracted to separate modules
  #3  Parallel engine execution via ThreadPoolExecutor (async_runner.py)
  #4  PDF now includes native score gauge (donut) + engine bar chart
  #6  Map bug fixed — pure Plotly scatter_geo (no Mapbox/pydeck token needed)
  #7  Sandbox status messages differentiate URL vs Hash/IP/Domain correctly
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import streamlit as st
import validators

# ── Path setup ─────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import cfg, ha_key_pool
from backend.logging_config import setup_logging
setup_logging()   # Configure GhostWire logger (level from DEBUG env var)
from backend.hybrid_analysis import ENV_WIN10_64, ENV_WIN7_32, ENV_ANDROID
from backend.audit_log       import get_log_path_str
from frontend.styles         import inject_css

# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="GhostWire CTI",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_css()

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown('<p class="slabel">API Keys</p>', unsafe_allow_html=True)

    vt_key     = cfg.VIRUSTOTAL_API_KEY
    abuse_key  = cfg.ABUSEIPDB_API_KEY
    shodan_key = cfg.SHODAN_API_KEY
    ha_key     = cfg.HYBRID_ANALYSIS_API_KEY

    for label, key in [
        ("VIRUSTOTAL",       vt_key),
        ("ABUSEIPDB",        abuse_key),
        ("SHODAN",           shodan_key),
        ("HYBRID ANALYSIS",  ha_key),
    ]:
        c = "#00ffb4" if key else "#ff5f87"
        s = "LOADED ✓" if key else "NOT SET ✗"
        st.markdown(
            f'<div style="font-family:Space Mono,monospace;font-size:0.68rem;'
            f'background:#080d15;border:1px solid rgba(0,255,180,0.08);'
            f'border-radius:6px;padding:0.45rem 0.75rem;margin-bottom:0.35rem">'
            f'<span style="color:#2a4060">{label}</span>'
            f'<span style="color:{c};float:right">{s}</span></div>',
            unsafe_allow_html=True,
        )

    if ha_key_pool.count > 1:
        st.markdown(
            f'<div style="font-family:Space Mono,monospace;font-size:0.65rem;'
            f'background:#080d15;border:1px solid rgba(0,255,180,0.06);'
            f'border-radius:6px;padding:0.35rem 0.75rem;margin-bottom:0.35rem;'
            f'color:#4a6a8a">'
            f'HA key rotation: <span style="color:#00ffb4">{ha_key_pool.count} keys</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<p class="slabel">Options</p>', unsafe_allow_html=True)
    run_sandbox    = st.toggle("Sandbox Analysis",        value=True)
    run_ai         = st.toggle("AI NLP (Ollama)",         value=True)
    run_ssl        = st.toggle("SSL/TLS Certificate",     value=True)
    run_pdns       = st.toggle("Passive DNS + IP Intel",  value=True)
    run_screenshot = st.toggle("Site Screenshot",         value=True)
    run_timeline   = st.toggle("WHOIS Timeline",          value=True)
    run_shodan     = st.toggle("Shodan Intel",            value=True)
    run_greynoise  = st.toggle("GreyNoise Context",       value=True)
    run_ha         = st.toggle("Hybrid Analysis Sandbox", value=True)

    ha_env_map = {
        "Windows 10 64-bit": ENV_WIN10_64,
        "Windows 7 32-bit":  ENV_WIN7_32,
        "Android":           ENV_ANDROID,
    }
    ha_env_label = st.selectbox("HA Environment", list(ha_env_map.keys()), index=0,
                                help="Sandbox OS environment for URL/File analysis")
    ha_env_id = ha_env_map[ha_env_label]

    _models      = ["phi3:mini", "llama3", "llama3.2", "mistral"]
    _idx         = _models.index(cfg.OLLAMA_MODEL) if cfg.OLLAMA_MODEL in _models else 0
    ollama_model = st.selectbox("Ollama Model", _models, index=_idx)

    st.markdown('<p class="slabel">Engines</p>', unsafe_allow_html=True)
    st.caption(
        "1. URL Heuristics\n"
        "2. WHOIS / Domain Age\n"
        "3. AI NLP (Ollama)\n"
        "4. VirusTotal / AbuseIPDB\n"
        "5. Technical Deception\n"
        "6. Sandbox Simulation\n"
        "7. SSL/TLS Certificate\n"
        "8. Passive DNS / IP Intel\n"
        "9. Scoring + Overrides\n"
        "10. Verdict Engine\n\n"
        "⚡ v6: Engines 3-8 run in parallel"
    )
    st.markdown('<p class="slabel">Audit Log</p>', unsafe_allow_html=True)
    st.caption(f"📋 {get_log_path_str()}")


# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="hero">
  <h1>GhostWire CTI</h1>
  <p>10-Engine · Multi-Vector · MITRE ATT&CK Mapped · v6 Parallel Engines</p>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Input Tabs
# ─────────────────────────────────────────────────────────────────────────────

tab_url, tab_hash, tab_email, tab_ip, tab_sandbox = st.tabs([
    "URL / Domain",
    "File / Hash",
    "Email / SMS",
    "IP Intelligence",
    "🧪 Sandbox",
])

with tab_url:
    url_input = st.text_area(
        "url_in", label_visibility="collapsed",
        placeholder="Paste a suspicious URL, domain, or IP address…",
        height=90, max_chars=2048,
    )
    c1, _ = st.columns([1, 4])
    with c1:
        url_go = st.button("Analyse", use_container_width=True, key="url_go")

with tab_hash:
    st.markdown(
        '<p style="color:#3a5a7a;font-size:0.75rem;font-family:Space Mono,monospace">'
        'SHA-256 / SHA-1 / MD5 hash lookup or upload a file for forensic analysis.</p>',
        unsafe_allow_html=True,
    )
    hash_input  = st.text_input("hash_in", label_visibility="collapsed",
                                 placeholder="44d88612fea8a8f36de82e1278abb02f  (paste hash here)",
                                 max_chars=128)
    file_upload = st.file_uploader(
        "Upload file",
        type=["pdf","doc","docx","xls","xlsx","xlsm","exe","dll","zip",
              "js","ps1","bat","vbs","eml","msg"],
        help="PDF, Office (macro detection), PE executables, scripts, email files",
    )
    c2, _ = st.columns([1, 4])
    with c2:
        hash_go = st.button("Analyse", use_container_width=True, key="hash_go")

with tab_email:
    st.markdown(
        '<p style="color:#3a5a7a;font-size:0.75rem;font-family:Space Mono,monospace">'
        'Paste raw email/SMS (headers + body) or upload an email screenshot for OCR.</p>',
        unsafe_allow_html=True,
    )
    email_input = st.text_area(
        "email_in", label_visibility="collapsed",
        placeholder="Paste raw email/SMS (headers + body)",
        height=120, max_chars=50000,
    )
    email_img = st.file_uploader(
        "Email screenshot (PNG/JPG)",
        type=["png","jpg","jpeg","webp"],
        key="email_img_up",
    )
    c3, _ = st.columns([1, 4])
    with c3:
        email_go = st.button("Analyse Email / SMS", use_container_width=True, key="email_go")

with tab_ip:
    st.markdown(
        '<p style="color:#3a5a7a;font-size:0.75rem;font-family:Space Mono,monospace">'
        'Standalone IP address intelligence — AbuseIPDB, Tor, VPN, ASN, geo.</p>',
        unsafe_allow_html=True,
    )
    ip_input = st.text_input(
        "ip_in", label_visibility="collapsed",
        placeholder="185.220.101.47", max_chars=45,
    )
    c4, _ = st.columns([1, 4])
    with c4:
        ip_go = st.button("Analyse IP", use_container_width=True, key="ip_go")

with tab_sandbox:
    st.markdown(
        '<p style="color:#3a5a7a;font-size:0.75rem;font-family:Space Mono,monospace">'
        'Hybrid Analysis Cloud Sandbox — URL / File / Hash / Domain / IP detonation.</p>',
        unsafe_allow_html=True,
    )
    ha_input_type = st.radio(
        "ha_type", ["URL / Domain", "File", "Hash", "IP Address"],
        horizontal=True, label_visibility="collapsed",
    )

    ha_url_input = ha_hash_inp = ha_ip_inp = ""
    ha_file_up = None

    if ha_input_type == "URL / Domain":
        ha_url_input = st.text_area(
            "ha_url_in", label_visibility="collapsed",
            placeholder="Paste URL or domain for sandbox detonation…",
            height=80, max_chars=2048,
        )
    elif ha_input_type == "File":
        ha_file_up = st.file_uploader(
            "Upload file for sandbox",
            type=["pdf","doc","docx","xls","xlsx","xlsm","exe","dll",
                  "zip","js","ps1","bat","vbs","eml","msg","py","sh","jar"],
            key="ha_file_up",
        )
    elif ha_input_type == "Hash":
        ha_hash_inp = st.text_input(
            "ha_hash_in", label_visibility="collapsed",
            placeholder="SHA-256 / SHA-1 / MD5 hash...", max_chars=128,
        )
    else:
        ha_ip_inp = st.text_input(
            "ha_ip_in", label_visibility="collapsed",
            placeholder="185.220.101.47", max_chars=45,
        )

    c5, _ = st.columns([1, 4])
    with c5:
        ha_go = st.button(
            "Detonate in Sandbox", use_container_width=True,
            key="ha_go", type="primary",
        )


# ─────────────────────────────────────────────────────────────────────────────
# URL input normalisation helper (shared)
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_url(raw: str) -> str:
    raw = raw.strip()
    return ("http://" + raw) if raw and not raw.startswith(("http://","https://")) else raw


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline dispatch
# ─────────────────────────────────────────────────────────────────────────────

if url_go:
    raw = url_input.strip()
    if not raw:
        st.warning("Please enter a URL, domain, or IP address.")
        st.stop()
    if len(raw) > 2048:
        st.error("❌ Input too long (max 2048 characters).")
        st.stop()

    from pipelines.pipeline_url import run as _run_url
    _run_url(
        _normalise_url(raw),
        vt_key=vt_key, abuse_key=abuse_key, shodan_key=shodan_key,
        ollama_model=ollama_model,
        run_ai=run_ai, run_sandbox=run_sandbox, run_ssl=run_ssl,
        run_pdns=run_pdns, run_screenshot=run_screenshot,
        run_timeline=run_timeline, run_shodan=run_shodan,
        run_greynoise=run_greynoise,
    )

elif hash_go:
    from pipelines.pipeline_hash import run as _run_hash
    _run_hash(
        hash_input=hash_input,
        file_upload=file_upload,
        vt_key=vt_key,
    )

elif email_go:
    from pipelines.pipeline_email import run as _run_email
    _run_email(email_input=email_input, email_img=email_img)

elif ip_go:
    ip_raw = ip_input.strip()
    if not ip_raw:
        st.warning("Please enter an IP address.")
        st.stop()
    from pipelines.pipeline_ip import run as _run_ip
    _run_ip(
        ip_raw=ip_raw,
        abuse_key=abuse_key, vt_key=vt_key, shodan_key=shodan_key,
        run_shodan=run_shodan, run_greynoise=run_greynoise,
    )

elif ha_go:
    from pipelines.pipeline_sandbox import run as _run_sandbox
    _run_sandbox(
        ha_input_type=ha_input_type,
        ha_url_input=ha_url_input,
        ha_file_up=ha_file_up,
        ha_hash_inp=ha_hash_inp,
        ha_ip_inp=ha_ip_inp,
        ha_key=ha_key,
        ha_env_id=ha_env_id,
        run_ha=run_ha,
        ollama_model=ollama_model,
    )
