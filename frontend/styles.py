"""
frontend/styles.py
------------------
All CSS for GhostWire CTI v6.
"""

GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap');

/* ── Base ── */
html,body,[data-testid="stAppViewContainer"]{
  background:#060a10;color:#c0d4e8;font-family:'Syne',sans-serif
}
[data-testid="stHeader"]{background:transparent}
[data-testid="stSidebar"]{
  background:#080d15;border-right:1px solid rgba(0,255,180,0.1)
}
[data-testid="stAppViewContainer"]::before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:repeating-linear-gradient(
    0deg,rgba(0,255,180,0.012) 0,rgba(0,255,180,0.012) 1px,transparent 1px,transparent 5px
  )
}

/* ── Hero ── */
.hero{text-align:center;padding:1.5rem 0 0.5rem}
.hero h1{
  font-family:'Space Mono',monospace;
  font-size:clamp(1.4rem,3vw,2.4rem);
  background:linear-gradient(135deg,#00ffb4 0%,#00c8ff 50%,#ff2d8a 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;margin:0
}
.hero p{color:#3a5a7a;font-size:0.7rem;letter-spacing:0.2em;text-transform:uppercase;margin-top:0.3rem}

/* ── Section labels ── */
.slabel{
  font-family:'Space Mono',monospace;font-size:0.6rem;
  letter-spacing:0.22em;text-transform:uppercase;color:#00ffb4;
  border-bottom:1px solid rgba(0,255,180,0.1);padding-bottom:0.3rem;margin:1rem 0 0.55rem
}

/* ── Cards ── */
.card{
  background:rgba(255,255,255,0.022);border:1px solid rgba(255,255,255,0.07);
  border-radius:10px;padding:1rem 1.3rem;margin-bottom:0.85rem
}
.card-hi{border-color:rgba(0,255,180,0.2);background:rgba(0,255,180,0.025)}
.card-warn{border-color:rgba(255,45,85,0.35);background:rgba(255,45,85,0.06)}

/* ── Engine score bars ── */
.ebar{margin-bottom:0.6rem}
.ebar-label{
  font-family:'Space Mono',monospace;font-size:0.62rem;
  letter-spacing:0.08em;text-transform:uppercase;color:#4a6a8a;
  margin-bottom:0.18rem;display:flex;justify-content:space-between
}
.ebar-track{height:4px;background:#0f1c2a;border-radius:3px}
.ebar-fill{height:4px;border-radius:3px}

/* ── IOC / Badge system ── */
.ioc-badge{
  display:inline-block;background:rgba(255,45,85,0.12);
  border:1px solid rgba(255,45,85,0.3);color:#ff6b8a;
  font-family:'Space Mono',monospace;font-size:0.62rem;
  padding:0.18rem 0.42rem;border-radius:4px;margin:0.15rem;word-break:break-all
}
.rule-badge{
  display:inline-block;background:rgba(255,208,96,0.1);
  border:1px solid rgba(255,208,96,0.3);color:#ffd060;
  font-family:'Space Mono',monospace;font-size:0.62rem;
  padding:0.18rem 0.42rem;border-radius:4px;margin:0.15rem
}
.ok-badge{
  display:inline-block;background:rgba(0,255,180,0.08);
  border:1px solid rgba(0,255,180,0.25);color:#00ffb4;
  font-family:'Space Mono',monospace;font-size:0.62rem;
  padding:0.18rem 0.42rem;border-radius:4px;margin:0.15rem
}

/* ── Detection flags ── */
.flag-item{
  font-family:'Space Mono',monospace;font-size:0.7rem;color:#8aaac8;
  padding:0.28rem 0;border-bottom:1px solid rgba(255,255,255,0.04);line-height:1.5
}
.flag-item:last-child{border-bottom:none}
.flag-item::before{content:"›  ";color:#00ffb4}

/* ── Threat banner ── */
.threat-banner{border-radius:12px;padding:1.3rem;text-align:center;margin:0.4rem 0 0.9rem}
.threat-label{font-family:'Space Mono',monospace;font-size:0.6rem;letter-spacing:0.25em;text-transform:uppercase;opacity:0.6}
.threat-value{font-family:'Space Mono',monospace;font-size:2.4rem;font-weight:700;line-height:1.1}
.threat-score{font-family:'Space Mono',monospace;font-size:0.9rem;opacity:0.45}

/* ── Behavioral signal pills ── */
.sig-pill{border-radius:8px;padding:0.6rem 0.4rem;text-align:center;border:1px solid}
.sig-pill .si{font-size:1rem;line-height:1}
.sig-pill .sn{font-family:'Space Mono',monospace;font-size:0.56rem;letter-spacing:0.1em;text-transform:uppercase;margin-top:0.2rem}

/* ── Verdict / mitigation ── */
.verdict-box{
  background:#080d15;border-radius:8px;padding:0.9rem 1.1rem;
  font-family:'Space Mono',monospace;font-size:0.72rem;line-height:1.75;
  color:#a0c0d8;border-left:3px solid
}
.mit-step{
  font-size:0.82rem;color:#c0d4e8;padding:0.45rem 0.4rem 0.45rem 0.7rem;
  border-bottom:1px solid rgba(255,255,255,0.04);line-height:1.5
}
.mit-step:last-child{border-bottom:none}
.ai-box{
  background:rgba(196,122,255,0.05);border:1px solid rgba(196,122,255,0.18);
  border-radius:8px;padding:0.85rem 1rem;font-family:'Space Mono',monospace;
  font-size:0.72rem;line-height:1.75;color:#b8c8d8
}

/* ── Override / warning banners ── */
.override-banner{
  background:rgba(255,45,85,0.08);border:1px solid rgba(255,45,85,0.35);
  border-radius:8px;padding:0.75rem 1rem;font-family:'Space Mono',monospace;
  font-size:0.72rem;color:#ff6b8a;margin:0.5rem 0;line-height:1.6
}
.rule-banner{
  background:rgba(255,208,96,0.06);border:1px solid rgba(255,208,96,0.25);
  border-radius:8px;padding:0.65rem 0.9rem;font-family:'Space Mono',monospace;
  font-size:0.7rem;color:#ffd060;margin:0.35rem 0
}

/* ── SSL cert rows ── */
.cert-row{
  display:flex;justify-content:space-between;font-family:'Space Mono',monospace;
  font-size:0.68rem;padding:0.28rem 0;border-bottom:1px solid rgba(255,255,255,0.04)
}
.cert-row:last-child{border-bottom:none}
.cert-key{color:#3a5a7a}
.cert-val{color:#c0d4e8;word-break:break-all;text-align:right;max-width:60%}

/* ── MITRE ATT&CK cards (v5 redesign) ── */
.mitre-card{
  background:linear-gradient(135deg,rgba(0,200,255,0.06) 0%,rgba(0,255,180,0.04) 100%);
  border:1px solid rgba(0,200,255,0.2);border-radius:10px;
  padding:0.75rem 1rem;margin-bottom:0.6rem;position:relative;overflow:hidden
}
.mitre-card::before{
  content:"";position:absolute;top:0;left:0;width:3px;height:100%;
  background:linear-gradient(180deg,#00c8ff,#00ffb4)
}
.mitre-tac-id{
  font-family:'Space Mono',monospace;font-size:0.62rem;
  background:rgba(0,200,255,0.15);border:1px solid rgba(0,200,255,0.4);
  color:#00c8ff;border-radius:4px;padding:0.2rem 0.55rem;
  display:inline-block;margin-right:0.5rem
}
.mitre-tech-id{
  font-family:'Space Mono',monospace;font-size:0.6rem;
  background:rgba(0,255,180,0.08);border:1px solid rgba(0,255,180,0.25);
  color:#00ffb4;border-radius:4px;padding:0.15rem 0.45rem;
  display:inline-block
}
.mitre-tac-name{
  font-family:'Syne',sans-serif;font-size:0.82rem;font-weight:600;
  color:#c0d4e8;margin-top:0.3rem
}
.mitre-desc{
  font-family:'Space Mono',monospace;font-size:0.62rem;
  color:#4a6a8a;margin-top:0.2rem;line-height:1.5
}
.mitre-phase{
  position:absolute;top:0.5rem;right:0.8rem;
  font-family:'Space Mono',monospace;font-size:0.55rem;
  letter-spacing:0.15em;text-transform:uppercase;
  color:rgba(0,200,255,0.4)
}

/* ── Confidence meter ── */
.conf-meter{
  background:#0a1520;border:1px solid rgba(0,255,180,0.1);
  border-radius:8px;padding:0.7rem 1rem;margin-bottom:0.5rem
}
.conf-label{
  font-family:'Space Mono',monospace;font-size:0.58rem;
  letter-spacing:0.2em;text-transform:uppercase;color:#3a5a7a
}
.conf-value{
  font-family:'Space Mono',monospace;font-size:1.8rem;
  font-weight:700;color:#00c8ff;line-height:1.1
}
.conf-bar-track{height:3px;background:#0f1c2a;border-radius:2px;margin-top:0.4rem}
.conf-bar-fill{height:3px;border-radius:2px;background:linear-gradient(90deg,#00ffb4,#00c8ff)}

/* ── Confidence factors ── */
.cfac-row{
  display:flex;justify-content:space-between;align-items:center;
  font-family:'Space Mono',monospace;font-size:0.62rem;
  color:#4a6a8a;padding:0.22rem 0
}
.cfac-bar{height:3px;background:#0f1c2a;border-radius:2px;margin-top:0.15rem}
.cfac-fill{height:3px;border-radius:2px}

/* ── Source badge (VT / Abuse / DNS) ── */
.source-badge{
  display:inline-flex;align-items:center;gap:0.4rem;
  background:#080d15;border:1px solid rgba(255,255,255,0.07);
  border-radius:6px;padding:0.3rem 0.7rem;
  font-family:'Space Mono',monospace;font-size:0.65rem;
  margin-bottom:0.3rem;width:100%
}
.source-badge .sb-label{color:#3a5a7a;flex:1}
.source-badge .sb-val{font-weight:700}

/* ── Inputs & buttons ── */
textarea,[data-testid="stTextArea"] textarea{
  background:#0a1520 !important;color:#c0d4e8 !important;
  border:1px solid rgba(0,255,180,0.18) !important;
  border-radius:8px !important;font-family:'Space Mono',monospace !important;
  font-size:0.8rem !important
}
.stButton>button{
  background:linear-gradient(135deg,#00ffb4,#00c8ff) !important;
  color:#060a10 !important;font-family:'Space Mono',monospace !important;
  font-weight:700 !important;border:none !important;
  border-radius:8px !important;letter-spacing:0.08em !important
}
.stButton>button:hover{opacity:0.85 !important;transform:translateY(-1px) !important}
#MainMenu,footer,[data-testid="stToolbar"]{visibility:hidden}

/* ── Sidebar həmişə açıq — collapse düyməsini gizlət ── */
[data-testid="collapsedControl"],
button[kind="header"],
.st-emotion-cache-1egp75f,
.st-emotion-cache-czk5ss{
  display:none !important;
  visibility:hidden !important;
  pointer-events:none !important;
}
section[data-testid="stSidebar"]{
  transform:none !important;
  min-width:260px !important;
  visibility:visible !important;
}

/* ── CTI Report — Hacker Theme ── */
.cti-report-wrap{
  background:linear-gradient(180deg,#020608 0%,#060a10 100%);
  border:1px solid rgba(0,255,180,0.15);border-radius:14px;
  padding:1.5rem;position:relative;overflow:hidden
}
.cti-report-wrap::before{
  content:"";position:absolute;top:0;left:0;right:0;bottom:0;pointer-events:none;
  background:repeating-linear-gradient(
    90deg,transparent,transparent 60px,rgba(0,255,180,0.015) 60px,rgba(0,255,180,0.015) 61px
  ),repeating-linear-gradient(
    0deg,transparent,transparent 60px,rgba(0,200,255,0.01) 60px,rgba(0,200,255,0.01) 61px
  );
  z-index:0
}
.cti-report-header{
  font-family:"Space Mono",monospace;font-size:0.58rem;
  letter-spacing:0.35em;text-transform:uppercase;
  color:#00ffb4;border-bottom:1px solid rgba(0,255,180,0.12);
  padding-bottom:0.6rem;margin-bottom:1rem;
  display:flex;justify-content:space-between;align-items:center
}
.cti-report-header .cti-tlp{
  background:rgba(255,180,0,0.12);border:1px solid rgba(255,180,0,0.3);
  color:#ffb400;padding:0.15rem 0.55rem;border-radius:4px;font-size:0.55rem
}
.cti-section-title{
  font-family:"Space Mono",monospace;font-size:0.6rem;
  letter-spacing:0.3em;text-transform:uppercase;
  color:#00c8ff;margin:1.2rem 0 0.5rem;
  border-left:3px solid #00c8ff;padding-left:0.6rem
}
.cti-verdict-hacker{
  background:linear-gradient(135deg,#020a06 0%,#010608 100%);
  border:1px solid rgba(0,255,180,0.25);border-radius:10px;
  padding:1rem 1.2rem;font-family:"Space Mono",monospace;
  font-size:0.72rem;line-height:1.8;color:#7af0c0;
  position:relative;overflow:hidden
}
.cti-verdict-hacker::before{
  content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
  background:linear-gradient(180deg,#00ffb4,#00c8ff,#ff2d8a)
}
.cti-summary-hacker{
  background:rgba(0,20,10,0.6);border:1px solid rgba(0,255,180,0.1);
  border-radius:8px;padding:0.85rem 1rem;
  font-family:"Space Mono",monospace;font-size:0.7rem;
  line-height:1.8;color:#8ab8a8
}
.cti-mit-item{
  font-family:"Space Mono",monospace;font-size:0.72rem;color:#c0e8d0;
  padding:0.4rem 0.4rem 0.4rem 0.8rem;
  border-bottom:1px solid rgba(0,255,180,0.06);line-height:1.5;
  border-left:2px solid rgba(0,255,180,0.2)
}
.cti-mit-item:last-child{border-bottom:none}
.cti-ioc-wrap{display:flex;flex-wrap:wrap;gap:0.3rem;margin-top:0.4rem}
.cti-ioc-item{
  font-family:"Space Mono",monospace;font-size:0.6rem;
  background:rgba(255,45,85,0.1);border:1px solid rgba(255,45,85,0.25);
  color:#ff8aaa;border-radius:4px;padding:0.18rem 0.5rem;word-break:break-all
}
.cti-score-grid{
  display:grid;grid-template-columns:repeat(3,1fr);gap:0.5rem;margin:0.6rem 0
}
.cti-score-cell{
  background:rgba(0,255,180,0.03);border:1px solid rgba(0,255,180,0.1);
  border-radius:8px;padding:0.5rem 0.7rem;text-align:center
}
.cti-score-cell .csc-label{
  font-family:"Space Mono",monospace;font-size:0.53rem;
  letter-spacing:0.15em;text-transform:uppercase;color:#3a6a5a
}
.cti-score-cell .csc-val{
  font-family:"Space Mono",monospace;font-size:1.2rem;
  font-weight:700;color:#00ffb4;line-height:1.1
}
.cti-timestamp{
  font-family:"Space Mono",monospace;font-size:0.6rem;
  color:#2a4a3a;text-align:right;margin-top:0.8rem;letter-spacing:0.08em
}
/* Matrix rain scanline overlay on banner */
.cti-threat-banner-hacker{
  background:linear-gradient(135deg,rgba(2,8,4,0.95) 0%,rgba(2,6,10,0.95) 100%);
  border:1px solid;border-radius:12px;padding:1.5rem;text-align:center;
  position:relative;overflow:hidden;margin:0.6rem 0 1rem
}
.cti-threat-banner-hacker::after{
  content:"";position:absolute;inset:0;pointer-events:none;
  background:repeating-linear-gradient(
    0deg,rgba(0,0,0,0) 0px,rgba(0,0,0,0) 2px,rgba(0,0,0,0.15) 2px,rgba(0,0,0,0.15) 4px
  )
}
.cti-threat-banner-hacker .ctb-label{
  font-family:"Space Mono",monospace;font-size:0.55rem;
  letter-spacing:0.4em;text-transform:uppercase;opacity:0.5
}
.cti-threat-banner-hacker .ctb-value{
  font-family:"Space Mono",monospace;font-size:2.8rem;font-weight:700;
  line-height:1;text-shadow:0 0 30px currentColor
}
.cti-threat-banner-hacker .ctb-score{
  font-family:"Space Mono",monospace;font-size:0.8rem;opacity:0.4;margin-top:0.3rem
}
</style>
"""


def inject_css() -> None:
    """Call this once at the top of app.py to inject global styles."""
    import streamlit as st
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
