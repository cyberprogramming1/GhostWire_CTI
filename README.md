<div align="center">

```
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗    ██╗██╗██████╗ ███████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║    ██║██║██╔══██╗██╔════╝
 ██║  ███╗███████║██║   ██║███████╗   ██║   ██║ █╗ ██║██║██████╔╝█████╗  
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║███╗██║██║██╔══██╗██╔══╝  
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚███╔███╔╝██║██║  ██║███████╗
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝
```

**CTI v6 — Cyber Threat Intelligence Platform**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.45.0-red?style=flat-square&logo=streamlit)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-81%2F81%20passing-brightgreen?style=flat-square)](#testing)
[![Security](https://img.shields.io/badge/Security-Hardened-blue?style=flat-square)](#security-hardening)

*10-Engine · Multi-Vector · MITRE ATT&CK Heatmap · Parallel Engines · Privacy-First AI*

</div>

---

GhostWire is a professional, locally-deployable Cyber Threat Intelligence platform built for **SOC analysts, threat hunters, and incident responders**. It combines static analysis, reputation intelligence, behavioral sandboxing, and local AI inference to assess threats across five attack vectors — all from a dark terminal-style interface.

> **Privacy-first:** All AI analysis runs locally via [Ollama](https://ollama.com). No data is ever sent to external AI APIs.

---
![Url_Gif](assets/url_gif.gif)
## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Keys](#api-keys)
- [Project Structure](#project-structure)
- [Security Hardening](#security-hardening)
- [Detection Methodology](#detection-methodology)
- [MITRE ATT&CK](#mitre-attck)
- [PDF Reports](#pdf-reports)
- [Testing](#testing)
- [Performance](#performance)
- [Known Limitations](#known-limitations)

---

## Features

### 5 Analysis Pipelines

| Pipeline | Input | What it does |
|----------|-------|-------------|
| **URL / Domain** | URL, domain, IP | 10-engine parallel analysis with AI legitimacy assessment |
| **File / Hash** | File upload or hash string | VirusTotal, PE analysis, macro detection, forensics |
| **Email / SMS** | Raw headers + body or screenshot | Header forensics, SPF/DKIM/DMARC, social engineering detection |
| **IP Intelligence** | IPv4 / IPv6 | AbuseIPDB, Tor/VPN detection, ASN, Shodan, GreyNoise, geo map |
| **Sandbox** | URL, File, Hash, Domain, IP | Hybrid Analysis cloud detonation + AI threat narrative |

### 10 Detection Engines

| # | Engine | What it detects |
|---|--------|----------------|
| 1 | **URL Heuristics** | Entropy scoring, suspicious TLD, DGA patterns, encoded chars |
| 2 | **WHOIS / Domain Age** | Registration recency, registrar risk, recently-expired domains |
| 3 | **AI NLP (Ollama)** | Urgency, financial threats, manipulation — runs fully local |
| 4 | **Infrastructure Reputation** | VirusTotal engines + community votes/comments/relations, AbuseIPDB |
| 5 | **Technical Deception** | Homoglyph attacks, typosquatting, subdomain traps, brand impersonation |
| 6 | **Sandbox Simulation** | Credential harvesting, crypto drainers, malware dropper patterns |
| 7 | **SSL/TLS Certificate** | Certificate age, issuer trust, domain mismatch, self-signed |
| 8 | **Passive DNS / IP Intel** | Geolocation, ASN reputation, Tor/VPN/proxy detection |
| 9 | **Shodan Intel** | Open ports, CVEs, service banners |
| 10 | **GreyNoise Context** | Mass-scanning vs targeted traffic classification |

> **v6:** Engines 3–10 run in parallel via `ThreadPoolExecutor` — ~3-5x faster than sequential.

---

## Architecture

```
GhostWire_CTI_v6/
│
├── app.py                          # Entry point — 331 lines, dispatches to pipelines
├── config.py                       # API key loader, HA key rotator, URL defanger
├── pytest.ini                      # Test configuration
│
├── pipelines/                      # One module per analysis pipeline
│   ├── pipeline_url.py             # URL / Domain / IP — uses parallel engine runner
│   ├── pipeline_hash.py            # File / Hash forensics
│   ├── pipeline_email.py           # Email / SMS forensics
│   ├── pipeline_ip.py              # Standalone IP intelligence
│   └── pipeline_sandbox.py        # Hybrid Analysis sandbox
│
├── backend/                        # Analysis engines — all synchronous, independently testable
│   ├── async_runner.py             # ThreadPoolExecutor parallel engine coordinator
│   ├── logging_config.py           # Structured logging (level from DEBUG env var)
│   ├── heuristics.py               # URL Heuristics engine
│   ├── whois_check.py              # WHOIS / domain age
│   ├── ai_analyzer.py              # Ollama NLP + domain legitimacy + HA AI summary
│   ├── reputation.py               # VirusTotal v3 + AbuseIPDB
│   ├── deception.py                # Technical deception detection
│   ├── sandbox.py                  # Static sandbox simulation + SSRF guard
│   ├── ssl_engine.py               # SSL/TLS certificate analysis
│   ├── passive_dns.py              # Passive DNS + IP intel
│   ├── hash_engine.py              # File/hash forensics + PE analysis
│   ├── email_engine.py             # Email/SMS forensics + OCR
│   ├── ip_intel.py                 # Standalone IP intelligence
│   ├── hybrid_analysis.py          # Hybrid Analysis API + key rotation
│   ├── external_intel.py           # Shodan + GreyNoise
│   ├── scoring.py                  # Weighted scoring + AZ domain tiering + overrides
│   ├── verdict.py                  # Threat classification + mitigation steps
│   ├── pdf_report.py               # PDF CTI report generator (native charts)
│   ├── audit_log.py                # JSON audit trail with URL defanging
│   └── whois_timeline.py           # WHOIS + cert history timeline builder
│
├── frontend/                       # UI rendering — all Streamlit components
│   ├── styles.py                   # GhostWire dark terminal CSS
│   ├── components.py               # Gauges, MITRE heatmap, cards, IOC chips
│   ├── url_renderer.py             # URL/Domain results renderer
│   ├── ha_renderer.py              # Hybrid Analysis results + AI summary
│   ├── other_renderers.py          # Hash / Email / IP renderers
│   └── extra_widgets.py            # Threat map, WHOIS timeline, Shodan/GreyNoise panels
│
└── tests/                          # Unit test suite (81 tests, all passing)
    ├── conftest.py
    ├── test_scoring.py             # AZ domain tiering, brand squatting, overrides
    ├── test_ssrf.py                # SSRF guard — all private/reserved ranges
    ├── test_hash_validation.py     # Hash format + domain sanitization
    └── test_config.py              # Defanging, key rotation, IP privacy check
```

---

## Quick Start

### Prerequisites

- Python **3.11+**
- [Ollama](https://ollama.com/download) — for AI features (optional but recommended)

### Installation

```bash
# 1. Clone
git clone https://github.com/yourusername/GhostWire_CTI.git
cd GhostWire_CTI

# 2. Virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Dependencies
pip install -r requirements.txt

# 4. Playwright browser (screenshot engine)
playwright install chromium

# 5. Pull an Ollama model
ollama pull phi3:mini            # Recommended — fast, 2.3 GB
# ollama pull llama3             # More capable, 4.7 GB
# ollama pull mistral            # Balanced, 4.1 GB

# 6. Configure API keys
cp .env.example .env
nano .env                        # Fill in your keys

# 7. Run
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501)

---

## Configuration

### `.env` file

```env
# ── Required ──────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY=your_vt_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# ── Optional ──────────────────────────────────────────────────────────
SHODAN_API_KEY=your_shodan_key_here
GREYNOISE_API_KEY=your_greynoise_key_here

# ── Hybrid Analysis — supports key rotation ───────────────────────────
# Add multiple keys for automatic round-robin rotation.
# When one key hits rate limit (429), the pool cools it for 65s
# and switches to the next key automatically.
HYBRID_ANALYSIS_API_KEY=your_primary_ha_key
HYBRID_ANALYSIS_API_KEY_2=your_second_ha_key
HYBRID_ANALYSIS_API_KEY_3=your_third_ha_key

# ── Ollama (local AI) ─────────────────────────────────────────────────
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=phi3:mini

# ── Tuning ────────────────────────────────────────────────────────────
SANDBOX_MAX_BYTES=524288        # Max page content fetched (bytes)
REQUEST_TIMEOUT=8               # HTTP timeout per request (seconds)
DEBUG=false                     # Set true for full engine telemetry logs
GHOSTWIRE_LOG_PATH=             # Custom audit log path (default: ~/.ghostwire/audit.jsonl)
```

### Hybrid Analysis key rotation

GhostWire supports up to **10 HA keys** in the pool. This is useful because the free tier is limited to 5 submissions/hour per key:

```env
HYBRID_ANALYSIS_API_KEY=key_1
HYBRID_ANALYSIS_API_KEY_2=key_2
HYBRID_ANALYSIS_API_KEY_3=key_3
# ... up to HYBRID_ANALYSIS_API_KEY_10
```

The pool uses round-robin rotation. When a key gets rate-limited (HTTP 429), it enters a 65-second cooldown and the next available key is used automatically. The sidebar shows how many keys are loaded.

### Logging

```bash
# Default: WARNING level (only real problems logged)
streamlit run app.py

# Debug mode: full engine telemetry
DEBUG=true streamlit run app.py
```

---

## API Keys

| Service | Free Tier | Required | Get it |
|---------|-----------|----------|--------|
| VirusTotal | 4 req/min, 500/day | **Yes** | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | 1,000 req/day | **Yes** | [abuseipdb.com/register](https://www.abuseipdb.com/register) |
| Shodan | InternetDB (limited) | No | [account.shodan.io](https://account.shodan.io) |
| GreyNoise | Community API | No | [greynoise.io/signup](https://www.greynoise.io/signup) |
| Hybrid Analysis | 5 submissions/hr | No | [hybrid-analysis.com/signup](https://www.hybrid-analysis.com/signup) |
| Ollama | Free, runs locally | No | [ollama.com/download](https://ollama.com/download) |

GhostWire works with only **VirusTotal + AbuseIPDB**. Every other source degrades gracefully when not configured.

---

## Project Structure

### Sidebar toggles

Every engine can be enabled/disabled at runtime from the sidebar:

| Toggle | Effect |
|--------|--------|
| Sandbox Analysis | Local static sandbox simulation |
| AI NLP (Ollama) | Local LLM analysis |
| SSL/TLS Certificate | Certificate inspection |
| Passive DNS + IP Intel | Geolocation + ASN |
| Site Screenshot | Playwright Chromium capture |
| WHOIS Timeline | Registration + cert history chart |
| Shodan Intel | Port/CVE/banner analysis |
| GreyNoise Context | Scanner classification |
| Hybrid Analysis Sandbox | Cloud detonation |

### Hybrid Analysis sandbox environments

Select from the sidebar before submitting:

| Environment | Use case |
|-------------|----------|
| Windows 10 64-bit | Modern PE files, Office docs, scripts |
| Windows 7 32-bit | Legacy malware, older exploits |
| Android | APK files, mobile malware |

---

## Security Hardening

GhostWire was built with defence-in-depth across every layer.

### Input validation

| Input | Constraint | Enforced at |
|-------|-----------|-------------|
| URL | Max 2,048 chars | UI + pipeline |
| Hash | Strict hex regex: 32/40/64 chars only | UI + `_validate_hash()` |
| IP address | `[\d.:a-fA-F]{2,45}` pattern | UI + pipeline |
| Email body | Max 50 KB | UI |
| File upload | Max 50 MB | UI + pipeline |
| Email screenshot | Max 10 MB | UI + pipeline |
| HA file submission | Max 100 MB | pipeline + HA engine |
| Domain/IP for HA search | Allowlist regex, max 253 chars | `_sanitize_domain()` |

### SSRF protection

Every outbound HTTP request passes through `_is_ssrf_target()` before execution:

```
Blocked ranges:  127.x.x.x  10.x.x.x  172.16-31.x.x  192.168.x.x
                 169.254.x.x (AWS metadata)  ::1  fe80::/10
Blocked schemes: file://  ftp://  gopher://  data:  dict://  ldap://  ldaps://
Redirect chains: re-validated at every hop
Playwright:      SSRF guard runs before browser launch + network layer blocking
```

### XSS prevention

- All user-supplied strings rendered through `html.escape()` at every call site
- `unsafe_allow_html=True` only used with pre-escaped strings
- No raw f-string HTML injection points in any renderer
- Content-Security-Policy configured in `.streamlit/config.toml`:
  ```
  frame-ancestors 'none'   object-src 'none'   form-action 'self'
  ```

### Code safety

- **No `eval`, `exec`, or `pickle`** anywhere in the codebase
- **No `shell=True`** in any subprocess call
- **No `verify=False`** — SSL verification always enabled
- **No hardcoded secrets** — all values from environment only
- API keys never logged — replaced with `***` in any exception string
- `Config` object is read-only after initialization (`__slots__` enforced)

### Playwright browser hardening

```python
java_script_enabled = False      # JS disabled at context level
bypass_csp         = False
permissions        = []          # No permissions granted
storage_state      = None        # Isolated — no cookies survive
# Script/XHR/fetch/WebSocket blocked at network layer (second layer)
# Hard 8-second navigation timeout
# --no-sandbox NOT used — setuid-sandbox disable used instead
```

### Audit log security

- All targets **defanged** before writing: `https://evil.com` → `hxxps://evil[.]com`
- Log rotates automatically at 50 MB
- Logging failures never crash the pipeline (`except Exception: pass`)

### HTTP security headers (`.streamlit/config.toml`)

```toml
"X-Content-Type-Options"  = "nosniff"
"X-Frame-Options"         = "DENY"
"Referrer-Policy"         = "no-referrer"
"Permissions-Policy"      = "geolocation=(), microphone=(), camera=()"
```

### Thread safety

`async_runner.py` runs engines concurrently via `ThreadPoolExecutor`:

- No shared mutable state between threads
- Each engine creates its own `requests.Session`
- Exceptions caught per-thread, returned as typed error stubs
- HA key pool uses `threading.Lock()` for safe concurrent access
- Pipeline never crashes if one engine times out (90s hard limit per engine)

### PDF injection prevention

- `_safe_str()` strips null bytes + control characters before embedding
- Score values clamped to `[0, 100]` — no bar chart overflow
- All strings truncated to safe max lengths before writing

---

## Detection Methodology

### Score weighting

| Engine | Max contribution |
|--------|-----------------|
| SSL/TLS Certificate | 50 |
| WHOIS / Domain Age | 40 |
| Infrastructure Reputation | 40 |
| URL Heuristics | 30 |
| AI NLP | 30 |
| Technical Deception | 30 |
| Sandbox Simulation | 30 |
| Passive DNS / IP | 30 |

Raw scores are summed then normalized by ÷2 to prevent score inflation from multiple engines firing simultaneously.

### Threat levels

| Score | Level | Meaning |
|-------|-------|---------|
| 0–19 | **SAFE** | No significant indicators |
| 20–39 | **LOW** | Minor anomalies, likely benign |
| 40–64 | **MEDIUM** | Multiple suspicious signals |
| 65–84 | **HIGH** | Strong phishing/malware indicators |
| 85–100 | **CRITICAL** | Confirmed malicious infrastructure |

### Override rules

| Rule | Condition | Effect |
|------|-----------|--------|
| Infrastructure Override | VT detections > 8 engines | Score locked to CRITICAL (85+) |
| High Abuse | AbuseIPDB ≥ 90% | Score locked to CRITICAL |
| Brand Squatting | 2+ squatting keywords in hostname | +35 penalty |
| AI Legitimacy Veto | Ollama confirms domain is legitimate (high/medium confidence) | VT relations signal suppressed — prevents false positives |
| AZ Domain Tiering | `.az` / `.gov.az` domains | Three-tier system: AZ_SAFE / AZ_REVIEW / AZ_SUSPECT |

### AZ domain tiering

GhostWire has a dedicated false-positive prevention system for Azerbaijani domains, where VT "related files" are frequently legitimate user-uploaded documents (bank statements, airline tickets, government forms):

```
AZ_SAFE    → VT=0, Abuse=0, no community signals   → Score ceiling: 19
AZ_REVIEW  → Relations only, no votes/comments      → Score ceiling: 35, relations suppressed
AZ_SUSPECT → VT detections OR abuse≥30 OR votes≥5  → Normal scoring, no ceiling
```

---

## MITRE ATT&CK

GhostWire renders an **interactive Plotly heatmap** for MITRE ATT&CK coverage:

- **X-axis:** All 14 tactic phases (Reconnaissance → Impact)
- **Y-axis:** Specific technique IDs detected
- **Cell colour:** Detection frequency — dark=zero, red=high
- **Hover:** Full tactic/technique details on mouse-over
- **Detail cards:** Expandable list below the heatmap

Techniques are mapped across:
- URL/Domain pipeline — phishing, drive-by, C2 staging
- Hybrid Analysis sandbox — full TTP execution chain
- IP Intelligence — C2 communication, scanning, exfiltration

---

## PDF Reports

Every pipeline exports a professional PDF report with native embedded charts (no external images).

| Pipeline | Report includes |
|----------|----------------|
| **URL / Domain** | Score gauge (donut) + engine bar chart, Executive Summary, Source Intel (VT/AbuseIPDB/Shodan/GreyNoise), IOCs, MITRE ATT&CK, Behavioral Signals, Mitigation Steps |
| **File / Hash** | File Intel, VirusTotal Results, Weaponization Indicators, IOCs, Recommended Actions |
| **Email / SMS** | Header Intel, Auth Analysis (SPF/DKIM/DMARC), AI Content Analysis, IOCs, Actions |
| **IP Intelligence** | Score gauge, Geolocation, ASN/ISP, Threat Intel, Shodan, GreyNoise, IOCs |
| **Hybrid Analysis** | HA verdict gauge, AI Threat Narrative, Network IOCs, Behavioral Analysis, MITRE ATT&CK, AV Detections |

All reports are classified **TLP:AMBER** with persistent header/footer on every page.

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

**81 tests, all passing.** Test coverage:

| File | Tests | Covers |
|------|-------|--------|
| `test_scoring.py` | 38 | AZ domain tiering (AZ_SAFE/REVIEW/SUSPECT), brand squatting 2-keyword rule, infra override threshold, entropy, free hosting, subdomain trap |
| `test_ssrf.py` | 22 | All blocked schemes (file/ftp/gopher/data/ldap), all private IP ranges (127/10/172.16/192.168/169.254), Streamlit port 8501 |
| `test_hash_validation.py` | 11 | MD5/SHA1/SHA256 format, injection attempts, domain sanitization |
| `test_config.py` | 10 | URL defanging, Config read-only enforcement, HA key pool round-robin + cooldown, IP privacy check |

---

## Performance

| Metric | Sequential (v5) | Parallel (v6) |
|--------|----------------|--------------|
| URL analysis wall-clock | ~25–40s | ~8–15s |
| Bottleneck | Slowest engine blocks all others | Slowest engine only |
| VT + AbuseIPDB + Shodan + GreyNoise | 4 sequential calls | 4 concurrent calls |
| Engine failure impact | Pipeline error | Graceful stub, analysis continues |

---

## Known Limitations

- **Streamlit rerun model** — each button click triggers a full page rerun. This is a Streamlit architectural constraint, not a GhostWire bug.
- **Ollama required for AI features** — all other engines work normally if Ollama is not running. AI sections are skipped with a clear warning.
- **Hybrid Analysis rate limits** — free accounts: 5 submissions/hour, 200 API calls/day. Use key pool rotation to extend this.
- **VirusTotal free tier** — 4 requests/minute. URL analysis runs 2–3 VT calls. Expect throttling on rapid successive scans.
- **Local sandbox** (Sandbox engine in URL pipeline) performs static HTTP analysis only — no JavaScript execution. Use the Hybrid Analysis tab for full dynamic detonation.
- **Screenshot engine** requires network access to the target. Disabled automatically if the site is unreachable or blocks headless browsers.

---

## Contributing

Pull requests welcome. Open an issue before starting major work.

Areas for contribution:
- Additional threat intel integrations (URLhaus, PhishTank, AlienVault OTX)
- STIX 2.1 / TAXII 2.1 export for IOC sharing
- Slack / Teams / PagerDuty alerting webhooks
- Docker Compose deployment with Nginx + TLS

---

## Acknowledgements

| Service | Used for |
|---------|----------|
| [VirusTotal](https://www.virustotal.com) | Multi-engine reputation, community signals |
| [AbuseIPDB](https://www.abuseipdb.com) | IP abuse intelligence |
| [Shodan](https://www.shodan.io) | Port / CVE / banner intel |
| [GreyNoise](https://www.greynoise.io) | Internet noise classification |
| [Hybrid Analysis](https://www.hybrid-analysis.com) | Cloud sandbox detonation |
| [Ollama](https://ollama.ai) | Local LLM inference — no data leaves machine |
| [MITRE ATT&CK](https://attack.mitre.org) | Adversarial TTP framework |
| [Streamlit](https://streamlit.io) | Python web app framework |
| [ReportLab](https://www.reportlab.com) | PDF generation + native chart rendering |
| [Plotly](https://plotly.com) | MITRE heatmap, threat map, WHOIS timeline |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

*Built for Blue Teams, SOC Analysts, and Threat Intelligence professionals.*

</div>
