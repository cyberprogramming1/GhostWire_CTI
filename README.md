```
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗    ██╗██╗██████╗ ███████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║    ██║██║██╔══██╗██╔════╝
██║  ███╗███████║██║   ██║███████╗   ██║   ██║ █╗ ██║██║██████╔╝█████╗
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║███╗██║██║██╔══██╗██╔══╝
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚███╔███╔╝██║██║  ██║███████╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝

                    C T I   P L A T F O R M   v 6
         [ 10-Engine · Multi-Vector · MITRE ATT&CK Mapped · Parallel ]
```

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12-00ffb4?style=for-the-badge&logo=python&logoColor=black)
![Streamlit](https://img.shields.io/badge/Streamlit-1.40+-00c8ff?style=for-the-badge&logo=streamlit&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-Ready-0db7ed?style=for-the-badge&logo=docker&logoColor=white)
![STIX](https://img.shields.io/badge/STIX-2.1-c47aff?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-ff2d55?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-ffd060?style=for-the-badge)

**Track the adversary. Measure the threat. Export the report.**

<br>

![GhostWire IP Intelligence](assets/IP_Intelligence.gif)

</div>

---

## `> whoami`

**GhostWire CTI** is an open-source, locally-run Cyber Threat Intelligence platform with a parallel engine architecture. It processes URLs, domains, IPs, file hashes, emails/SMS, and sandbox detonations through 10 independent analysis engines simultaneously.

All analysis runs **on your machine**. No data leaves your environment — Ollama AI runs locally. External APIs are query-only: you ask, they answer.

```
TARGET ──► [URL / IP / HASH / EMAIL / FILE]
                    │
          ┌─────────▼─────────┐
          │  10 ENGINE POOL   │  ← concurrent.futures (parallel)
          │                   │
          │  1. Heuristics    │  URL structural analysis
          │  2. WHOIS         │  Domain age, registrar
          │  3. AI NLP        │  Ollama LLM (local)
          │  4. VirusTotal    │  70+ AV engines
          │  5. Deception     │  Typosquatting, homoglyph
          │  6. Sandbox       │  Behavioral simulation
          │  7. SSL/TLS       │  Certificate analysis
          │  8. Passive DNS   │  IP intel, ASN, geo
          │  9. Shodan        │  Port scan, CVE, banner
          │  10. GreyNoise    │  Internet scanner classification
          │                   │
          │  + URLhaus        │  abuse.ch malware URL DB
          │  + OTX            │  AlienVault threat intel
          │  + Hybrid Anal.   │  Cloud sandbox detonation
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │  SCORING ENGINE   │  0–100 risk score
          │  VERDICT ENGINE   │  SAFE/LOW/MEDIUM/HIGH/CRITICAL
          │  STIX 2.1 EXPORT  │  TAXII-compatible IOC bundle
          │  PDF REPORT       │  Forensic report (ReportLab)
          │  AUDIT LOG        │  JSONL audit trail
          └───────────────────┘
```

---

## `> ls -la features/`

### Analysis Pipelines (5 Tabs)

| Tab | What it analyzes | Parallel Engines |
|-----|-----------------|-----------------|
| **URL / Domain** | Any URL, domain, or IP | 10+ |
| **File / Hash** | SHA-256/SHA-1/MD5 lookup or file upload | 4 |
| **Email / SMS** | Raw headers + body, OCR screenshot | 7 |
| **IP Intelligence** | Standalone deep IP analysis | 6 |
| **🧪 Sandbox** | Hybrid Analysis cloud detonation | HA API |

### 10 Analysis Engines

```
ENGINE 1 ── URL Heuristics
  ├─ URL length penalty (>75 = suspicious, >100 = high risk)
  ├─ '@' symbol detection (credential obfuscation trick)
  ├─ Raw IP address in URL (instead of domain name)
  ├─ HTTP vs HTTPS check
  ├─ Suspicious TLDs (.tk, .ml, .cf, .ga, .gq)
  ├─ Excessive subdomains (≥4 = subdomain trap)
  ├─ Long random path segments
  ├─ Suspicious keywords (login, secure, verify, update)
  └─ Hex/base64 encoded path components

ENGINE 2 ── WHOIS / Domain Age
  ├─ Domain age (under 30 days = high risk)
  ├─ Creation/expiry date anomaly
  ├─ Registrar reputation (NjAL.la, Freenom → penalty)
  └─ Privacy-protected WHOIS in suspicious context

ENGINE 3 ── AI NLP (Ollama — local LLM)
  ├─ Model: phi3:mini / llama3 / llama3.2 / mistral
  ├─ URGENCY signal (24 hours, act now, final warning)
  ├─ FINANCIAL_THREAT (payment, prize, tax, crypto)
  ├─ MANIPULATION (authority impersonation, fear, scarcity)
  ├─ Domain legitimacy assessment
  └─ Structured JSON output (deterministic parsing)

ENGINE 4 ── Reputation (VirusTotal + AbuseIPDB)
  ├─ VT: 70+ AV engine scan
  ├─ VT Community votes (malicious/harmless)
  ├─ VT Community comments NLP
  ├─ VT Relations (linked malicious files)
  ├─ VT Domain popularity rank
  ├─ AbuseIPDB: confidence score + report count
  ├─ Tor exit node detection
  └─ DNS: A/MX/NS/TXT/SPF/DMARC records

ENGINE 5 ── Technical Deception
  ├─ Typosquatting (Levenshtein distance ≤2 from known brands)
  ├─ Homoglyph attack (Unicode lookalike characters)
  ├─ Punycode / IDN domain detection
  ├─ URL redirect chain depth
  ├─ Link shortener detection (bit.ly, tinyurl, t.co...)
  └─ 50+ global brand database

ENGINE 6 ── Sandbox Simulation
  ├─ HTTP response header analysis
  ├─ Server fingerprinting
  ├─ Redirect chain tracking
  ├─ Parked domain detection (content pattern matching)
  ├─ VPN/Proxy ASN identification
  └─ Content keyword matching

ENGINE 7 ── SSL/TLS Certificate
  ├─ Certificate validity (start/expiry dates)
  ├─ Free CA detection (Let's Encrypt, ZeroSSL, Buypass)
  ├─ SAN (Subject Alt Names) mismatch
  ├─ Self-signed certificate flag
  ├─ Wildcard certificate + suspicious domain combo
  └─ Certificate age (≤7 days = fresh phishing infrastructure)

ENGINE 8 ── Passive DNS + IP Intel
  ├─ IP geolocation (country, city, ASN)
  ├─ ASN-based risk (hosting provider abuse scores)
  ├─ Shared hosting density
  ├─ VPN/Proxy/Tor provider ASN recognition
  └─ PTR (reverse DNS) analysis

ENGINE 9 ── Shodan Intel
  ├─ Open port map (full port inventory)
  ├─ Service banners (HTTP, SSH, FTP, SMB...)
  ├─ CVE list (known exploits present)
  ├─ Shodan tags: tor, vpn, honeypot, cloud
  ├─ CPE (software version fingerprint)
  └─ InternetDB fallback (works without API key)

ENGINE 10 ── GreyNoise Context
  ├─ Mass internet scanner classification
  ├─ RIOT (known benign services: Google, Cloudflare...)
  ├─ Actor attribution
  ├─ Scan intent (what was it looking for?)
  └─ Community API (works without API key)
```

### Additional Threat Intelligence Layers

```
URLHAUS (abuse.ch)
  ├─ Active malware URL database
  ├─ Tags: phishing/malware/botnet/c2
  ├─ URL status (online/offline/unknown)
  ├─ Associated files (SHA256 + malware family)
  └─ Host-based lookup (domain + IP)

OTX — AlienVault Open Threat Exchange
  ├─ Pulse count (how many threat intel reports mention this IOC)
  ├─ MITRE ATT&CK technique IDs (T1566, T1059...)
  ├─ Threat actor attribution (Lazarus, APT28...)
  ├─ Campaign pulse names ("Emotet Wave 2024")
  ├─ Targeted countries/sectors
  └─ FP-safe scoring: only contributes when corroborated by VT

HYBRID ANALYSIS (Cloud Sandbox)
  ├─ URL/File/Hash/Domain/IP detonation
  ├─ Environments: Windows 10 64-bit / Windows 7 32-bit / Android
  ├─ Threat score + verdict (malicious/suspicious/clean)
  ├─ MITRE ATT&CK mapping
  ├─ Extracted IOCs (domains, IPs, registry keys, dropped files)
  ├─ Network connections (C2 traffic)
  ├─ Dropped file analysis
  ├─ Key rotation: up to 10 API keys in pool (auto-rotates on 429)
  └─ Polling: real-time status updates (max ~2 min wait)
```

---

## `> cat architecture.txt`

```
ghostwire_cti_v6/
│
├── app.py                      # Streamlit entry point — tab routing, rate limiter
├── config.py                   # Config singleton + URL defanging + HA key rotator
├── requirements.txt            # Pinned dependencies (supply-chain attack prevention)
├── Dockerfile                  # python:3.12-slim + ghostwire non-root user
├── docker-compose.yml          # ghostwire + ollama containers
│
├── backend/                    # Analysis engines — all business logic lives here
│   ├── ai_analyzer.py          # Ollama LLM client, JSON prompt engineering
│   ├── async_runner.py         # concurrent.futures parallel engine pool
│   ├── audit_log.py            # JSONL audit trail, session tracking, URL defanging
│   ├── cti_report.py           # CTIReport dataclass, score aggregator
│   ├── deception.py            # Typosquat, homoglyph, redirect, shortener detection
│   ├── email_engine.py         # Email header parser, OCR, brand impersonation
│   ├── external_intel.py       # Shodan + GreyNoise API clients
│   ├── forensic_engine.py      # Deep file forensics (PE, PDF, Office, ZIP)
│   ├── hash_engine.py          # Hash lookup, file upload, forensic pipeline
│   ├── heuristics.py           # URL structural analysis (15 checks)
│   ├── hybrid_analysis.py      # HA Cloud Sandbox, key pool rotation
│   ├── ip_intel.py             # IP standalone pipeline, geo, ASN
│   ├── logging_config.py       # Logger setup (DEBUG env var controlled)
│   ├── otx_engine.py           # AlienVault OTX — MITRE ATT&CK, pulses, actor
│   ├── passive_dns.py          # DNS, IP geo, ASN, VPN/Proxy ASN detection
│   ├── pdf_report.py           # ReportLab PDF generator (inline charts, no Plotly)
│   ├── reputation.py           # VirusTotal + AbuseIPDB API clients
│   ├── sandbox.py              # Local sandbox simulation (HTTP behavioral analysis)
│   ├── scoring.py              # Score aggregator, whitelist, override logic
│   ├── screenshot_engine.py    # Playwright Chromium (headless, JS disabled)
│   ├── ssl_engine.py           # TLS certificate analysis, CA detection
│   ├── stix_export.py          # STIX 2.1 bundle + CSV IOC export
│   ├── urlhaus_engine.py       # abuse.ch URLhaus API client
│   ├── verdict.py              # Verdict calculator, mitigation library
│   ├── whois_check.py          # WHOIS domain age, registrar analysis
│   └── whois_timeline.py       # WHOIS historical timeline builder
│
├── frontend/                   # UI rendering components
│   ├── components.py           # Shared widgets (verdict banner, IOC table, gauge...)
│   ├── extra_widgets.py        # WHOIS timeline, threat map, Shodan/GN panels
│   ├── ha_renderer.py          # Hybrid Analysis results renderer
│   ├── other_renderers.py      # Hash, email, IP pipeline renderers
│   ├── otx_panel.py            # OTX panel (MITRE chips, actor badges)
│   ├── stix_panel.py           # STIX 2.1 export UI + download buttons
│   ├── styles.py               # inject_css() — dark hacker UI, Space Mono font
│   ├── url_renderer.py         # URL pipeline main renderer
│   └── urlhaus_panel.py        # URLhaus panel renderer
│
├── pipelines/                  # Pipeline orchestrators
│   ├── pipeline_email.py       # Email/SMS analysis orchestration
│   ├── pipeline_hash.py        # Hash/File forensic pipeline
│   ├── pipeline_ip.py          # IP intelligence pipeline
│   ├── pipeline_sandbox.py     # Hybrid Analysis sandbox pipeline
│   └── pipeline_url.py         # URL/Domain/IP main pipeline
│
├── tests/                      # Unit tests (pytest)
│   ├── test_config.py          # Config loader tests
│   ├── test_email_engine.py    # Email parser tests
│   ├── test_hash_validation.py # Hash format validation
│   ├── test_otx_engine.py      # OTX engine mock tests
│   ├── test_scoring.py         # Scoring engine (whitelist, FP, squatting)
│   ├── test_ssrf.py            # SSRF protection tests
│   └── test_urlhaus_engine.py  # URLhaus mock tests
│
├── assets/                     # Screenshots, GIFs, UI media
├── .streamlit/
│   ├── config.toml             # Streamlit server configuration
│   └── secrets.toml.example    # Secrets template
└── env.example                 # API key template
```

---

## `> cat scoring_engine.md`

### Scoring Mechanism (0–100)

```
RAW SCORE calculation:

  heuristics_score     (0–30)   URL structure
  whois_score          (0–40)   Domain age
  ai_score             (0–30)   Ollama NLP
  reputation_score     (0–50)   VT + AbuseIPDB
  deception_score      (0–40)   Typosquat + homoglyph
  sandbox_score        (0–25)   Behavioral analysis
  ssl_score            (0–20)   Certificate anomaly
  pdns_score           (0–20)   Passive DNS
  shodan_score         (0–15)   Port/CVE intel
  greynoise_score      (0–15)   Scanner classification
  urlhaus_score        (0–20)   Malware URL DB
  otx_score            (0–12)   Threat intel (FP-safe)

  RAW    = Σ(engine_scores × weight)
  NORMAL = RAW / 2.0             ← normalization factor
  FINAL  = min(NORMAL, 100)      ← hard cap at 100

OVERRIDES:
  ├─ INFRA_OVERRIDE   : VT relations ≥ 8 malicious files → score locked ≥ 85
  ├─ BRAND_SQUATTING  : 2+ squatting keywords + new domain → +35 pts
  ├─ SUBDOMAIN_TRAP   : free hosting TLD + deep subdomain chain
  ├─ AZ_WHITELIST     : .gov.az / .edu.az / .mil.az → fully protected
  └─ ENTERPRISE_LIST  : paypal.com, apple.com, google.com...

VERDICT THRESHOLDS:
  SAFE      0–19    #00ffb4  (cyber green)
  LOW       20–39   #78d97a
  MEDIUM    40–64   #ffd060  (amber)
  HIGH      65–84   #ff6b35  (orange)
  CRITICAL  85–100  #ff2d55  (red)
```

---

## `> cat security_model.txt`

GhostWire implements a well-considered security model throughout the codebase:

**URL Defanging** — `config.py::defang_url()`. Every URL written to the audit log is automatically defanged: `https://evil.com` → `hxxps://evil[.]com`. Prevents accidental clicks from log viewers, email clients, and SIEM systems.

**SSRF Protection** — Tested in `tests/test_ssrf.py`. The screenshot engine (`screenshot_engine.py`) runs Playwright in headless + JavaScript-disabled mode. `run_screenshot` defaults to **off**.

**WHOIS Injection Prevention** — `whois_check.py::_extract_root_domain()` sanitizes the domain string with strict regex (`[a-zA-Z0-9.-_]` only) before passing it to `python-whois`, which shells out to the system `whois` binary.

**Supply Chain Attack Prevention** — All packages in `requirements.txt` are pinned with `==`. The comment reads: *"To update: audit changelog first, then update version + re-test."*

**Non-root Docker User** — The Dockerfile creates a `ghostwire` user with UID/GID 1000. The container never runs as root.

**Rate Limiting** — `app.py` enforces two-layer rate limiting:
- Minimum gap: 5 seconds between requests (same session)
- Per-minute cap: max 10 requests per 60-second window

**HA Key Rotation** — `config.py::_HAKeyRotator`. Thread-safe round-robin pool supporting up to 10 Hybrid Analysis API keys. On 429, the offending key cools down for 65 seconds and the pool automatically switches to the next available key.

**Audit Trail** — `backend/audit_log.py`. Every analysis is written to `~/.ghostwire/audit.jsonl` in JSONL format. Fields: session ID, hostname, request sequence number, defanged target, verdict, score, duration.

**FP-Safe OTX Scoring** — OTX pulse count alone never increases the score. It only contributes when VirusTotal also flags the indicator (`vt_malicious > 0`). Protects against stale or low-quality community pulses causing false positives.

---

## `> cat install.md`

### Requirements

- Python 3.12+
- [Ollama](https://ollama.ai) — for local AI
- API keys (see table below)

### Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/GhostWire_CTI_v6.git
cd GhostWire_CTI_v6

# 2. Virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Playwright Chromium (screenshot engine)
python -m playwright install chromium

# 5. Configure environment
cp env.example .env
# Open .env and fill in your API keys

# 6. Pull Ollama model
ollama pull phi3:mini            # 2.3GB — fast
# ollama pull llama3             # 4.7GB — more accurate

# 7. Start Ollama server (separate terminal)
ollama serve

# 8. Launch GhostWire
streamlit run app.py
```

Open your browser: `http://localhost:8501`

---

### Docker Quick Start

```bash
# 1. Configure environment
cp env.example .env
# Fill in your API keys

# 2. Build and start
docker compose build
docker compose up -d

# 3. Pull Ollama model (one-time)
docker exec ghostwire-ollama ollama pull phi3:mini

# 4. Open browser
# http://localhost:8501
```

**Docker Compose starts two containers:**
- `ghostwire` — Streamlit app (port 8501)
- `ghostwire-ollama` — Local Ollama AI server (port 11434)

---

## `> cat api_keys.md`

| Service | Purpose | Free Tier | Get Key |
|---------|---------|-----------|---------|
| **VirusTotal** | 70+ AV engines, community | 500/day, 4/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **AbuseIPDB** | IP abuse confidence score | 1,000/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| **Shodan** | Port scan, CVE, banners | InternetDB (no key needed) | [account.shodan.io](https://account.shodan.io) |
| **GreyNoise** | Scanner classification | Community API (no key needed) | [greynoise.io](https://greynoise.io) |
| **URLhaus** | Malware URL database | ~10 req/min without key | [auth.abuse.ch](https://auth.abuse.ch) |
| **Hybrid Analysis** | Cloud sandbox detonation | 200 req/min, 5 submissions/hr | [hybrid-analysis.com](https://www.hybrid-analysis.com/signup) |
| **AlienVault OTX** | MITRE ATT&CK, actor attribution | Unlimited (key required) | [otx.alienvault.com](https://otx.alienvault.com/settings) |
| **Ollama** | Local AI NLP | ∞ (local, free) | [ollama.ai](https://ollama.ai) |

**Minimum required:** VirusTotal + AbuseIPDB. All others are optional — analysis continues gracefully if they are unavailable.

---

## `> cat env.md`

```env
# ── Required (minimum) ───────────────────────────
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here

# ── Recommended ──────────────────────────────────
HYBRID_ANALYSIS_API_KEY=your_key_here
OTX_API_KEY=your_key_here
URLHAUS_API_KEY=your_key_here

# ── HA Key Rotation Pool (optional) ─────────────
HYBRID_ANALYSIS_API_KEY_2=second_key
HYBRID_ANALYSIS_API_KEY_3=third_key
# ... supported up to HYBRID_ANALYSIS_API_KEY_10

# ── Shodan + GreyNoise (optional) ────────────────
SHODAN_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here

# ── Local AI ─────────────────────────────────────
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=phi3:mini    # phi3:mini | llama3 | llama3.2 | mistral

# ── App Behaviour ────────────────────────────────
SANDBOX_MAX_BYTES=524288   # 512KB — sandbox content fetch limit
REQUEST_TIMEOUT=8           # HTTP timeout in seconds
DEBUG=false

# ── Audit Log ────────────────────────────────────
# Default: ~/.ghostwire/audit.jsonl
# GHOSTWIRE_LOG_PATH=/custom/path/audit.jsonl
```

---

## `> cat forensic_engine.md`

`backend/forensic_engine.py` — deep forensic analysis engine that fires when a file is uploaded:

```
FILE INPUT
    │
    ├─ Hash computation      MD5 + SHA1 + SHA256 (computed simultaneously)
    ├─ File type detection   Magic bytes (never trusts the extension)
    ├─ Entropy analysis      Shannon entropy → packed/encrypted = high
    │
    ├─ PE Analysis (EXE/DLL)
    │   ├─ Section entropy (>7.0 = packed/obfuscated)
    │   ├─ Import table (suspicious API calls: VirtualAlloc, CreateRemoteThread...)
    │   ├─ Rich header anomaly
    │   ├─ Overlay data (trailing bytes after PE = appended payload)
    │   └─ Timestamp anomaly (1970 or future date = tampered)
    │
    ├─ PDF Analysis
    │   ├─ Embedded JavaScript (/JS, /JavaScript in streams)
    │   ├─ Auto-exec actions (/OpenAction, /AA)
    │   ├─ Embedded files (/EmbeddedFile)
    │   ├─ Obfuscation detection (filter chains, encoded streams)
    │   └─ C2 indicator extraction (URLs/IPs embedded in content)
    │
    ├─ Office Analysis (DOCX/XLSX/XLSM — ZIP format)
    │   ├─ VBA macro detection (presence of vbaProject.bin)
    │   ├─ Auto-exec macros (AutoOpen, Document_Open, Workbook_Open)
    │   ├─ External relationships (remote template injection, OLE)
    │   ├─ PowerShell string detection
    │   └─ Shellcode pattern matching
    │
    ├─ Metadata Anomaly
    │   ├─ Author/Creator fields (red flag keywords)
    │   ├─ Software fingerprint (known malware builder signatures)
    │   ├─ MIME type mismatch (extension ≠ actual file type)
    │   └─ Creation vs modification time gap
    │
    └─ C2 Indicator Extraction
        ├─ URL patterns (http/https/ftp strings in binary)
        ├─ IP address patterns
        ├─ DGA domain pattern heuristics
        └─ Base64/hex decoded string analysis
```

---

## `> cat stix_export.md`

GhostWire exports a fully compliant STIX 2.1 / TAXII-compatible IOC bundle:

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "id": "bundle--<uuid>",
  "objects": [
    { "type": "identity",     ... },  // GhostWire tool identity
    { "type": "indicator",    ... },  // URL/domain/IP/hash IOC
    { "type": "malware",      ... },  // If signature detected
    { "type": "threat-actor", ... },  // If OTX attributed
    { "type": "relationship", ... },  // IOC → threat links
    { "type": "report",       ... }   // Bundle wrapper
  ]
}
```

**Direct TAXII 2.1 integration:**
```bash
curl -X POST https://taxii.yourorg.com/api/collections/{id}/objects/ \
  -H "Content-Type: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer $TAXII_TOKEN" \
  -d @ghostwire_stix_export.json
```

**CSV IOC export** is also available for bulk import into SIEM platforms.

Deterministic UUID generation: the same IOC always produces the same STIX ID (`uuid5` + GhostWire namespace). No duplicate conflicts when pushing to TAXII servers.

---

## `> cat pdf_report.md`

`backend/pdf_report.py` generates a complete forensic PDF report using ReportLab:

- **Zero external rendering dependencies** — all charts drawn natively in ReportLab (no Plotly PDF render required)
- Color palette matches the GhostWire dark UI exactly
- Report sections include:
  - Verdict banner (color-coded by threat level)
  - Engine score breakdown (horizontal bar chart)
  - IOC list (all URLs defanged)
  - MITRE ATT&CK technique IDs
  - WHOIS + SSL certificate details
  - Hybrid Analysis sandbox results
  - OTX threat actor attribution
  - Mitigation steps

---

## `> cat tests.md`

```bash
# Run all tests
pytest tests/ -v

# Specific module
pytest tests/test_scoring.py -v
pytest tests/test_ssrf.py -v

# With coverage
pytest tests/ --cov=backend --cov-report=term-missing
```

| Test file | What it covers |
|-----------|---------------|
| `test_scoring.py` | AZ domain tiering, whitelist, squatting, override, entropy |
| `test_email_engine.py` | Urgency patterns, brand detection, header parsing |
| `test_hash_validation.py` | MD5/SHA1/SHA256 format validation |
| `test_otx_engine.py` | OTX mock responses, FP-safe scoring logic |
| `test_urlhaus_engine.py` | URLhaus mock responses, graceful degradation |
| `test_ssrf.py` | SSRF attack prevention |
| `test_config.py` | Config loader, defang_url, HA key rotator |

---

## `> cat changelog.md`

```
v6   — 10-Engine parallel architecture (concurrent.futures)
       URLhaus abuse.ch integration
       GreyNoise community API
       PDF report (ReportLab, fully offline charts)
       STIX 2.1 export engine
       AZ regional whitelist (.gov.az, .edu.az, .mil.az)
       WHOIS injection prevention
       Non-root Docker user
       Session-level rate limiting
       Audit log v2 (session ID, hostname, request sequence)

v6.1 — OTX AlienVault integration (MITRE ATT&CK, actor, pulses)
       HA Key Rotation Pool (10 keys, thread-safe, cooldown)
       Plotly map replaced (pydeck removed — no MAPBOX_API_KEY needed)
       Screenshot engine default=OFF (SSRF risk mitigation)
       Score normalization factor introduced (reduced FP rate)
       INFRA_OVERRIDE threshold raised 5→8 (fewer false positives)
       SQUATTING_PENALTY reduced 50→35 (score calibration)
```

---

## `> cat mitre.md`

GhostWire maps analysis findings to the MITRE ATT&CK framework:

| Technique | ID | Detection Engine |
|-----------|-----|-----------------|
| Phishing | T1566 | Email engine + AI NLP |
| Spearphishing Link | T1566.002 | URL + deception engine |
| Drive-by Compromise | T1189 | Sandbox + SSL |
| Exploit Public-Facing App | T1190 | Shodan CVE |
| Command and Scripting | T1059 | Forensic (PS1, VBA, JS) |
| Obfuscated Files | T1027 | Entropy + encoding detection |
| Remote Template Injection | T1221 | Office forensic engine |
| Exfiltration over C2 | T1041 | C2 indicator extraction |
| Dynamic Resolution | T1568 | DGA pattern heuristics |
| Web Service C2 | T1102 | Domain + sandbox analysis |

ATT&CK technique IDs from OTX pulses are rendered as chips in the UI panel.

---

## `> cat license.md`

```
MIT License

You are free to use, copy, modify, and distribute this project.
Condition: retain the original license text.

Warning: This tool is intended solely for lawful security research,
authorized penetration testing, and protection of your own systems.
Unauthorized use against third-party systems is illegal and unethical.
```

---

## `> cat credits.md`

GhostWire CTI is built on the following open APIs and projects:

- **[VirusTotal](https://virustotal.com)** — Google's antivirus aggregation platform
- **[AbuseIPDB](https://abuseipdb.com)** — IP abuse reporting database
- **[Shodan](https://shodan.io)** — The search engine for the internet
- **[GreyNoise](https://greynoise.io)** — Internet scanner intelligence
- **[abuse.ch / URLhaus](https://urlhaus.abuse.ch)** — Malware URL sharing platform
- **[AlienVault OTX](https://otx.alienvault.com)** — Open Threat Exchange
- **[Hybrid Analysis](https://hybrid-analysis.com)** — Falcon Sandbox (CrowdStrike)
- **[Ollama](https://ollama.ai)** — Local LLM runtime
- **[Streamlit](https://streamlit.io)** — Python web UI framework
- **[ReportLab](https://reportlab.com)** — PDF generation library
- **[Playwright](https://playwright.dev)** — Headless browser automation
- **[MITRE ATT&CK](https://attack.mitre.org)** — Adversary tactic and technique framework

---

```
> connection established
> target acquired
> analysis complete
> stay ghost.
                                        — GhostWire CTI v6
```
