```
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗    ██╗██╗██████╗ ███████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║    ██║██║██╔══██╗██╔════╝
██║  ███╗███████║██║   ██║███████╗   ██║   ██║ █╗ ██║██║██████╔╝█████╗
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║███╗██║██║██╔══██╗██╔══╝
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚███╔███╔╝██║██║  ██║███████╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝

                    C T I   P L A T F O R M   v 7
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

![GhostWire IP Intelligence](assets/IP_Intelligence%20.gif)

</div>

---

## `> whoami`

**GhostWire CTI** is an open-source, locally-run Cyber Threat Intelligence platform built for analysts who don't want their investigation data leaking to a SaaS vendor.

Submit a suspicious URL, file hash, email, IP, or raw file — ten analysis engines fire in parallel. Results land in seconds: a risk score, a verdict, a STIX 2.1 bundle ready for your TAXII server, and a PDF forensic report.

The AI runs locally via Ollama. External APIs are query-only — you send the IOC, they return data. Nothing else leaves your machine.

```
TARGET ──► [URL / IP / HASH / EMAIL / FILE]
                    │
          ┌─────────▼─────────┐
          │  10 ENGINE POOL   │  ← concurrent.futures (parallel)
          │                   │
          │  1. Heuristics    │  URL structural analysis
          │  2. WHOIS         │  Domain age, registrar
          │  3. AI NLP        │  Ollama LLM (local, offline)
          │  4. VirusTotal    │  70+ AV engines
          │  5. Deception     │  Typosquatting, homoglyph
          │  6. Sandbox       │  Behavioral simulation
          │  7. SSL/TLS       │  Certificate anomaly
          │  8. Passive DNS   │  ASN, geo, VPN detection
          │  9. Shodan        │  Ports, CVEs, banners
          │  10. GreyNoise    │  Internet scanner classification
          │                   │
          │  + URLhaus        │  abuse.ch malware URL database
          │  + OTX            │  AlienVault threat intel
          │  + Hybrid Anal.   │  Cloud sandbox detonation
          │  + Forensic Eng.  │  Deep file analysis (PE/PDF/Office)
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │  SCORING ENGINE   │  0–100 risk score
          │  VERDICT ENGINE   │  SAFE/LOW/MEDIUM/HIGH/CRITICAL
          │  STIX 2.1 EXPORT  │  TAXII-compatible IOC bundle
          │  PDF REPORT       │  Full forensic report (ReportLab)
          │  AUDIT LOG        │  JSONL audit trail, defanged URLs
          └───────────────────┘
```

---

## `> ls -la features/`

### 5 Analysis Pipelines

| Tab | Input | Parallel Engines |
|-----|-------|-----------------|
| **URL / Domain** | Any URL, domain, or IP address | 10+ |
| **File / Hash** | SHA-256 / SHA-1 / MD5 lookup or file upload | 4 + Forensic |
| **Email / SMS** | Raw headers + body, or OCR screenshot | 7 |
| **IP Intelligence** | Standalone deep IP analysis | 6 |
| **Sandbox** | Hybrid Analysis cloud detonation | HA API |

---

### Engine Detail

**Engine 1 — URL Heuristics**
Structural analysis before any network call. Catches raw IPs in URLs, `@` credential tricks, encoded path components, suspicious TLDs (`.tk .ml .cf .ga`), excessive subdomains, and keyword patterns like `login`, `secure`, `verify`, `update`.

**Engine 2 — WHOIS / Domain Age**
Domains under 30 days old score high. Checks registrar reputation, privacy-protected WHOIS in suspicious context, and creation/expiry anomalies.

**Engine 3 — AI NLP (Ollama, local)**
Runs `phi3:mini`, `llama3`, `llama3.2`, or `mistral` locally. Detects urgency language, financial threats, authority impersonation, and provides a domain legitimacy assessment. Structured JSON output — no hallucinated free-text verdicts.

**Engine 4 — Reputation (VirusTotal + AbuseIPDB)**
70+ AV engine scan via VT. Community votes, comments NLP, malicious file relations, domain popularity rank. AbuseIPDB confidence score, report count, Tor exit node detection, DNS record analysis.

**Engine 5 — Technical Deception**
Levenshtein distance check against 50+ global brands. Unicode homoglyph detection, Punycode/IDN domain flagging, redirect chain depth, link shortener identification.

**Engine 6 — Sandbox Simulation**
Local behavioral analysis: HTTP response headers, server fingerprinting, redirect chain tracking, parked domain content patterns, VPN/proxy ASN identification.

**Engine 7 — SSL/TLS Certificate**
Certificate validity, free CA detection (Let's Encrypt, ZeroSSL), SAN mismatch, self-signed flag, wildcard abuse detection. Certs under 7 days old → fresh phishing infrastructure flag.

**Engine 8 — Passive DNS + IP Intel**
Geolocation, ASN-based risk scoring, shared hosting density, VPN/proxy/Tor ASN recognition, PTR reverse DNS analysis.

**Engine 9 — Shodan**
Full open port inventory, service banners (HTTP/SSH/FTP/SMB), CVE list, Shodan tags. Falls back to InternetDB — works without an API key.

**Engine 10 — GreyNoise**
Mass internet scanner classification. RIOT benign service detection (Google, Cloudflare). Actor attribution, scan intent analysis. Community API works without a key.

---

### Additional Intel Layers

**URLhaus (abuse.ch)** — Active malware URL database. Tags: phishing/malware/botnet/c2. Shows URL status (online/offline), associated malware family, and SHA256 of dropped files.

**OTX (AlienVault)** — Pulse count, MITRE ATT&CK technique IDs, threat actor attribution (Lazarus, APT28...), campaign names. Infrastructure-signal pulses (Tor exit nodes, HoneyNet feeds, C2 feeds, scanner feeds) contribute to score independently of VirusTotal — no false negatives on network-classified threats.

**Hybrid Analysis** — Cloud sandbox detonation for URLs, files, hashes, domains, and IPs. Environments: Windows 10 64-bit, Windows 7 32-bit, Android. Supports up to 10 API keys in rotation pool — auto-switches on 429.

---

### Forensic Engine (File Upload)

When a file is uploaded, `backend/forensic_engine.py` runs in parallel with the VT/URLhaus/OTX lookups:

```
FILE BYTES
    │
    ├─ Hash computation       MD5 + SHA1 + SHA256
    ├─ Magic byte detection   Never trusts the extension
    ├─ MIME mismatch check    Extension ≠ actual type → masquerading flag
    │
    ├─ PE (EXE / DLL)
    │   ├─ Section entropy    >7.2 = packed/encrypted/crypter
    │   ├─ Import analysis    VirtualAlloc, CreateRemoteThread, WinExec...
    │   ├─ Compile timestamp  Zeroed = timestamp stomping
    │   └─ Overlay data       Bytes after PE = appended payload
    │
    ├─ PDF
    │   ├─ /JS /JavaScript    Embedded script execution
    │   ├─ /OpenAction /AA    Auto-exec on document open
    │   ├─ /Launch            External process execution
    │   ├─ /EmbeddedFile      Hidden file inside PDF
    │   ├─ Polyglot detection PDF/ZIP dual-format (GootLoader technique)
    │   └─ Creator tool check msfvenom / Cobalt Strike signatures
    │
    ├─ Office (DOCX / XLSX / XLSM)
    │   ├─ VBA macro presence vbaProject.bin detection
    │   ├─ Auto-exec triggers AutoOpen, Document_Open, Workbook_Open
    │   ├─ Chr() obfuscation  >20 Chr() calls = string hiding
    │   ├─ PowerShell in VBA  Inline PS execution chains
    │   └─ OLE embedded objs  External template / OLE injection
    │
    ├─ ZIP bomb detection
    │   ├─ Ratio check        >100:1 compression ratio
    │   ├─ Absolute size cap  >100MB uncompressed → blocked
    │   ├─ Metadata spoof     file_size=0 with real compressed data
    │   └─ Nested archives    Matryoshka / 42.zip style
    │
    ├─ Sandbox evasion patterns
    │   ├─ Long sleep()       Timeout evasion
    │   ├─ IsDebuggerPresent  Anti-analysis
    │   ├─ VM string checks   vmware / virtualbox / qemu / sandbox
    │   └─ Mouse / window     User presence detection
    │
    └─ Network indicator extraction
        ├─ URL / domain / IP  Strings embedded in binary
        ├─ DGA pattern        Random-looking domains + abuse TLDs
        └─ C2Indicator objs   Confidence-scored with context
```

**Result:** `ForensicReport` with risk score, threat level, final verdict, MIME mismatch flag, extracted IOCs, AI NLP label, engine divergence explanation, and a plain-English answer to *"why does this hash flag in VT but look clean in a container?"*

---

## `> cat scoring_engine.md`

```
Score components (0–100 final):

  heuristics_score     URL structure
  whois_score          Domain age
  ai_score             Ollama NLP
  reputation_score     VT + AbuseIPDB
  deception_score      Typosquat + homoglyph
  sandbox_score        Behavioral simulation
  ssl_score            Certificate anomaly
  pdns_score           Passive DNS
  shodan_score         Port / CVE intel
  greynoise_score      Scanner classification
  urlhaus_score        Malware URL database
  otx_score            Threat intel (infra-signal aware)
  forensic_score       File deep analysis

  FINAL = min(Σ(engine × weight) / 2.0, 100)

Score Floor Rules:
  TOR_EXIT_NODE     Confirmed Tor exit node → minimum MEDIUM (40)
  VT_DETECTION      VT ≥3 malicious engines → minimum 35
  INFRA_OVERRIDE    VT relations ≥8 malicious files → locked ≥ 85
  BRAND_SQUATTING   2+ squatting signals + new domain → +35 pts
  AZ_WHITELIST      .gov.az / .edu.az / .mil.az → fully protected

OTX Infrastructure Signals (VT-independent scoring):
  Tor Exit Node     +20 pts  (anonymisation infrastructure)
  HoneyNet Feed     +15 pts  (active attacker/scanner feed)
  C2/Botnet Feed    +18 pts  (malware infrastructure)
  Brute Force Feed  +12 pts  (active attack feed)
  Scanner Feed      +10 pts  (mass reconnaissance feed)
  Malware Feed      +15 pts  (malware distribution feed)

Verdict thresholds:
  SAFE      0–19    ████ #00ffb4
  LOW      20–39    ████ #78d97a
  MEDIUM   40–64    ████ #ffd060
  HIGH     65–84    ████ #ff6b35
  CRITICAL 85–100   ████ #ff2d55
```

---

## `> cat security_model.txt`

**URL Defanging** — Every URL written to the audit log is defanged: `https://evil.com` → `hxxps://evil[.]com`. Prevents hot-links in log viewers, email clients, and SIEMs.

**SSRF Protection** — Screenshot engine runs Playwright headless with JavaScript disabled. `run_screenshot` defaults to off. Tested in `tests/test_ssrf.py`.

**WHOIS Injection Prevention** — Domain string sanitized with strict regex before shelling out to `python-whois`.

**Supply Chain Hardening** — All packages in `requirements.txt` pinned with `==`. No floating versions.

**Non-root Docker** — `ghostwire` user UID/GID 1000. Container never runs as root.

**Rate Limiting** — Two-layer: 5-second minimum gap between requests (per session) + 10 requests per 60-second window. Process-level counter prevents multi-tab bypass.

**HA Key Rotation** — Thread-safe round-robin pool, up to 10 Hybrid Analysis API keys. On 429, offending key cools for 65 seconds; pool switches automatically.

**OTX Infrastructure Scoring** — OTX pulse count alone never increases the score for generic pulses. Infrastructure-signal pulses (Tor exit, HoneyNet, C2, scanner feeds) are authoritative by definition and score independently — VT cannot detect network-classified threats. All other pulse types require VirusTotal corroboration.

**DoS Protection** — PDF/binary scan capped at 5 MB decode limit. ReDoS-safe regex patterns (bounded quantifiers, no unbounded lazy `.*?`). String extraction capped at 5 MB.

**Prompt Injection Prevention** — Filenames sanitized before embedding in Ollama prompts. Only alphanumeric, dot, dash, space, and parentheses are allowed.

**Ollama Model Whitelist** — Only explicitly approved model identifiers are passed to the Ollama API. Unknown model names fall back to `phi3:mini` with a warning.

**SHA-256 Validation** — Hash strings validated with `re.fullmatch(r"[0-9a-fA-F]{64}", ...)` before URL interpolation into VT API calls.

**Audit Trail** — `~/.ghostwire/audit.jsonl`. Fields: session ID, hostname, request sequence, defanged target, verdict, score, duration.

---

## `> cat mitre_map.txt`

| Technique | ID | Engine |
|-----------|-----|--------|
| Phishing | T1566 | Email + AI NLP |
| Spearphishing Link | T1566.002 | URL + Deception |
| Drive-by Compromise | T1189 | Sandbox + SSL |
| Exploit Public-Facing App | T1190 | Shodan CVE |
| Command and Scripting Interpreter | T1059 | Forensic (PS1/VBA/JS) |
| Obfuscated Files or Information | T1027 | Entropy + encoding |
| Remote Template Injection | T1221 | Office forensic |
| Exfiltration over C2 | T1041 | C2 indicator extraction |
| Dynamic Resolution / DGA | T1568 | DGA pattern heuristics |
| Web Service C2 | T1102 | Domain + sandbox |

ATT&CK technique IDs from OTX pulses render as chips in the UI. Exported in STIX 2.1 bundles and PDF reports.

---

## `> cat install.md`

### Requirements

- Python 3.12+
- [Ollama](https://ollama.com) (local AI)
- VirusTotal + AbuseIPDB API keys (minimum)

### Quick Start

```bash
git clone https://github.com/yourusername/GhostWire_CTI.git
cd GhostWire_CTI

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt
python -m playwright install chromium

cp env.example .env               # fill in your API keys

ollama pull phi3:mini             # 2.3 GB — fast
ollama serve                      # separate terminal

streamlit run app.py
# → http://localhost:8501
```

### Docker

```bash
cp env.example .env               # fill in your API keys
docker compose build
docker compose up -d
docker exec ghostwire-ollama ollama pull phi3:mini
# → http://localhost:8501
```

Two containers: `ghostwire` (Streamlit, port 8501) + `ghostwire-ollama` (Ollama, port 11434).

---

## `> cat api_keys.md`

| Service | Purpose | Free Tier | Link |
|---------|---------|-----------|------|
| **VirusTotal** | 70+ AV engines | 500/day, 4/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **AbuseIPDB** | IP abuse confidence | 1,000/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| **Shodan** | Ports, CVEs, banners | InternetDB (no key) | [account.shodan.io](https://account.shodan.io) |
| **GreyNoise** | Scanner classification | Community API (no key) | [greynoise.io](https://greynoise.io) |
| **URLhaus** | Malware URL database | ~10 req/min | [auth.abuse.ch](https://auth.abuse.ch) |
| **Hybrid Analysis** | Cloud sandbox | 200 req/min, 5 sub/hr | [hybrid-analysis.com](https://www.hybrid-analysis.com/signup) |
| **AlienVault OTX** | MITRE ATT&CK, actors | Unlimited (key required) | [otx.alienvault.com](https://otx.alienvault.com/settings) |
| **Ollama** | Local AI NLP | ∞ free, runs offline | [ollama.ai](https://ollama.ai) |

Minimum required: **VirusTotal + AbuseIPDB**. All others degrade gracefully.

> **Hybrid Analysis note:** Free accounts start at `Restricted` auth level (hash lookup only). To enable URL submission and file detonation, visit **hybrid-analysis.com → Profile → API Key** and request upgrade to `Default` level (free, requires account verification).

---

## `> cat env.example`

```env
# Required
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here

# Recommended
HYBRID_ANALYSIS_API_KEY=your_key_here
OTX_API_KEY=your_key_here
URLHAUS_API_KEY=your_key_here

# HA Key Pool (up to 10 keys, auto-rotates on 429)
HYBRID_ANALYSIS_API_KEY_2=second_key
HYBRID_ANALYSIS_API_KEY_3=third_key

# Optional
SHODAN_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here

# Local AI
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=phi3:mini

# App
SANDBOX_MAX_BYTES=524288
REQUEST_TIMEOUT=8
DEBUG=false
```

---

## `> cat architecture.txt`

```
ghostwire_cti/
│
├── app.py                      # Streamlit entry point, tab routing, rate limiter
├── config.py                   # Config singleton, URL defanging, HA key rotator
├── requirements.txt            # Pinned dependencies
├── Dockerfile                  # python:3.12-slim, non-root ghostwire user
├── docker-compose.yml          # ghostwire + ollama containers
│
├── backend/
│   ├── forensic_engine.py      # Deep file analysis: PE/PDF/Office/ZIP/shellcode
│   ├── hash_engine.py          # Hash lookup + file pipeline
│   ├── ai_analyzer.py          # Ollama client, JSON prompt engineering
│   ├── async_runner.py         # concurrent.futures parallel engine pool
│   ├── audit_log.py            # JSONL audit trail, defanging
│   ├── caching.py              # CacheManager — VT/WHOIS/SSL/DNS cache layers
│   ├── deception.py            # Typosquat, homoglyph, redirect, shortener
│   ├── email_engine.py         # Header parser, OCR, brand impersonation
│   ├── external_intel.py       # Shodan + GreyNoise clients
│   ├── heuristics.py           # URL structural analysis (15 checks)
│   ├── hybrid_analysis.py      # HA Cloud Sandbox, key pool rotation
│   ├── ip_intel.py             # IP standalone pipeline
│   ├── logging_config.py       # Centralised logging configuration
│   ├── otx_engine.py           # AlienVault OTX — MITRE, pulses, actor, infra signals
│   ├── passive_dns.py          # DNS, geo, ASN, VPN detection
│   ├── pdf_report.py           # ReportLab PDF generator
│   ├── reputation.py           # VirusTotal + AbuseIPDB clients
│   ├── sandbox.py              # Local behavioral sandbox simulation
│   ├── scoring.py              # Score aggregator, whitelist, overrides, Tor floor
│   ├── screenshot_engine.py    # Playwright headless (JS disabled)
│   ├── ssl_engine.py           # TLS certificate analysis
│   ├── stix_export.py          # STIX 2.1 bundle + CSV IOC export
│   ├── urlhaus_engine.py       # abuse.ch URLhaus client
│   ├── url_utils.py            # Shared URL helpers (normalise, extract, detect)
│   ├── verdict.py              # Verdict calculator, mitigation library
│   ├── whois_check.py          # WHOIS domain age, registrar
│   └── whois_timeline.py       # Historical WHOIS timeline
│
├── frontend/
│   ├── components.py           # Shared widgets: gauge, banner, IOC chips
│   ├── extra_widgets.py        # WHOIS timeline, threat map, Shodan/GN panels
│   ├── ha_renderer.py          # Hybrid Analysis results renderer
│   ├── other_renderers.py      # Hash, email, IP, forensic renderers
│   ├── otx_panel.py            # OTX panel (MITRE chips, actor badges)
│   ├── stix_panel.py           # STIX 2.1 export UI
│   ├── styles.py               # inject_css() — dark UI, Space Mono
│   ├── url_renderer.py         # URL pipeline main renderer
│   └── urlhaus_panel.py        # URLhaus panel renderer
│
├── pipelines/
│   ├── pipeline_email.py       # Email/SMS orchestration
│   ├── pipeline_hash.py        # Hash/File + Forensic Engine orchestration
│   ├── pipeline_ip.py          # IP intelligence pipeline
│   ├── pipeline_sandbox.py     # Hybrid Analysis sandbox pipeline
│   └── pipeline_url.py         # URL/Domain/IP main pipeline
│
└── tests/
    ├── conftest.py                  # Shared fixtures and mocks
    ├── test_caching.py              # CacheManager behaviour
    ├── test_config.py               # Config loader, defang_url, HA key rotator
    ├── test_email_engine.py         # Urgency patterns, brand detection
    ├── test_hash_validation.py      # MD5 / SHA1 / SHA256 format validation
    ├── test_otx_engine.py           # OTX mock responses, infra-signal scoring
    ├── test_scoring.py              # AZ domain tiers, whitelist, overrides
    ├── test_scoring_normalization.py# Score normalisation edge cases
    ├── test_ssrf.py                 # SSRF prevention
    ├── test_urlhaus_engine.py       # URLhaus mock + graceful degradation
    ├── test_urlhaus_integration.py  # URLhaus integration tests
    └── test_v8_fixes.py             # Forensic wiring, dead file removal, fixes
```

---

## `> cat stix_export.md`

GhostWire exports fully compliant STIX 2.1 bundles with deterministic UUIDs — the same IOC always produces the same STIX ID. No duplicate conflicts on repeated TAXII pushes.

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "objects": [
    { "type": "identity"     },
    { "type": "indicator"    },
    { "type": "malware"      },
    { "type": "threat-actor" },
    { "type": "relationship" },
    { "type": "report"       }
  ]
}
```

Push to TAXII 2.1:
```bash
curl -X POST https://taxii.yourorg.com/api/collections/{id}/objects/ \
  -H "Content-Type: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer $TAXII_TOKEN" \
  -d @ghostwire_stix_export.json
```

CSV IOC export also available for bulk SIEM import.

---

## `> cat tests.md`

```bash
pytest tests/ -v
PYTHONUTF8=1 pytest tests/ --cov=backend --cov-report=term-missing
```

| Test | Covers |
|------|--------|
| `test_scoring.py` | AZ domain tiers, whitelist, squatting, overrides, Tor floor |
| `test_scoring_normalization.py` | Score normalisation edge cases |
| `test_email_engine.py` | Urgency patterns, brand impersonation, header parsing |
| `test_hash_validation.py` | MD5 / SHA1 / SHA256 format validation |
| `test_otx_engine.py` | OTX mock responses, infrastructure-signal scoring |
| `test_urlhaus_engine.py` | URLhaus mock responses, graceful degradation |
| `test_urlhaus_integration.py` | URLhaus end-to-end integration |
| `test_caching.py` | CacheManager hit/miss/expiry behaviour |
| `test_ssrf.py` | SSRF prevention |
| `test_config.py` | Config loader, defang_url, HA key rotator |
| `test_v8_fixes.py` | Forensic engine wiring, dead file removal, integration |

---
## Credits

- [VirusTotal](https://virustotal.com) — Google's AV aggregation platform
- [AbuseIPDB](https://abuseipdb.com) — IP abuse reporting database
- [Shodan](https://shodan.io) — The search engine for the internet
- [GreyNoise](https://greynoise.io) — Internet scanner intelligence
- [abuse.ch / URLhaus](https://urlhaus.abuse.ch) — Malware URL database
- [AlienVault OTX](https://otx.alienvault.com) — Open Threat Exchange
- [Hybrid Analysis](https://hybrid-analysis.com) — Falcon Sandbox (CrowdStrike)
- [Ollama](https://ollama.ai) — Local LLM runtime
- [Streamlit](https://streamlit.io) — Python web UI framework
- [ReportLab](https://reportlab.com) — PDF generation
- [Playwright](https://playwright.dev) — Headless browser automation
- [MITRE ATT&CK](https://attack.mitre.org) — Adversary tactic framework

---

[MIT License](LICENSE)

---

```
> connection established
> target acquired
> analysis complete
> stay ghost.
                                        — GhostWire CTI v7
```
