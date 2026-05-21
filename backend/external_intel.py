"""
backend/external_intel.py
-------------------------
External Threat Intelligence — Shodan + GreyNoise
GhostWire CTI v6

SHODAN:
  - Host information (open ports, banners, vulns, tags)
  - InternetDB (free, no key) — ports/tags/CPEs/vulns for any IP
  - Full API (with key) — full banner grab, CVE list, geolocation

GREYNOISE:
  - Community API (free) — is this IP a known internet scanner/noise?
  - Full API (with key)  — intent, actor, tags, CVE exploitation attempts
  - Key insight: GreyNoise separates benign scanners from malicious actors.
    An IP mass-scanning the internet is different from a targeted attacker.

Both sources feed score adjustments and MITRE tagging.
"""

from __future__ import annotations

import logging

import re
from dataclasses import dataclass, field
from typing import Optional

import requests

logger = logging.getLogger(__name__)


TIMEOUT = 8
SAFE_UA = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; GhostWire CTI/5.0; "
        "SecurityResearch; contact: security@example.com)"
    )
}

# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class ShodanResult:
    available: bool           = False   # True if any data returned
    used_key:  bool           = False   # True if full API used, False = InternetDB

    # Host basics
    ip:           str         = ""
    hostnames:    list[str]   = field(default_factory=list)
    domains:      list[str]   = field(default_factory=list)
    country:      Optional[str] = None
    org:          Optional[str] = None
    isp:          Optional[str] = None
    asn:          Optional[str] = None

    # Port + service data
    open_ports:   list[int]   = field(default_factory=list)
    services:     list[dict]  = field(default_factory=list)  # {port, transport, product, version}

    # Vulnerability data
    cves:         list[str]   = field(default_factory=list)
    vuln_count:   int         = 0

    # Tags (Shodan-assigned: "tor", "vpn", "honeypot", "cloud", etc.)
    tags:         list[str]   = field(default_factory=list)

    # CPE (software identification)
    cpes:         list[str]   = field(default_factory=list)

    # Banners (raw service banners — up to 5)
    banners:      list[str]   = field(default_factory=list)

    # Risk signals
    score_contribution: int   = 0
    flags:  list[str]         = field(default_factory=list)
    iocs:   list[str]         = field(default_factory=list)
    errors: list[str]         = field(default_factory=list)


@dataclass
class GreyNoiseResult:
    available:    bool        = False
    used_key:     bool        = False

    # Classification
    noise:        bool        = False   # True = mass internet scanner
    riot:         bool        = False   # True = known benign service (Google, Cloudflare…)
    classification: Optional[str] = None  # "malicious" | "benign" | "unknown"
    name:         Optional[str] = None    # Actor name if known

    # Intent
    intent:       Optional[str] = None   # "scanning" | "brute_force" | "exploit"

    # Tags assigned by GreyNoise
    tags:         list[str]   = field(default_factory=list)

    # CVE exploitation attempts seen from this IP
    cve_attempts: list[str]   = field(default_factory=list)

    # Metadata
    first_seen:   Optional[str] = None
    last_seen:    Optional[str] = None
    country:      Optional[str] = None
    asn:          Optional[str] = None
    org:          Optional[str] = None

    # Score
    score_contribution: int   = 0
    flags:  list[str]         = field(default_factory=list)
    iocs:   list[str]         = field(default_factory=list)
    errors: list[str]         = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# SHODAN
# ─────────────────────────────────────────────────────────────────────────────

# Tags that indicate malicious/risky infrastructure
SHODAN_RISK_TAGS = {
    "tor",           "vpn",          "scanner",     "botnet",
    "malware",       "c2",           "phishing",    "spam",
    "proxy",         "anonymizer",   "self-signed",
}
SHODAN_NEUTRAL_TAGS = {
    "cloud",         "cdn",          "hosting",     "isp",
    "database",      "webserver",    "api",
}

# Ports that indicate suspicious activity when open
SUSPICIOUS_PORTS = {
    4444, 4445, 4446,           # Metasploit default
    1080, 8080, 3128,           # Proxy ports
    9001, 9002,                 # Tor relay
    6667, 6668, 6669,           # IRC (botnet C2)
    31337,                      # Back Orifice
    12345, 23, 512, 513, 514,   # Legacy/dangerous
}


def _query_shodan_internetdb(ip: str) -> dict:
    """
    Shodan InternetDB — free, no API key required.
    Returns ports, hostnames, tags, CPEs, vulns for any IPv4.
    """
    try:
        r = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            headers=SAFE_UA, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"empty": True}
    except Exception as e:
        return {"error": str(e)}
    return {}


def _query_shodan_api(ip: str, api_key: str) -> dict:
    """
    Shodan full API — requires key.
    Returns banners, CVE list, full service info, organisation.
    """
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            headers=SAFE_UA, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"empty": True}
        else:
            return {"error": f"Shodan API HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _parse_shodan_internetdb(data: dict, result: ShodanResult) -> None:
    """Parse Shodan InternetDB response (free tier)."""
    if data.get("empty") or data.get("error"):
        result.errors.append(
            data.get("error", "Shodan InternetDB: No data for this IP")
        )
        return

    result.available  = True
    result.open_ports = data.get("ports", [])
    result.cpes       = data.get("cpes", [])
    result.hostnames  = data.get("hostnames", [])
    result.tags       = data.get("tags", [])

    # CVEs from InternetDB
    vulns = data.get("vulns", [])
    result.cves      = vulns[:10]
    result.vuln_count = len(vulns)

    _score_shodan(result)


def _parse_shodan_api(data: dict, result: ShodanResult) -> None:
    """Parse full Shodan API response."""
    if data.get("empty") or data.get("error"):
        result.errors.append(
            data.get("error", "Shodan: No data for this IP")
        )
        return

    result.available  = True
    result.used_key   = True
    result.hostnames  = data.get("hostnames", [])
    result.domains    = data.get("domains", [])
    result.country    = data.get("country_name")
    result.org        = data.get("org")
    result.isp        = data.get("isp")
    result.asn        = data.get("asn")
    result.tags       = data.get("tags", [])
    result.open_ports = data.get("ports", [])

    # Vulnerabilities
    vulns = data.get("vulns", {})
    if isinstance(vulns, dict):
        result.cves       = list(vulns.keys())[:10]
    elif isinstance(vulns, list):
        result.cves       = vulns[:10]
    else:
        result.cves       = []
    result.vuln_count = len(result.cves)

    # Service banners
    for svc in (data.get("data") or [])[:8]:
        port     = svc.get("port", 0)
        transport = svc.get("transport", "tcp")
        product  = svc.get("product", "")
        version  = svc.get("version", "")
        banner   = svc.get("data", "")[:200].replace("\n", " ").strip()

        result.services.append({
            "port": port, "transport": transport,
            "product": product, "version": version,
        })
        if banner:
            result.banners.append(f":{port}/{transport} — {banner[:150]}")

    _score_shodan(result)


def _score_shodan(result: ShodanResult) -> None:
    """Score Shodan findings and generate flags."""
    score = 0

    # Risk tags
    risk_tags = [t for t in result.tags if t.lower() in SHODAN_RISK_TAGS]
    if risk_tags:
        score += min(len(risk_tags) * 8, 20)
        result.flags.append(
            f"🔍 Shodan Tags: {', '.join(risk_tags)} — infrastructure risk indicators"
        )
        result.iocs.extend([f"SHODAN_TAG:{t}" for t in risk_tags])

    # Suspicious ports
    sus_ports = [p for p in result.open_ports if p in SUSPICIOUS_PORTS]
    if sus_ports:
        score += min(len(sus_ports) * 6, 18)
        result.flags.append(
            f"🔌 Shodan Ports: {sus_ports} — suspicious/malicious service ports open"
        )
        result.iocs.append(f"SUSPICIOUS_PORTS:{sus_ports}")

    # CVE count
    if result.vuln_count >= 5:
        score += 20
        result.flags.append(
            f"⚠️ Shodan CVEs: {result.vuln_count} vulnerabilities — "
            f"unpatched/exposed: {', '.join(result.cves[:4])}"
        )
        result.iocs.append(f"SHODAN_CVES:{result.vuln_count}")
    elif result.vuln_count >= 1:
        score += 10
        result.flags.append(
            f"⚠️ Shodan CVEs: {result.vuln_count} known vulnerabilities "
            f"({', '.join(result.cves[:3])})"
        )

    # Port count (many open ports = exposed/misconfigured)
    if len(result.open_ports) >= 20:
        score += 8
        result.flags.append(
            f"🔌 Shodan: {len(result.open_ports)} open ports — highly exposed host"
        )
    elif result.open_ports:
        result.flags.append(
            f"🔌 Shodan Open Ports: {sorted(result.open_ports)[:10]}"
        )

    if not result.flags:
        result.flags.append(
            f"✅ Shodan InternetDB: No suspicious ports or CVEs found"
        )

    result.score_contribution = min(score, 30)


def analyze_shodan(ip: str, api_key: Optional[str] = None) -> ShodanResult:
    """
    Query Shodan for IP intelligence.
    Uses free InternetDB if no API key, full API if key provided.
    """
    result     = ShodanResult()
    result.ip  = ip

    if api_key:
        data = _query_shodan_api(ip, api_key)
        _parse_shodan_api(data, result)
    else:
        data = _query_shodan_internetdb(ip)
        _parse_shodan_internetdb(data, result)
        if not result.available:
            result.flags.append(
                "Shodan InternetDB: No data — add SHODAN_API_KEY to .env for full scan"
            )
        else:
            result.flags.insert(0, "ℹ Shodan InternetDB (free tier — add key for full banners+CVEs)")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# GREYNOISE
# ─────────────────────────────────────────────────────────────────────────────

# GreyNoise tags that indicate malicious activity
GREYNOISE_MALICIOUS_TAGS = {
    "scanner", "brute_force", "exploit", "malware", "trojan",
    "ransomware", "bot", "c2", "phishing", "spam", "worm",
    "credential_stuffing", "web_crawler_malicious", "dos", "ddos",
    "ssh_scanner", "rdp_scanner", "sql_injection",
}
GREYNOISE_BENIGN_TAGS = {
    "google", "cloudflare", "microsoft", "amazon", "researcher",
    "search_engine", "security_scanner_benign", "cdn",
}


def _query_greynoise_community(ip: str) -> dict:
    """
    GreyNoise Community API (free, no key needed).
    Returns: noise, riot, classification, name, link.
    """
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={**SAFE_UA, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"message": "not_found"}
        elif r.status_code == 429:
            return {"error": "GreyNoise rate limit — try again later"}
        else:
            return {"error": f"GreyNoise Community HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _query_greynoise_api(ip: str, api_key: str) -> dict:
    """
    GreyNoise full GNQL API.
    Returns intent, actor, tags, CVE attempts, detailed metadata.
    """
    try:
        r = requests.get(
            f"https://api.greynoise.io/v2/noise/context/{ip}",
            headers={
                **SAFE_UA,
                "key": api_key,
                "Accept": "application/json",
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"seen": False}
        else:
            return {"error": f"GreyNoise API HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _parse_greynoise_community(data: dict, result: GreyNoiseResult) -> None:
    """Parse GreyNoise Community API response."""
    if data.get("error"):
        result.errors.append(f"GreyNoise Community: {data['error']}")
        return
    if data.get("message") == "not_found":
        result.flags.append("GreyNoise: IP not observed in mass-scanning data")
        return

    result.available      = True
    result.noise          = bool(data.get("noise", False))
    result.riot           = bool(data.get("riot", False))
    result.classification = data.get("classification")
    result.name           = data.get("name")

    _score_greynoise(result)


def _parse_greynoise_api(data: dict, result: GreyNoiseResult) -> None:
    """Parse GreyNoise full API response."""
    if data.get("error"):
        result.errors.append(f"GreyNoise: {data['error']}")
        return
    if not data.get("seen", True):
        result.flags.append("GreyNoise: IP not observed in mass-scanning data")
        return

    result.available      = True
    result.used_key       = True
    result.noise          = bool(data.get("noise", False))
    result.riot           = bool(data.get("riot", False))
    result.classification = data.get("classification")
    result.name           = data.get("actor")
    result.intent         = data.get("raw_data", {}).get("scan", [{}])[0].get("flag") if data.get("raw_data") else None
    result.first_seen     = data.get("first_seen")
    result.last_seen      = data.get("last_seen")
    result.country        = data.get("metadata", {}).get("country")
    result.asn            = data.get("metadata", {}).get("asn")
    result.org            = data.get("metadata", {}).get("organization")

    result.tags           = data.get("tags", [])[:10]

    # CVE exploitation attempts
    cve_pattern = re.compile(r"CVE-\d{4}-\d+")
    all_tag_text = " ".join(result.tags)
    result.cve_attempts   = cve_pattern.findall(all_tag_text)[:5]

    _score_greynoise(result)


def _score_greynoise(result: GreyNoiseResult) -> None:
    """
    Score GreyNoise signals.

    Key logic:
      RIOT = known benign service → score reduction
      noise=True + classification=malicious → significant risk
      noise=False = NOT a mass scanner → likely targeted attacker (higher risk)
    """
    score = 0

    if result.riot:
        # RIOT: known benign internet service (Google, Cloudflare, etc.)
        result.flags.append(
            f"✅ GreyNoise RIOT: {result.name or 'Known service'} — "
            f"benign internet infrastructure (false positive eliminated)"
        )
        result.score_contribution = -10   # Reduce overall score
        return

    if result.noise and result.classification == "malicious":
        score += 22
        result.flags.append(
            f"🔴 GreyNoise: MALICIOUS mass-scanner — "
            f"actively scanning internet ({result.name or 'unknown actor'})"
        )
        result.iocs.append(f"GREYNOISE_MALICIOUS:{result.classification}")

    elif result.noise and result.classification == "benign":
        result.flags.append(
            f"ℹ GreyNoise: Benign internet scanner "
            f"({result.name or 'research/security tool'})"
        )

    elif result.noise:
        score += 10
        result.flags.append(
            f"⚠️ GreyNoise: Internet background noise — "
            f"mass-scanning activity detected (classification: {result.classification})"
        )

    elif result.available and not result.noise:
        # Not a mass scanner → if flagged elsewhere = likely targeted attacker
        score += 8
        result.flags.append(
            "⚠️ GreyNoise: NOT in background noise — "
            "targeted activity (not mass-scanner — more suspicious)"
        )

    # Malicious tags from full API
    if result.tags:
        mal_tags = [t for t in result.tags if any(
            m in t.lower() for m in GREYNOISE_MALICIOUS_TAGS
        )]
        if mal_tags:
            score += min(len(mal_tags) * 5, 15)
            result.flags.append(
                f"🏷 GreyNoise Tags: {', '.join(mal_tags[:5])}"
            )
            result.iocs.extend([f"GREYNOISE_TAG:{t}" for t in mal_tags[:3]])

    # CVE exploitation attempts
    if result.cve_attempts:
        score += min(len(result.cve_attempts) * 5, 15)
        result.flags.append(
            f"⚠️ GreyNoise CVE exploitation: {', '.join(result.cve_attempts)}"
        )
        result.iocs.extend([f"EXPLOIT_ATTEMPT:{cve}" for cve in result.cve_attempts])

    # First/last seen
    if result.first_seen and result.last_seen:
        result.flags.append(
            f"📅 GreyNoise observed: {result.first_seen} → {result.last_seen}"
        )

    result.score_contribution = min(score, 25)


def analyze_greynoise(ip: str, api_key: Optional[str] = None) -> GreyNoiseResult:
    """
    Query GreyNoise for IP threat context.
    Always uses the Community API (https://api.greynoise.io/v3/community/{ip}) — no key required.
    """
    result = GreyNoiseResult()
    data   = _query_greynoise_community(ip)
    _parse_greynoise_community(data, result)
    return result
