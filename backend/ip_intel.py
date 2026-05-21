"""
backend/ip_intel.py
-------------------
Deep IP Intelligence Engine — GhostWire CTI v6
"""

from __future__ import annotations

import logging

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Optional

import requests

logger = logging.getLogger(__name__)



def _is_public_ip(ip: str) -> bool:
    """
    Returns True only if the IP is a globally routable public address.
    Blocks private, loopback, link-local, multicast, reserved ranges.
    Prevents leaking internal IPs to external APIs (AbuseIPDB, VirusTotal).
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
        return (
            not addr.is_private and
            not addr.is_loopback and
            not addr.is_link_local and
            not addr.is_reserved and
            not addr.is_multicast and
            not addr.is_unspecified
        )
    except ValueError:
        return False

TIMEOUT   = 8
TIMEOUT_S = 5   # short timeout for secondary sources

SAFE_UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# ── MITRE ATT&CK mapping ─────────────────────────────────────────────────────

MITRE_TACTIC_MAP: dict[str, list[tuple[str, str, str]]] = {
    "tor": [
        ("TA0011", "T1090.003", "Command & Control — Multi-hop Proxy"),
        ("TA0005", "T1036",     "Defense Evasion — Masquerading"),
    ],
    "vpn": [
        ("TA0011", "T1090",     "Command & Control — Proxy"),
        ("TA0042", "T1583.003", "Resource Development — Virtual Private Server"),
    ],
    "botnet": [
        ("TA0011", "T1071",     "Command & Control — Application Layer Protocol"),
        ("TA0009", "T1041",     "Exfiltration — Exfiltration Over C2 Channel"),
    ],
    "scanner": [
        ("TA0043", "T1595",     "Reconnaissance — Active Scanning"),
        ("TA0007", "T1046",     "Discovery — Network Service Discovery"),
    ],
    "phishing": [
        ("TA0001", "T1566",     "Initial Access — Phishing"),
        ("TA0042", "T1583",     "Resource Development — Acquire Infrastructure"),
    ],
    "malware": [
        ("TA0002", "T1059",     "Execution — Command & Scripting Interpreter"),
        ("TA0011", "T1105",     "C2 — Ingress Tool Transfer"),
    ],
    "proxy": [
        ("TA0011", "T1090",     "Command & Control — Proxy"),
        ("TA0003", "T1133",     "Persistence — External Remote Services"),
    ],
    "abuse": [
        ("TA0042", "T1583",     "Resource Development — Acquire Infrastructure"),
        ("TA0040", "T1498",     "Impact — Network Denial of Service"),
    ],
    "spam": [
        ("TA0001", "T1566.001", "Initial Access — Spearphishing Attachment"),
        ("TA0042", "T1583",     "Resource Development — Acquire Infrastructure"),
    ],
    "c2": [
        ("TA0011", "T1071.001", "C2 — Web Protocols"),
        ("TA0011", "T1095",     "C2 — Non-Application Layer Protocol"),
    ],
}

APT_CATEGORY_MAP: dict[str, list[str]] = {
    "tor":      ["APT28", "Lazarus Group", "Sandworm", "APT29"],
    "botnet":   ["Emotet", "TrickBot", "QakBot", "IcedID"],
    "scanner":  ["APT41", "Volt Typhoon", "Salt Typhoon"],
    "phishing": ["APT29", "Turla", "TA453", "APT28"],
    "malware":  ["Cobalt Strike", "APT32", "FIN7"],
    "vpn":      ["APT28", "APT29", "Turla"],
    "proxy":    ["APT28", "Turla", "APT29", "Lazarus Group"],
    "c2":       ["Cobalt Strike", "APT41", "Lazarus Group"],
    "spam":     ["TA453", "FIN7", "Emotet"],
}

BULLETPROOF_ORGS = [
    "shinjiru", "combahton", "serverius", "frantech", "ponynet",
    "ddos-guard", "flokinet", "legitbase", "alexanderhosting",
    "maxko", "layerhost", "xtom", "hostkey",
]

VPN_ORGS = [
    "nordvpn", "expressvpn", "mullvad", "protonvpn", "surfshark",
    "cyberghost", "ipvanish", "private internet access", "hidemyass",
    "torguard", "astrill", "windscribe", "bulletvpn", "ivacy",
]

# VT comment NLP keywords
_VT_MAL_KEYWORDS = [
    "phishing", "malware", "scam", "spam", "malicious", "threat",
    "ransomware", "trojan", "c2", "c&c", "botnet", "exploit",
    "payload", "dropper", "loader", "brute", "scanner", "flood",
    "ddos", "miner", "cryptominer", "abuse", "attack", "hack",
]
_VT_BENIGN_KEYWORDS = [
    "false positive", "fp", "legitimate", "safe", "trusted",
    "whitelist", "official", "harmless", "clean",
]


# ── Data Model ────────────────────────────────────────────────────────────────

@dataclass
class IPIntelResult:
    """Full multi-source IP intelligence report."""
    score: int = 0

    # Identity
    ip:           str           = ""
    ip_version:   str           = "IPv4"
    rdns:         Optional[str] = None

    # Geo
    country:      Optional[str]   = None
    country_code: Optional[str]   = None
    city:         Optional[str]   = None
    region:       Optional[str]   = None
    timezone:     Optional[str]   = None
    latitude:     Optional[float] = None
    longitude:    Optional[float] = None

    # ASN / ISP
    asn:          Optional[str] = None
    asn_org:      Optional[str] = None
    isp:          Optional[str] = None

    # Infrastructure flags
    is_tor:         bool = False
    is_vpn:         bool = False
    is_proxy:       bool = False
    is_datacenter:  bool = False
    is_bulletproof: bool = False
    is_mobile:      bool = False

    # AbuseIPDB
    abuse_confidence: int       = 0
    abuse_reports:    int       = 0
    abuse_country:    Optional[str] = None
    abuse_categories: list[str] = field(default_factory=list)
    last_reported:    Optional[str] = None

    # VirusTotal IP intel
    vt_malicious:          int       = 0
    vt_total_engines:      int       = 0
    vt_community_votes_mal: int      = 0
    vt_community_votes_harm: int     = 0
    vt_community_comments_mal: int   = 0
    vt_malicious_files:    int       = 0
    vt_categories:         list[str] = field(default_factory=list)

    # ipinfo.io privacy flags
    ipinfo_vpn:        bool = False
    ipinfo_proxy:      bool = False
    ipinfo_tor:        bool = False
    ipinfo_relay:      bool = False
    ipinfo_abuse_contact: Optional[str] = None

    # BGP / ASN
    bgp_prefix:   Optional[str] = None
    bgp_rir:      Optional[str] = None

    # Threat categories
    threat_categories: list[str] = field(default_factory=list)

    # Open ports (inferred)
    open_ports: list[str] = field(default_factory=list)

    # MITRE ATT&CK
    mitre_tactics: list[tuple[str, str, str]] = field(default_factory=list)

    # Related APT groups
    apt_groups: list[str] = field(default_factory=list)

    # Confidence breakdown
    source_agreement:   int = 0
    source_quality:     int = 0
    scanner_consensus:  int = 0
    provider_agreement: int = 0
    overall_confidence: int = 0

    # Passive DNS
    historical_ips:   list[str] = field(default_factory=list)
    dns_change_count: int       = 0

    # Source tracking
    sources_queried:  list[str] = field(default_factory=list)
    sources_hit:      int       = 0

    last_seen:  Optional[str] = None
    first_seen: Optional[str] = None

    flags:  list[str] = field(default_factory=list)
    iocs:   list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_ipv6(ip: str) -> bool:
    return ":" in ip


def _rdns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _load_tor_exits() -> set[str]:
    try:
        r = requests.get(
            "https://check.torproject.org/torbulkexitlist",
            headers=SAFE_UA, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return set(r.text.strip().splitlines())
    except Exception as _exc:
        logger.debug("Suppressed exception in %s: %s", __name__, _exc)
    return set()


# ── SOURCE 1: ip-api.com ─────────────────────────────────────────────────────

def _fetch_ip_api(ip: str, result: IPIntelResult) -> None:
    """Geo + ASN + proxy/datacenter/VPN flags (free, no key)."""
    fields = (
        "status,message,country,countryCode,region,regionName,"
        "city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query"
    )
    try:
        r = requests.get(
            f"https://ip-api.com/json/{ip}?fields={fields}",
            headers=SAFE_UA, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result.country       = data.get("country")
                result.country_code  = data.get("countryCode")
                result.city          = data.get("city")
                result.region        = data.get("regionName")
                result.timezone      = data.get("timezone")
                result.latitude      = data.get("lat")
                result.longitude     = data.get("lon")
                result.isp           = data.get("isp")
                result.asn_org       = data.get("org")
                result.asn           = data.get("as", "").split()[0] if data.get("as") else None
                result.is_datacenter = bool(data.get("hosting", False))
                result.is_proxy      = bool(data.get("proxy", False))
                result.is_vpn        = result.is_proxy
                result.is_mobile     = bool(data.get("mobile", False))
                result.sources_queried.append("ip-api.com")

                org_lower = (result.asn_org or "").lower()
                for vpn_name in VPN_ORGS:
                    if vpn_name in org_lower:
                        result.is_vpn = True
                        break
                for bp in BULLETPROOF_ORGS:
                    if bp in org_lower:
                        result.is_bulletproof = True
                        break
            else:
                result.errors.append(f"ip-api.com: {data.get('message', 'failed')}")
    except Exception as e:
        result.errors.append(f"ip-api.com error: {e}")


# ── SOURCE 2: AbuseIPDB ──────────────────────────────────────────────────────

def _fetch_abuseipdb(ip: str, api_key: str, result: IPIntelResult) -> None:
    """
    AbuseIPDB v2 — full verbose check.
    Captures: confidence, reports, categories, last_reported, usage_type.
    """
    CATEGORY_NAMES = {
        3: "Fraud Orders", 4: "DDOS Attack", 5: "FTP Brute-Force",
        6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
        9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
        12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
        15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
        18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
        21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
    }
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            result.abuse_confidence = data.get("abuseConfidenceScore", 0)
            result.abuse_reports    = data.get("totalReports", 0)
            result.abuse_country    = data.get("countryCode")
            result.last_reported    = data.get("lastReportedAt", "")[:10] if data.get("lastReportedAt") else None
            result.last_seen        = result.last_reported

            # Decode category IDs
            cat_ids = data.get("reports", [{}])[0].get("categories", []) if data.get("reports") else []
            # Also pull from usageType
            usage = (data.get("usageType") or "").lower()
            if "tor" in usage:
                result.is_tor = True
            if "vpn" in usage or "proxy" in usage:
                result.is_vpn = True

            # Build category list from all reports
            all_cat_ids: set[int] = set()
            for report in (data.get("reports") or [])[:20]:
                for cid in (report.get("categories") or []):
                    all_cat_ids.add(cid)
            result.abuse_categories = [
                CATEGORY_NAMES.get(cid, f"Category {cid}") for cid in sorted(all_cat_ids)
            ]
            result.sources_queried.append("AbuseIPDB")
        else:
            result.errors.append(f"AbuseIPDB HTTP {r.status_code}")
    except Exception as e:
        result.errors.append(f"AbuseIPDB error: {e}")


# ── SOURCE 3: VirusTotal IP ──────────────────────────────────────────────────

def _fetch_virustotal_ip(ip: str, api_key: str, result: IPIntelResult) -> None:
    """
    Full VT IP intelligence:
      - Engine scan results
      - Community votes (malicious / harmless)
      - Community comments (NLP)
      - Communicating / downloaded / referrer files
    """
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    # ── Engine scan ───────────────────────────────────────────────────
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data  = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            result.vt_malicious     = stats.get("malicious", 0)
            result.vt_total_engines = sum(stats.values()) if stats else 0
            result.vt_categories    = list(set(attrs.get("tags", [])))[:6]
            result.sources_queried.append("VirusTotal")

            # Total votes from attributes
            total_votes = attrs.get("total_votes", {})
            result.vt_community_votes_mal  = total_votes.get("malicious", 0)
            result.vt_community_votes_harm = total_votes.get("harmless", 0)

            if result.vt_malicious >= 5:
                result.flags.append(
                    f"🔴 VirusTotal IP: {result.vt_malicious}/{result.vt_total_engines} "
                    f"engines flagged MALICIOUS"
                )
                result.iocs.append(f"VT_IP_MALICIOUS:{result.vt_malicious}_ENGINES")
            elif result.vt_malicious >= 1:
                result.flags.append(
                    f"🟠 VirusTotal IP: {result.vt_malicious} engine(s) flagged"
                )
            else:
                result.flags.append(
                    f"✅ VirusTotal IP: {result.vt_total_engines} engines scanned — clean"
                )

            # Network info from VT
            net = attrs.get("network", "")
            if net:
                result.bgp_prefix = net

        elif r.status_code == 404:
            result.flags.append("VirusTotal IP: Not in database yet")
        else:
            result.errors.append(f"VirusTotal IP HTTP {r.status_code}")
    except Exception as e:
        result.errors.append(f"VirusTotal IP error: {e}")
        return

    # ── Community Votes ───────────────────────────────────────────────
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes",
            headers=headers, params={"limit": 40}, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            votes = r.json().get("data", [])
            mal_v  = sum(1 for v in votes if v.get("attributes", {}).get("verdict") == "malicious")
            harm_v = sum(1 for v in votes if v.get("attributes", {}).get("verdict") == "harmless")
            if mal_v > result.vt_community_votes_mal:
                result.vt_community_votes_mal  = mal_v
                result.vt_community_votes_harm = harm_v

            if result.vt_community_votes_mal >= 3:
                result.flags.append(
                    f"👎 VT Community Votes: {result.vt_community_votes_mal} malicious "
                    f"vs {result.vt_community_votes_harm} harmless"
                )
                result.iocs.append(f"VT_COMMUNITY_VOTES_MAL:{result.vt_community_votes_mal}")
            elif result.vt_community_votes_mal >= 1:
                result.flags.append(
                    f"👎 VT Community: {result.vt_community_votes_mal} user(s) voted malicious"
                )
            elif result.vt_community_votes_harm >= 2:
                result.flags.append(
                    f"👍 VT Community: {result.vt_community_votes_harm} users voted harmless"
                )
    except Exception as e:
        result.errors.append(f"VT votes error: {e}")

    # ── Community Comments NLP ────────────────────────────────────────
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments",
            headers=headers, params={"limit": 10}, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            comments = r.json().get("data", [])
            mal_comments: list[str] = []
            for c in comments:
                text      = c.get("attributes", {}).get("text", "").lower()
                upvotes   = c.get("attributes", {}).get("votes", {}).get("positive", 0)
                mal_hits  = [kw for kw in _VT_MAL_KEYWORDS if kw in text]
                ben_hits  = [kw for kw in _VT_BENIGN_KEYWORDS if kw in text]
                if len(mal_hits) >= 2 and not ben_hits:
                    mal_comments.append(text[:120])
                    result.vt_community_comments_mal += 1

            if mal_comments:
                result.flags.append(
                    f"💬 VT Comments: {len(mal_comments)} comment(s) flag this IP as malicious"
                )
                for i, snippet in enumerate(mal_comments[:2]):
                    result.flags.append(f'   Comment {i+1}: "{snippet.strip()}…"')
                result.iocs.append("VT_COMMUNITY_COMMENTS_MALICIOUS")
            elif comments:
                result.flags.append(
                    f"💬 VT Comments: {len(comments)} comment(s) — no malicious signals"
                )
            else:
                result.flags.append("💬 VT Comments: No community comments yet")
    except Exception as e:
        result.errors.append(f"VT comments error: {e}")

    # ── Relations: communicating files ───────────────────────────────
    for rel_name, rel_label in [
        ("communicating_files", "communicating files"),
        ("downloaded_files",    "downloaded files"),
    ]:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/{rel_name}",
                headers=headers, params={"limit": 10}, timeout=TIMEOUT,
            )
            if r.status_code == 200:
                items = r.json().get("data", [])
                mal_files = sum(
                    1 for item in items
                    if item.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) >= 3
                )
                result.vt_malicious_files += mal_files
                if mal_files > 0:
                    result.flags.append(
                        f"🔗 VT Relations [{rel_name}]: {mal_files}/{len(items)} "
                        f"{rel_label} are MALICIOUS"
                    )
                    result.iocs.append(f"VT_MALICIOUS_{rel_name.upper()}:{mal_files}")
                elif items:
                    result.flags.append(
                        f"🔗 VT Relations [{rel_name}]: {len(items)} found, none malicious"
                    )
        except Exception as e:
            result.errors.append(f"VT {rel_name} error: {e}")


# ── SOURCE 4: ipinfo.io ──────────────────────────────────────────────────────

def _fetch_ipinfo(ip: str, result: IPIntelResult) -> None:
    """
    ipinfo.io free tier — enriches ASN, org, and privacy flags.
    Privacy object: vpn, proxy, tor, relay, hosting, service.
    """
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            headers=SAFE_UA, timeout=TIMEOUT_S,
        )
        if r.status_code == 200:
            data = r.json()
            result.sources_queried.append("ipinfo.io")

            # Fill in geo gaps
            if not result.city and data.get("city"):
                result.city = data["city"]
            if not result.region and data.get("region"):
                result.region = data["region"]
            if not result.country and data.get("country"):
                result.country = data["country"]

            # ASN enrichment
            if not result.asn and data.get("org"):
                parts = data["org"].split(" ", 1)
                result.asn     = parts[0] if parts[0].startswith("AS") else None
                result.asn_org = parts[1] if len(parts) > 1 else data["org"]

            # Abuse contact
            abuse = data.get("abuse", {})
            result.ipinfo_abuse_contact = abuse.get("email")

            # Privacy flags (ipinfo.io paid feature — gracefully skipped if absent)
            privacy = data.get("privacy", {})
            if privacy:
                result.ipinfo_vpn   = bool(privacy.get("vpn",   False))
                result.ipinfo_proxy = bool(privacy.get("proxy", False))
                result.ipinfo_tor   = bool(privacy.get("tor",   False))
                result.ipinfo_relay = bool(privacy.get("relay", False))

                if result.ipinfo_tor:
                    result.is_tor = True
                    result.flags.append("ipinfo.io confirms: Tor exit node")
                if result.ipinfo_vpn or result.ipinfo_proxy:
                    result.is_vpn = True
                    result.flags.append("ipinfo.io confirms: VPN/proxy infrastructure")
                if result.ipinfo_relay:
                    result.flags.append("ipinfo.io: iCloud Private Relay node")
    except Exception as e:
        result.errors.append(f"ipinfo.io error: {e}")


# ── SOURCE 5: Tor Project exit list ─────────────────────────────────────────

def _check_tor(ip: str, result: IPIntelResult) -> None:
    tor_exits = _load_tor_exits()
    if ip in tor_exits:
        result.is_tor = True
        result.flags.append("✅ Tor Project: confirmed in official bulk exit list")
        result.sources_queried.append("Tor Project")
    if result.rdns and ("tor" in result.rdns.lower() or "exit" in result.rdns.lower()):
        result.is_tor = True


# ── SOURCE 6: HackerTarget passive DNS ──────────────────────────────────────

def _fetch_hackertarget(ip: str, result: IPIntelResult) -> None:
    """Reverse IP lookup — hosted domains on this IP."""
    try:
        r = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            headers=SAFE_UA, timeout=TIMEOUT_S,
        )
        if r.status_code == 200 and "No DNS A records" not in r.text and "error" not in r.text.lower():
            domains = [d.strip() for d in r.text.strip().splitlines() if d.strip()][:10]
            result.historical_ips   = domains
            result.dns_change_count = len(domains)
            result.sources_queried.append("HackerTarget")
            if len(domains) >= 5:
                result.flags.append(
                    f"🌐 Passive DNS: {len(domains)} domains hosted on this IP — "
                    f"shared/bulletproof hosting indicator"
                )
            elif domains:
                result.flags.append(f"🌐 Passive DNS: {len(domains)} domain(s) hosted here")
    except Exception as e:
        result.errors.append(f"HackerTarget error: {e}")


# ── SOURCE 7: BGPView ASN enrichment ─────────────────────────────────────────

def _fetch_bgpview(ip: str, result: IPIntelResult) -> None:
    """BGPView.io — prefix, RIR, ASN details (free, no key)."""
    try:
        r = requests.get(
            f"https://api.bgpview.io/ip/{ip}",
            headers=SAFE_UA, timeout=TIMEOUT_S,
        )
        if r.status_code == 200:
            data   = r.json().get("data", {})
            prefix = data.get("prefixes", [{}])[0] if data.get("prefixes") else {}
            if prefix:
                result.bgp_prefix = prefix.get("prefix")
                result.bgp_rir    = prefix.get("rir_allocation", {}).get("rir_name")
                asn_info = prefix.get("asn", {})
                if asn_info and not result.asn:
                    result.asn     = f"AS{asn_info.get('asn', '')}"
                    result.asn_org = asn_info.get("name")
                result.sources_queried.append("BGPView")
    except Exception as e:
        result.errors.append(f"BGPView error: {e}")


# ── Threat category inference ────────────────────────────────────────────────

def _infer_categories(result: IPIntelResult) -> list[str]:
    cats: set[str] = set()

    if result.is_tor:
        cats |= {"tor", "anonymizer", "proxy"}
    if result.is_vpn or result.ipinfo_vpn or result.ipinfo_proxy:
        cats |= {"vpn", "proxy", "anonymizer"}
    if result.is_bulletproof:
        cats |= {"abuse", "bulletproof"}
    if result.abuse_confidence >= 80:
        cats.add("abuse")
    if result.abuse_confidence >= 60:
        cats.add("malicious")
    if result.vt_malicious >= 3:
        cats.add("malicious")
    if result.vt_malicious_files >= 2:
        cats.add("malware")

    # From AbuseIPDB category names
    for cat_name in result.abuse_categories:
        cat_lower = cat_name.lower()
        if "phish" in cat_lower:
            cats.add("phishing")
        if "spam" in cat_lower or "email" in cat_lower:
            cats.add("spam")
        if "ddos" in cat_lower or "flood" in cat_lower:
            cats.add("ddos")
        if "brute" in cat_lower or "ssh" in cat_lower:
            cats.add("scanner")
        if "scan" in cat_lower or "port" in cat_lower:
            cats.add("scanner")
        if "proxy" in cat_lower or "vpn" in cat_lower:
            cats.add("proxy")
        if "botnet" in cat_lower or "malware" in cat_lower:
            cats.add("botnet")
        if "exploit" in cat_lower or "hack" in cat_lower:
            cats.add("malware")

    # RDNS patterns
    rdns_lower = (result.rdns or "").lower()
    if "tor"  in rdns_lower or "exit" in rdns_lower: cats.add("tor")
    if "vpn"  in rdns_lower:                          cats.add("vpn")
    if "scan" in rdns_lower or "shodan" in rdns_lower: cats.add("scanner")
    if "mail" in rdns_lower or "smtp"  in rdns_lower: cats.add("spam")
    if "bot"  in rdns_lower:                           cats.add("botnet")

    # VT community signal
    if result.vt_community_votes_mal >= 2 or result.vt_community_comments_mal >= 1:
        cats.add("abuse")
    if result.vt_community_comments_mal >= 2:
        cats.add("malicious")

    return sorted(cats)


# ── Open port inference ───────────────────────────────────────────────────────

def _infer_open_ports(result: IPIntelResult) -> list[str]:
    ports: set[str] = set()

    if result.is_datacenter or result.abuse_confidence > 0:
        ports |= {":80", ":443"}
    if result.is_tor:
        ports |= {":9001", ":9002", ":80", ":443"}
    if result.is_vpn:
        ports |= {":1194", ":51820", ":443"}    # OpenVPN, WireGuard, SSL-VPN
    if result.is_bulletproof:
        ports |= {":80", ":443", ":8080", ":8443"}

    rdns_lower = (result.rdns or "").lower()
    if "smtp" in rdns_lower or "mail" in rdns_lower:
        ports |= {":25", ":587", ":465"}

    # AbuseIPDB category hints
    for cat in result.abuse_categories:
        cat_lower = cat.lower()
        if "ssh" in cat_lower:
            ports.add(":22")
        if "ftp" in cat_lower:
            ports.add(":21")

    return sorted(ports)


# ── MITRE + APT mapping ───────────────────────────────────────────────────────

def _map_mitre_and_apt(
    categories: list[str],
) -> tuple[list[tuple[str, str, str]], list[str]]:
    seen: set[str] = set()
    tactics: list[tuple[str, str, str]] = []
    apts: set[str] = set()

    for cat in categories:
        for tac in MITRE_TACTIC_MAP.get(cat, []):
            key = f"{tac[0]}-{tac[1]}"
            if key not in seen:
                seen.add(key)
                tactics.append(tac)
        for apt in APT_CATEGORY_MAP.get(cat, []):
            apts.add(apt)

    return tactics[:8], sorted(apts)[:6]


# ── Confidence computation ────────────────────────────────────────────────────

def _compute_confidence(result: IPIntelResult) -> None:
    """
    Multi-source confidence score.
    More sources agreeing = higher confidence.
    """
    # Source agreement: how many independent sources flag this IP
    sources_flagging = 0
    if result.abuse_confidence >= 50:   sources_flagging += 1
    if result.is_tor:                    sources_flagging += 1
    if result.is_vpn and (result.ipinfo_vpn or result.ipinfo_proxy): sources_flagging += 1
    if result.vt_malicious >= 1:         sources_flagging += 1
    if result.vt_community_votes_mal >= 1: sources_flagging += 1
    if result.vt_malicious_files >= 1:   sources_flagging += 1
    if result.is_bulletproof:            sources_flagging += 1
    result.sources_hit      = sources_flagging
    result.source_agreement = min(sources_flagging * 14, 100)

    # Source quality: best signal is AbuseIPDB + VT together
    result.source_quality = min(
        (result.abuse_confidence * 0.6 + result.vt_malicious * 8), 100
    )

    # Scanner consensus: threat categories
    result.scanner_consensus = min(len(result.threat_categories) * 13, 100)

    # Provider agreement: multiple sources confirm same verdict
    both_abuse_vt  = result.abuse_confidence >= 50 and result.vt_malicious >= 1
    both_tor_abuse = result.is_tor and result.abuse_confidence >= 30
    result.provider_agreement = (
        95 if (both_abuse_vt or both_tor_abuse) else
        75 if result.abuse_confidence >= 70 else
        60 if result.abuse_confidence >= 50 else
        40 if result.abuse_confidence >= 20 else
        25
    )

    # Weighted overall
    result.overall_confidence = min(
        int(
            result.source_agreement   * 0.30
            + result.source_quality   * 0.30
            + result.scanner_consensus * 0.20
            + result.provider_agreement * 0.20
        ),
        100,
    )


# ── Scoring ───────────────────────────────────────────────────────────────────

def _compute_score(result: IPIntelResult) -> int:
    """
    Multi-source calibrated scoring.
    AbuseIPDB 71% → HIGH (not LOW).
    VT community signals supplement raw engine count.
    """
    score = 0

    # ── AbuseIPDB (primary, dominant) ────────────────────────────────
    if result.abuse_confidence >= 90:
        score += 40
        result.flags.append(
            f"🔴 AbuseIPDB: CRITICAL — {result.abuse_confidence}% confidence, "
            f"{result.abuse_reports} abuse reports"
        )
        result.iocs.append(f"ABUSIVE_IP:{result.ip}")
    elif result.abuse_confidence >= 70:
        score += 32
        result.flags.append(
            f"🟠 AbuseIPDB: HIGH — {result.abuse_confidence}% confidence, "
            f"{result.abuse_reports} reports"
        )
        result.iocs.append(f"ABUSIVE_IP:{result.ip}")
    elif result.abuse_confidence >= 50:
        score += 22
        result.flags.append(
            f"🟡 AbuseIPDB: MEDIUM — {result.abuse_confidence}% confidence, "
            f"{result.abuse_reports} reports"
        )
    elif result.abuse_confidence >= 20:
        score += 12
        result.flags.append(
            f"AbuseIPDB: {result.abuse_confidence}% confidence "
            f"({result.abuse_reports} reports)"
        )
    elif result.abuse_reports > 0:
        score += 5
        result.flags.append(
            f"AbuseIPDB: {result.abuse_reports} historical report(s) — low confidence"
        )
    else:
        result.flags.append("AbuseIPDB: No abuse history found")

    # AbuseIPDB categories (add context)
    if result.abuse_categories:
        result.flags.append(
            f"📋 AbuseIPDB Categories: {', '.join(result.abuse_categories[:6])}"
        )

    # ── VirusTotal engine detections ─────────────────────────────────
    if result.vt_malicious >= 5:
        score += 25
    elif result.vt_malicious >= 1:
        score += 15

    # ── VT community votes ────────────────────────────────────────────
    if result.vt_community_votes_mal >= 5:
        score += 20
    elif result.vt_community_votes_mal >= 2:
        score += min(result.vt_community_votes_mal * 4, 16)
    elif result.vt_community_votes_mal == 1:
        score += 4

    # ── VT community comments ─────────────────────────────────────────
    if result.vt_community_comments_mal >= 3:
        score += 18
    elif result.vt_community_comments_mal >= 1:
        score += result.vt_community_comments_mal * 7

    # ── VT malicious related files ────────────────────────────────────
    if result.vt_malicious_files >= 3:
        score += 22
    elif result.vt_malicious_files >= 1:
        score += result.vt_malicious_files * 8

    # ── Tor exit node ─────────────────────────────────────────────────
    if result.is_tor:
        score += 22
        result.flags.append("🧅 Confirmed Tor exit node — attacker anonymisation")
        result.iocs.append(f"TOR_EXIT_NODE:{result.ip}")

    # ── VPN / proxy ───────────────────────────────────────────────────
    if result.is_vpn:
        score += 12
        result.flags.append(f"VPN/proxy detected: {result.asn_org or 'Unknown ASN'}")
        result.iocs.append(f"VPN_IP:{result.ip}")

    # ── Bulletproof hosting ───────────────────────────────────────────
    if result.is_bulletproof:
        score += 18
        result.flags.append(
            f"☠️ Bulletproof hosting: {result.asn_org} — resists abuse takedowns"
        )
        result.iocs.append(f"BULLETPROOF:{result.asn_org}")

    # ── Privacy flags (ipinfo) ────────────────────────────────────────
    if result.ipinfo_tor or result.ipinfo_vpn or result.ipinfo_relay:
        score += 8

    # ── Passive DNS (many domains = shared/bulletproof) ───────────────
    if result.dns_change_count >= 8:
        score += 8
    elif result.dns_change_count >= 4:
        score += 4

    if score == 0:
        result.flags.append("✅ No threat signals found — IP appears clean")

    return min(score, 100)


# ── Main entry ────────────────────────────────────────────────────────────────

def analyze_ip(
    ip: str,
    abuse_api_key: Optional[str] = None,
    vt_api_key:   Optional[str] = None,
) -> IPIntelResult:
    """
    Full multi-source IP intelligence analysis.

    Sources queried (in order):
      1. ip-api.com      — geo + proxy/hosting flags
      2. AbuseIPDB       — abuse confidence + report categories
      3. VirusTotal      — engine scan + votes + comments + relations
      4. ipinfo.io       — ASN enrichment + privacy flags
      5. Tor Project     — official exit node list
      6. HackerTarget    — passive DNS / hosted domains
      7. BGPView         — ASN + prefix + RIR details
    """
    result        = IPIntelResult()
    result.ip     = ip.strip()
    result.ip_version = "IPv6" if _is_ipv6(ip) else "IPv4"

    # rDNS first (used by multiple steps)
    result.rdns = _rdns(ip)

    # Source 1: geo + infrastructure flags
    _fetch_ip_api(ip, result)

    # Source 2: AbuseIPDB — only for public IPs (prevent internal IP leak)
    if abuse_api_key:
        if _is_public_ip(ip):
            _fetch_abuseipdb(ip, abuse_api_key, result)
        else:
            result.errors.append("AbuseIPDB: skipped — private/internal IP not submitted to external API")
    else:
        result.errors.append("AbuseIPDB: API key not set — add ABUSEIPDB_API_KEY to .env")

    # Source 3: VirusTotal — only for public IPs
    if vt_api_key:
        if _is_public_ip(ip):
            _fetch_virustotal_ip(ip, vt_api_key, result)
        else:
            result.errors.append("VirusTotal: skipped — private/internal IP not submitted to external API")
    else:
        result.errors.append("VirusTotal: API key not set — add VIRUSTOTAL_API_KEY to .env")

    # Source 4: ipinfo.io enrichment
    _fetch_ipinfo(ip, result)

    # Source 5: Tor official list
    _check_tor(ip, result)

    # Source 6: passive DNS
    _fetch_hackertarget(ip, result)

    # Source 7: BGP / ASN
    _fetch_bgpview(ip, result)

    # Infer threat categories from all signals
    result.threat_categories = _infer_categories(result)

    # Infer open ports
    result.open_ports = _infer_open_ports(result)

    # MITRE + APT mapping
    result.mitre_tactics, result.apt_groups = _map_mitre_and_apt(result.threat_categories)

    # Confidence breakdown
    _compute_confidence(result)

    # Final calibrated score
    result.score = _compute_score(result)

    # Always add IP as first IOC
    ip_ioc = f"IP:{ip}"
    if ip_ioc not in result.iocs:
        result.iocs.insert(0, ip_ioc)

    return result
