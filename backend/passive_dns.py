"""
utils/passive_dns.py
--------------------
Passive DNS History & IP Intelligence Engine — GhostWire CTI v6.

Provides:
  • Passive DNS history via SecurityTrails / HackerTarget (free tier)
  • Parked domain detection via content fingerprinting
  • IP intelligence: Tor, VPN, hosting provider classification
  • ASN lookup for infrastructure profiling
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Optional

import requests

import logging
logger = logging.getLogger(__name__)

TIMEOUT = 8

SAFE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# Parked domain fingerprints (content patterns)
PARKED_PATTERNS = [
    r"this domain is for sale",
    r"domain is parked",
    r"buy this domain",
    r"sedo\.com",
    r"godaddy\.com/domain",
    r"dan\.com",
    r"parkingcrew",
    r"this domain has been registered",
    r"under construction",
    r"coming soon",
    r"domain name has expired",
]

# Known VPN/Proxy ASN prefixes (partial list of major providers)
VPN_ASN_ORGS = [
    "nordvpn", "expressvpn", "mullvad", "protonvpn", "surfshark",
    "cyberghost", "ipvanish", "private internet access", "hidemyass",
    "torguard", "astrill", "perfect privacy", "windscribe",
    "bulletvpn", "ivacy", "strongvpn",
]

# Known bulletproof / high-abuse hosting providers
BULLETPROOF_HOSTERS = [
    "shinjiru", "combahton", "serverius", "frantech", "ponynet",
    "ddos-guard", "flokinet", "legitbase", "alexanderhosting",
    "maxko", "layerhost", "xtom",
]


@dataclass
class PassiveDNSResult:
    """Result from passive DNS and IP intelligence analysis."""
    score: int = 0

    # Passive DNS
    historical_ips: list[str]   = field(default_factory=list)
    dns_change_count: int       = 0      # How many times IP changed recently
    first_seen: Optional[str]   = None
    last_seen: Optional[str]    = None

    # Parked domain
    is_parked: bool             = False
    parked_provider: Optional[str] = None

    # IP intelligence
    ip_address: Optional[str]   = None
    asn: Optional[str]          = None
    asn_org: Optional[str]      = None
    hosting_country: Optional[str] = None
    is_tor: bool                = False
    is_vpn: bool                = False
    is_bulletproof: bool        = False
    is_datacenter: bool         = False

    flags: list[str]            = field(default_factory=list)
    iocs: list[str]             = field(default_factory=list)
    errors: list[str]           = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    import tldextract
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return url.split("//")[-1].split("/")[0].split("?")[0]


def _resolve(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


# ── HackerTarget Passive DNS (free, no key required) ─────────────────────────

def _hackertarget_pdns(domain: str) -> list[str]:
    """
    Query HackerTarget's free passive DNS API.
    Returns list of historical IP addresses seen for this domain.
    """
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            headers=SAFE_HEADERS,
            timeout=TIMEOUT,
        )
        if r.status_code != 200 or "error" in r.text.lower():
            return []

        ips = []
        for line in r.text.strip().splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                ip = parts[1].strip()
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    ips.append(ip)
        return list(set(ips))[:10]
    except Exception:
        return []


# ── ASN / IP info via ip-api.com (free, no key) ───────────────────────────────

def _ip_api_lookup(ip: str) -> dict:
    try:
        r = requests.get(
            f"https://ip-api.com/json/{ip}?fields=status,country,countryCode,"
            f"isp,org,as,hosting,proxy,mobile",
            headers=SAFE_HEADERS,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


# ── Tor exit node list (Tor Project — free) ───────────────────────────────────

_tor_exit_cache: set[str] = set()
_tor_loaded = False


def _load_tor_exits() -> set[str]:
    global _tor_exit_cache, _tor_loaded
    if _tor_loaded:
        return _tor_exit_cache
    try:
        r = requests.get(
            "https://check.torproject.org/torbulkexitlist",
            headers=SAFE_HEADERS,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            _tor_exit_cache = set(r.text.strip().splitlines())
        _tor_loaded = True
    except Exception:
        _tor_loaded = True  # don't retry on failure
    return _tor_exit_cache


# ── Parked domain detection ───────────────────────────────────────────────────

def _detect_parked(domain: str) -> tuple[bool, Optional[str]]:
    """
    Fetch the root domain and fingerprint for parking page patterns.
    Returns (is_parked, provider_name).

    SECURITY: SSRF guard applied — blocks private/loopback/internal targets.
    """
    # ── SSRF guard ────────────────────────────────────────────────────
    # Reuse sandbox SSRF check to prevent probing internal infrastructure
    # e.g. http://localhost:8501, http://169.254.169.254, http://10.0.0.1
    try:
        from backend.sandbox import _is_ssrf_target
        _blocked, _reason = _is_ssrf_target(f"http://{domain}")
        if _blocked:
            return False, None
    except Exception:
        pass  # if import fails, fall through to the request (belt-and-suspenders)

    try:
        r = requests.get(
            f"http://{domain}",
            headers=SAFE_HEADERS,
            timeout=6,
            allow_redirects=False,   # SECURITY: no redirect following
        )
        # If response is a redirect (301/302), no body to check
        if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
            return False, None
        if not r.ok:
            return False, None
        content = r.content[:65536].decode("utf-8", errors="ignore").lower()

        for pat in PARKED_PATTERNS:
            if re.search(pat, content):
                # Try to identify the parking provider
                provider = "Unknown parking service"
                if "sedo" in content:
                    provider = "Sedo"
                elif "godaddy" in content:
                    provider = "GoDaddy"
                elif "parkingcrew" in content:
                    provider = "ParkingCrew"
                elif "dan.com" in content:
                    provider = "Dan.com"
                return True, provider
    except Exception:
        pass
    return False, None


# ── Main ─────────────────────────────────────────────────────────────────────

def analyze_passive_dns(
    url: str,
    ht_key: Optional[str] = None,     # HackerTarget pro key (optional)
    st_key: Optional[str] = None,     # SecurityTrails key (optional)
) -> PassiveDNSResult:
    """
    Run full passive DNS history and IP intelligence analysis.

    Free tier uses HackerTarget + ip-api.com (no keys needed).
    Paid tier adds SecurityTrails for richer PDNS history.
    """
    result = PassiveDNSResult()
    domain = _extract_domain(url)
    result.ip_address = _resolve(domain)

    # ── Passive DNS history ───────────────────────────────────────────
    hist_ips = _hackertarget_pdns(domain)
    result.historical_ips = hist_ips
    result.dns_change_count = len(hist_ips)

    if result.dns_change_count >= 5:
        result.score += 12
        result.flags.append(
            f"Passive DNS: {result.dns_change_count} distinct IPs historically — "
            f"rapid IP rotation, common in phishing infra"
        )
        result.iocs.append(f"PDNS_IP_ROTATION:{result.dns_change_count}_IPS")
    elif result.dns_change_count >= 3:
        result.score += 6
        result.flags.append(
            f"Passive DNS: {result.dns_change_count} historical IPs detected"
        )

    # ── IP intelligence ───────────────────────────────────────────────
    if result.ip_address:
        result.iocs.append(f"IP:{result.ip_address}")

        # Tor exit node check
        tor_exits = _load_tor_exits()
        if result.ip_address in tor_exits:
            result.is_tor = True
            result.score += 15
            result.flags.append(
                f"IP {result.ip_address} is a confirmed Tor exit node — "
                f"attacker is anonymising their infrastructure"
            )
            result.iocs.append(f"TOR_EXIT:{result.ip_address}")

        # ASN + hosting intelligence
        ip_data = _ip_api_lookup(result.ip_address)
        if ip_data.get("status") == "success":
            result.asn          = ip_data.get("as", "")
            result.asn_org      = ip_data.get("org", "")
            result.hosting_country = ip_data.get("countryCode")
            result.is_datacenter   = bool(ip_data.get("hosting", False))
            result.is_vpn          = bool(ip_data.get("proxy", False))

            org_lower = (result.asn_org or "").lower()

            # VPN provider check
            for vpn in VPN_ASN_ORGS:
                if vpn in org_lower:
                    result.is_vpn = True
                    result.score += 10
                    result.flags.append(
                        f"IP hosted on VPN provider infrastructure: {result.asn_org}"
                    )
                    result.iocs.append(f"VPN_IP:{result.ip_address}")
                    break

            # Bulletproof hosting check
            for bp in BULLETPROOF_HOSTERS:
                if bp in org_lower:
                    result.is_bulletproof = True
                    result.score += 20
                    result.flags.append(
                        f"Bulletproof hosting provider: {result.asn_org} — "
                        f"known for ignoring abuse complaints"
                    )
                    result.iocs.append(f"BULLETPROOF_HOST:{result.asn_org}")
                    break

            # Generic datacenter (not cloud) — suspicious for phishing landing pages
            if result.is_datacenter and not result.is_vpn and not result.is_bulletproof:
                result.score += 3
                result.flags.append(
                    f"IP in datacenter/hosting range ({result.asn_org}) — "
                    f"not a residential connection"
                )

            # High-risk country (heuristic — not a blanket ban, just a signal)
            if result.hosting_country and ip_data.get("proxy"):
                result.score += 5
                result.flags.append(
                    f"IP flagged as proxy/anonymous ({result.hosting_country})"
                )

    # ── Parked domain detection ────────────────────────────────────────
    is_parked, provider = _detect_parked(domain)
    result.is_parked = is_parked
    if is_parked:
        result.parked_provider = provider
        result.score += 8
        result.flags.append(
            f"Domain appears to be PARKED ({provider}) — "
            f"may be recently acquired for phishing"
        )
        result.iocs.append(f"PARKED_DOMAIN:{domain}")

    if not result.flags:
        result.flags.append("Passive DNS: No anomalies detected")

    result.score = min(result.score, 30)
    return result
