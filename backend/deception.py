"""
utils/deception.py
------------------
Technical Deception Analysis Engine — GhostWire CTI v6.

Detects:
  • Typosquatting against top-50 global brands
  • Subdomain hijacking / deep nesting patterns
  • Hidden redirect chains (URL-in-URL, open redirects)
  • Homoglyph / punycode IDN attacks
  • Suspicious TLDs catalogued from phishing campaigns
  • URL shortener abuse
  • Misleading path obfuscation tricks
"""

import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import tldextract

import logging

logger = logging.getLogger(__name__)



@dataclass
class DeceptionResult:
    score: int = 0
    typosquat_target: Optional[str] = None     # Brand being impersonated
    typosquat_distance: Optional[int] = None   # Levenshtein distance
    has_homoglyph: bool = False
    has_punycode: bool = False
    redirect_depth: int = 0
    shortener_detected: bool = False
    flags: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)


# ── Brand database ───────────────────────────────────────────────────────────

BRANDS = [
    "paypal","google","facebook","apple","microsoft","amazon","netflix",
    "instagram","twitter","linkedin","dropbox","spotify","adobe","ebay",
    "wellsfargo","bankofamerica","chase","citibank","hsbc","barclays",
    "dhl","fedex","ups","usps","whatsapp","telegram","discord","steam",
    "coinbase","binance","blockchain","metamask","opensea","gmail",
    "outlook","yahoo","office365","sharepoint","onedrive","icloud",
    "hulu","disney","twitch","youtube","tiktok","snapchat",
]

SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly",
    "dlvr.it","is.gd","v.gd","shorte.st","adf.ly","bc.vc",
    "cutt.ly","rebrand.ly","short.io","tiny.cc","rb.gy",
}

HIGH_RISK_TLDS = {
    ".tk",".ml",".ga",".cf",".gq",            # Freenom freebies — massively abused
    ".xyz",".top",".click",".link",".online",
    ".site",".website",".tech",               # Cheap & throwaway
    ".zip",".mov",".png",                     # Confusable file-extension TLDs
    ".support",".security",".login",          # Authority-impersonation TLDs
    ".accountant",".loan",".download",
}

# Common homoglyph substitutions (Latin lookalikes)
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",   # Cyrillic
    "ο": "o", "ν": "v", "α": "a",                         # Greek
    "ı": "i", "ĺ": "l", "ḷ": "l",
    "0": "o", "1": "l", "3": "e", "5": "s", "4": "a",    # Leet-speak
}


# ── Levenshtein distance (no external dep) ───────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca != cb)))
        prev = curr
    return prev[-1]


# ── Homoglyph / punycode detection ───────────────────────────────────────────

def _normalise_homoglyphs(text: str) -> str:
    """Replace known homoglyphs with their ASCII equivalents."""
    return "".join(HOMOGLYPHS.get(c, c) for c in text)


def _detect_homoglyph(hostname: str) -> tuple[bool, bool]:
    """Return (has_homoglyph, has_punycode)."""
    has_punycode = "xn--" in hostname.lower()

    # Check for non-ASCII characters after unicode normalisation
    try:
        hostname.encode("ascii")
        has_homoglyph = False
    except UnicodeEncodeError:
        has_homoglyph = True

    # Check leet-speak only if a brand-like pattern exists with digit substitution
    # Don't flag 'bank123.com' — only flag 'g00gle.com', 'paypa1.com' style patterns
    digits_as_letters = False
    if re.search(r'[013458]', hostname):
        # Only flag if digit appears ADJACENT to brand-like letter sequences
        # Replace digits with letters and check if result is close to a brand
        leet_map = {'0':'o','1':'l','3':'e','5':'s','4':'a','8':'b'}
        normalized_host = ''.join(leet_map.get(c, c) for c in hostname.lower())
        # Only flag if the normalized version looks different from original
        if normalized_host != hostname.lower():
            # Check if normalization reveals a brand name
            ext_d = tldextract.extract(normalized_host)
            sld_norm = ext_d.domain.lower()
            digits_as_letters = any(
                brand in sld_norm or sld_norm in brand
                for brand in ["google","paypal","apple","microsoft","amazon",
                              "facebook","netflix","ebay","linkedin","outlook"]
                if abs(len(sld_norm) - len(brand)) <= 2
            )
    return has_homoglyph or digits_as_letters, has_punycode


# ── Typosquatting detection ───────────────────────────────────────────────────

def _detect_typosquat(domain_part: str) -> tuple[Optional[str], Optional[int]]:
    """
    Compare the SLD (second-level domain) against known brands using
    Levenshtein distance ≤ 2 AND length similarity heuristic.
    """
    normalised = _normalise_homoglyphs(domain_part.lower())

    best_brand: Optional[str] = None
    best_dist: Optional[int] = None

    for brand in BRANDS:
        # Only compare against brands of similar length (±4 chars)
        if abs(len(normalised) - len(brand)) > 4:
            continue
        dist = _levenshtein(normalised, brand)
        # Distance ≤ 2 and NOT an exact match to avoid false positives on
        # legitimate subdomains of the brand itself
        if 0 < dist <= 2:
            if best_dist is None or dist < best_dist:
                best_brand = brand
                best_dist = dist

    return best_brand, best_dist


# ── Subdomain abuse ───────────────────────────────────────────────────────────

def _detect_subdomain_abuse(parsed: urllib.parse.ParseResult) -> list[str]:
    flags = []
    hostname = parsed.hostname or ""
    parts = [p for p in hostname.split(".") if p]
    depth = len(parts) - 2

    if depth >= 4:
        flags.append(f"Extreme subdomain depth ({depth} levels) — sophisticated spoofing")
    elif depth >= 2:
        flags.append(f"Deep subdomain nesting ({depth} levels) — possible brand spoofing")

    # Check if a brand name appears in a subdomain (not the SLD)
    if len(parts) > 2:
        subdomains = ".".join(parts[:-2]).lower()
        for brand in BRANDS:
            if brand in subdomains:
                flags.append(
                    f"Brand name '{brand}' in subdomain — classic subdomain hijacking pattern"
                )
                break

    return flags


# ── Redirect chain detection ──────────────────────────────────────────────────

def _detect_redirects(url: str) -> tuple[int, list[str]]:
    flags = []
    depth = 0

    # Count embedded URLs (URL-in-URL open redirect)
    http_count = url.lower().count("http", 8)
    if http_count >= 2:
        depth = http_count
        flags.append(f"Redirect chain detected — {http_count} embedded URLs")

    # Common open-redirect parameter names
    redirect_params = ["redirect", "url", "next", "return", "goto", "target", "link", "redir"]
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    for param in redirect_params:
        if param in qs:
            flags.append(f"Open-redirect parameter detected: '?{param}='")
            depth += 1

    return depth, flags


# ── URL shortener detection ───────────────────────────────────────────────────

def _detect_shortener(hostname: str) -> bool:
    return hostname.lower() in SHORTENERS or hostname.lower().startswith("bit.")


# ── Path obfuscation ─────────────────────────────────────────────────────────

def _detect_path_tricks(parsed: urllib.parse.ParseResult) -> list[str]:
    flags = []
    path = parsed.path.lower()
    query = parsed.query.lower()
    full = path + "?" + query

    # Double encoding
    if "%25" in full:
        flags.append("Double URL encoding detected — possible WAF bypass attempt")

    # Null byte injection
    if "%00" in full:
        flags.append("Null byte in URL — server-side injection attempt")

    # Excessive dots (path traversal)
    if "../" in path or "%2e%2e" in path:
        flags.append("Path traversal sequence detected")

    # Long random-looking tokens (credential harvesting pages often use these)
    tokens = re.findall(r"[a-zA-Z0-9]{40,}", full)
    if tokens:
        flags.append(f"Long random token in URL ({len(tokens[0])} chars) — possible tracking/harvesting token")

    return flags


# ── Main ─────────────────────────────────────────────────────────────────────

def analyze_deception(url: str) -> DeceptionResult:
    """
    Run all technical deception checks against the URL.

    Returns a DeceptionResult whose score is capped at 30.
    """
    result = DeceptionResult()

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        result.flags.append("URL parsing failed — structure is severely malformed")
        result.score = 15
        return result

    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)
    sld = ext.domain.lower()
    tld = f".{ext.suffix}".lower() if ext.suffix else ""

    # 1. High-risk TLD
    for bad_tld in HIGH_RISK_TLDS:
        if tld == bad_tld or tld.endswith(bad_tld):
            result.score += 8
            result.flags.append(f"High-risk TLD '{tld}' — widely abused in phishing campaigns")
            result.iocs.append(f"RISKY_TLD:{tld}")
            break

    # 2. Typosquatting
    brand, dist = _detect_typosquat(sld)
    if brand:
        result.typosquat_target  = brand
        result.typosquat_distance = dist
        result.score += 12
        result.flags.append(
            f"Typosquatting detected — '{sld}' ≈ '{brand}' (edit distance: {dist})"
        )
        result.iocs.append(f"TYPOSQUAT:{sld}→{brand}")

    # 3. Homoglyph / punycode
    has_hg, has_pny = _detect_homoglyph(hostname)
    if has_pny:
        result.has_punycode = True
        result.score += 10
        result.flags.append("Punycode/IDN domain detected — possible homograph attack")
        result.iocs.append(f"PUNYCODE_DOMAIN:{hostname}")
    elif has_hg:
        result.has_homoglyph = True
        result.score += 8
        result.flags.append("Homoglyph characters or leet-substitutions in domain")

    # 4. Subdomain abuse
    sub_flags = _detect_subdomain_abuse(parsed)
    for f in sub_flags:
        result.flags.append(f)
        result.score += 5

    # 5. Redirect chains
    depth, redir_flags = _detect_redirects(url)
    result.redirect_depth = depth
    for f in redir_flags:
        result.flags.append(f)
        result.score += 6

    # 6. URL shortener
    if _detect_shortener(hostname):
        result.shortener_detected = True
        result.score += 7
        result.flags.append(f"URL shortener detected ({hostname}) — hides true destination")
        result.iocs.append(f"URL_SHORTENER:{hostname}")

    # 7. Path obfuscation
    path_flags = _detect_path_tricks(parsed)
    for f in path_flags:
        result.flags.append(f)
        result.score += 4

    if not result.flags:
        result.flags.append("No technical deception patterns detected")

    result.score = min(result.score, 30)
    return result
