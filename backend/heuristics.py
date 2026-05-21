"""
utils/heuristics.py
-------------------
URL Heuristics Engine for GhostWire CTI Local.

Performs fast, offline technical analysis of a URL to identify
structural red flags commonly found in phishing links.
"""

import re
import urllib.parse
from dataclasses import dataclass, field

import logging

logger = logging.getLogger(__name__)



@dataclass
class HeuristicsResult:
    """Structured result from the URL heuristics engine."""
    score: int = 0                        # Risk contribution (0–30)
    flags: list[str] = field(default_factory=list)  # Human-readable findings
    details: dict = field(default_factory=dict)      # Raw metric values


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def _check_length(url: str) -> tuple[int, str | None]:
    """
    Penalise unusually long URLs.
    Phishing URLs often pad with subdomains or random paths to hide intent.
    """
    length = len(url)
    if length > 100:
        return 10, f"URL is very long ({length} chars > 100)"
    if length > 75:
        return 5, f"URL is moderately long ({length} chars > 75)"
    return 0, None


def _check_at_symbol(url: str) -> tuple[int, str | None]:
    """
    Detect '@' in the URL.
    Browsers treat everything before '@' as credentials and ignore it,
    making this a classic obfuscation trick.
    """
    if "@" in url:
        return 8, "URL contains '@' — possible credential obfuscation"
    return 0, None


def _check_ip_address(url: str) -> tuple[int, str | None]:
    """
    Detect raw IP addresses used instead of a domain name.
    Legitimate services almost never expose raw IPs in links.
    """
    ipv4_pattern = re.compile(
        r"https?://(\d{1,3}\.){3}\d{1,3}"
    )
    if ipv4_pattern.match(url):
        return 10, "URL uses a raw IP address instead of a domain"
    return 0, None


def _check_https(url: str) -> tuple[int, str | None]:
    """
    Flag plain HTTP links.
    Phishing pages frequently skip TLS to cut setup time.
    """
    if url.lower().startswith("http://"):
        return 5, "URL uses plain HTTP (not HTTPS)"
    return 0, None


def _check_suspicious_tld(parsed_url: urllib.parse.ParseResult) -> tuple[int, str | None]:
    """
    Penalise top-level domains heavily abused in phishing campaigns.
    """
    high_risk_tlds = {
        ".tk", ".ml", ".ga", ".cf", ".gq",   # Free Freenom TLDs
        ".xyz", ".top", ".click", ".link",
        ".zip", ".mov",                        # Confusable file-extension TLDs
    }
    hostname = parsed_url.hostname or ""
    for tld in high_risk_tlds:
        if hostname.endswith(tld):
            return 7, f"Domain uses a high-risk TLD: '{tld}'"
    return 0, None


def _check_subdomain_depth(parsed_url: urllib.parse.ParseResult) -> tuple[int, str | None]:
    """
    Count subdomain levels.
    Deep nesting (e.g. secure.paypal.login.evil.com) is a common spoofing
    technique that buries the real domain at the end.
    """
    hostname = parsed_url.hostname or ""
    parts = [p for p in hostname.split(".") if p]
    # Strip leading 'www' — it's a standard prefix, not a suspicious subdomain
    if parts and parts[0].lower() == "www":
        parts = parts[1:]
    depth = len(parts) - 2  # subtract SLD + TLD
    if depth >= 3:
        return 8, f"Very deep subdomain nesting ({depth} levels) — possible spoofing"
    if depth >= 2:
        return 4, f"Multiple subdomains ({depth} levels) — review carefully"
    return 0, None


def _check_hyphen_abuse(parsed_url: urllib.parse.ParseResult) -> tuple[int, str | None]:
    """
    Detect brand-impersonation patterns like 'paypal-secure-login.com'.
    Hyphens in the hostname are a textbook phishing indicator.
    """
    hostname = parsed_url.hostname or ""
    # Strip TLD for counting
    parts = hostname.rsplit(".", 2)
    domain_part = parts[0] if parts else hostname
    hyphen_count = domain_part.count("-")
    if hyphen_count >= 2:
        return 7, f"Many hyphens in domain ({hyphen_count}) — possible brand spoofing"
    if hyphen_count == 1:
        return 3, "Hyphen in domain name — minor concern"
    return 0, None


def _check_suspicious_keywords(url: str) -> tuple[int, str | None]:
    """
    Match known phishing keyword patterns in the full URL string.
    """
    keywords = [
        "login", "signin", "verify", "secure", "account",
        "update", "confirm", "banking", "password", "credential",
        "support", "authenticate", "validation",
    ]
    url_lower = url.lower()
    found = [kw for kw in keywords if kw in url_lower]
    if len(found) >= 3:
        return 8, f"Multiple phishing keywords in URL: {', '.join(found[:5])}"
    if found:
        return 3, f"Phishing keyword(s) detected: {', '.join(found)}"
    return 0, None


def _check_redirect_chain(url: str) -> tuple[int, str | None]:
    """
    Detect URL-in-URL patterns (open redirect abuse).
    e.g. legit.com/redirect?url=http://evil.com
    """
    # Count occurrences of 'http' after the scheme portion
    http_count = url.lower().count("http", 8)
    if http_count >= 1:
        return 7, "Possible open-redirect or URL-in-URL detected"
    return 0, None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> HeuristicsResult:
    """
    Run all heuristic checks against the supplied URL.

    Returns a HeuristicsResult whose ``score`` is capped at 30
    (the maximum contribution this engine can add to the total risk score).

    Args:
        url: The raw URL string to analyse.

    Returns:
        HeuristicsResult with score, flags, and raw metric details.
    """
    result = HeuristicsResult()

    # Basic sanity — ensure the URL has a scheme for parsing
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        result.flags.append("Could not parse URL structure")
        result.score = 15
        return result

    # Run each check and accumulate
    checks = [
        _check_length(url),
        _check_at_symbol(url),
        _check_ip_address(url),
        _check_https(url),
        _check_suspicious_tld(parsed),
        _check_subdomain_depth(parsed),
        _check_hyphen_abuse(parsed),
        _check_suspicious_keywords(url),
        _check_redirect_chain(url),
    ]

    raw_score = 0
    for points, flag in checks:
        if points:
            raw_score += points
        if flag:
            result.flags.append(flag)

    # Store diagnostic details
    result.details = {
        "url_length": len(url),
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "path": parsed.path,
    }

    # Cap the heuristics contribution at 30 points
    result.score = min(raw_score, 30)
    return result
