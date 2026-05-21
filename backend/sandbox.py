"""
utils/sandbox.py
----------------
Sandbox Behavioral Analysis Engine — GhostWire CTI v6.
"""

import re
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Optional

import requests

import logging
logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    score: int = 0
    # Behavioral triggers
    credential_harvesting: bool = False
    malware_distribution: bool = False
    drive_by_download: bool = False
    fake_login_page: bool = False
    crypto_drainer: bool = False
    tech_support_scam: bool = False
    # Technical findings
    final_url: Optional[str] = None           # After redirect chain
    redirect_count: int = 0
    server_header: Optional[str] = None
    content_type: Optional[str] = None
    page_title: Optional[str] = None
    suspicious_forms: int = 0
    external_scripts: list[str] = field(default_factory=list)
    # Output
    flags: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── Pattern libraries ────────────────────────────────────────────────────────

# Credential harvesting patterns in HTML
CREDENTIAL_PATTERNS = [
    r'<input[^>]+type=["\']password["\']',
    r'<input[^>]+name=["\'](?:pass|password|passwd|pwd|secret)["\']',
    r'<form[^>]+action=["\'][^"\']*(?:login|signin|verify|auth)["\']',
    r'(?:enter|confirm|reset)\s+your\s+password',
    r'verify\s+your\s+(?:identity|account|email)',
]

# Drive-by download / malware distribution
MALWARE_PATTERNS = [
    r'\.exe["\'\s]',
    r'application/(?:octet-stream|x-msdownload)',
    r'<script[^>]+src=["\'][^"\']*(?:\.js\?[a-z0-9]{16,})["\']',  # Obfuscated JS
    r'eval\s*\(',
    r'document\.write\s*\(',
    r'window\.location\s*=',
    r'(?:powershell|cmd\.exe|wscript)',
]

# Fake login page indicators
FAKE_LOGIN_PATTERNS = [
    r'<title>[^<]*(?:paypal|microsoft|google|apple|amazon|facebook|netflix|bank)[^<]*</title>',
    r'(?:secure|official|verified)\s+(?:login|sign.?in)',
    r'your\s+account\s+(?:has\s+been|is)\s+(?:suspended|locked|compromised)',
]

# Crypto drainer patterns
CRYPTO_PATTERNS = [
    r'connect\s+(?:your\s+)?wallet',
    r'(?:metamask|coinbase\s+wallet|trust\s+wallet)',
    r'(?:seed\s+phrase|recovery\s+phrase|private\s+key)',
    r'claim\s+(?:your\s+)?(?:nft|airdrop|reward)',
]

# Tech support scam
TECH_SUPPORT_PATTERNS = [
    r'(?:call|contact)\s+(?:microsoft|apple|google)\s+support',
    r'your\s+(?:computer|device|pc)\s+(?:has\s+been|is)\s+(?:hacked|infected|compromised)',
    r'toll.?free[:\s]+[\d\-\+\(\)]{7,}',
    r'do\s+not\s+(?:close|ignore)\s+this\s+(?:page|window|alert)',
]

SAFE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


# ── HTTP analysis ────────────────────────────────────────────────────────────

# ── SSRF Protection ──────────────────────────────────────────────────────────
# Blocks requests to private/internal/link-local/loopback ranges.
# Without this, an attacker submitting http://169.254.169.254/ or
# http://localhost:8501/ could probe internal infrastructure.

_BLOCKED_SCHEMES = {"file", "ftp", "gopher", "data", "dict", "ldap", "ldaps"}

def _is_ssrf_target(url: str) -> tuple[bool, str]:
    """
    Returns (is_blocked, reason).
    Resolves the hostname and checks against private/reserved IP ranges.
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)

        # Block dangerous schemes
        if parsed.scheme.lower() in _BLOCKED_SCHEMES:
            return True, f"Blocked scheme: {parsed.scheme}"

        hostname = parsed.hostname or ""

        # Literal IP check
        try:
            addr = ipaddress.ip_address(hostname)
            if (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_reserved or
                    addr.is_multicast or addr.is_unspecified):
                return True, f"Blocked private/internal IP: {hostname}"
        except ValueError:
            pass  # not a literal IP — resolve it

        # DNS resolution check (catches internal hostnames like "localhost", "metadata")
        try:
            resolved_ip = socket.gethostbyname(hostname)
            addr = ipaddress.ip_address(resolved_ip)
            if (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_reserved or
                    addr.is_multicast or addr.is_unspecified):
                return True, f"Hostname '{hostname}' resolves to internal IP: {resolved_ip}"
        except socket.gaierror:
            pass  # DNS failure — let requests handle it

    except Exception as e:
        return True, f"URL validation error: {e}"

    return False, ""


def _safe_fetch(url: str) -> tuple[Optional[requests.Response], str]:
    """
    Perform a safe GET request with strict limits.
    Returns (response, error_string).
    Content is read up to 512KB only.

    SECURITY: SSRF protection validates the URL resolves to a public IP
    before making the request. Private/loopback/link-local ranges are blocked.
    """
    # ── SSRF guard ────────────────────────────────────────────────────
    blocked, reason = _is_ssrf_target(url)
    if blocked:
        return None, f"SSRF blocked: {reason}"

    try:
        session = requests.Session()
        r = session.get(
            url,
            headers=SAFE_HEADERS,
            timeout=8,
            allow_redirects=False,   # SECURITY: follow redirects manually to re-check each hop
            stream=True,
        )

        # ── Manual redirect following with SSRF check on each hop ─────
        MAX_REDIRECTS = 5
        hops = 0
        while r.is_redirect and hops < MAX_REDIRECTS:
            next_url = r.headers.get("Location", "")
            if not next_url:
                break
            # Resolve relative redirects
            if next_url.startswith("/"):
                from urllib.parse import urlparse
                p = urlparse(url)
                next_url = f"{p.scheme}://{p.netloc}{next_url}"
            # SSRF check on redirect destination
            blocked, reason = _is_ssrf_target(next_url)
            if blocked:
                return None, f"SSRF blocked in redirect: {reason}"
            r = session.get(next_url, headers=SAFE_HEADERS, timeout=8,
                            allow_redirects=False, stream=True)
            url = next_url
            hops += 1
        # Read only first 512KB — enough for fingerprinting, avoids DoS
        content = b""
        for chunk in r.iter_content(chunk_size=8192):
            content += chunk
            if len(content) >= 524288:  # 512KB
                break
        r._content = content
        return r, ""
    except requests.exceptions.SSLError:
        return None, "SSL certificate error — possible self-signed cert (phishing indicator)"
    except requests.exceptions.ConnectionError:
        return None, "Connection refused — domain may be inactive or geo-blocked"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except Exception as e:
        return None, str(e)


def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>([^<]{1,120})</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else None


def _count_forms(html: str) -> int:
    return len(re.findall(r"<form", html, re.IGNORECASE))


def _extract_external_scripts(html: str, base_host: str) -> list[str]:
    """Find script tags loading from third-party domains."""
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    external = []
    for src in srcs:
        if src.startswith("http") and base_host not in src:
            external.append(src[:80])
        elif src.startswith("//") and base_host not in src:
            external.append(src[:80])
    return external[:10]


def _match_patterns(html: str, patterns: list[str]) -> bool:
    html_lower = html.lower()
    for pat in patterns:
        if re.search(pat, html_lower, re.IGNORECASE):
            return True
    return False


# ── Main ─────────────────────────────────────────────────────────────────────

def analyze_sandbox(url: str) -> SandboxResult:
    """
    Simulate sandbox behavioral analysis via safe static HTTP inspection.

    Score capped at 30 points.
    """
    result = SandboxResult()

    response, error = _safe_fetch(url)

    if error:
        result.errors.append(f"Sandbox fetch: {error}")
        # SSL errors are themselves a phishing indicator
        if "SSL" in error or "certificate" in error:
            result.score += 8
            result.flags.append(f"SSL error — {error}")
        return result

    if response is None:
        result.errors.append("Could not reach URL for sandbox analysis")
        return result

    # ── HTTP metadata ───────────────────────────────────────────────────
    result.final_url      = response.url
    result.redirect_count = len(response.history)
    result.server_header  = response.headers.get("Server", "Unknown")
    result.content_type   = response.headers.get("Content-Type", "")

    if result.redirect_count >= 3:
        result.score += 8
        result.flags.append(
            f"Sandbox: {result.redirect_count} HTTP redirects detected — evasion behaviour"
        )
        result.iocs.append(f"REDIRECT_CHAIN:{result.redirect_count}_HOPS")

    # Check for suspicious final domain (redirect destination)
    if result.final_url and result.final_url != url:
        result.flags.append(f"Redirected to: {result.final_url[:80]}")
        result.iocs.append(f"FINAL_URL:{result.final_url[:80]}")

    # ── Content analysis ────────────────────────────────────────────────
    try:
        html = response.content.decode("utf-8", errors="ignore")
    except Exception:
        result.errors.append("Could not decode page content")
        return result

    from urllib.parse import urlparse
    base_host = urlparse(url).hostname or ""

    result.page_title      = _extract_title(html)
    result.suspicious_forms = _count_forms(html)
    result.external_scripts = _extract_external_scripts(html, base_host)

    # ── Behavioral triggers ─────────────────────────────────────────────

    if _match_patterns(html, CREDENTIAL_PATTERNS):
        result.credential_harvesting = True
        result.score += 20
        result.flags.append("Sandbox: Credential harvesting form detected 🚨")
        result.iocs.append("BEHAVIOR:CREDENTIAL_HARVESTING")

    if _match_patterns(html, MALWARE_PATTERNS):
        result.malware_distribution = True
        result.score += 25
        result.flags.append("Sandbox: Malware distribution / obfuscated JS detected 🚨")
        result.iocs.append("BEHAVIOR:MALWARE_DISTRIBUTION")

    if _match_patterns(html, FAKE_LOGIN_PATTERNS):
        result.fake_login_page = True
        result.score += 15
        result.flags.append("Sandbox: Fake branded login page indicators found")
        result.iocs.append("BEHAVIOR:FAKE_LOGIN_PAGE")

    if _match_patterns(html, CRYPTO_PATTERNS):
        result.crypto_drainer = True
        result.score += 18
        result.flags.append("Sandbox: Crypto wallet drainer patterns detected 🚨")
        result.iocs.append("BEHAVIOR:CRYPTO_DRAINER")

    if _match_patterns(html, TECH_SUPPORT_PATTERNS):
        result.tech_support_scam = True
        result.score += 12
        result.flags.append("Sandbox: Tech support scam page indicators found")
        result.iocs.append("BEHAVIOR:TECH_SUPPORT_SCAM")

    # ── Suspicious form count ────────────────────────────────────────────
    if result.suspicious_forms >= 3:
        result.score += 5
        result.flags.append(f"Sandbox: {result.suspicious_forms} forms on page — data collection")

    # ── External scripts ─────────────────────────────────────────────────
    if len(result.external_scripts) >= 5:
        result.score += 4
        result.flags.append(
            f"Sandbox: {len(result.external_scripts)} external scripts — possible skimmer"
        )

    # ── Missing security headers ─────────────────────────────────────────
    missing = []
    for header in ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]:
        if header not in response.headers:
            missing.append(header)
    if len(missing) >= 2:
        result.flags.append(f"Missing security headers: {', '.join(missing)}")

    if not result.flags:
        result.flags.append("Sandbox: No malicious behavioral patterns detected")

    result.score = min(result.score, 30)
    return result
