"""
utils/ssl_engine.py
--------------------
SSL/TLS Certificate Analysis Engine — GhostWire CTI v6.
"""

from __future__ import annotations

import re
import socket
import ssl
import datetime
from dataclasses import dataclass, field
from typing import Optional

import tldextract

import logging
logger = logging.getLogger(__name__)


# ── Configuration constants ───────────────────────────────────────────────────

FREE_CA_ISSUERS = {
    "let's encrypt",
    "letsencrypt",
    "zerossl",
    "buypass",
    "ssl.com free",
    "sectigo rsa domain",          # sometimes used in free tiers
}

SUSPICIOUS_CA_COMBOS = {
    # If these appear in Issuer O + free-hosting domain, flag harder
    "r3", "r10", "r11", "e1", "e2",   # Let's Encrypt intermediate CAs
    "zerossl rsa domain",
    "actalis authentication root ca",
}

PORT      = 443
TIMEOUT   = 8
CT_API    = "https://crt.sh/?q={domain}&output=json"  # free, no key needed


@dataclass
class SSLResult:
    """Result from the SSL/TLS certificate analysis engine."""
    score: int                          = 0

    # Certificate basics
    issuer_cn: Optional[str]            = None
    issuer_org: Optional[str]           = None
    subject_cn: Optional[str]           = None
    not_before: Optional[datetime.datetime] = None
    not_after:  Optional[datetime.datetime] = None
    days_remaining: Optional[int]       = None
    cert_age_days:  Optional[int]       = None    # days since issuance

    # Analysis flags
    is_free_ca: bool                    = False
    is_self_signed: bool                = False
    is_expired: bool                    = False
    hostname_mismatch: bool             = False
    has_wildcard_san: bool              = False
    short_validity: bool                = False   # cert valid < 30 days from issuance

    # SANs
    san_domains: list[str]              = field(default_factory=list)

    # CT log findings
    ct_cert_count: Optional[int]        = None    # how many certs issued for domain

    flags: list[str]                    = field(default_factory=list)
    iocs:  list[str]                    = field(default_factory=list)
    errors: list[str]                   = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_hostname(url: str) -> str:
    """Pull the bare hostname from any URL or bare domain."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        import urllib.parse
        return urllib.parse.urlparse(url).hostname or url
    except Exception:
        return url


def _parse_x509_name(name_obj) -> dict[str, str]:
    """Convert an ssl X509Name into a plain dict."""
    result: dict[str, str] = {}
    for attr in name_obj:
        if isinstance(attr, tuple):
            k, v = attr
            result[k] = v
        elif isinstance(attr, (list, tuple)):
            for k, v in attr:
                result[k] = v
    return result


def _get_san_domains(cert: dict) -> list[str]:
    """Extract Subject Alternative Names from a parsed cert dict."""
    sans: list[str] = []
    for field_name, value in cert.get("subjectAltName", []):
        if field_name.upper() == "DNS":
            sans.append(value.lower())
    return sans


def _fetch_cert(hostname: str) -> tuple[Optional[dict], Optional[str]]:
    """
    Connect to the host on port 443 and retrieve the TLS certificate.
    Returns (cert_dict, error_string).

    The connection uses check_hostname=False so we can report mismatches
    rather than raising an exception.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_OPTIONAL   # get cert even if untrusted

    try:
        with socket.create_connection((hostname, PORT), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert, None
    except ssl.SSLCertVerificationError as e:
        # Still try to get the cert with no verification
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode    = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, PORT), timeout=TIMEOUT) as sock:
                with ctx2.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    return cert, f"Verification failed: {e}"
        except Exception as e2:
            return None, f"SSL connection failed: {e2}"
    except ConnectionRefusedError:
        return None, "Port 443 refused — host does not serve HTTPS"
    except socket.timeout:
        return None, "SSL handshake timed out"
    except OSError as e:
        return None, f"Network error: {e}"
    except Exception as e:
        return None, f"Unexpected SSL error: {e}"


def _parse_ssl_date(dt_str: str) -> Optional[datetime.datetime]:
    """Parse the date strings returned by ssl.getpeercert()."""
    # Format: 'May 10 12:00:00 2025 GMT'
    try:
        return datetime.datetime.strptime(dt_str, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=datetime.timezone.utc
        )
    except Exception:
        try:
            return datetime.datetime.fromisoformat(dt_str)
        except Exception:
            return None


def _ct_log_count(domain: str) -> Optional[int]:
    """
    Query crt.sh for the number of certificates ever issued for this domain.
    High counts on a very young domain can indicate a sophisticated attacker
    rotating certs rapidly.  Returns None on failure.
    """
    import requests as req
    import time as _time

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "GhostWire-CTI/5.0"}

    for attempt in range(3):
        try:
            r = req.get(url, timeout=15, headers=headers)
            if r.status_code == 200 and r.text.strip().startswith("["):
                return len(r.json())
            if r.status_code == 429:
                _time.sleep(2 ** attempt)
                continue
            break
        except (req.exceptions.Timeout, req.exceptions.ConnectionError):
            if attempt < 2:
                _time.sleep(2 ** attempt)
            continue
        except Exception:
            break
    return None


# ── Core analysis ─────────────────────────────────────────────────────────────

def _analyse_cert(
    cert: dict,
    hostname: str,
    fetch_error: Optional[str],
    result: SSLResult,
    domain_age_days: Optional[int],
) -> None:
    """Populate result from the raw cert dict."""

    # ── Self-signed: issuer == subject ────────────────────────────────
    issuer  = dict(x for tup in cert.get("issuer",  []) for x in (tup if isinstance(tup[0], tuple) else [tup]))
    subject = dict(x for tup in cert.get("subject", []) for x in (tup if isinstance(tup[0], tuple) else [tup]))

    # Flatten multi-level tuples from getpeercert()
    def _flatten(raw):
        out: dict[str, str] = {}
        for item in raw:
            if item and isinstance(item[0], tuple):
                for k, v in item:
                    out[k] = v
            elif item and isinstance(item[0], str):
                out[item[0]] = item[1] if len(item) > 1 else ""
        return out

    issuer_d  = _flatten(cert.get("issuer",  []))
    subject_d = _flatten(cert.get("subject", []))

    result.issuer_cn  = issuer_d.get("commonName",        "")
    result.issuer_org = issuer_d.get("organizationName",  "")
    result.subject_cn = subject_d.get("commonName",       "")

    if result.issuer_cn and result.subject_cn:
        result.is_self_signed = (result.issuer_cn.strip() == result.subject_cn.strip())

    # ── Validity window ───────────────────────────────────────────────
    nb_str = cert.get("notBefore", "")
    na_str = cert.get("notAfter",  "")
    now    = datetime.datetime.now(tz=datetime.timezone.utc)

    if nb_str:
        result.not_before = _parse_ssl_date(nb_str)
    if na_str:
        result.not_after = _parse_ssl_date(na_str)

    if result.not_after:
        delta = result.not_after - now
        result.days_remaining = delta.days
        result.is_expired = result.days_remaining < 0

    if result.not_before:
        result.cert_age_days = (now - result.not_before).days
        if result.not_after and result.not_before:
            total_validity = (result.not_after - result.not_before).days
            result.short_validity = total_validity < 30

    # ── SAN extraction ────────────────────────────────────────────────
    result.san_domains = _get_san_domains(cert)
    wildcards = [s for s in result.san_domains if s.startswith("*")]
    if wildcards:
        result.has_wildcard_san = True

    # ── Hostname mismatch ─────────────────────────────────────────────
    hn = hostname.lower()
    cn = (result.subject_cn or "").lower()
    san_match = any(
        hn == s or (s.startswith("*.") and hn.endswith(s[1:]))
        for s in result.san_domains
    )
    cn_match = (hn == cn) or (cn.startswith("*.") and hn.endswith(cn[2:]))
    if not san_match and not cn_match and (result.subject_cn or result.san_domains):
        result.hostname_mismatch = True

    # ── Free CA detection ─────────────────────────────────────────────
    issuer_lower = (result.issuer_org or result.issuer_cn or "").lower()
    for ca in FREE_CA_ISSUERS:
        if ca in issuer_lower:
            result.is_free_ca = True
            break

    # ── Scoring ───────────────────────────────────────────────────────

    if result.is_self_signed:
        result.score += 20
        result.flags.append(
            f"Self-signed certificate — issuer '{result.issuer_cn}' equals subject"
        )
        result.iocs.append("CERT:SELF_SIGNED")

    elif fetch_error and "Verification" in fetch_error:
        result.score += 15
        result.flags.append(f"Certificate verification failed: {fetch_error}")
        result.iocs.append("CERT:VERIFICATION_FAILED")

    if result.is_expired:
        result.score += 15
        result.flags.append(
            f"Certificate EXPIRED {abs(result.days_remaining)} days ago"
        )
        result.iocs.append("CERT:EXPIRED")
    elif result.days_remaining is not None and result.days_remaining < 7:
        result.score += 8
        result.flags.append(
            f"Certificate expires in {result.days_remaining} days — "
            f"possible throwaway infrastructure"
        )

    if result.hostname_mismatch:
        result.score += 20
        result.flags.append(
            f"Hostname mismatch — cert CN='{result.subject_cn}' "
            f"does not match '{hostname}'"
        )
        result.iocs.append("CERT:HOSTNAME_MISMATCH")

    if result.has_wildcard_san:
        result.score += 10
        result.flags.append(
            f"Wildcard SAN detected: {wildcards[0]} — "
            f"single cert covers unlimited subdomains"
        )

    if result.short_validity:
        result.score += 8
        result.flags.append(
            "Certificate issued for < 30 days — disposable/throwaway cert"
        )
        result.iocs.append("CERT:SHORT_VALIDITY")

    # ── Free CA + Domain age combo (key rule) ─────────────────────────
    if result.is_free_ca:
        ca_name = result.issuer_org or result.issuer_cn or "Free CA"

        if domain_age_days is not None and domain_age_days < 30:
            result.score += 25
            result.flags.append(
                f"HIGH-RISK COMBO: Free CA ({ca_name}) + domain age {domain_age_days}d "
                f"— classic phishing certificate pattern"
            )
            result.iocs.append("CERT:FREE_CA_YOUNG_DOMAIN")

        elif domain_age_days is not None and domain_age_days < 90:
            result.score += 15
            result.flags.append(
                f"Elevated risk: Free CA ({ca_name}) + domain age {domain_age_days}d "
                f"(< 90 days)"
            )
            result.iocs.append("CERT:FREE_CA_NEW_DOMAIN")

        else:
            result.score += 5
            result.flags.append(
                f"Free CA issuer: {ca_name} — legitimate but commonly used in phishing"
            )

    else:
        if result.issuer_org:
            result.flags.append(
                f"Certificate issued by: {result.issuer_org} — paid/enterprise CA"
            )

    if not result.is_expired and result.days_remaining is not None:
        result.flags.append(
            f"Certificate valid for {result.days_remaining} more days "
            f"(expires {result.not_after.strftime('%Y-%m-%d') if result.not_after else 'unknown'})"
        )


# ── Public entry point ────────────────────────────────────────────────────────

def analyze_ssl(
    url: str,
    domain_age_days: Optional[int] = None,
) -> SSLResult:
    """
    Perform full SSL/TLS certificate analysis on the target URL.

    Args:
        url:              Target URL or bare hostname.
        domain_age_days:  Optional domain age from WHOIS (enables the
                          free-CA + young-domain risk combo rule).

    Returns:
        SSLResult with score (0–50), flags, and IOCs.
    """
    result  = SSLResult()
    hostname = _extract_hostname(url)

    # Plain HTTP — no cert to check
    if url.strip().startswith("http://") and not url.strip().startswith("https://"):
        result.score += 5
        result.flags.append("Target uses plain HTTP — no TLS certificate present")
        result.iocs.append("NO_TLS")
        return result

    cert, fetch_error = _fetch_cert(hostname)

    if cert is None:
        err_msg = fetch_error or "Could not retrieve certificate"
        result.errors.append(err_msg)
        if "refused" in err_msg.lower() or "http" in err_msg.lower():
            result.flags.append(f"SSL check: {err_msg}")
        else:
            result.score += 10
            result.flags.append(f"SSL error — {err_msg}")
            result.iocs.append("CERT:UNREACHABLE")
        return result

    if fetch_error:
        result.errors.append(fetch_error)

    _analyse_cert(cert, hostname, fetch_error, result, domain_age_days)

    # ── Certificate Transparency log check ────────────────────────────
    try:
        ext = tldextract.extract(hostname)
        root_domain = f"{ext.domain}.{ext.suffix}"
        ct_count = _ct_log_count(root_domain)
        result.ct_cert_count = ct_count

        if ct_count is not None:
            if domain_age_days is not None and domain_age_days < 30 and ct_count > 5:
                result.score += 10
                result.flags.append(
                    f"CT logs: {ct_count} certificates issued for a {domain_age_days}-day-old "
                    f"domain — aggressive cert rotation"
                )
                result.iocs.append(f"CERT:CT_ROTATION:{ct_count}")
            elif ct_count > 0:
                result.flags.append(
                    f"CT logs: {ct_count} certificate(s) found for this domain"
                )
    except Exception:
        pass

    result.score = min(result.score, 50)
    return result
