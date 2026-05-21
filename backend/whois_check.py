"""
utils/whois_check.py
--------------------
WHOIS & DNS Domain Age Engine for GhostWire CTI Local.

Resolves the registrar creation date of a domain and flags newly
registered domains, which are a strong indicator of phishing
infrastructure set up just-in-time for an attack.
"""

import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import tldextract

import logging
logger = logging.getLogger(__name__)

# ``whois`` is imported lazily inside functions to give a helpful error
# message if the package is missing rather than crashing at module load.


@dataclass
class WhoisResult:
    """Structured result from the WHOIS / DNS analysis engine."""
    score: int = 0                              # Risk contribution (0–40)
    domain_age_days: Optional[int] = None       # None = could not determine
    creation_date: Optional[str] = None         # ISO-formatted string
    registrar: Optional[str] = None
    flags: list[str] = field(default_factory=list)
    error: Optional[str] = None                 # Non-fatal error description


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_root_domain(url: str) -> str:
    """
    Return only the registrable domain (e.g. 'paypal.com') from any URL,
    stripping subdomains so WHOIS queries succeed reliably.

    SECURITY: Sanitizes domain to alphanumeric + dots + hyphens only.
    Prevents injection via python-whois which passes domain to system whois.
    """
    extracted = tldextract.extract(url)
    if extracted.domain and extracted.suffix:
        raw = f"{extracted.domain}.{extracted.suffix}"
    else:
        raw = url.split("//")[-1].split("/")[0].split("?")[0]

    # Strict sanitization: only allow valid domain characters
    import re as _re
    sanitized = _re.sub(r"[^a-zA-Z0-9.-]", "", raw)
    # Max domain length: 253 chars per RFC 1035
    return sanitized[:253]


def _normalise_date(raw: object) -> Optional[datetime]:
    """
    WHOIS libraries return creation dates in wildly inconsistent formats:
    datetime objects, lists of datetimes, or strings.  This normaliser
    extracts the earliest valid datetime regardless of format.
    """
    if isinstance(raw, list):
        dates = [_normalise_date(item) for item in raw]
        valid = [d for d in dates if d is not None]
        return min(valid) if valid else None

    if isinstance(raw, datetime):
        # Ensure timezone-aware for correct age calculation
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw

    if isinstance(raw, str):
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d",
            "%d-%b-%Y",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(raw.strip(), fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None


def _resolve_domain(domain: str) -> bool:
    """
    Quick DNS A-record check.  If the domain does not resolve we still
    proceed with WHOIS but note the failure.
    """
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_domain(url: str) -> WhoisResult:
    """
    Perform WHOIS lookup on the domain extracted from ``url`` and score
    its age against the 30-day phishing-window threshold.

    Scoring:
        +40  — domain created < 30 days ago  (very high risk)
        +20  — domain created < 90 days ago  (elevated risk)
        +10  — domain created < 180 days ago (mild concern)
          0  — domain is older               (no penalty)

    Args:
        url: Any URL or bare hostname to analyse.

    Returns:
        WhoisResult with score, age in days, and optional flags.
    """
    try:
        import whois  # python-whois
    except ImportError:
        result = WhoisResult()
        result.error = "python-whois not installed — skipping domain age check"
        result.flags.append("WHOIS library unavailable")
        return result

    result = WhoisResult()
    domain = _extract_root_domain(url)

    # ---- DNS pre-check ------------------------------------------------
    if not _resolve_domain(domain):
        result.flags.append(f"Domain '{domain}' does not resolve via DNS")
        # Still attempt WHOIS — domain may be new/propagating

    # ---- WHOIS lookup -------------------------------------------------
    try:
        w = whois.whois(domain)
    except Exception as exc:
        result.error = f"WHOIS lookup failed: {exc}"
        result.flags.append("Could not retrieve WHOIS data")
        # Assign a moderate score when we cannot verify age
        result.score = 15
        return result

    # ---- Parse registrar ----------------------------------------------
    registrar_raw = getattr(w, "registrar", None)
    if isinstance(registrar_raw, list):
        registrar_raw = registrar_raw[0] if registrar_raw else None
    result.registrar = str(registrar_raw) if registrar_raw else "Unknown"

    # ---- Parse creation date ------------------------------------------
    creation_raw = getattr(w, "creation_date", None)
    creation_dt = _normalise_date(creation_raw)

    if creation_dt is None:
        result.flags.append("Could not determine domain creation date")
        result.score = 10  # Moderate penalty for opacity
        return result

    # ---- Calculate age ------------------------------------------------
    now = datetime.now(tz=timezone.utc)
    age_delta = now - creation_dt
    age_days = age_delta.days

    result.domain_age_days = age_days
    result.creation_date = creation_dt.strftime("%Y-%m-%d")

    # ---- Scoring ------------------------------------------------------
    if age_days < 30:
        result.score = 40
        result.flags.append(
            f"⚠ Domain is only {age_days} day(s) old — very high risk"
        )
    elif age_days < 90:
        result.score = 20
        result.flags.append(
            f"Domain is {age_days} days old (< 90 days) — elevated risk"
        )
    elif age_days < 180:
        result.score = 10
        result.flags.append(
            f"Domain is {age_days} days old (< 6 months) — mild concern"
        )
    else:
        result.score = 0
        years = age_days // 365
        result.flags.append(
            f"Domain is {age_days} days old (~{years} yr) — age looks normal"
        )

    return result
