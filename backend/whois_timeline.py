"""
backend/whois_timeline.py
--------------------------
WHOIS + DNS Change Timeline Engine — GhostWire CTI v6

Builds a visual timeline of:
  - Domain registration date
  - Domain expiry date
  - First/last DNS resolution (from HackerTarget)
  - Certificate history milestones (from crt.sh)
  - Key risk events (domain age, rapid cert issuance)

Returns structured data consumed by frontend/timeline_renderer.py
for Plotly timeline visualization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

import logging
logger = logging.getLogger(__name__)

TIMEOUT  = 8
SAFE_UA  = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; GhostWire CTI/5.0)"
    )
}


@dataclass
class TimelineEvent:
    """A single event on the WHOIS/DNS timeline."""
    date:        str            # ISO date string YYYY-MM-DD
    label:       str            # Short label shown on timeline
    description: str            # Longer description for tooltip
    category:    str            # "registration" | "dns" | "cert" | "risk" | "expiry"
    severity:    str = "info"   # "info" | "warning" | "critical"


@dataclass
class WhoisTimelineResult:
    domain:           str              = ""
    events:           list[TimelineEvent] = field(default_factory=list)
    domain_age_days:  Optional[int]    = None
    registration_date: Optional[str]  = None
    expiry_date:       Optional[str]  = None
    registrar:         Optional[str]  = None
    cert_count:        int             = 0
    errors:            list[str]       = field(default_factory=list)


def _safe_date(raw) -> Optional[str]:
    """Normalise various date formats to YYYY-MM-DD string."""
    if not raw:
        return None
    if isinstance(raw, list):
        raw = raw[0]
    if isinstance(raw, datetime):
        return raw.strftime("%Y-%m-%d")
    if isinstance(raw, str):
        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"]:
            try:
                return datetime.strptime(raw.strip(), fmt).strftime("%Y-%m-%d")
            except ValueError:
                continue
    return None


def _fetch_whois_events(domain: str, result: WhoisTimelineResult) -> None:
    """Fetch WHOIS data and add registration/expiry events."""
    try:
        import whois
        w = whois.whois(domain)

        reg_date = _safe_date(getattr(w, "creation_date", None))
        exp_date = _safe_date(getattr(w, "expiration_date", None))
        upd_date = _safe_date(getattr(w, "updated_date", None))
        registrar_raw = getattr(w, "registrar", None)
        if isinstance(registrar_raw, list):
            registrar_raw = registrar_raw[0]
        result.registrar = str(registrar_raw) if registrar_raw else None

        now = datetime.now(tz=timezone.utc)
        # Use naive datetime for arithmetic with strptime results (which are also naive)
        now_naive = now.replace(tzinfo=None)

        if reg_date:
            result.registration_date = reg_date
            reg_dt = datetime.strptime(reg_date, "%Y-%m-%d")
            age    = (now_naive - reg_dt).days
            result.domain_age_days = age

            severity = "critical" if age < 30 else ("warning" if age < 90 else "info")
            result.events.append(TimelineEvent(
                date        = reg_date,
                label       = "Domain Registered",
                description = (
                    f"Domain registered {age} days ago via "
                    f"{result.registrar or 'Unknown registrar'}. "
                    + ("⚠️ Very new domain — high phishing risk!" if age < 30 else
                       "⚠️ Recently registered." if age < 90 else
                       f"Domain is {age // 365} year(s) old.")
                ),
                category    = "registration",
                severity    = severity,
            ))

        if upd_date and upd_date != reg_date:
            result.events.append(TimelineEvent(
                date        = upd_date,
                label       = "WHOIS Updated",
                description = "Domain WHOIS record was last updated (possible ownership change).",
                category    = "registration",
                severity    = "warning",
            ))

        if exp_date:
            result.expiry_date = exp_date
            exp_dt = datetime.strptime(exp_date, "%Y-%m-%d")
            days_left = (exp_dt - now_naive).days
            severity = "critical" if days_left < 30 else ("warning" if days_left < 90 else "info")
            result.events.append(TimelineEvent(
                date        = exp_date,
                label       = "Domain Expires",
                description = (
                    f"Domain expires in {days_left} days. "
                    + ("⚠️ Expiring soon — may be abandoned/squatted!" if days_left < 90 else "")
                ),
                category    = "expiry",
                severity    = severity,
            ))

    except ImportError:
        result.errors.append("python-whois not installed")
    except Exception as e:
        result.errors.append(f"WHOIS lookup failed: {e}")


def _fetch_cert_events(domain: str, result: WhoisTimelineResult) -> None:
    """Fetch certificate history from crt.sh and add cert events."""
    import time as _time

    url = f"https://crt.sh/?q={domain}&output=json"
    certs = None

    for attempt in range(3):
        try:
            r = requests.get(url, headers=SAFE_UA, timeout=15)
            if r.status_code == 200:
                certs = r.json()
                break
            if r.status_code == 429:
                _time.sleep(2 ** attempt)
                continue
            result.errors.append(f"crt.sh returned HTTP {r.status_code}")
            return
        except requests.exceptions.Timeout:
            if attempt < 2:
                _time.sleep(2 ** attempt)
                continue
            result.errors.append("crt.sh timed out after 3 attempts — skipping CT log data")
            return
        except requests.exceptions.ConnectionError:
            if attempt < 2:
                _time.sleep(2 ** attempt)
                continue
            result.errors.append("crt.sh connection refused — skipping CT log data")
            return
        except Exception as e:
            result.errors.append(f"crt.sh lookup failed: {e}")
            return

    if not certs:
        return

    try:
        result.cert_count = len(certs)

        # Group by month to avoid clutter
        seen_months: set[str] = set()
        cert_events: list[TimelineEvent] = []

        for cert in sorted(certs, key=lambda c: c.get("not_before", ""))[:50]:
            not_before = cert.get("not_before", "")[:10]
            if not not_before:
                continue
            month = not_before[:7]
            if month in seen_months:
                continue
            seen_months.add(month)

            issuer = cert.get("issuer_name", "")
            is_free = any(ca in issuer.lower() for ca in ["let's encrypt", "zerossl", "buypass"])

            cert_events.append(TimelineEvent(
                date        = not_before,
                label       = "TLS Cert Issued",
                description = (
                    f"Certificate issued by: {issuer[:60] or 'Unknown CA'}. "
                    + ("⚠️ Free CA — common in phishing infrastructure." if is_free else "")
                ),
                category    = "cert",
                severity    = "warning" if is_free else "info",
            ))

        # Only add up to 6 cert events to keep timeline readable
        result.events.extend(cert_events[:6])

        # Risk event: many certs in short time = suspicious rotation
        if result.cert_count >= 10:
            result.events.append(TimelineEvent(
                date        = datetime.now().strftime("%Y-%m-%d"),
                label       = f"{result.cert_count} Certs Total",
                description = (
                    f"⚠️ {result.cert_count} certificates in CT logs — "
                    f"high cert rotation suggests phishing kit cycling."
                ),
                category    = "risk",
                severity    = "warning",
            ))

    except Exception as e:
        result.errors.append(f"crt.sh lookup failed: {e}")


def build_whois_timeline(domain: str) -> WhoisTimelineResult:
    """
    Build a complete WHOIS + DNS + cert timeline for a domain.
    Returns structured data for Plotly timeline visualization.
    """
    result = WhoisTimelineResult()
    result.domain = domain

    # Get WHOIS registration/expiry
    _fetch_whois_events(domain, result)

    # Get certificate history
    _fetch_cert_events(domain, result)

    # Sort all events chronologically
    def _sort_key(e: TimelineEvent) -> str:
        try:
            return e.date
        except Exception:
            return "9999-01-01"

    result.events.sort(key=_sort_key)
    return result
