"""
backend/urlhaus_engine.py
--------------------------
GhostWire CTI v6 — URLhaus Threat Intelligence Engine.

URLhaus is operated by abuse.ch — free API for malware URL / hash / host lookups.
API docs: https://urlhaus-api.abuse.ch/

Auth key (URLHAUS_API_KEY) is optional.
  - Without key  : public lookups work, rate limit ~10 req/min
  - With key     : higher rate limits, submit capabilities
  - Key location : https://auth.abuse.ch/user/me  → copy "API Auth Key"
  - .env entry   : URLHAUS_API_KEY=xxxx

Graceful degradation:
  If URLHAUS_API_KEY is missing or API is unreachable,
  the engine returns an empty/safe result and logs a warning.
  The rest of the pipeline continues unaffected.

Three lookup modes (one function per pipeline):
  query_url_host(url)   → pipeline_url  (URL + extracted host)
  query_hash(hash_str)  → pipeline_hash (MD5 or SHA256)
  query_host(host)      → pipeline_ip   (hostname or IP)
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

URLHAUS_API_BASE = "https://urlhaus-api.abuse.ch/v1"
TIMEOUT = 10  # seconds — abuse.ch can be slow under load

SAFE_UA = {
    "User-Agent": "GhostWire-CTI/6.0 (SecurityResearch; abuse.ch API client)"
}

# Threat tags from URLhaus that indicate high-risk payloads
HIGH_RISK_TAGS = {
    "exe", "dll", "bat", "ps1", "vbs", "js",       # executables / scripts
    "ransomware", "trojan", "botnet", "miner",       # malware families
    "emotet", "qbot", "trickbot", "cobalt",          # known campaigns
    "c2", "c&c", "rat", "stealer", "dropper",        # behaviour tags
}


# ── Data Model ────────────────────────────────────────────────────────────────

@dataclass
class URLhausResult:
    """Unified result object for all three URLhaus lookup modes."""

    available:    bool = False  # True if API returned usable data
    used_key:     bool = False  # True if URLHAUS_API_KEY was present

    # Core verdict from URLhaus
    query_status: str = ""      # "is_host" | "no_results" | "invalid_host" | etc.
    threat:       Optional[str] = None   # e.g. "malware_download"

    # URL-level data (URL lookup mode)
    url_status:   Optional[str] = None   # "online" | "offline" | "unknown"
    urls_found:   int = 0                # how many malicious URLs found for this host

    # Payload / hash data (hash lookup mode)
    md5_hash:     Optional[str] = None
    sha256_hash:  Optional[str] = None
    file_type:    Optional[str] = None
    file_size:    Optional[int] = None
    signature:    Optional[str] = None   # malware family name if identified
    virustotal:   Optional[str] = None   # VT link if available

    # Tags from URLhaus (malware family, file type, campaign)
    tags: list[str] = field(default_factory=list)

    # Associated URLs returned in host/hash lookups
    associated_urls: list[dict] = field(default_factory=list)  # [{url, status, threat, date}]

    # Risk scoring
    score_contribution: int = 0
    flags:  list[str] = field(default_factory=list)
    iocs:   list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── API Key Helper ─────────────────────────────────────────────────────────────

def _get_api_key() -> str:
    """Read URLHAUS_API_KEY from environment (loaded from .env via config.py)."""
    return os.environ.get("URLHAUS_API_KEY", "").strip()


def _build_headers() -> dict:
    """Build request headers — include auth key if available."""
    h = {**SAFE_UA, "Accept": "application/json"}
    key = _get_api_key()
    if key:
        # URLhaus uses Auth-Key header for authenticated requests
        h["Auth-Key"] = key
    return h


# ── Raw API Calls ─────────────────────────────────────────────────────────────

_ALLOWED_ENDPOINTS: frozenset = frozenset({"url", "host", "payload"})


def _sanitize_lookup_value(value: str, max_len: int = 512) -> str:
    """Strip control characters and limit length — prevents header/log injection."""
    return "".join(ch for ch in value if ch.isprintable() and ch not in "\r\n\t")[:max_len]


def _post_urlhaus(endpoint: str, payload: dict) -> dict:
    """
    POST to URLhaus API endpoint.
    Returns parsed JSON or an error dict.
    Never raises — all exceptions are caught.

    Security hardening (v7):
      - Endpoint whitelist: only "url", "host", "payload" accepted
      - Input sanitization: control chars stripped from all payload values
      - Response size limit: 2MB cap before JSON parse (memory bomb prevention)
      - SSRF: base URL is a module-level constant — cannot be redirected
    """
    # SECURITY: Whitelist valid endpoints only
    if endpoint not in _ALLOWED_ENDPOINTS:
        logger.error("URLhaus: blocked disallowed endpoint %r", endpoint)
        return {"error": "invalid_endpoint"}

    # SECURITY: Sanitize all payload values
    safe_payload = {k: _sanitize_lookup_value(str(v)) for k, v in payload.items()}

    url = f"{URLHAUS_API_BASE}/{endpoint}/"
    try:
        resp = requests.post(
            url,
            data=safe_payload,
            headers=_build_headers(),
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            # SECURITY: Limit response size before JSON parse
            if len(resp.content) > 2_000_000:
                logger.warning("URLhaus response too large (%d bytes)", len(resp.content))
                return {"error": "response_too_large"}

            # Guard: empty body → treat as no_results (not a JSON parse error)
            raw = resp.content.strip()
            if not raw:
                logger.warning("URLhaus returned empty body for endpoint %r", endpoint)
                return {"query_status": "no_results"}

            # Guard: HTML response (abuse.ch occasionally returns maintenance page)
            if raw[:1] in (b"<", b"!"):
                logger.warning("URLhaus returned non-JSON (HTML?) for endpoint %r", endpoint)
                return {"error": "non_json_response"}

            try:
                return resp.json()
            except Exception as json_exc:
                logger.warning(
                    "URLhaus JSON decode error for endpoint %r: %s | body[:80]=%r",
                    endpoint, json_exc, raw[:80]
                )
                return {"error": f"json_decode: {str(json_exc)[:60]}"}
        elif resp.status_code == 429:
            logger.warning("URLhaus rate limit hit — add URLHAUS_API_KEY for higher limits")
            return {"error": "rate_limit", "message": "URLhaus rate limit — add API key"}
        else:
            return {"error": f"http_{resp.status_code}"}
    except requests.Timeout:
        logger.warning("URLhaus timeout after %ds", TIMEOUT)
        return {"error": "timeout"}
    except Exception as exc:
        logger.warning("URLhaus API error: %s", exc)
        return {"error": str(exc)[:100]}



# ── Scoring Logic ─────────────────────────────────────────────────────────────

def _score_result(result: URLhausResult) -> None:
    """
    Apply risk scoring based on URLhaus findings.
    Max contribution: 30 points (consistent with other engines).

    Real-world calibration (FP reduction):
    - "offline" alone: historically online ≠ currently dangerous. Lower weight.
    - Host with 1-2 associated URLs: shared hosting FP risk. Min threshold = 3.
    - Tags without url_status confirmation: only add if corroborated by other signal.
    - Hash+signature: strongest signal — always high score (confirmed malware sample).
    """
    score = 0

    # ── URL status signal ─────────────────────────────────────────────
    # ONLINE + known threat = confirmed active malware delivery
    if result.url_status == "online" and result.threat:
        score += 28
        result.flags.append(
            f"🔴 URLhaus: ACTIVE malware URL — status=online, threat={result.threat}"
        )
        result.iocs.append(f"URLHAUS_ACTIVE:{result.threat}")

    elif result.url_status == "online":
        # Online but no threat label — still dangerous
        score += 20
        result.flags.append("🔴 URLhaus: URL currently ONLINE in malware database")
        result.iocs.append("URLHAUS_ONLINE")

    elif result.url_status == "offline" and result.threat:
        # FP FIX: "offline" alone is historical — score lower than before.
        # Legitimate sites get compromised, cleaned, and go offline in URLhaus.
        # Only raise score meaningfully when threat label confirms malware family.
        score += 10
        result.flags.append(
            f"🟠 URLhaus: Previously malicious (now offline) — threat={result.threat}. "
            f"Historical record — verify with VT before action."
        )
        result.iocs.append(f"URLHAUS_OFFLINE:{result.threat}")

    elif result.url_status == "offline":
        # Offline with no threat label — very low confidence, just note it
        score += 4
        result.flags.append(
            "⚠️ URLhaus: URL was listed as malicious but is now offline (no threat label). "
            "Low confidence — corroborate with other engines."
        )

    # ── Host/IP associated URL count ──────────────────────────────────
    # FP FIX: Shared hosting means many legitimate domains on same IP.
    # Threshold raised: 1-2 URLs = very common on shared hosters, skip.
    # Only flag at 3+ with graduated scoring.
    if result.urls_found >= 10:
        score += 20
        result.flags.append(
            f"🔴 URLhaus: {result.urls_found} malicious URLs on this host — "
            f"bulletproof/dedicated malware hosting suspected"
        )
        result.iocs.append(f"URLHAUS_HOST_URLS:{result.urls_found}")
    elif result.urls_found >= 5:
        score += 14
        result.flags.append(
            f"🟠 URLhaus: {result.urls_found} malicious URLs on this host — "
            f"likely malware-friendly hosting"
        )
        result.iocs.append(f"URLHAUS_HOST_URLS:{result.urls_found}")
    elif result.urls_found >= 3:
        score += 8
        result.flags.append(
            f"⚠️ URLhaus: {result.urls_found} malicious URLs linked to this host. "
            f"Possible shared hosting — check if IP is a CDN/cloud."
        )
        result.iocs.append(f"URLHAUS_HOST_URLS:{result.urls_found}")
    # 1-2 URLs: suppressed (shared hosting FP — too unreliable to score)

    # ── Hash-based verdict (malware sample lookup) ────────────────────
    # Strongest signal: exact hash match = file confirmed as malware payload
    if result.signature:
        score += 25
        result.flags.append(
            f"🔴 URLhaus: Hash confirmed as {result.signature} malware sample "
            f"(exact SHA256/MD5 match in abuse.ch database)"
        )
        result.iocs.append(f"URLHAUS_MALWARE:{result.signature}")
    elif result.sha256_hash and result.associated_urls:
        # Hash in URLhaus but no family ID — still a confirmed malware payload
        score += 18
        result.flags.append(
            f"🟠 URLhaus: Hash in malware database — "
            f"{len(result.associated_urls)} delivery URLs tracked (unknown family)"
        )
        result.iocs.append("URLHAUS_HASH_KNOWN")

    # ── High-risk tags ────────────────────────────────────────────────
    # FP FIX: Only score tags when corroborated by at least one other signal
    # (url_status or hash match). Tags alone are too broad.
    if result.tags:
        risky = [t for t in result.tags if t.lower() in HIGH_RISK_TAGS]
        if risky:
            # Only add tag score if there's another confirmed signal
            has_other_signal = bool(result.url_status or result.signature or result.sha256_hash)
            if has_other_signal:
                tag_score = min(len(risky) * 3, 9)  # capped lower than before
                score += tag_score
                result.flags.append(
                    f"🏷 URLhaus Tags (corroborated): {', '.join(risky[:5])} — "
                    f"high-risk payload indicators"
                )
                result.iocs.extend([f"URLHAUS_TAG:{t}" for t in risky[:3]])
            else:
                # Tags without corroboration — informational only, no score
                result.flags.append(
                    f"🏷 URLhaus Tags (informational): {', '.join(risky[:5])} — "
                    f"no active URL/hash confirmation"
                )
        else:
            # Non-high-risk tags — informational only
            result.flags.append(f"🏷 URLhaus Tags: {', '.join(result.tags[:5])}")

    # Clean result
    if not result.flags and result.available:
        result.flags.append("✅ URLhaus: Not found in malware URL / host database")

    result.score_contribution = min(score, 30)


# ── URL Lookup (pipeline_url) ─────────────────────────────────────────────────

def query_url_host(url: str) -> URLhausResult:
    """
    Pipeline URL: Query URLhaus for both the full URL and extracted hostname.

    Steps:
      1. POST /url/   → check if exact URL is in URLhaus
      2. POST /host/  → check if host has any associated malware URLs
      3. Merge results → score → return

    Used by: pipeline_url.py via async_runner.py (urlhaus_url engine)
    """
    result = URLhausResult()
    key = _get_api_key()
    result.used_key = bool(key)

    # Extract hostname for host lookup
    try:
        import urllib.parse as _up
        parsed = _up.urlparse(url if "://" in url else "http://" + url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    # ── Step 1: URL lookup ────────────────────────────────────────────
    url_data = _post_urlhaus("url", {"url": url})

    if url_data.get("error"):
        err = url_data.get("message") or url_data["error"]
        result.errors.append(f"URLhaus URL lookup: {err}")
        logger.warning("URLhaus URL lookup failed: %s", err)
    else:
        status = url_data.get("query_status", "")
        result.query_status = status

        if status == "is_url":
            result.available = True
            result.url_status = url_data.get("url_status")
            result.threat     = url_data.get("threat")
            result.tags       = url_data.get("tags") or []

            # Collect associated payload info
            payloads = url_data.get("payloads") or []
            for p in payloads[:5]:
                if p.get("signature"):
                    result.signature = p["signature"]
                result.sha256_hash = result.sha256_hash or p.get("response_sha256")
                result.md5_hash    = result.md5_hash    or p.get("response_md5")

        elif status in ("no_results",):
            # "no_results" = URL is not in malware database
            result.available = True
        elif status == "ok":
            # "ok" = URLhaus API success wrapper — check if url_status field exists
            # Some API versions return "ok" with url_status/threat populated (FIX #3)
            result.available = True
            url_status_field = url_data.get("url_status")
            if url_status_field:
                result.url_status = url_status_field
                result.threat = url_data.get("threat")
                result.tags = url_data.get("tags") or []
                # Parse payloads if present
                payloads = url_data.get("payloads") or []
                for p in payloads[:5]:
                    if p.get("signature"):
                        result.signature = p["signature"]
                    result.sha256_hash = result.sha256_hash or p.get("response_sha256")
                    result.md5_hash = result.md5_hash or p.get("response_md5")
        elif status in ("invalid_url", "invalid_host", "invalid_format"):
            result.available = False
            result.errors.append(
                f"URLhaus: Query rejected — {status} "
                f"(check URL format or try adding http:// prefix)"
            )
        elif status:
            # Truly unknown status — log but don't surface as error to user
            result.available = True   # assume API worked
            logger.warning("URLhaus URL lookup: unrecognised status %r — treating as no_results", status)

    # ── Step 2: Host lookup ───────────────────────────────────────────
    if hostname:
        host_data = _post_urlhaus("host", {"host": hostname})

        if not host_data.get("error"):
            h_status = host_data.get("query_status", "")

            if h_status == "is_host":
                result.available = True
                h_urls = host_data.get("urls") or []
                result.urls_found = len(h_urls)

                # Store top 5 associated URLs for display
                for u in h_urls[:5]:
                    result.associated_urls.append({
                        "url":    u.get("url", ""),
                        "status": u.get("url_status", ""),
                        "threat": u.get("threat", ""),
                        "date":   u.get("date_added", ""),
                    })

                # Merge tags from host data
                for u in h_urls[:10]:
                    for t in (u.get("tags") or []):
                        if t not in result.tags:
                            result.tags.append(t)

    _score_result(result)
    return result


# ── Hash Lookup (pipeline_hash) ───────────────────────────────────────────────

def query_hash(hash_str: str) -> URLhausResult:
    """
    Pipeline Hash: Check if a file hash (MD5 or SHA256) exists in URLhaus.

    URLhaus stores hashes of malware samples delivered via tracked URLs.
    A hit here means the file was actively used in a malware campaign.

    Used by: pipeline_hash.py via async_runner_hash (urlhaus_hash engine)
    """
    result = URLhausResult()
    key = _get_api_key()
    result.used_key = bool(key)

    # Detect hash type by length
    h = hash_str.strip().lower()
    if len(h) == 32 and re.fullmatch(r"[0-9a-f]+", h):
        payload = {"md5_hash": h}
    elif len(h) == 64 and re.fullmatch(r"[0-9a-f]+", h):
        payload = {"sha256_hash": h}
    else:
        result.errors.append(f"URLhaus: Unsupported hash format (need MD5/SHA256), got len={len(h)}")
        return result

    data = _post_urlhaus("payload", payload)

    if data.get("error"):
        err = data.get("message") or data["error"]
        result.errors.append(f"URLhaus hash lookup: {err}")
        logger.warning("URLhaus hash lookup failed: %s", err)
        return result

    status = data.get("query_status", "")
    result.query_status = status

    if status == "is_payload":
        result.available   = True
        result.md5_hash    = data.get("md5_hash")
        result.sha256_hash = data.get("sha256_hash")
        result.file_type   = data.get("file_type")
        result.file_size   = data.get("file_size")
        result.signature   = data.get("signature")   # malware family if identified
        result.virustotal  = data.get("virustotal")

        # Associated delivery URLs
        urls = data.get("urls") or []
        for u in urls[:5]:
            result.associated_urls.append({
                "url":    u.get("url", ""),
                "status": u.get("url_status", ""),
                "threat": u.get("threat", ""),
                "date":   u.get("date_added", ""),
            })
        result.urls_found = len(urls)

        # Extract tags from associated URLs
        for u in urls[:10]:
            for t in (u.get("tags") or []):
                if t not in result.tags:
                    result.tags.append(t)

    elif status in ("no_results", "ok"):
        # "no_results" / "ok" = hash not found in malware database
        result.available = True
    elif status in ("invalid_md5", "invalid_sha256", "invalid_hash", "invalid_format"):
        result.available = False
        result.errors.append(
            f"URLhaus: Hash query rejected — {status} "
            f"(verify hash is valid MD5 or SHA256)"
        )
    elif status:
        # Truly unknown status — log warning, treat as no_results
        result.available = True
        logger.warning("URLhaus hash lookup: unrecognised status %r — treating as no_results", status)

    _score_result(result)
    return result


# ── Host/IP Lookup (pipeline_ip) ──────────────────────────────────────────────

def query_host(host: str) -> URLhausResult:
    """
    Pipeline IP: Check if an IP or hostname has hosted malware URLs.

    URLhaus tracks which IPs/domains have served malware payloads.
    Multiple malicious URLs on a single IP = bulletproof hosting signal.

    Used by: pipeline_ip.py via run_ip_urlhaus_parallel (urlhaus_ip engine)
    """
    result = URLhausResult()
    key = _get_api_key()
    result.used_key = bool(key)

    data = _post_urlhaus("host", {"host": host})

    if data.get("error"):
        err = data.get("message") or data["error"]
        result.errors.append(f"URLhaus host lookup: {err}")
        logger.warning("URLhaus host lookup failed for %s: %s", host, err)
        return result

    status = data.get("query_status", "")
    result.query_status = status

    if status == "is_host":
        result.available = True
        urls = data.get("urls") or []
        result.urls_found = len(urls)

        for u in urls[:5]:
            result.associated_urls.append({
                "url":    u.get("url", ""),
                "status": u.get("url_status", ""),
                "threat": u.get("threat", ""),
                "date":   u.get("date_added", ""),
            })

        # Merge tags
        for u in urls[:10]:
            for t in (u.get("tags") or []):
                if t not in result.tags:
                    result.tags.append(t)

        # First URL's threat type as overall threat label
        if urls:
            result.threat = urls[0].get("threat")

    elif status in ("no_results", "ok"):
        # "ok" = API ran successfully but host has no malware URLs on record
        result.available = True
    elif status in ("invalid_host", "invalid_ip", "invalid_format"):
        result.available = False
        result.errors.append(
            f"URLhaus: Host query rejected — {status} "
            f"(check host/IP format)"
        )
    elif status:
        # Truly unknown status — log warning, treat as no_results
        result.available = True
        logger.warning("URLhaus host lookup: unrecognised status %r — treating as no_results", status)

    _score_result(result)
    return result
