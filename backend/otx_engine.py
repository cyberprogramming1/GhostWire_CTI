"""
backend/otx_engine.py
----------------------
GhostWire CTI v7 — AlienVault OTX (Open Threat Exchange) Engine.


"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Caching ───────────────────────────────────────────────────────────────────
try:
    from backend.caching import CacheManager as _CacheManager
    _otx_cache = _CacheManager("otx", ttl_hours=24)
except ImportError:
    _otx_cache = None

# ── Constants ──────────────────────────────────────────────────────────────────

OTX_API_BASE = "https://otx.alienvault.com/api/v1"
TIMEOUT      = 12   # OTX can be slower than abuse.ch under load

_SAFE_UA = {
    "User-Agent": "GhostWire-CTI/7.0 (SecurityResearch; OTX API client)",
    "Accept":     "application/json",
}

# Corroboration thresholds — OTX score only fires when VT also confirms
_PULSE_HIGH_THRESHOLD = 10   # >= 10 pulses + VT hit → +12 pts
_PULSE_MED_THRESHOLD  = 3    # >=  3 pulses + VT hit → +6  pts

# MITRE ATT&CK tactic names for display (technique ID prefix → tactic)
_MITRE_TACTIC_MAP: dict[str, str] = {
    "T1566": "Phishing",        "T1059": "Execution",
    "T1055": "Injection",       "T1071": "C2 Protocol",
    "T1027": "Obfuscation",     "T1105": "Ingress Transfer",
    "T1036": "Masquerading",    "T1082": "System Discovery",
    "T1083": "File Discovery",  "T1047": "WMI",
    "T1021": "Lateral Movement","T1486": "Ransomware",
    "T1490": "Inhibit Recovery","T1140": "Deobfuscation",
    "T1078": "Valid Accounts",  "T1133": "External Remote",
    "T1190": "Exploit Public",  "T1203": "Client Exploit",
}

# Known high-profile APT / threat actor names for badge highlighting
_HIGH_PROFILE_ACTORS: frozenset[str] = frozenset({
    "lazarus", "apt28", "apt29", "cozy bear", "fancy bear",
    "cobalt strike", "turla", "fin7", "darkside", "revil",
    "lockbit", "conti", "emotet", "qbot", "trickbot",
    "scattered spider", "unc2452", "hafnium",
})


# ── Data Model ────────────────────────────────────────────────────────────────

@dataclass
class OTXResult:
    """Unified result from AlienVault OTX indicator lookup."""

    available:      bool = False   # True if API returned usable data
    indicator_type: str  = ""      # "domain" | "IPv4" | "url" | "FileHash-*"

    # Core OTX metrics
    pulse_count:    int  = 0       # how many threat intel pulses mention this IOC
    # Top pulse names (for display — human-readable campaign context)
    pulse_names:    list[str] = field(default_factory=list)

    # MITRE ATT&CK
    attack_ids:     list[str] = field(default_factory=list)   # ["T1566", "T1059"]
    attack_tactics: list[str] = field(default_factory=list)   # ["Phishing", "Execution"]

    # Threat actor attribution
    adversaries:    list[str] = field(default_factory=list)   # ["Lazarus Group"]
    malware_families: list[str] = field(default_factory=list) # ["Emotet", "QBot"]

    # Targeted context
    targeted_countries:  list[str] = field(default_factory=list)
    targeted_industries: list[str] = field(default_factory=list)

    # Reputation
    reputation: Optional[int] = None   # OTX reputation score (-100 to 0, negative=bad)

    # Scoring
    score_contribution: int        = 0
    flags:  list[str]              = field(default_factory=list)
    iocs:   list[str]              = field(default_factory=list)
    errors: list[str]              = field(default_factory=list)


# ── API Helpers ───────────────────────────────────────────────────────────────

def _get_api_key() -> str:
    return os.environ.get("OTX_API_KEY", "").strip()


def _build_headers() -> dict:
    h = {**_SAFE_UA}
    key = _get_api_key()
    if key:
        h["X-OTX-APIKEY"] = key
    return h


_ALLOWED_INDICATOR_TYPES: frozenset[str] = frozenset({
    "domain", "hostname", "IPv4", "IPv6",
    "url", "URI",
    "FileHash-MD5", "FileHash-SHA256", "FileHash-SHA1",
})

_ALLOWED_SECTIONS: frozenset[str] = frozenset({
    "general", "reputation",
})


def _sanitize(value: str, max_len: int = 512) -> str:
    """Strip control chars — prevent log/header injection."""
    return "".join(ch for ch in value if ch.isprintable() and ch not in "\r\n\t")[:max_len]


def _get_indicator(indicator_type: str, indicator: str, section: str) -> dict:
    """
    GET /api/v1/indicators/{type}/{indicator}/{section}

    Security hardening:
      - indicator_type whitelist
      - section whitelist
      - input sanitization
      - response size cap (2MB)
    """
    # Whitelist checks
    if indicator_type not in _ALLOWED_INDICATOR_TYPES:
        logger.error("OTX: blocked disallowed indicator type %r", indicator_type)
        return {"error": "invalid_indicator_type"}
    if section not in _ALLOWED_SECTIONS:
        logger.error("OTX: blocked disallowed section %r", section)
        return {"error": "invalid_section"}

    safe_indicator = _sanitize(indicator)

    # ── Cache lookup ──────────────────────────────────────────────────
    # Key: "indicator_type:indicator:section" — unique per request type
    _cache_key = f"{indicator_type}:{safe_indicator}:{section}"
    if _otx_cache is not None:
        _cached = _otx_cache.get(_cache_key)
        if _cached is not None:
            logger.debug("OTX cache HIT [%s/%s/%s]", indicator_type, safe_indicator[:20], section)
            return _cached

    url = f"{OTX_API_BASE}/indicators/{indicator_type}/{safe_indicator}/{section}"

    try:
        resp = requests.get(
            url,
            headers=_build_headers(),
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            if len(resp.content) > 2_000_000:
                logger.warning("OTX response too large (%d bytes)", len(resp.content))
                return {"error": "response_too_large"}
            data = resp.json()
            # Cache successful responses only
            if _otx_cache is not None:
                _otx_cache.set(_cache_key, data)
            return data
        elif resp.status_code == 400:
            return {"error": "invalid_indicator", "status": 400}
        elif resp.status_code == 401:
            # 401 without key = endpoint requires auth; 401 with key = invalid key
            key = _get_api_key()
            if key:
                logger.warning("OTX: API key invalid — add OTX_API_KEY to .env")
                return {"error": "unauthorized"}
            else:
                logger.info("OTX: endpoint requires API key — add OTX_API_KEY to .env (free)")
                return {"error": "key_required"}
        elif resp.status_code == 404:
            # 404 = indicator not found in OTX = clean / unknown
            return {"error": "not_found"}
        elif resp.status_code == 429:
            logger.warning("OTX rate limit hit")
            return {"error": "rate_limit"}
        else:
            return {"error": f"http_{resp.status_code}"}
    except requests.Timeout:
        logger.warning("OTX timeout after %ds for %s", TIMEOUT, indicator[:60])
        return {"error": "timeout"}
    except Exception as exc:
        logger.warning("OTX API error: %s", exc)
        return {"error": str(exc)[:100]}


# ── Parsing ───────────────────────────────────────────────────────────────────

def _parse_general(data: dict, result: OTXResult) -> None:
    """Extract pulse_info, ATT&CK IDs, adversaries, malware families."""

    pulse_info = data.get("pulse_info") or {}
    result.pulse_count = pulse_info.get("count", 0)

    pulses: list[dict] = pulse_info.get("pulses") or []

    # Collect top 5 pulse names (most recent first — API returns newest first)
    result.pulse_names = [
        p.get("name", "")
        for p in pulses[:5]
        if p.get("name")
    ]

    # MITRE ATT&CK IDs — deduplicated across all pulses
    seen_ids: set[str] = set()
    for p in pulses:
        for aid in (p.get("attack_ids") or []):
            tid = str(aid).strip().upper()
            # Validate format: T followed by 4+ digits, optionally .xxx
            if re.match(r"^T\d{4}(\.\d{3})?$", tid) and tid not in seen_ids:
                seen_ids.add(tid)
                result.attack_ids.append(tid)
                # Map to human-readable tactic name
                base = tid[:5]   # e.g. T1566.001 → T1566
                tactic = _MITRE_TACTIC_MAP.get(base)
                if tactic and tactic not in result.attack_tactics:
                    result.attack_tactics.append(tactic)

    # Threat actor (adversary) attribution
    seen_adv: set[str] = set()
    for p in pulses:
        adv = (p.get("adversary") or "").strip()
        if adv and adv.lower() not in seen_adv:
            seen_adv.add(adv.lower())
            result.adversaries.append(adv)

    # Malware families from tags — collect across all pulses
    seen_mal: set[str] = set()
    for p in pulses:
        for tag in (p.get("tags") or []):
            t = tag.strip()
            if t and t.lower() not in seen_mal:
                seen_mal.add(t.lower())
                result.malware_families.append(t)

    # Targeted countries and industries (from first 10 pulses)
    seen_c: set[str] = set()
    seen_i: set[str] = set()
    for p in pulses[:10]:
        for c in (p.get("targeted_countries") or []):
            if c and c not in seen_c:
                seen_c.add(c); result.targeted_countries.append(c)
        for i in (p.get("industries") or []):
            if i and i not in seen_i:
                seen_i.add(i); result.targeted_industries.append(i)

    # OTX reputation (available on domain/IPv4 general endpoint)
    rep = data.get("reputation")
    if isinstance(rep, (int, float)):
        result.reputation = int(rep)


def _parse_reputation(data: dict, result: OTXResult) -> None:
    """Parse /reputation section — provides a numeric reputation score."""
    rep = data.get("reputation")
    if isinstance(rep, (int, float)) and result.reputation is None:
        result.reputation = int(rep)



_INFRA_PULSE_KEYWORDS: list[tuple[frozenset[str], int, str]] = [
    # (keywords_any_match,  score_pts, flag_label)
    (
        frozenset({"tor exit", "tor-exit", "torexit", "tor node", "tor network"}),
        20,
        "🧅 OTX: Confirmed Tor Exit Node — anonymisation infrastructure",
    ),
    (
        frozenset({"honeynet", "honey net", "honeypot", "honey pot"}),
        15,
        "🍯 OTX: Found in HoneyNet feed — known malicious scanner/attacker",
    ),
    (
        frozenset({"scanner", "scanning", "mass scan", "shodan", "internet scan"}),
        10,
        "🔍 OTX: Found in mass-scanner feed — aggressive reconnaissance activity",
    ),
    (
        frozenset({"c2", "c&c", "command and control", "command & control", "botnet", "bot net"}),
        18,
        "☠️ OTX: Found in C2/Botnet feed — active malware infrastructure",
    ),
    (
        frozenset({"brute force", "bruteforce", "brute-force", "ssh brute", "rdp brute"}),
        12,
        "🔨 OTX: Found in brute-force attacker feed",
    ),
    (
        frozenset({"malware", "malicious", "ransomware", "dropper", "backdoor", "trojan"}),
        15,
        "☣️ OTX: Found in malware-distribution feed",
    ),
]


def _detect_infra_signals(result: OTXResult) -> int:
   
    if not result.pulse_names:
        return 0

    infra_score  = 0
    matched_cats: set[str] = set()

    all_names_lower = " | ".join(result.pulse_names).lower()

    for keywords, pts, flag in _INFRA_PULSE_KEYWORDS:
        for kw in keywords:
            if kw in all_names_lower:
                cat = flag.split(":")[0]   # e.g. "🧅 OTX"
                if cat not in matched_cats:
                    matched_cats.add(cat)
                    infra_score += pts
                    result.flags.append(flag)
                    # Add a short IOC tag
                    ioc_tag = (
                        "TOR_EXIT_NODE"   if "Tor" in flag else
                        "HONEYNET_FEED"   if "HoneyNet" in flag else
                        "SCANNER_FEED"    if "scanner" in flag else
                        "C2_BOTNET_FEED"  if "C2" in flag else
                        "BRUTEFORCE_FEED" if "brute" in flag else
                        "MALWARE_FEED"
                    )
                    result.iocs.append(f"OTX_{ioc_tag}:{result.pulse_count}_pulses")
                break   # Only count each category once

    return infra_score


# ── Scoring ───────────────────────────────────────────────────────────────────

def _score_result(result: OTXResult, vt_malicious: int = 0) -> None:
    
    score = 0

    if result.pulse_count == 0:
        # Not in any OTX pulse — clean (or unknown)
        if result.available:
            result.flags.append("✅ OTX: No threat intel pulses found for this indicator")
        result.score_contribution = 0
        return

    # ── Pulse count flag (always shown — context value regardless of VT) ──
    pulse_label = (
        "🔴" if result.pulse_count >= 20 else
        "🟠" if result.pulse_count >= 5  else
        "⚠️"
    )
    result.flags.append(
        f"{pulse_label} OTX: Found in {result.pulse_count} threat intel pulse(s)"
    )

   
    infra_score = _detect_infra_signals(result)
    if infra_score > 0:
        score += infra_score
        result.flags.append(
            f"🚨 OTX Infrastructure Signal: +{infra_score} pts "
            f"(classification feed — VT corroboration not required)"
        )
        result.iocs.append(f"OTX_PULSES:{result.pulse_count}")

    # ── Corroborated scoring (requires VT confirmation) ───────────────
    if vt_malicious > 0:
        if result.pulse_count >= _PULSE_HIGH_THRESHOLD:
            corr_score = 12
            score += corr_score
            if f"OTX_PULSES:{result.pulse_count}" not in result.iocs:
                result.iocs.append(f"OTX_PULSES:{result.pulse_count}")
            result.flags.append(
                f"🔴 OTX Corroborated: {result.pulse_count} pulses + VT confirmed → HIGH confidence"
            )
        elif result.pulse_count >= _PULSE_MED_THRESHOLD:
            corr_score = 6
            score += corr_score
            if f"OTX_PULSES:{result.pulse_count}" not in result.iocs:
                result.iocs.append(f"OTX_PULSES:{result.pulse_count}")
            result.flags.append(
                f"🟠 OTX Corroborated: {result.pulse_count} pulses + VT confirmed"
            )
        # 1-2 pulses even with VT — too low to score (noisy), context only
    elif infra_score == 0:
        # Non-infrastructure pulses without VT — informational only
        result.flags.append(
            f"⚠️ OTX: {result.pulse_count} pulse(s) but VT shows clean — "
            f"possible stale/FP pulses. Context only, no score added."
        )

    # ── MITRE ATT&CK — always show, no score (context only) ──────────
    if result.attack_ids:
        id_display = " · ".join(
            f"{tid}" + (f" [{_MITRE_TACTIC_MAP.get(tid[:5], '')}]"
                        if _MITRE_TACTIC_MAP.get(tid[:5]) else "")
            for tid in result.attack_ids[:6]
        )
        result.flags.append(f"🎯 MITRE ATT&CK: {id_display}")
        result.iocs.extend([f"MITRE:{tid}" for tid in result.attack_ids[:4]])

    # ── Threat actor attribution ──────────────────────────────────────
    if result.adversaries:
        actors = result.adversaries[:3]
        high_profile = [
            a for a in actors
            if any(hp in a.lower() for hp in _HIGH_PROFILE_ACTORS)
        ]
        if high_profile:
            result.flags.append(
                f"🕵️ OTX Attribution: {', '.join(high_profile)} — HIGH-PROFILE THREAT ACTOR"
            )
            result.iocs.extend([f"OTX_ACTOR:{a}" for a in high_profile[:2]])
        else:
            result.flags.append(f"🕵️ OTX Attribution: {', '.join(actors)}")

    # ── OTX reputation score ──────────────────────────────────────────
    if result.reputation is not None and result.reputation < -50:
        result.flags.append(
            f"📊 OTX Reputation: {result.reputation} (very negative — strong malicious signal)"
        )

    result.score_contribution = min(score, 35)   # FIX v7: raised cap (was 15) — infra signals can add up to 35


# ── Public API ────────────────────────────────────────────────────────────────

def query_indicator(
    indicator: str,
    indicator_type: str,
    vt_malicious: int = 0,
) -> OTXResult:
    """
    Main entry point — query OTX for any indicator type.

    Parameters
    ----------
    indicator      : The value to look up (domain, IP, URL, hash)
    indicator_type : OTX type string — "domain", "IPv4", "url",
                     "FileHash-MD5", "FileHash-SHA256"
    vt_malicious   : VT engine count — used for corroborated scoring

    Returns OTXResult with pulse context, MITRE IDs, actors, and score.
    """
    result = OTXResult(indicator_type=indicator_type)

    # OTX supports public lookups without API key (reduced rate limits)
    # We still proceed without key — auth header is simply omitted
    if indicator_type not in _ALLOWED_INDICATOR_TYPES:
        result.errors.append(f"OTX: unsupported indicator type {indicator_type!r}")
        return result

    # ── General section (pulse_info, ATT&CK, adversaries) ─────────────
    general_data = _get_indicator(indicator_type, indicator, "general")

    if "error" in general_data:
        err = general_data["error"]
        if err == "not_found":
            # 404 = clean/unknown — not an error, perfectly normal
            result.available = True
            result.flags.append("✅ OTX: Indicator not found in threat database")
        elif err in ("unauthorized", "key_required"):
            result.errors.append("OTX: API key required — add OTX_API_KEY to .env (free at otx.alienvault.com)")
        elif err == "rate_limit":
            result.errors.append("OTX: rate limit reached — retry in a moment")
        elif err == "timeout":
            result.errors.append("OTX: request timed out — OTX may be slow, retry later")
        elif err == "invalid_indicator":
            result.errors.append(f"OTX: indicator format rejected ({indicator_type})")
        else:
            result.errors.append(f"OTX lookup failed: {err}")
        _score_result(result, vt_malicious)
        return result

    result.available = True
    _parse_general(general_data, result)

    _score_result(result, vt_malicious)
    return result


# ── Convenience wrappers per pipeline ────────────────────────────────────────

def query_domain(domain: str, vt_malicious: int = 0) -> OTXResult:
    """pipeline_url — domain lookup."""
    return query_indicator(domain, "domain", vt_malicious)


def query_ip(ip: str, vt_malicious: int = 0) -> OTXResult:
    """pipeline_ip — IPv4 lookup."""
    return query_indicator(ip, "IPv4", vt_malicious)


def query_url(url: str, vt_malicious: int = 0) -> OTXResult:
    """pipeline_url — full URL lookup."""
    return query_indicator(url, "url", vt_malicious)


def query_hash(hash_str: str, vt_malicious: int = 0) -> OTXResult:
    """pipeline_hash — file hash lookup (MD5 or SHA256)."""
    h = hash_str.strip().lower()
    if len(h) == 32 and re.fullmatch(r"[0-9a-f]+", h):
        itype = "FileHash-MD5"
    elif len(h) == 64 and re.fullmatch(r"[0-9a-f]+", h):
        itype = "FileHash-SHA256"
    else:
        r = OTXResult()
        r.errors.append(f"OTX: unsupported hash length {len(h)} — need MD5 or SHA256")
        return r
    return query_indicator(hash_str.strip(), itype, vt_malicious)
