"""
utils/verdict.py
----------------
Verdict Calculator — GhostWire CTI v6 v4

The single authoritative function `calculate_verdict()` is the final
decision layer.  It receives the aggregated score + engine results and
produces a structured Verdict object consumed by the UI and cti_report.

Override priority (highest → lowest):
  1. Infrastructure Override  (VT > 5 malicious → CRITICAL, always)
  2. Brand Squatting          (keyword penalty applied to score first)
  3. Subdomain Trap           (free-hosting entropy replaces WHOIS)
  4. Weighted Confidence      (sandbox > AI NLP in weighting)
  5. Normal scoring           (sum of all engines)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import logging
logger = logging.getLogger(__name__)


# ── Verdict dataclass ─────────────────────────────────────────────────────────

@dataclass
class Verdict:
    """Final verdict produced by calculate_verdict()."""

    # Classification
    threat_level:  str   = "SAFE"       # SAFE / LOW / MEDIUM / HIGH / CRITICAL
    score:         int   = 0            # 0–100
    colour:        str   = "#00ffb4"
    bg_colour:     str   = "rgba(0,255,180,0.08)"

    # Override flags
    infra_override:    bool = False
    subdomain_trap:    bool = False
    brand_squatting:   bool = False

    # Narrative
    one_line:       str = ""    # One-sentence verdict for UI banner
    full_verdict:   str = ""    # Multi-sentence for the verdict box
    mitigation:     list[str] = field(default_factory=list)

    # Metadata
    engines_triggered: list[str] = field(default_factory=list)
    total_iocs:        int        = 0

    # Whitelist
    is_whitelisted:   bool = False
    whitelist_org:    str  = ""


# ── Threat level classification ───────────────────────────────────────────────

_LEVELS = [
    (85, "CRITICAL", "#ff2d55", "rgba(255,45,85,0.10)"),
    (65, "HIGH",     "#ff6b35", "rgba(255,107,53,0.10)"),
    (40, "MEDIUM",   "#ffd060", "rgba(255,208,96,0.08)"),
    (20, "LOW",      "#78d97a", "rgba(120,217,122,0.08)"),
    (0,  "SAFE",     "#00ffb4", "rgba(0,255,180,0.08)"),
]


def _classify(score: int) -> tuple[str, str, str]:
    for threshold, level, colour, bg in _LEVELS:
        if score >= threshold:
            return level, colour, bg
    return "SAFE", "#00ffb4", "rgba(0,255,180,0.08)"


# ── Mitigation library ────────────────────────────────────────────────────────

_MITIGATIONS_CRITICAL = [
    "🚫 DO NOT visit, click, or interact with this URL under any circumstances",
    "🔐 If you already visited — change ALL passwords from a clean device immediately",
    "🏦 Contact your bank/financial institution immediately if credentials may be compromised",
    "🛡 Report to your security team as Priority 1 incident",
    "📧 Forward phishing email to: reportphishing@apwg.org and your email provider",
    "🚧 Block the domain and IP at firewall / DNS resolver level",
    "📋 Submit all IOCs to your SIEM / threat intelligence platform",
]

_MITIGATIONS_HIGH = [
    "⚠️ Do NOT enter credentials or personal data on this site",
    "🔍 Verify legitimacy by navigating directly to the official domain",
    "📞 Contact the organisation through known-good official channels",
    "🛡 Report to IT/security team for investigation",
    "🚧 Consider blocking domain at DNS level",
]

_MITIGATIONS_MEDIUM = [
    "⚠️ Do NOT enter credentials — verify site authenticity first",
    "🔍 Cross-check the domain against the official website",
    "📞 Confirm with the sender through an independent channel",
]

_MITIGATIONS_LOW = [
    "✅ No immediate action required — standard security hygiene applies",
    "🔍 Verify domain authenticity before entering any sensitive information",
]

_MITIGATIONS_SAFE = [
    "✅ No threat indicators detected — standard browsing precautions apply",
]

_MITIGATIONS_COMMON = [
    "🔑 Enable Multi-Factor Authentication (MFA) on all critical accounts",
    "🔄 Keep browser, OS, and security tools updated",
    "📚 Report suspicious messages to your organisation's security team",
]


def _build_mitigation(level: str, iocs: list[str], extra_notes: list[str]) -> list[str]:
    base = {
        "CRITICAL": _MITIGATIONS_CRITICAL,
        "HIGH":     _MITIGATIONS_HIGH,
        "MEDIUM":   _MITIGATIONS_MEDIUM,
        "LOW":      _MITIGATIONS_LOW,
        "SAFE":     _MITIGATIONS_SAFE,
    }.get(level, _MITIGATIONS_LOW)

    steps = list(base)
    steps.extend(extra_notes)
    steps.extend(_MITIGATIONS_COMMON)

    if iocs:
        steps.append(
            f"📋 Key IOCs for threat intel: {', '.join(iocs[:5])}"
        )

    return steps


# ── Verdict narrative builder ─────────────────────────────────────────────────

_ONE_LINERS = {
    "CRITICAL": "Multiple independent engines confirm active malicious infrastructure.",
    "HIGH":     "Strong convergence of phishing indicators — treat as malicious.",
    "MEDIUM":   "Significant suspicious signals detected — manual review required.",
    "LOW":      "Minor concerns noted — proceed with caution.",
    "SAFE":     "No significant threat indicators detected.",
}


def _build_full_verdict(
    score: int,
    level: str,
    engines_triggered: list[str],
    iocs: list[str],
    infra_override: bool,
    subdomain_trap: bool,
    brand_squatting: bool,
    extra_context: str = "",
) -> str:
    parts: list[str] = []

    parts.append(
        f"VERDICT: {level} RISK — Score {score}/100. "
        f"{len(engines_triggered)} detection engine(s) triggered: "
        f"{', '.join(engines_triggered) if engines_triggered else 'baseline heuristics'}."
    )

    if infra_override:
        parts.append(
            "INFRASTRUCTURE OVERRIDE ACTIVE: VirusTotal confirmed more than "
            f"5 malicious detections. Final verdict is locked to CRITICAL regardless "
            f"of other engine results."
        )

    if subdomain_trap:
        parts.append(
            "SUBDOMAIN TRAP RULE APPLIED: The domain resides on a free-hosting "
            "platform. Root domain age is not a reliable signal here — risk was "
            "scored on subdomain entropy and keyword analysis instead."
        )

    if brand_squatting:
        parts.append(
            "BRAND SQUATTING RULE APPLIED: High-value keywords (bank, secure, login, "
            "verify, etc.) were detected in a domain that does not appear on the "
            "enterprise whitelist. A +50 point penalty was applied."
        )

    if iocs:
        parts.append(
            f"{len(iocs)} Indicator(s) of Compromise identified: "
            f"{', '.join(iocs[:4])}{'…' if len(iocs) > 4 else ''}."
        )

    if extra_context:
        parts.append(extra_context)

    return " ".join(parts)


# ── Public API ────────────────────────────────────────────────────────────────

def calculate_verdict(
    score: int,
    engines_triggered: list[str],
    all_iocs: list[str],
    infra_override:  bool = False,
    subdomain_trap:  bool = False,
    brand_squatting: bool = False,
    extra_mitigation_notes: Optional[list[str]] = None,
    extra_context: str = "",
    url: str = "",
    vt_malicious: int = 0,
    abuse_confidence: int = 0,
) -> Verdict:
    """
    Compute the final Verdict from a pre-calculated score.

    This function is the single authoritative verdict-producer.
    All override flags must already be computed by scoring.py before
    calling here — calculate_verdict() only classifies and narrates.

    Args:
        score:                   Final integer score 0–100.
        engines_triggered:       Names of engines that contributed risk.
        all_iocs:                Flat deduplicated IOC list from all engines.
        infra_override:          True if infrastructure override was applied.
        subdomain_trap:          True if subdomain trap rule fired.
        brand_squatting:         True if brand squatting penalty was applied.
        extra_mitigation_notes:  Additional specific mitigation steps.
        extra_context:           Extra text appended to the verdict narrative.

    Returns:
        Verdict object ready for UI rendering and report generation.
    """
    v = Verdict()
    v.score           = max(0, min(score, 100))
    v.infra_override  = infra_override
    v.subdomain_trap  = subdomain_trap
    v.brand_squatting = brand_squatting
    v.engines_triggered = engines_triggered
    v.total_iocs      = len(all_iocs)

    # ── Whitelist detection for LEGIT badge ───────────────────────────
    try:
        from backend.scoring import _classify_az_domain, _check_infra_domain
        import urllib.parse as _up
        _parsed = _up.urlparse(url if url.startswith("http") else "http://" + url)
        _wl_host = (_parsed.hostname or url).lower().lstrip("www.")

        # LEGIT badge: only AZ_SAFE tier domains (VT=0, Abuse=0, no community signals)
        # AZ_REVIEW → not fully safe (relations exist), no badge
        # AZ_SUSPECT / global domains → no badge
        _infra, _ = _check_infra_domain(_wl_host)
        if not _infra:
            _az_tier, _az_reason = _classify_az_domain(_wl_host, type("R", (), {
                "vt_malicious": vt_malicious,
                "abuse_confidence": abuse_confidence,
                "vt_community_malicious_votes": 0,
                "vt_community_malicious_comments": 0,
                "vt_malicious_files_related": 0,
                "vt_community_comment_texts": [],
            })())
            v.is_whitelisted = (_az_tier == "AZ_SAFE")
            v.whitelist_org  = _az_reason if v.is_whitelisted else ""
        else:
            v.is_whitelisted = False
            v.whitelist_org  = ""
    except Exception:
        v.is_whitelisted, v.whitelist_org = False, ""

    # Forced classification when infrastructure override is active
    if infra_override and v.score < 85:
        v.score = 85

    v.threat_level, v.colour, v.bg_colour = _classify(v.score)

    v.one_line = _ONE_LINERS.get(v.threat_level, "")

    v.full_verdict = _build_full_verdict(
        v.score, v.threat_level,
        engines_triggered, all_iocs,
        infra_override, subdomain_trap, brand_squatting,
        extra_context,
    )

    v.mitigation = _build_mitigation(
        v.threat_level,
        all_iocs,
        extra_mitigation_notes or [],
    )

    return v
