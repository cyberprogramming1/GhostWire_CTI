"""
utils/cti_report.py
-------------------
CTI Report Generator — GhostWire CTI v6.

Aggregates all engine results into a structured Cyber Threat Intelligence
report following the format:
  • Threat Level
  • Key Indicators (IOCs)
  • Analyst's Summary
  • Final Verdict & Logic
  • Mitigation Steps
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

from backend.heuristics  import HeuristicsResult
from backend.whois_check import WhoisResult
from backend.ai_analyzer import AIAnalysisResult
from backend.reputation  import ReputationResult
from backend.deception   import DeceptionResult
from backend.sandbox     import SandboxResult

import logging

logger = logging.getLogger(__name__)



@dataclass
class CTIReport:
    """Complete CTI forensic report."""
    # Scores
    total_score: int = 0
    heuristics_score: int = 0
    whois_score: int = 0
    ai_score: int = 0
    reputation_score: int = 0
    deception_score: int = 0
    sandbox_score: int = 0

    # Threat classification
    threat_level: str = "LOW"              # LOW / MEDIUM / HIGH / CRITICAL
    threat_colour: str = "#00ffb4"
    threat_bg: str = "rgba(0,255,180,0.08)"

    # IOC aggregation
    all_iocs: list[str] = field(default_factory=list)

    # Report sections
    analyst_summary: str = ""
    verdict_logic: str = ""
    mitigation_steps: list[str] = field(default_factory=list)

    # Metadata
    target_url: str = ""
    analysis_timestamp: str = ""
    analysis_duration_s: float = 0.0


# ── Classification ────────────────────────────────────────────────────────────

def _classify(score: int) -> tuple[str, str, str]:
    """Return (threat_level, hex_colour, bg_rgba)."""
    if score >= 85:
        return "CRITICAL", "#ff2d55", "rgba(255,45,85,0.10)"
    if score >= 65:
        return "HIGH",     "#ff6b35", "rgba(255,107,53,0.10)"
    if score >= 40:
        return "MEDIUM",   "#ffd060", "rgba(255,208,96,0.08)"
    if score >= 20:
        return "LOW",      "#78d97a", "rgba(120,217,122,0.08)"
    return "SAFE",         "#00ffb4", "rgba(0,255,180,0.08)"


# ── Summary generator ─────────────────────────────────────────────────────────

def _build_summary(
    url: str,
    score: int,
    level: str,
    h: HeuristicsResult,
    w: WhoisResult,
    ai: AIAnalysisResult,
    rep: ReputationResult,
    dec: DeceptionResult,
    sb: SandboxResult,
) -> str:
    parts = []

    parts.append(
        f"Target '{url[:60]}{'...' if len(url)>60 else ''}' received a composite "
        f"risk score of {score}/100, classifying it as **{level}** threat level."
    )

    if h.score >= 20:
        parts.append(
            f"URL structural analysis flagged {len(h.flags)} technical indicators "
            f"including suspicious TLD usage, phishing keyword density, and HTTP "
            f"(non-HTTPS) transport."
        )

    if w.score >= 20:
        parts.append(
            f"Domain age analysis revealed the registrant domain is only "
            f"{w.domain_age_days} day(s) old — consistent with freshly provisioned "
            f"phishing infrastructure."
        )
    elif w.score >= 10:
        parts.append(
            "WHOIS inspection could not confirm domain creation date, which may "
            "indicate privacy-protected registration or a very new domain."
        )

    if dec.typosquat_target:
        parts.append(
            f"Technical deception analysis identified a typosquatting attack "
            f"impersonating '{dec.typosquat_target}' with an edit distance of "
            f"{dec.typosquat_distance} — a deliberate brand impersonation attempt."
        )

    if rep.vt_malicious >= 3:
        parts.append(
            f"VirusTotal multi-engine scan returned {rep.vt_malicious} malicious "
            f"detections across {rep.vt_total_engines} security vendors, confirming "
            f"known-bad infrastructure."
        )

    if rep.abuse_confidence >= 50:
        parts.append(
            f"The resolved IP address ({rep.ip_address}) carries an AbuseIPDB "
            f"confidence score of {rep.abuse_confidence}% with {rep.abuse_reports} "
            f"historical abuse reports."
        )

    if sb.credential_harvesting:
        parts.append(
            "Sandbox behavioral analysis detected active credential harvesting "
            "form elements — the page is actively designed to steal user passwords."
        )

    if sb.malware_distribution:
        parts.append(
            "Sandbox detected obfuscated JavaScript and potential malware "
            "distribution mechanisms — drive-by download attack suspected."
        )

    if ai.urgency_detected or ai.manipulation_detected:
        triggers = []
        if ai.urgency_detected:    triggers.append("urgency")
        if ai.manipulation_detected: triggers.append("manipulation")
        if ai.financial_threat_detected: triggers.append("financial threat")
        parts.append(
            f"AI NLP analysis identified social-engineering tactics: "
            f"{', '.join(triggers)} — consistent with targeted phishing lure."
        )

    if ai.summary and not ai.error:
        parts.append(f"AI Assessment: {ai.summary}")

    return " ".join(parts)


# ── Verdict logic ─────────────────────────────────────────────────────────────

def _build_verdict(score: int, level: str, iocs: list[str], engines_triggered: list[str]) -> str:
    verdict_map = {
        "CRITICAL": (
            f"VERDICT: MALICIOUS INFRASTRUCTURE CONFIRMED. "
            f"Score {score}/100 driven by convergence of {len(engines_triggered)} independent "
            f"detection engines: {', '.join(engines_triggered)}. "
            f"The volume and specificity of IOCs ({len(iocs)} indicators) exceed the threshold "
            f"for reasonable doubt. This URL represents an active threat and should be "
            f"immediately blocked, reported, and quarantined."
        ),
        "HIGH": (
            f"VERDICT: HIGH PROBABILITY PHISHING/MALWARE. "
            f"Score {score}/100 indicates strong convergence of threat signals across "
            f"{len(engines_triggered)} engines. While not all indicators are definitive, "
            f"the pattern is consistent with an active phishing campaign. "
            f"Treat as malicious until proven otherwise."
        ),
        "MEDIUM": (
            f"VERDICT: SUSPICIOUS — MANUAL REVIEW REQUIRED. "
            f"Score {score}/100 reflects moderate risk indicators. "
            f"The URL exhibits {len(iocs)} IOC(s) that warrant further investigation. "
            f"Do not enter credentials. Verify through official channels."
        ),
        "LOW": (
            f"VERDICT: LOW RISK — MINOR CONCERNS NOTED. "
            f"Score {score}/100 with {len(iocs)} minor indicator(s). "
            f"No confirmed malicious activity detected, but some structural patterns "
            f"are suboptimal. Proceed with standard caution."
        ),
        "SAFE": (
            f"VERDICT: NO SIGNIFICANT THREAT DETECTED. "
            f"Score {score}/100. All major detection engines returned clean results. "
            f"Standard browsing precautions remain advisable."
        ),
    }
    return verdict_map.get(level, verdict_map["MEDIUM"])


# ── Mitigation steps ──────────────────────────────────────────────────────────

def _build_mitigations(level: str, iocs: list[str], sb: SandboxResult, rep: ReputationResult) -> list[str]:
    steps = []

    if level in ("CRITICAL", "HIGH"):
        steps += [
            "🚫 DO NOT click, visit, or interact with this URL under any circumstances",
            "🔐 If you have already visited — change all passwords from a clean device immediately",
            "🛡 Report to your security team / IT department as a Priority 1 incident",
            "📧 Forward phishing email to: reportphishing@apwg.org & your email provider",
            "🏦 Contact your bank immediately if any financial credentials may be compromised",
        ]
    elif level == "MEDIUM":
        steps += [
            "⚠️ Do NOT enter any credentials or personal information on this site",
            "🔍 Verify the URL by navigating directly to the official domain",
            "📞 Confirm legitimacy by contacting the organisation through official channels",
            "🛡 Report to your IT/security team for further investigation",
        ]
    else:
        steps += [
            "✅ No immediate action required — standard security hygiene applies",
            "🔍 Verify domain authenticity before entering sensitive information",
        ]

    if sb.credential_harvesting:
        steps.append("🔑 Credential harvesting detected — treat any submitted data as compromised")

    if sb.crypto_drainer:
        steps.append("💰 Crypto drainer detected — do NOT connect any wallets to this site")

    if rep.is_tor:
        steps.append("🧅 Tor exit node IP — flag for network-level blocking at firewall")

    if rep.ip_address:
        steps.append(f"🚧 Block IP {rep.ip_address} at firewall / DNS level")

    if iocs:
        steps.append(f"📋 Submit the following IOCs to your SIEM/threat intel platform: {', '.join(iocs[:5])}")

    steps.append("📚 Enable multi-factor authentication (MFA) on all critical accounts")
    steps.append("🔄 Keep browser and OS updated — patches close drive-by download vectors")

    return steps


# ── Main aggregator ───────────────────────────────────────────────────────────

def build_cti_report(
    url: str,
    h: HeuristicsResult,
    w: WhoisResult,
    ai: AIAnalysisResult,
    rep: ReputationResult,
    dec: DeceptionResult,
    sb: SandboxResult,
    duration: float = 0.0,
) -> CTIReport:
    """
    Aggregate all engine results into a complete CTI forensic report.
    """
    report = CTIReport()
    report.target_url = url
    report.analysis_timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report.analysis_duration_s = round(duration, 2)

    # Individual scores
    report.heuristics_score  = h.score
    report.whois_score       = w.score
    report.ai_score          = ai.score
    report.reputation_score  = rep.score
    report.deception_score   = dec.score
    report.sandbox_score     = sb.score

    # Total (weighted, capped at 100)
    raw = h.score + w.score + ai.score + rep.score + dec.score + sb.score
    report.total_score = min(raw, 100)

    # Classification
    report.threat_level, report.threat_colour, report.threat_bg = _classify(report.total_score)

    # IOC aggregation (deduplicated)
    all_iocs = list(dict.fromkeys(
        h.flags[:2] +   # heuristics doesn't produce IOC list, use flags as proxy
        w.flags[:1] +
        rep.iocs +
        dec.iocs +
        sb.iocs
    ))
    # Filter to only actual IOC-style entries (IP:, VT_, BEHAVIOR: etc.)
    report.all_iocs = [i for i in (rep.iocs + dec.iocs + sb.iocs + ai.flags[:2]) if i]

    # Which engines triggered
    engines_triggered = []
    if h.score >= 15:      engines_triggered.append("URL Heuristics")
    if w.score >= 10:      engines_triggered.append("WHOIS/Domain Age")
    if ai.score >= 15:     engines_triggered.append("AI NLP")
    if rep.score >= 10:    engines_triggered.append("Infrastructure Reputation")
    if dec.score >= 10:    engines_triggered.append("Technical Deception")
    if sb.score >= 10:     engines_triggered.append("Sandbox Behavior")

    report.analyst_summary = _build_summary(url, report.total_score, report.threat_level,
                                             h, w, ai, rep, dec, sb)
    report.verdict_logic   = _build_verdict(report.total_score, report.threat_level,
                                             report.all_iocs, engines_triggered)
    report.mitigation_steps = _build_mitigations(report.threat_level, report.all_iocs, sb, rep)

    return report
