"""
backend/scoring.py
------------------
Advanced Scoring Engine & Behavioral Signal Aggregator
GhostWire CTI v6
"""

from __future__ import annotations

import math
import urllib.parse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from backend.heuristics  import HeuristicsResult
    from backend.whois_check import WhoisResult
    from backend.ai_analyzer import AIAnalysisResult, DomainLegitimacyResult
    from backend.reputation  import ReputationResult
    from backend.deception   import DeceptionResult
    from backend.sandbox     import SandboxResult
    from backend.ssl_engine  import SSLResult
    from backend.passive_dns import PassiveDNSResult


# ── Constants ─────────────────────────────────────────────────────────────────

INFRA_OVERRIDE_THRESHOLD = 8        # Raised from 5 to reduce FP
INFRA_OVERRIDE_MIN_SCORE = 85

FREE_HOSTING_TLDS: set[str] = {
    "github.io", "gitlab.io", "pages.dev", "netlify.app",
    "vercel.app", "weebly.com", "wix.com", "squarespace.com",
    "webflow.io", "glitch.me", "replit.dev", "firebaseapp.com",
    "web.app", "surge.sh", "tiiny.site", "000webhostapp.com",
    "wordpress.com", "blogspot.com", "tumblr.com",
}

SQUATTING_KEYWORDS: set[str] = {
    "bank", "banking", "secure", "security", "login", "signin",
    "verify", "verification", "account", "password", "credential",
    "update", "confirm", "paypal", "apple", "google", "microsoft",
    "amazon", "netflix", "crypto", "wallet", "transfer", "payment",
    "invoice", "tax", "irs", "refund", "reward", "prize",
}

ENTERPRISE_WHITELIST: set[str] = {
    "paypal.com", "apple.com", "google.com", "microsoft.com",
    "amazon.com", "netflix.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "citibank.com", "hsbc.com", "barclays.com",
    "coinbase.com", "binance.com", "kraken.com",
    "irs.gov", "gov.uk", "europa.eu", "gov.az",
}

SQUATTING_PENALTY  = 35   # Reduced from 50
SANDBOX_WEIGHT     = 1.2  # Reduced from 1.4
AI_NLP_WEIGHT      = 0.85

# Normalization: raw scores can hit 200+; divide before capping at 100
SCORE_NORMALIZATION_FACTOR = 2.0


# ── Regional / Static Whitelist ───────────────────────────────────────────────
# Fallback for when Ollama is unavailable.
# Domains and TLDs here are immune to VT relations FP scoring.
# Format:
#   WHITELISTED_TLDS      — any domain ending with these suffixes is protected
#   WHITELISTED_DOMAINS   — exact root domain matches (subdomain-agnostic)

WHITELISTED_TLDS: tuple[str, ...] = (
    ".gov.az",
    ".edu.az",
    ".mil.az",
    ".int.az",
)

# ── INFRA_DOMAINS: Partial whitelist — ONLY relations suppressed ──────────────
# High-traffic global mail/infra providers. Relations suppressed (user-uploaded
# samples appear in VT relations for ANY popular service). However:
#   → Community VOTES are still scored  (users report abuse directly)
#   → Community COMMENTS are still scored (analysts note phishing campaigns)
#   → AbuseIPDB confidence still scored
# .az / .gov.az domains are handled fully by _classify_az_domain() regex logic.
INFRA_DOMAINS: dict[str, str] = {
    "163.com":              "NetEase 163 Mail (China)",
    "126.com":              "NetEase 126 Mail (China)",
    "qq.com":               "Tencent QQ",
    "mail.ru":              "Mail.ru (VK)",
    "yandex.ru":            "Yandex Mail",
    "yandex.com":           "Yandex",
    "outlook.com":          "Microsoft Outlook",
    "hotmail.com":          "Microsoft Hotmail",
    "live.com":             "Microsoft Live",
    "gmail.com":            "Google Gmail",
    "yahoo.com":            "Yahoo Mail",
    "protonmail.com":       "ProtonMail",
    "proton.me":            "ProtonMail",
    "icloud.com":           "Apple iCloud Mail",
    "gmx.com":              "GMX Mail",
    "gmx.net":              "GMX Mail",
    "zoho.com":             "Zoho Mail",
    "tutanota.com":         "Tutanota Mail",
    "aol.com":              "AOL Mail",
}

# ── Combined lookup (used by _check_static_whitelist) ────────────────────────
# .az domains are now handled by _classify_az_domain() regex — not here.
WHITELISTED_DOMAINS: dict[str, str] = {**INFRA_DOMAINS}


# ── Known legitimate subdomain prefixes for whitelisted domains ──────────────
# Only these subdomain prefixes are allowed on whitelisted root domains.
# This prevents: phishing.azal.az, evil.kapitalbank.az, steal.socar.az etc.
# Add new legitimate subdomains here as needed.
ALLOWED_SUBDOMAIN_PREFIXES: frozenset[str] = frozenset({
    "www", "mail", "webmail", "smtp", "imap", "pop", "mx",
    "m", "mobile", "app", "api", "cdn", "static", "assets",
    "booking", "checkin", "online", "my", "portal", "secure",
    "support", "help", "info", "news", "media", "blog",
    "careers", "jobs", "eticket", "ticket",
    "online", "e", "login", "auth", "sso",
    "ib", "ibank", "internet", "kabinet",
    "az", "en", "ru",   # language prefixes
})

# ── Known legitimate .gov.az / .edu.az subdomains ────────────────────────────
# TLD whitelist (.gov.az) is powerful — only known-good 2nd-level domains allowed.
# Format: "subdomain.gov.az" or "subdomain.edu.az" etc.
WHITELISTED_TLD_SUBDOMAINS: dict[str, str] = {
    # .gov.az — only explicitly known government portals
    "taxes.gov.az":    "Azerbaijan Tax Ministry",
    "customs.gov.az":  "Azerbaijan Customs Committee",
    "sosial.gov.az":   "Azerbaijan Social Protection Ministry",
    "edu.gov.az":      "Azerbaijan Education Ministry",
    "mia.gov.az":      "Azerbaijan Interior Ministry",
    "e-gov.az":        "Azerbaijan e-Government Portal",
    "azerbaijane-gov.az": "Azerbaijan e-Government Portal",
    # .edu.az — add known universities as needed
}


# ── AZ TLD Regex Patterns ────────────────────────────────────────────────────
# Used by _classify_az_domain() to detect ANY .az or .gov.az domain
# regardless of whether it is in the explicit whitelist.
# Purpose: apply a distinct, gentler scoring path for all Azerbaijani domains.

import re as _re

import logging
logger = logging.getLogger(__name__)

# Matches any domain ending in .az  (covers .gov.az, .edu.az, .com.az, .net.az, .org.az etc.)
_AZ_TLD_RE    = _re.compile(r'(?:^|\.)az$', _re.IGNORECASE)

# Matches specifically *.gov.az  or  *.edu.az  or  *.mil.az
_AZ_GOV_RE    = _re.compile(r'(?:^|\.)(?:gov|edu|mil|int)\.az$', _re.IGNORECASE)

# Suspicious comment keywords — if ANY appear, AZ domain is NOT auto-safe
_SUSPICIOUS_COMMENT_KEYWORDS: frozenset[str] = frozenset({
    "phishing", "malicious", "scam", "spam", "fraud", "fake",
    "malware", "trojan", "ransomware", "exploit", "suspicious",
    "dangerous", "harmful", "attack", "hacked", "compromised",
    "botnet", "c2", "command", "credential", "harvest", "stealer",
})


def _is_az_domain(domain: str) -> bool:
    """Return True if domain ends in .az (any subdomain of .az TLD)."""
    bare = domain.lower().strip()
    return bool(_AZ_TLD_RE.search(bare))


def _is_az_gov_domain(domain: str) -> bool:
    """Return True if domain is under .gov.az / .edu.az / .mil.az."""
    bare = domain.lower().strip()
    return bool(_AZ_GOV_RE.search(bare))


def _has_suspicious_community_comment(rep: object) -> bool:
    """
    Scan VT community comment text for suspicious keywords.
    Returns True only if a comment explicitly mentions malicious activity.
    Absence of comments → False (safe assumption for .az domains).
    """
    comments_text: list[str] = getattr(rep, "vt_community_comment_texts", [])
    if not comments_text:
        return False
    combined = " ".join(str(c).lower() for c in comments_text)
    return any(kw in combined for kw in _SUSPICIOUS_COMMENT_KEYWORDS)


def _classify_az_domain(
    domain: str,
    rep:    object,
) -> tuple[str, str]:
    """
    Classify an .az or .gov.az domain into a scoring tier.

    Returns (tier, reason):
      "AZ_SAFE"     — fully clean: VT=0, Abuse=0, no community signals
                      → treat as LEGIT, score ceiling applied
      "AZ_REVIEW"   — minor signals (relations only, no votes/comments/suspicious text)
                      → light scoring, no ceiling, not auto-LEGIT
      "AZ_SUSPECT"  — real community signals (votes/comments with suspicious keywords)
                      → score normally like any unknown domain
      "NOT_AZ"      — domain does not match .az TLD at all

    Logic (in order):
      1. Not .az → NOT_AZ
      2. VT malicious engines > 0 OR AbuseIPDB ≥ 30 → AZ_SUSPECT
      3. Suspicious community comments → AZ_SUSPECT
      4. Malicious votes ≥ 5 → AZ_SUSPECT
      5. Only relations (no votes, no suspicious comments) → AZ_REVIEW
      6. Everything zero → AZ_SAFE
    """
    bare = domain.lower().strip()

    if not _is_az_domain(bare):
        return "NOT_AZ", ""

    vt_malicious  = getattr(rep, "vt_malicious",  0)
    abuse_conf    = getattr(rep, "abuse_confidence", 0)
    votes         = getattr(rep, "vt_community_malicious_votes",    0)
    comments      = getattr(rep, "vt_community_malicious_comments",  0)
    relations     = getattr(rep, "vt_malicious_files_related",        0)
    has_sus_comment = _has_suspicious_community_comment(rep)

    domain_type = "gov/edu/mil .az" if _is_az_gov_domain(bare) else ".az"

    # ── Rule 1: Hard malicious signals → AZ_SUSPECT ──────────────────
    if vt_malicious > 0:
        return "AZ_SUSPECT", (
            f"{domain_type} domain with {vt_malicious} VT engine detections — "
            f"scored as standard unknown domain"
        )

    if abuse_conf >= 30:
        return "AZ_SUSPECT", (
            f"{domain_type} domain with AbuseIPDB={abuse_conf}% — "
            f"scored as standard unknown domain"
        )

    # ── Rule 2: Suspicious community comments → AZ_SUSPECT ───────────
    if has_sus_comment:
        return "AZ_SUSPECT", (
            f"{domain_type} domain: community comment contains suspicious keywords — "
            f"scored as standard unknown domain"
        )

    # ── Rule 3: Significant malicious votes → AZ_SUSPECT ─────────────
    if votes >= 5:
        return "AZ_SUSPECT", (
            f"{domain_type} domain: {votes} malicious community votes — "
            f"scored as standard unknown domain"
        )

    # ── Rule 4: Relations only (no votes, no suspicious comments) ──────
    # Relations on .az domains are almost always user-uploaded samples
    # (bank statements, airline tickets, gov documents uploaded to VT).
    if relations > 0 and votes == 0 and comments == 0:
        return "AZ_REVIEW", (
            f"{domain_type} domain: {relations} VT relations but "
            f"no malicious votes/comments — relations likely user-uploaded "
            f"documents (bank/airline/gov). Light scoring applied."
        )

    # ── Rule 4b: Low votes (1-4) with no suspicious comments → AZ_REVIEW
    # Not enough to be AZ_SUSPECT (threshold is 5), but not fully clean either.
    if 0 < votes < 5 and not has_sus_comment:
        return "AZ_REVIEW", (
            f"{domain_type} domain: {votes} malicious vote(s) (below threshold=5) "
            f"with no suspicious comment keywords. Light scoring applied."
        )

    # ── Rule 5: Completely clean → AZ_SAFE ───────────────────────────
    return "AZ_SAFE", (
        f"{domain_type} domain: VT=0, Abuse=0, no malicious community activity. "
        f"Treated as LEGIT — score ceiling applied."
    )


def _check_static_whitelist(domain: str) -> tuple[bool, str]:
    """
    Check if a domain matches the static regional/global whitelist.
    Returns (is_whitelisted, organization_name).

    Security rules:
      1. Exact match in WHITELISTED_DOMAINS → whitelisted
      2. www.<root> → whitelisted (www is always safe)
      3. <prefix>.<root> where prefix in ALLOWED_SUBDOMAIN_PREFIXES → whitelisted
      4. Any OTHER subdomain of a whitelisted root → NOT whitelisted
         (prevents phishing.azal.az, evil.kapitalbank.az attacks)
      5. .gov.az / .edu.az / .mil.az TLD domains → only if explicitly
         listed in WHITELISTED_TLD_SUBDOMAINS (prevents fake.gov.az)
    """
    domain = domain.lower().strip()

    # Strip leading www. for comparison (www is always trusted)
    bare = domain[4:] if domain.startswith("www.") else domain

    # ── Rule 1: Exact match ────────────────────────────────────────────
    if bare in WHITELISTED_DOMAINS:
        return True, WHITELISTED_DOMAINS[bare]

    # ── Rule 2: Single allowed subdomain prefix ───────────────────────
    # Only ONE level of subdomain allowed: prefix.root.tld
    # Prevents: evil.phishing.azal.az (2 levels deep — never trusted)
    parts = bare.split(".")
    if len(parts) >= 3:
        prefix    = parts[0]
        root      = ".".join(parts[1:])   # e.g. azal.az

        if root in WHITELISTED_DOMAINS:
            if prefix in ALLOWED_SUBDOMAIN_PREFIXES:
                return True, WHITELISTED_DOMAINS[root]
            else:
                # Subdomain NOT in allowed list — do NOT whitelist
                # e.g. phishing.azal.az, evil.kapitalbank.az
                return False, ""

    # ── Rule 3: TLD whitelist (.gov.az etc.) — explicit only ──────────
    # We do NOT trust *all* .gov.az subdomains automatically.
    # Only domains explicitly listed in WHITELISTED_TLD_SUBDOMAINS pass.
    for tld in WHITELISTED_TLDS:
        if bare.endswith(tld) or bare == tld.lstrip("."):
            if bare in WHITELISTED_TLD_SUBDOMAINS:
                return True, WHITELISTED_TLD_SUBDOMAINS[bare]
            # Not in explicit list → fall through to normal scoring
            return False, ""

    return False, ""


# ── Behavioral Signals ────────────────────────────────────────────────────────

@dataclass
class BehavioralSignals:
    """All signals derived from real engine outputs. No hardcoded values."""

    # AI NLP signals
    urgency:             bool = False
    financial_threat:    bool = False
    manipulation:        bool = False

    # Compound sandbox + deception
    credential_harvest:  bool = False
    fake_login_page:     bool = False
    malware_dropper:     bool = False
    crypto_drainer:      bool = False
    tech_support_scam:   bool = False

    # Infrastructure
    tor_exit_node:        bool = False
    vpn_detected:         bool = False
    high_abuse_ip:        bool = False

    # SSL
    free_ca_young_domain: bool = False
    cert_invalid:         bool = False

    # Scoring overrides
    infrastructure_override: bool = False
    subdomain_trap_active:   bool = False
    brand_squatting:         bool = False

    # UI display log
    score_adjustments:    list[tuple[str, int]] = field(default_factory=list)
    overall_confidence:   int = 50


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_infra_domain(domain: str) -> tuple[bool, str]:
    """
    Check if domain is an INFRA_DOMAIN (global mail provider etc.).
    These get PARTIAL whitelist: only relations suppressed.
    Votes + comments still apply — community can raise score to HIGH/CRITICAL.
    AbuseIPDB still applies. Score ceiling NOT applied.
    Example: 163.com with malicious community votes → correctly goes HIGH.
    """
    domain = domain.lower().strip()
    bare   = domain[4:] if domain.startswith("www.") else domain
    if bare in INFRA_DOMAINS:
        return True, INFRA_DOMAINS[bare]
    parts = bare.split(".")
    if len(parts) >= 3:
        root = ".".join(parts[1:])
        if root in INFRA_DOMAINS and parts[0] in ALLOWED_SUBDOMAIN_PREFIXES:
            return True, INFRA_DOMAINS[root]
    return False, ""


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _root_domain(hostname: str) -> str:
    try:
        import tldextract
        ext = tldextract.extract(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    return hostname


def _is_free_hosting(hostname: str) -> tuple[bool, str]:
    hn = hostname.lower()
    for platform in FREE_HOSTING_TLDS:
        if hn.endswith("." + platform):
            return True, platform
    return False, ""


# ── Rule 1: Infrastructure Override ──────────────────────────────────────────

def _apply_infra_override(
    score: int,
    vt_malicious: int,
    abuse_confidence: int,
    sig: BehavioralSignals,
) -> tuple[int, list[str]]:
    flags: list[str] = []
    triggered = vt_malicious > INFRA_OVERRIDE_THRESHOLD or abuse_confidence >= 90

    if triggered:
        sig.infrastructure_override = True
        if score < INFRA_OVERRIDE_MIN_SCORE:
            boost = INFRA_OVERRIDE_MIN_SCORE - score
            sig.score_adjustments.append(("Infra Override", boost))
            flags.append(
                f"INFRASTRUCTURE OVERRIDE: VT={vt_malicious} malicious "
                f"(threshold >{INFRA_OVERRIDE_THRESHOLD}). Score locked to CRITICAL."
            )
            return INFRA_OVERRIDE_MIN_SCORE, flags

    return score, flags


# ── Rule 1b: VT Community Signals Override ────────────────────────────────────

def _apply_vt_community_override(
    score: int,
    rep: "ReputationResult",
    sig: BehavioralSignals,
    legitimacy: Optional["DomainLegitimacyResult"] = None,
    url: str = "",
) -> tuple[int, list[str]]:
    """
    VT engines clean olsa belə, community votes/comments/relations
    yüksəkdirsə score-u müvafiq səviyyəyə qaldır.

    FP FIX: AI legitimacy assessment mövcuddursa və domain legitim
    hesab edilirsə (high/medium confidence), relations siqnalı
    susdurilir — çünki legitim domenlərdə istifadəçilərin yüklədikləri
    fayllar relations-da malicious görünə bilər.

    Məntiq:
      - Votes ≥ 20 malicious            → minimum HIGH (65)
      - Votes ≥ 10                       → minimum MEDIUM (45)
      - Comments malicious ≥ 5           → +15
      - Relations malicious files ≥ 5    → minimum HIGH (65)  [legitim domenlərdə skip]
      - Votes + Comments + Relations     → minimum HIGH (65)
    """
    flags: list[str] = []

    votes     = getattr(rep, "vt_community_malicious_votes",   0)
    comments  = getattr(rep, "vt_community_malicious_comments", 0)
    relations = getattr(rep, "vt_malicious_files_related",       0)

    if votes == 0 and comments == 0 and relations == 0:
        return score, flags

    # ── Static Whitelist Gate (Ollama fallback) ───────────────────────
    # Extract root domain from the url parameter passed to compute_final_score.
    # ReputationResult does not store the queried domain, so we derive it here.
    try:
        import urllib.parse as _up
        _parsed = _up.urlparse(url if url.startswith("http") else "http://" + url)
        _host   = (_parsed.hostname or url).lower()
    except Exception:
        _host = url.lower()

    # ── Tri-path whitelist gate ──────────────────────────────────────
    #
    # PATH 1 — AZ_LEGIT (explicit whitelist: azal.az, kapitalbank.az…)
    #   → ALL signals suppressed. Score ceiling applied elsewhere.
    #
    # PATH 2 — AZ TLD tiering (.az / .gov.az domains NOT in explicit list)
    #   → _classify_az_domain() decides per signal profile:
    #     • AZ_SAFE    → all signals zeroed, treated as LEGIT
    #     • AZ_REVIEW  → only relations suppressed, votes/comments light-scored
    #     • AZ_SUSPECT → scored normally (community confirmed something bad)
    #
    # PATH 3 — INFRA domains (163.com, mail.ru…)
    #   → Relations suppressed only; votes+comments fully active
    #
    # PATH 4 — Unknown global domains
    #   → All signals fully scored; AI analysis applied
    #
    infra_only, infra_org = _check_infra_domain(_host)

    # Run AZ TLD classifier for all non-infra domains
    az_tier = "NOT_AZ"
    az_tier_reason = ""
    if not infra_only:
        az_tier, az_tier_reason = _classify_az_domain(_host, rep)

    # ── Apply gate decisions ──────────────────────────────────────────
    relations_suppressed      = False
    votes_comments_suppressed = False

    if az_tier == "AZ_SAFE":
        # PATH 2a: .az domain — completely clean, no signals at all
        votes_comments_suppressed = True
        relations_suppressed      = True
        flags.append(
            f"✅ AZ TLD SAFE: '{_host}' — {az_tier_reason} "
            f"VT=0, Abuse=0, votes=0, comments=0. "
            f"Treated as LEGIT — all community signals suppressed."
        )
        votes = comments = relations = 0

    elif az_tier == "AZ_REVIEW":
        # PATH 2b: .az domain — relations only, no votes/comments
        # Relations suppressed (user-uploaded .az docs: bank statements,
        # airline tickets, government forms uploaded to VirusTotal)
        relations_suppressed = True
        flags.append(
            f"⚠️ AZ TLD REVIEW: '{_host}' — {az_tier_reason} "
            f"Relations suppressed. Votes/comments scored lightly."
        )
        relations = 0

    elif az_tier == "AZ_SUSPECT":
        # PATH 2c: .az domain but community confirmed something bad
        # Score normally — do NOT suppress anything
        flags.append(
            f"🔴 AZ TLD SUSPECT: '{_host}' — {az_tier_reason} "
            f"Scoring as standard unknown domain."
        )
        # No suppression — fall through to normal scoring below

    elif infra_only:
        # PATH 3: Global infra domain — relations suppressed only
        relations_suppressed = True
        if relations > 0:
            flags.append(
                f"⚠️ INFRA DOMAIN: '{_host}' → {infra_org}. "
                f"VT relations suppressed ({relations} related files — user-uploaded samples). "
                f"Community votes ({votes}) and comments ({comments}) remain active."
            )
        relations = 0

    elif (
        legitimacy is not None
        and legitimacy.ran
        and legitimacy.is_legitimate
        and legitimacy.confidence in ("high", "medium")
    ):
        # PATH 4a: AI confirmed legit — suppress relations
        relations_suppressed = True
        if relations > 0:
            org = legitimacy.organization or "legitimate organization"
            flags.append(
                f"✅ AI LEGITIMACY OVERRIDE: Domain identified as {org} "
                f"({legitimacy.confidence} confidence) — "
                f"VT relations signal suppressed ({relations} related files ignored). "
                f"{legitimacy.relations_explained}"
            )
        relations = 0

    # PATH 4b: Unknown global domain — all signals active (no gate fires)

    # ── Early exit if everything zeroed ──────────────────────────────
    if votes == 0 and comments == 0 and relations == 0:
        return score, flags

    new_score = score
    triggered = []

    # ── Votes signal ─────────────────────────────────────────────────
    # AZ_SUSPECT: votes≥5 already triggered classifier → minimum HIGH (65)
    # Global/INFRA: votes≥5 → MEDIUM floor (35), votes≥10 → HIGH (45+)
    _az_suspect_active = (az_tier == "AZ_SUSPECT")

    if not votes_comments_suppressed:
        if votes >= 20:
            if new_score < 65:
                new_score = 65
            triggered.append(f"VT Community Votes: {votes} malicious")
            sig.score_adjustments.append(("VT Community Votes Override", new_score - score))
        elif votes >= 10:
            if new_score < 45:
                new_score = 45
            triggered.append(f"VT Community Votes: {votes} malicious")
            sig.score_adjustments.append(("VT Community Votes Override", new_score - score))
        elif votes >= 5:
            # AZ_SUSPECT: community confirmed malicious on a .az domain → HIGH floor
            _floor = 65 if _az_suspect_active else 35
            if new_score < _floor:
                new_score = _floor
            triggered.append(f"VT Community Votes: {votes} malicious")
            sig.score_adjustments.append(("VT Community Votes (AZ_SUSPECT→HIGH)" if _az_suspect_active else "VT Community Votes (medium)", new_score - score))

        # ── Comments signal ───────────────────────────────────────────
        if comments >= 5:
            comment_boost = 15
            new_score = min(new_score + comment_boost, 100)
            triggered.append(f"VT Community Comments: {comments} malicious")
            sig.score_adjustments.append(("VT Malicious Comments", comment_boost))
        elif comments >= 2:
            comment_boost = 8
            new_score = min(new_score + comment_boost, 100)
            triggered.append(f"VT Community Comments: {comments} malicious")
            sig.score_adjustments.append(("VT Malicious Comments", comment_boost))

        # ── INFRA + community convergence → AI flag needed ─────────────
        # 163.com scenario: votes≥5 + comments≥2 → mark for AI CRITICAL check
        if infra_only and votes >= 5 and comments >= 2:
            sig.score_adjustments.append(("INFRA Community Convergence", 0))
            triggered.append(
                f"INFRA domain with community convergence "
                f"(votes={votes}, comments={comments}) → AI analysis required"
            )
            # Ensure minimum HIGH for confirmed spam infra
            if new_score < 65:
                new_score = 65

    # ── Relations signal — only if not suppressed ─────────────────────
    if not relations_suppressed:
        if relations >= 5:
            if new_score < 65:
                new_score = 65
            triggered.append(f"VT Relations malicious files: {relations}")
            sig.score_adjustments.append(("VT Relations Override", new_score - score))
        elif relations >= 2:
            relation_boost = 10
            new_score = min(new_score + relation_boost, 100)
            triggered.append(f"VT Relations malicious files: {relations}")
            sig.score_adjustments.append(("VT Relations Boost", relation_boost))

        # Triple signal (votes + comments + relations) → HIGH floor
        orig_relations = getattr(rep, "vt_malicious_files_related", 0)
        if votes >= 5 and comments >= 1 and orig_relations >= 1:
            if new_score < 65:
                new_score = 65
                sig.score_adjustments.append(("VT Triple Signal Override", new_score - score))
            triggered.append("Triple VT signal (votes+comments+relations) → HIGH risk floor")

    if triggered:
        flags.append(
            f"⚠️ VT COMMUNITY OVERRIDE: {' | '.join(triggered)} "
            f"→ Score raised from {score} to {new_score}"
        )

    return new_score, flags



# ── Rule 2: Subdomain Trap ────────────────────────────────────────────────────

def _apply_subdomain_trap(
    hostname: str,
    domain_age_score: int,
    sig: BehavioralSignals,
) -> tuple[int, list[str]]:
    """FP FIX: Free hosting alone is NOT penalized. Only high-entropy or keyword-stuffed subdomains."""
    flags: list[str] = []
    is_free, platform = _is_free_hosting(hostname)

    if not is_free:
        return domain_age_score, flags

    sig.subdomain_trap_active = True

    parts  = hostname.split(".")
    n_plat = len(platform.split("."))
    subdom = ".".join(parts[: len(parts) - n_plat])

    entropy   = _shannon_entropy(subdom)
    sub_score = 0

    flags.append(f"Free-hosting platform '{platform}' detected — domain age signal suppressed.")

    if entropy > 3.5:
        sub_score += 20
        flags.append(f"High-entropy subdomain '{subdom}' (H={entropy:.2f}) — phishing kit indicator")
    elif entropy > 2.5:
        sub_score += 8
        flags.append(f"Moderate-entropy subdomain (H={entropy:.2f})")

    sub_lower = subdom.lower()
    found_kw  = [k for k in SQUATTING_KEYWORDS if k in sub_lower]
    if found_kw:
        sub_score += 12
        flags.append(f"Squatting keywords in subdomain: {', '.join(found_kw[:4])}")

    # FP FIX: No penalty if no suspicious signals
    if sub_score == 0:
        flags.append("Free hosting with clean subdomain — no penalty applied.")
        return 0, flags

    sig.score_adjustments.append(("Subdomain Trap", sub_score - domain_age_score))
    return sub_score, flags


# ── Rule 3: Brand Squatting ───────────────────────────────────────────────────

def _apply_brand_squatting(
    url: str,
    hostname: str,
    vt_malicious: int,
    sig: BehavioralSignals,
) -> tuple[int, list[str]]:
    """FP FIX: Requires 2+ keywords (was 1). Single keyword no longer triggers."""
    flags: list[str] = []
    root = _root_domain(hostname)

    if root in ENTERPRISE_WHITELIST:
        return 0, []

    # SECURITY FP FIX: Only scan HOSTNAME — not path/query
    # "confirm.legit.com/account" should NOT fire just because
    # path has "account" and hostname has "confirm"
    # Squatting keywords must appear in the HOSTNAME portion
    try:
        import urllib.parse as _sq_up
        _sq_parsed = _sq_up.urlparse(url if url.startswith("http") else "http://" + url)
        _sq_host = (_sq_parsed.hostname or "").lower()
    except Exception:
        _sq_host = hostname.lower()

    found = [k for k in SQUATTING_KEYWORDS if k in _sq_host]

    # FP FIX: 2+ keywords required IN HOSTNAME
    if len(found) >= 2:
        sig.brand_squatting = True
        sig.score_adjustments.append(("Brand Squatting", SQUATTING_PENALTY))
        flags.append(
            f"BRAND SQUATTING: {len(found)} keywords ({', '.join(found[:5])}) "
            f"in non-whitelisted domain '{root}' → +{SQUATTING_PENALTY}"
        )
        return SQUATTING_PENALTY, flags

    return 0, []


# ── Rule 4: Weighted Confidence ───────────────────────────────────────────────

def _apply_weighted_confidence(sandbox_score: int, ai_score: int) -> tuple[int, int]:
    return (
        min(int(sandbox_score * SANDBOX_WEIGHT), 40),
        min(int(ai_score * AI_NLP_WEIGHT), 25),
    )


# ── Confidence Scorer ────────────────────────────────────────────────────────

def _calculate_confidence(
    vt_malicious: int,
    vt_total: int,
    abuse_confidence: int,
    engines_triggered: int,
    sig: BehavioralSignals,
) -> int:
    base = 35
    if vt_total > 0:
        consensus = (vt_malicious / vt_total) * 100
        base += 20 if consensus >= 30 else (10 if consensus >= 10 else 0)
    if abuse_confidence >= 50:
        base += 15
    elif abuse_confidence >= 20:
        base += 8
    if engines_triggered >= 5:
        base += 15
    elif engines_triggered >= 3:
        base += 10
    elif engines_triggered >= 2:
        base += 5
    if sig.infrastructure_override:
        base += 10
    if sig.brand_squatting:
        base += 5
    return min(base, 100)


# ── Signal Builder ───────────────────────────────────────────────────────────

def build_behavioral_signals(
    url:  str,
    h:    "HeuristicsResult",
    w:    "WhoisResult",
    ai:   "AIAnalysisResult",
    rep:  "ReputationResult",
    dec:  "DeceptionResult",
    sb:   "SandboxResult",
    ssl:  "SSLResult | None"        = None,
    pdns: "PassiveDNSResult | None" = None,
) -> BehavioralSignals:
    sig = BehavioralSignals()

    sig.urgency          = ai.urgency_detected
    sig.financial_threat = ai.financial_threat_detected
    sig.manipulation     = ai.manipulation_detected

    sig.credential_harvest = (
        sb.credential_harvesting
        or (dec.typosquat_target is not None and dec.score >= 15)
        or any("password" in f.lower() or "credential" in f.lower()
               for f in sb.flags + dec.flags)
    )

    sig.fake_login_page = (
        sb.fake_login_page
        or (dec.typosquat_target is not None and sb.suspicious_forms >= 1)
        or any("fake" in f.lower() or "login" in f.lower() or "brand" in f.lower()
               for f in sb.flags)
    )

    vt_malware_cats = {"malware", "trojan", "ransomware", "exploit", "backdoor", "virus"}
    sig.malware_dropper = (
        sb.malware_distribution
        or bool(vt_malware_cats & {c.lower() for c in rep.vt_categories})
        or any("malware" in f.lower() or "obfuscat" in f.lower() or "eval(" in f.lower()
               for f in sb.flags)
    )

    sig.crypto_drainer = (
        sb.crypto_drainer
        or any("crypto" in f.lower() or "wallet" in f.lower() or "drainer" in f.lower()
               for f in sb.flags + rep.flags)
    )

    sig.tech_support_scam = (
        sb.tech_support_scam
        or any("tech support" in f.lower() or "toll-free" in f.lower()
               for f in sb.flags + ai.flags)
    )

    sig.tor_exit_node = rep.is_tor or (pdns.is_tor if pdns else False)
    sig.vpn_detected  = getattr(rep, "is_vpn", False) or (pdns.is_vpn if pdns else False)
    # FP FIX: raised from 50 to 65
    sig.high_abuse_ip = rep.abuse_confidence >= 65

    if ssl:
        sig.free_ca_young_domain = (
            "FREE_CA_YOUNG_DOMAIN" in ssl.iocs or "FREE_CA_NEW_DOMAIN" in ssl.iocs
        )
        sig.cert_invalid = ssl.is_self_signed or ssl.hostname_mismatch or ssl.is_expired

    return sig


# ── Master Scorer ─────────────────────────────────────────────────────────────

def compute_final_score(
    url:  str,
    h:    "HeuristicsResult",
    w:    "WhoisResult",
    ai:   "AIAnalysisResult",
    rep:  "ReputationResult",
    dec:  "DeceptionResult",
    sb:   "SandboxResult",
    ssl:  Optional["SSLResult"]               = None,
    pdns: Optional["PassiveDNSResult"]         = None,
    sig:  Optional[BehavioralSignals]          = None,
    legitimacy: Optional["DomainLegitimacyResult"] = None,
) -> tuple[int, BehavioralSignals, list[str]]:
    """
    Compute final risk score with all override rules applied.
    Returns: (final_score_0_100, behavioral_signals, extra_rule_flags)
    """
    if sig is None:
        sig = build_behavioral_signals(url, h, w, ai, rep, dec, sb, ssl, pdns)

    extra_flags: list[str] = []

    try:
        hostname = urllib.parse.urlparse(
            url if url.startswith("http") else "http://" + url
        ).hostname or ""
    except Exception:
        hostname = ""

    # Apply weighted confidence (Rule 4 first)
    adj_sb_score, adj_ai_score = _apply_weighted_confidence(sb.score, ai.score)

    # Apply subdomain trap (Rule 2)
    whois_score, trap_flags = _apply_subdomain_trap(hostname, w.score, sig)
    extra_flags.extend(trap_flags)

    # Base aggregate
    ssl_score  = (ssl.score  if ssl  else 0)
    pdns_score = (pdns.score if pdns else 0)

    raw_base = (
        h.score + whois_score + adj_ai_score + rep.score
        + dec.score + adj_sb_score + ssl_score + pdns_score
    )

    # Apply brand squatting penalty (Rule 3)
    sq_penalty, sq_flags = _apply_brand_squatting(url, hostname, rep.vt_malicious, sig)
    raw_base += sq_penalty
    extra_flags.extend(sq_flags)

    # Normalize to prevent score inflation
    normalized = int(raw_base / SCORE_NORMALIZATION_FACTOR)
    score = max(0, min(normalized, 100))

    # Apply infrastructure override (Rule 1 — absolute, always last)
    score, override_flags = _apply_infra_override(
        score, rep.vt_malicious, rep.abuse_confidence, sig
    )
    extra_flags.extend(override_flags)

    # Apply VT community signals override (Rule 1b — votes/comments/relations)
    score, community_flags = _apply_vt_community_override(score, rep, sig, legitimacy, url)
    extra_flags.extend(community_flags)

    # ── Rule 5: AZ Domain Score Ceiling ─────────────────────────────────────
    # Applied to THREE categories (in priority order):
    #
    #   5a. AZ_LEGIT (explicit whitelist)  → ceiling 19 (LOW)
    #   5b. AZ TLD — AZ_SAFE tier          → ceiling 19 (LOW)
    #   5c. AZ TLD — AZ_REVIEW tier        → ceiling 35 (low MEDIUM)
    #       (not fully clean, but relations-only on .az docs)
    #   5d. AZ TLD — AZ_SUSPECT            → NO ceiling (normal scoring)
    #   5e. INFRA / global domains          → NO ceiling
    #
    # Ceiling only applied when: VT=0 AND Abuse<30 AND no infra_override
    _wl_host = hostname.lower() if hostname else ""

    # AZ TLD tier — regex-based, no explicit list needed
    _az_tier_final, _ = _classify_az_domain(_wl_host, rep)

    _clean_conditions = (
        not sig.infrastructure_override
        and rep.vt_malicious == 0
        and rep.abuse_confidence < 30
    )

    if _clean_conditions:
        if _az_tier_final == "AZ_SAFE":
            # .az domain — completely clean → LOW/SAFE ceiling
            _ceiling = 19
            if score > _ceiling:
                extra_flags.append(
                    f"✅ AZ TLD SAFE CEILING: '{_wl_host}'. "
                    f"VT=0, Abuse=0, no community signals. "
                    f"Score capped {score} → {_ceiling} (SAFE/LOW). "
                    f".az domain with no malicious indicators."
                )
                score = _ceiling

        elif _az_tier_final == "AZ_REVIEW":
            # .az domain — relations only → soft ceiling (below MEDIUM)
            _ceiling = 35
            if score > _ceiling:
                extra_flags.append(
                    f"⚠️ AZ TLD REVIEW CEILING: '{_wl_host}'. "
                    f"VT=0, Abuse=0, VT relations only (no votes/comments). "
                    f"Score capped {score} → {_ceiling}. "
                    f".az domain relations likely user-uploaded documents."
                )
                score = _ceiling

    # Calculate overall confidence
    engines_triggered = sum([
        h.score >= 15, w.score >= 10, ai.score >= 10,
        rep.score >= 10, dec.score >= 10, sb.score >= 10,
        (ssl.score >= 10 if ssl else False),
        (pdns.score >= 10 if pdns else False),
    ])
    sig.overall_confidence = _calculate_confidence(
        rep.vt_malicious, rep.vt_total_engines,
        rep.abuse_confidence, engines_triggered, sig,
    )

    # ── Rule 6: VT detections + newly registered domain → MEDIUM floor ──────
    # If VT flags ≥3 engines AND domain is newly registered (WHOIS score≥30),
    # the combination is too suspicious to stay at LOW.
    # Normalization can push raw score below 40 even with strong signals.
    # FIX v7: apply minimum 40 (MEDIUM entry) for this confirmed combo.
    _whois_score = getattr(w, "score", 0)
    if rep.vt_malicious >= 3 and _whois_score >= 30 and score < 40:
        extra_flags.append(
            f"⚠️ Score Floor: VT {rep.vt_malicious} detections + newly registered domain "
            f"(WHOIS={_whois_score}/40) → minimum MEDIUM (40)"
        )
        score = 40
        sig.score_adjustments.append(("VT+NewDomain Floor", 40 - normalized))

    # ── Rule 7: VT ≥3 alone → minimum LOW-HIGH floor (35) ───────────────────
    # Even without WHOIS signal: 3+ VT engines should never score below 35.
    elif rep.vt_malicious >= 3 and score < 35:
        extra_flags.append(
            f"⚠️ Score Floor: VT {rep.vt_malicious} engine detections → minimum 35"
        )
        score = 35
        sig.score_adjustments.append(("VT Detection Floor", 35 - normalized))

    return score, sig, extra_flags
