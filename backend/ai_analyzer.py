import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

import logging
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ollama client helper
# ---------------------------------------------------------------------------

def _get_ollama_client():
    """
    Return an ollama.Client pointed at the correct host.
    Compatible with both old (<=0.4.x) and new (>=0.5.x) ollama library versions.
    - v0.5+: timeout is accepted by Client.__init__()
    - v0.4.x: timeout is not supported at all — silently ignored via try/except
    """
    import ollama  # type: ignore
    host = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    try:
        return ollama.Client(host=host, timeout=60)
    except TypeError:
        # Older ollama library version — does not support timeout kwarg
        return ollama.Client(host=host)


def _get_ollama_base_url() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")


def _get_installed_models() -> list[str]:
    """
    Query Ollama /api/tags to get actually-installed models.
    Returns empty list if Ollama is not running or not reachable.
    Never raises.
    """
    try:
        import requests
        url = f"{_get_ollama_base_url()}/api/tags"
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            models = [m["name"] for m in data.get("models", [])]
            logger.debug("Ollama installed models: %s", models)
            return models
    except Exception as exc:
        logger.debug("Cannot reach Ollama /api/tags: %s", exc)
    return []


def _resolve_models(preferred: Optional[str] = None) -> list[str]:
    """
    Build ordered list of models to try:
      1. If preferred model given → try it first
      2. Installed models (from /api/tags) that match known good names
      3. Full fallback list (for environments where tags endpoint is blocked)
    Never returns empty list.
    """
    KNOWN_GOOD = [
        "phi3:mini", "phi3", "phi3:medium",
        "llama3.2", "llama3.2:latest", "llama3", "llama3:latest",
        "llama3.1", "llama3.1:latest",
        "mistral", "mistral:latest",
        "gemma2:2b", "gemma2", "gemma:2b",
        "qwen2:1.5b", "qwen2",
        "tinyllama", "tinyllama:latest",
    ]

    installed = _get_installed_models()
    ordered: list[str] = []

    if preferred and preferred not in ordered:
        ordered.append(preferred)

    # Prefer installed models in KNOWN_GOOD order
    for name in KNOWN_GOOD:
        if name in installed and name not in ordered:
            ordered.append(name)

    # Add any other installed models not in KNOWN_GOOD
    for name in installed:
        if name not in ordered:
            ordered.append(name)

    # Fallback: add KNOWN_GOOD even if not confirmed installed
    # (useful when tags endpoint is unreachable but Ollama is actually running)
    for name in KNOWN_GOOD:
        if name not in ordered:
            ordered.append(name)

    return ordered


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AIAnalysisResult:
    """Structured result returned by the AI NLP engine."""
    score: int = 0
    urgency_detected: bool = False
    financial_threat_detected: bool = False
    manipulation_detected: bool = False
    summary: str = ""
    raw_response: str = ""
    flags: list[str] = field(default_factory=list)
    error: Optional[str] = None
    model_used: Optional[str] = None   # NEW: which model succeeded


# ---------------------------------------------------------------------------
# Prompt engineering
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a cybersecurity analyst specialising in phishing and
social-engineering detection.  Analyse the text or URL provided by the user and
identify the following social-engineering signals:

1. URGENCY — language that pressures the recipient to act immediately
   (e.g. "your account will be suspended", "act within 24 hours").

2. FINANCIAL_THREAT — references to money loss, unpaid bills, tax debts,
   prize winnings, or financial account problems.

3. MANIPULATION — psychological tactics such as impersonating authority
   figures, creating fear, false scarcity, or appeals to trust.

Respond ONLY with a valid JSON object — no markdown, no extra text — in
exactly this schema:

{
  "urgency": true | false,
  "financial_threat": true | false,
  "manipulation": true | false,
  "summary": "<one concise sentence explaining your overall assessment>"
}"""


USER_PROMPT_TEMPLATE = """Analyse this content for phishing / social-engineering signals:

---
{content}
---

Remember: respond ONLY with the JSON object."""


# ---------------------------------------------------------------------------
# Domain Legitimacy Analyzer
# ---------------------------------------------------------------------------

DOMAIN_LEGITIMACY_SYSTEM = """You are a senior threat intelligence analyst specialising in
distinguishing legitimate domains from malicious infrastructure.

You will receive a structured summary of a domain's reputation data. Your task is to decide
whether this domain is a LEGITIMATE organization's domain or MALICIOUS/SUSPICIOUS infrastructure.

Key principles:
- A domain with 0 engine detections on VirusTotal is NOT automatically safe.
- A well-known company, government entity, airline, bank, or public service domain is almost
  always legitimate even if related files are flagged.
- Regional/national domains (.az, .gov.az, .com.az) for known local organizations are legitimate.
- Evaluate the COMBINATION of signals, not individual ones in isolation.
- URLhaus (abuse.ch) is a HIGH-CONFIDENCE malware database. If URLhaus shows MALICIOUS,
  the domain has ACTIVELY hosted malware payloads — this STRONGLY indicates malicious infrastructure.
  Do NOT declare a domain legitimate if URLhaus marks it as malicious.
- OTX AlienVault pulses > 0 means the threat community has flagged this domain.
- Overall threat score > 50 with URLhaus or OTX signals = very likely malicious.

Respond ONLY with this exact JSON (no markdown, no extra text):
{
  "is_legitimate": true | false,
  "confidence": "high" | "medium" | "low",
  "organization": "<name of the organization or null>",
  "reasoning": "<one sentence explaining your decision>",
  "relations_explained": "<one sentence about VT relations signal>"
}"""


@dataclass
class DomainLegitimacyResult:
    """Result of AI-based domain legitimacy assessment."""
    is_legitimate:      bool          = False
    confidence:         str           = "low"
    organization:       Optional[str] = None
    reasoning:          str           = ""
    relations_explained: str          = ""
    ran:                bool          = False
    error:              Optional[str] = None


def assess_domain_legitimacy(
    domain:           str,
    vt_malicious:     int,
    vt_total:         int,
    vt_relations_mal: int,
    abuse_confidence: int,
    domain_age_days:  Optional[int],
    popularity_rank:  Optional[int],
    vt_categories:    list[str],
    model:            Optional[str] = None,
    # FIX v7: additional threat signals — URLhaus, OTX, SSL
    urlhaus_score:    int = 0,
    urlhaus_flags:    Optional[list] = None,
    otx_pulses:       int = 0,
    ssl_score:        int = 0,
    final_score:      int = 0,
) -> DomainLegitimacyResult:
    """
    Ask the local LLM whether a domain is legitimate given all available signals.
    Returns DomainLegitimacyResult. If Ollama is unavailable, returns ran=False.

    FIX v7: Now includes URLhaus, OTX, SSL signals in context so the AI cannot
    declare a domain 'legitimate' while URLhaus shows it as a malware host.
    Also applies hard rule: if urlhaus_score > 0 AND is_legitimate → override to False.
    """
    result = DomainLegitimacyResult()

    age_str  = f"{domain_age_days} days old" if domain_age_days is not None else "unknown age"
    rank_str = f"#{popularity_rank}" if popularity_rank else "not ranked"
    cats_str = ", ".join(vt_categories) if vt_categories else "none"

    # Build URLhaus context string
    urlhaus_context = "No data"
    if urlhaus_score > 0:
        uh_flags_str = "; ".join((urlhaus_flags or [])[:3])
        urlhaus_context = f"MALICIOUS — score contribution: {urlhaus_score} pts. Flags: {uh_flags_str}"
    elif urlhaus_flags is not None:
        urlhaus_context = "Checked — not found in malware database"

    context = f"""Domain: {domain}

VirusTotal engine detections: {vt_malicious} / {vt_total} engines flagged as malicious
VirusTotal related malicious files: {vt_relations_mal} files linked to this domain
VirusTotal categories assigned: {cats_str}
AbuseIPDB confidence score: {abuse_confidence}%
Domain age: {age_str}
Popularity rank: {rank_str}
URLhaus (abuse.ch malware DB): {urlhaus_context}
OTX AlienVault threat pulses: {otx_pulses} pulses
SSL/TLS risk score: {ssl_score}/50
Overall threat score: {final_score}/100"""

    try:
        client = _get_ollama_client()
    except ImportError:
        result.error = "ollama not installed — pip install ollama"
        return result

    models_to_try = _resolve_models(model)
    messages = [
        {"role": "system", "content": DOMAIN_LEGITIMACY_SYSTEM},
        {"role": "user",   "content": context},
    ]

    for candidate in models_to_try[:6]:   # try up to 6 models
        try:
            response = client.chat(
                model=candidate,
                messages=messages,
                options={"temperature": 0.05, "num_predict": 300},
            )
            raw = response["message"]["content"]
            cleaned = re.sub(r"```(?:json)?", "", raw).strip()
            m = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if not m:
                continue
            parsed = json.loads(m.group())

            result.is_legitimate      = bool(parsed.get("is_legitimate", False))
            result.confidence         = str(parsed.get("confidence", "low"))
            result.organization       = parsed.get("organization") or None
            result.reasoning          = str(parsed.get("reasoning", ""))
            result.relations_explained = str(parsed.get("relations_explained", ""))
            result.ran                = True

            # ── HARD OVERRIDE: URLhaus or high threat score → never legitimate ──
            # FIX v7: LLM may still declare legitimate based on VT/AbuseIPDB alone.
            # If URLhaus confirmed malware hosting OR overall score is HIGH,
            # force is_legitimate=False regardless of LLM decision.
            if result.is_legitimate:
                if urlhaus_score > 0:
                    result.is_legitimate = False
                    result.confidence    = "high"
                    result.reasoning     = (
                        f"Override: URLhaus (abuse.ch) confirmed malware hosting "
                        f"(score +{urlhaus_score}) — domain cannot be considered legitimate."
                    )
                elif otx_pulses >= 3 and vt_malicious >= 1:
                    result.is_legitimate = False
                    result.confidence    = "medium"
                    result.reasoning     = (
                        f"Override: OTX {otx_pulses} threat pulses combined with "
                        f"VT {vt_malicious} detections — insufficient evidence of legitimacy."
                    )
                elif final_score >= 70 and vt_malicious >= 3:
                    result.is_legitimate = False
                    result.confidence    = "medium"
                    result.reasoning     = (
                        f"Override: Threat score {final_score}/100 with {vt_malicious} VT "
                        f"detections — high-confidence malicious assessment."
                    )

            return result

        except Exception as exc:
            err_str = str(exc)
            if "connection" in err_str.lower() or "refused" in err_str.lower():
                # Ollama not running — no point trying more models
                result.error = (
                    "Ollama not running. Start it: `ollama serve` "
                    "and pull a model: `ollama pull phi3:mini`"
                )
                return result
            logger.debug("Legitimacy model '%s' failed: %s", candidate, exc)
            continue

    result.error = (
        "All Ollama models failed — ensure Ollama is running: `ollama serve` "
        "and at least one model is pulled: `ollama pull phi3:mini`"
    )
    return result


# ---------------------------------------------------------------------------
# Ollama interaction
# ---------------------------------------------------------------------------

# Legacy constant kept for backward-compat imports
DEFAULT_MODELS = [
    "phi3:mini", "phi3", "llama3.2", "llama3", "mistral",
    "gemma2:2b", "tinyllama",
]


def _build_messages(content: str) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": USER_PROMPT_TEMPLATE.format(content=content)},
    ]


def _parse_llm_json(raw: str) -> Optional[dict]:
    """Robustly extract JSON from model response."""
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


def _score_from_parsed(parsed: dict) -> tuple[int, list[str]]:
    score = 0
    flags = []
    if parsed.get("urgency"):
        score += 15
        flags.append("AI detected urgency language (pressure tactics)")
    if parsed.get("financial_threat"):
        score += 10
        flags.append("AI detected financial threat / lure")
    if parsed.get("manipulation"):
        score += 5
        flags.append("AI detected psychological manipulation tactics")
    return min(score, 30), flags


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_text(
    content: str,
    model: Optional[str] = None,
) -> AIAnalysisResult:
    """
    Send content to local Ollama LLM for phishing signal analysis.

    Dynamically resolves installed models first, then falls through
    full fallback list. Timeout per model is 15s so the chain is fast.
    """
    result = AIAnalysisResult()

    try:
        client = _get_ollama_client()
    except ImportError:
        result.error = "ollama Python library not installed — run: pip install ollama"
        result.flags.append("Ollama library unavailable")
        return result

    messages = _build_messages(content)
    models_to_try = _resolve_models(model)

    last_error: Optional[str] = None
    ollama_reachable = False

    for candidate_model in models_to_try[:8]:   # max 8 attempts
        try:
            response = client.chat(
                model=candidate_model,
                messages=messages,
                options={
                    "temperature": 0.1,
                    "num_predict": 256,
                },
            )
            ollama_reachable = True
            raw_text: str = response["message"]["content"]
            result.raw_response = raw_text

            parsed = _parse_llm_json(raw_text)
            if parsed is None:
                last_error = f"Model '{candidate_model}' returned non-parseable output"
                logger.debug(last_error)
                continue

            result.urgency_detected          = bool(parsed.get("urgency", False))
            result.financial_threat_detected = bool(parsed.get("financial_threat", False))
            result.manipulation_detected     = bool(parsed.get("manipulation", False))
            result.summary                   = str(parsed.get("summary", "No summary."))
            result.score, result.flags       = _score_from_parsed(parsed)
            result.model_used                = candidate_model

            if not result.flags:
                result.flags.append("AI found no significant social-engineering signals")

            logger.info("AI analysis completed with model: %s", candidate_model)
            return result

        except Exception as exc:
            err_str = str(exc)
            # Check if this is a "model not found" error vs connectivity error
            if "model" in err_str.lower() and (
                "not found" in err_str.lower() or "pull" in err_str.lower()
            ):
                # Model not installed — try next silently
                logger.debug("Model '%s' not installed, trying next", candidate_model)
                last_error = f"Model '{candidate_model}' not installed"
            elif "connection" in err_str.lower() or "refused" in err_str.lower():
                # Ollama not running — no point trying more models
                result.error = (
                    "Ollama not running. Start it with: `ollama serve`\n"
                    "Then pull a model: `ollama pull phi3:mini`"
                )
                # Flag removed: error shown as caption in engine_card, flag would duplicate it
                result.score = 0
                return result
            else:
                last_error = f"Model '{candidate_model}' error: {err_str[:80]}"
                logger.debug(last_error)
            continue

    # All models failed
    if not ollama_reachable:
        result.error = (
            "Cannot reach Ollama. Start it: `ollama serve` "
            "and pull a model: `ollama pull phi3:mini` (heuristics only)"
        )
        # Flag removed: error shown as friendly caption, flag would duplicate it
    else:
        result.error = (
            f"No compatible model found. Pull one: `ollama pull phi3:mini`\n"
            f"Last error: {last_error}"
        )
        result.flags.append(
            "⚠ No compatible Ollama model — pull one: `ollama pull phi3:mini`"
        )

    result.score = 0
    return result


# ── Hybrid Analysis AI Summary ────────────────────────────────────────────────

@dataclass
class HASummaryResult:
    """AI-generated summary for Hybrid Analysis sandbox results."""
    summary: str = ""
    threat_narrative: str = ""
    recommended_actions: list[str] = field(default_factory=list)
    confidence: str = "low"
    error: Optional[str] = None


def generate_ha_ai_summary(ha_result, model: str = "phi3:mini") -> HASummaryResult:
    """
    Generate an AI narrative summary from Hybrid Analysis sandbox results.
    Uses Ollama locally — no data sent to external AI APIs.
    """
    try:
        client = _get_ollama_client()
    except ImportError:
        r = HASummaryResult()
        r.error = "Ollama library not installed"
        return r

    out = HASummaryResult()

    flags_text     = "\n".join(ha_result.flags[:15])      if ha_result.flags          else "None"
    iocs_text      = "\n".join(ha_result.iocs[:10])       if ha_result.iocs           else "None"
    sigs_text      = "\n".join(ha_result.signatures[:10]) if ha_result.signatures     else "None"
    mitre_text     = "\n".join(
        f"{m.get('tactic','?')} / {m.get('technique','?')} — {m.get('name','?')}"
        for m in ha_result.mitre_attcks[:8]
    ) if ha_result.mitre_attcks else "None"
    net_hosts_text = ", ".join(ha_result.contacted_hosts[:8]) if ha_result.contacted_hosts else "None"
    av_text        = "\n".join(
        f"{d['engine']}: {d['result']}"
        for d in ha_result.av_detections[:6]
    ) if ha_result.av_detections else "None"

    context = f"""
HYBRID ANALYSIS SANDBOX REPORT SUMMARY
=======================================
Verdict      : {ha_result.verdict.upper()}
Threat Score : {ha_result.threat_score or 'N/A'} / 100
AV Detection : {ha_result.av_detect}%
Malware Family: {ha_result.vx_family or 'Unknown'}
Environment  : {ha_result.environment}

BEHAVIORAL FLAGS:
{flags_text}

INDICATORS OF COMPROMISE:
{iocs_text}

BEHAVIORAL SIGNATURES:
{sigs_text}

MITRE ATT&CK TECHNIQUES:
{mitre_text}

NETWORK CONTACTS:
{net_hosts_text}

AV DETECTIONS:
{av_text}
""".strip()

    system_prompt = """You are a senior SOC analyst and threat intelligence expert.
You will receive a structured Hybrid Analysis sandbox report.
Respond ONLY with valid JSON — no markdown, no code fences, no extra text:
{
  "summary": "<2-3 sentence executive summary>",
  "threat_narrative": "<detailed technical narrative 3-5 sentences>",
  "recommended_actions": ["<action 1>", "<action 2>", "<action 3>", "<action 4>"],
  "confidence": "high" | "medium" | "low"
}"""

    user_prompt = f"Analyse this sandbox report:\n\n{context}"
    models_to_try = _resolve_models(model)

    for candidate in models_to_try[:6]:
        try:
            response = client.chat(
                model=candidate,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                options={"temperature": 0.2, "num_predict": 512},
            )
            raw = response["message"]["content"]
            parsed = _parse_llm_json(raw)
            if parsed is None:
                continue

            out.summary             = str(parsed.get("summary", ""))[:600]
            out.threat_narrative    = str(parsed.get("threat_narrative", ""))[:800]
            out.recommended_actions = [str(a)[:200] for a in (parsed.get("recommended_actions") or [])[:6]]
            out.confidence          = str(parsed.get("confidence", "low"))
            return out

        except Exception as exc:
            err_str = str(exc)
            if "connection" in err_str.lower() or "refused" in err_str.lower():
                out.error = "Ollama not running — start with: `ollama serve`"
                return out
            out.error = err_str[:120]
            continue

    if not out.summary:
        out.error = out.error or "All models failed to generate summary"
    return out
