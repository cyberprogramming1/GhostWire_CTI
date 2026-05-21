"""
utils/ai_analyzer.py
--------------------
AI NLP Engine for GhostWire CTI Local.

Sends the user-supplied text / URL to a locally running Ollama LLM
(Llama 3 or Phi-3) and asks it to detect social-engineering signals:
urgency, financial threats, and manipulation tactics.

The model is prompted to respond with structured JSON so results can
be parsed deterministically without brittle regex matching.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional

import logging
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AIAnalysisResult:
    """Structured result returned by the AI NLP engine."""
    score: int = 0                          # Risk contribution (0–30)
    urgency_detected: bool = False
    financial_threat_detected: bool = False
    manipulation_detected: bool = False
    summary: str = ""                       # One-sentence model explanation
    raw_response: str = ""                  # Full model output for debugging
    flags: list[str] = field(default_factory=list)
    error: Optional[str] = None


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
- A domain with 0 engine detections on VirusTotal is NOT automatically safe — phishing domains
  often evade detection engines.
- A domain with 0 detections but malicious RELATED FILES may be legitimate — files uploaded BY
  USERS of that service (e.g. airline, bank, gov site) frequently appear in VT relations.
- A well-known company, government entity, airline, bank, or public service domain is almost
  always legitimate even if related files are flagged.
- Regional/national domains (.az, .gov.az, .com.az) for known local organizations are legitimate.
- Evaluate the COMBINATION of signals, not individual ones in isolation.

Respond ONLY with this exact JSON (no markdown, no extra text):
{
  "is_legitimate": true | false,
  "confidence": "high" | "medium" | "low",
  "organization": "<name of the organization this domain belongs to, or null if unknown>",
  "reasoning": "<one sentence explaining your decision>",
  "relations_explained": "<one sentence explaining why the VT relations signal should or should not be trusted>"
}"""


@dataclass
class DomainLegitimacyResult:
    """Result of AI-based domain legitimacy assessment."""
    is_legitimate:      bool          = False
    confidence:         str           = "low"   # high / medium / low
    organization:       Optional[str] = None
    reasoning:          str           = ""
    relations_explained: str          = ""
    ran:                bool          = False    # True if AI actually ran
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
) -> DomainLegitimacyResult:
    """
    Ask the local LLM whether a domain is legitimate given all available signals.
    Called AFTER all reputation engines finish — AI sees the full picture.

    Returns DomainLegitimacyResult. If Ollama is unavailable, returns
    ran=False so callers can skip the legitimacy gate.
    """
    result = DomainLegitimacyResult()

    # Build a structured context string for the model
    age_str  = f"{domain_age_days} days old" if domain_age_days is not None else "unknown age"
    rank_str = f"#{popularity_rank}" if popularity_rank else "not ranked (unknown/low-traffic)"
    cats_str = ", ".join(vt_categories) if vt_categories else "none"

    context = f"""Domain: {domain}

VirusTotal engine detections: {vt_malicious} / {vt_total} engines flagged as malicious
VirusTotal related malicious files: {vt_relations_mal} files linked to this domain
VirusTotal categories assigned: {cats_str}
AbuseIPDB confidence score: {abuse_confidence}%
Domain age: {age_str}
Popularity rank: {rank_str}

Note: "related malicious files" means files that communicate with or were downloaded from
this domain — they may be malware samples uploaded by users of a legitimate service,
or actual malware hosted by a malicious domain. Context matters."""

    try:
        import ollama  # type: ignore
    except ImportError:
        result.error = "ollama not installed"
        return result

    models_to_try = [model] if model else DEFAULT_MODELS
    messages = [
        {"role": "system", "content": DOMAIN_LEGITIMACY_SYSTEM},
        {"role": "user",   "content": context},
    ]

    for candidate in models_to_try:
        try:
            response = ollama.chat(
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
            return result

        except Exception:
            continue

    result.error = "All Ollama models failed for legitimacy check"
    return result


# ---------------------------------------------------------------------------
# Ollama interaction
# ---------------------------------------------------------------------------

# Models to try in preference order (user can override via function arg)
DEFAULT_MODELS = ["llama3", "llama3.2", "phi3", "phi3:mini", "mistral"]


def _build_messages(content: str) -> list[dict]:
    """Construct the messages array for the Ollama chat API."""
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": USER_PROMPT_TEMPLATE.format(content=content)},
    ]


def _parse_llm_json(raw: str) -> Optional[dict]:
    """
    Robustly extract the JSON object from the model response.
    Handles cases where the model wraps output in markdown fences despite
    being told not to.
    """
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()

    # Find the first {...} block
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return None

    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return None


def _score_from_parsed(parsed: dict) -> tuple[int, list[str]]:
    """
    Convert the parsed JSON flags into a numeric risk score.

    Scoring:
        Urgency detected        → +15 pts
        Financial threat        → +10 pts
        Manipulation detected   → +5 pts
        Maximum contribution    → 30 pts
    """
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
    Send ``content`` to a local Ollama LLM for phishing signal analysis.

    The function tries each model in ``DEFAULT_MODELS`` (or the caller-
    supplied ``model``) until one succeeds, enabling graceful fallback
    across different Ollama installations.

    Args:
        content: The URL, email body, or message text to analyse.
        model:   Override the default model selection.

    Returns:
        AIAnalysisResult with score, individual flags, and a plain-English
        summary from the LLM.
    """
    try:
        import ollama  # type: ignore
    except ImportError:
        result = AIAnalysisResult()
        result.error = "ollama Python library not installed — skipping AI analysis"
        result.flags.append("Ollama library unavailable")
        return result

    result = AIAnalysisResult()
    messages = _build_messages(content)
    models_to_try = [model] if model else DEFAULT_MODELS

    last_error: Optional[str] = None

    for candidate_model in models_to_try:
        try:
            response = ollama.chat(
                model=candidate_model,
                messages=messages,
                options={
                    "temperature": 0.1,   # Low temp → deterministic JSON output
                    "num_predict": 256,   # Limit tokens; we only need a small JSON blob
                },
            )

            raw_text: str = response["message"]["content"]
            result.raw_response = raw_text

            parsed = _parse_llm_json(raw_text)

            if parsed is None:
                last_error = f"Model '{candidate_model}' returned non-parseable output"
                continue  # Try next model

            # Successful parse — populate result
            result.urgency_detected          = bool(parsed.get("urgency", False))
            result.financial_threat_detected = bool(parsed.get("financial_threat", False))
            result.manipulation_detected     = bool(parsed.get("manipulation", False))
            result.summary                   = str(parsed.get("summary", "No summary provided."))

            result.score, result.flags = _score_from_parsed(parsed)

            if not result.flags:
                result.flags.append("AI found no significant social-engineering signals")

            return result  # Success — exit loop

        except ollama.ResponseError as exc:
            # Model not pulled yet or Ollama server error
            last_error = f"Ollama error with model '{candidate_model}': {exc}"
            continue

        except Exception as exc:
            last_error = f"Unexpected error with model '{candidate_model}': {exc}"
            continue

    # All models failed
    result.error = last_error or "All Ollama models failed"
    result.flags.append("AI analysis could not complete — check Ollama is running")
    result.score = 0  # Don't penalise if we simply can't reach the model
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

    Parameters
    ----------
    ha_result : HAResult
        The parsed sandbox result object.
    model : str
        Ollama model name to use.

    Returns
    -------
    HASummaryResult with narrative, threat assessment, and recommended actions.
    """
    try:
        import ollama
    except ImportError:
        r = HASummaryResult()
        r.error = "Ollama library not installed"
        return r

    out = HASummaryResult()

    # Build a structured context block from HA results
    flags_text      = "\n".join(ha_result.flags[:15])         if ha_result.flags          else "None"
    iocs_text       = "\n".join(ha_result.iocs[:10])          if ha_result.iocs           else "None"
    sigs_text       = "\n".join(ha_result.signatures[:10])    if ha_result.signatures     else "None"
    mitre_text      = "\n".join(
        f"{m.get('tactic','?')} / {m.get('technique','?')} — {m.get('name','?')}"
        for m in ha_result.mitre_attcks[:8]
    ) if ha_result.mitre_attcks else "None"
    net_hosts_text  = ", ".join(ha_result.contacted_hosts[:8]) if ha_result.contacted_hosts else "None"
    av_text         = "\n".join(
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
Your task is to produce a clear, concise threat intelligence summary.

Respond ONLY with valid JSON — no markdown, no code fences, no extra text:
{
  "summary": "<2-3 sentence executive summary of what this sample/URL does and its threat level>",
  "threat_narrative": "<detailed technical narrative: attack chain, TTPs, objectives — 3-5 sentences>",
  "recommended_actions": ["<action 1>", "<action 2>", "<action 3>", "<action 4>"],
  "confidence": "high" | "medium" | "low"
}"""

    user_prompt = f"Analyse this sandbox report and provide a threat intelligence summary:\n\n{context}"

    models_to_try = [model, "phi3:mini", "llama3", "mistral"]
    seen: set[str] = set()
    ordered = [m for m in models_to_try if not (m in seen or seen.add(m))]  # deduplicate

    for candidate in ordered:
        try:
            response = ollama.chat(
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
            out.error = str(exc)[:120]
            continue

    if not out.summary:
        out.error = out.error or "All models failed to generate summary"
    return out
