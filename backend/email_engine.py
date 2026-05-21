from __future__ import annotations
import re, socket, json
from dataclasses import dataclass, field
from typing import Optional
import requests
import os

import logging
logger = logging.getLogger(__name__)
# Config is loaded via config.py (dotenv handled centrally)

TIMEOUT = 8
VT_BASE = "https://www.virustotal.com/api/v3"

KNOWN_BRANDS = {
    "paypal":["paypal.com"],"apple":["apple.com","icloud.com"],
    "google":["google.com","gmail.com","googlemail.com"],
    "microsoft":["microsoft.com","outlook.com","live.com","hotmail.com"],
    "amazon":["amazon.com","amazon.co.uk"],"facebook":["facebook.com","meta.com","fb.com"],
    "netflix":["netflix.com"],"dropbox":["dropbox.com"],"linkedin":["linkedin.com"],
    "twitter":["twitter.com","x.com"],"chase":["chase.com"],
    "bankofamerica":["bankofamerica.com"],"wellsfargo":["wellsfargo.com"],
    "dhl":["dhl.com","dhl.de"],"fedex":["fedex.com"],"ups":["ups.com"],
    "irs":["irs.gov"],"coinbase":["coinbase.com"],"binance":["binance.com"],
}

URGENCY_PATTERNS = [
    r"act\s+(?:immediately|now|urgently|fast)",
    r"within\s+\d+\s+(?:hours?|days?|minutes?)",
    r"your\s+account\s+(?:has\s+been|will\s+be|is)\s+(?:suspended|locked|closed|compromised)",
    r"verify\s+(?:your\s+)?(?:account|identity|information|email)\s+(?:now|immediately)",
    r"(?:last|final)\s+(?:warning|notice|reminder|chance)",
    r"expire[sd]?\s+(?:in|within|today|soon)",
    r"unusual\s+(?:sign.?in|activity|login|access)",
    r"limited\s+time",
    r"(?:click|tap)\s+(?:here|below|link)\s+(?:now|immediately|to\s+verify)",
]
AUTHORITY_PATTERNS = [
    r"(?:department\s+of|ministry\s+of|office\s+of)",
    r"(?:irs|fbi|cia|interpol|police|court)\s+(?:notice|warning|order)",
    r"legal\s+(?:action|proceedings?|notice)",
    r"(?:government|federal|official)\s+(?:notice|alert|warning)",
    r"this\s+is\s+(?:an?\s+)?(?:official|urgent|important)\s+(?:notice|message|alert)",
]
SPAM_PATTERNS = [
    r"(?:free|no\s+cost)\s+(?:sample|trial|quote|shipping)",
    r"(?:reply|contact)\s+(?:us|me)\s+(?:for|to\s+get|to\s+receive)",
    r"(?:wholesale|bulk|discount)\s+(?:price|deal|offer)",
    r"(?:we\s+(?:can|offer|provide)|our\s+(?:company|factory|distillery))",
    r"(?:catalog|catalogue|brochure|sample)\s+(?:available|upon\s+request|free)",
    r"(?:business|trade|cooperation)\s+(?:opportunity|partner|inquiry)",
]

_VT_MAL_KW  = ["phishing","malware","scam","spam","malicious","abuse","fraud","fake","botnet","c2"]
_VT_BENIGN_KW = ["false positive","fp","legitimate","safe","harmless"]

_AI_EMAIL_SYSTEM = """You are a cybersecurity analyst. Analyze the email text for these EXACT signals:
1. URGENCY — time pressure, deadlines, threats
2. FINANCIAL_THREAT — money, payments, prizes, crypto
3. MANIPULATION — psychological pressure, fear, false scarcity
4. IMPERSONATION — claiming to be someone else (brand, official)
5. SOCIAL_ENGINEERING — trust building, pretexting, cold outreach
6. VISUAL_DECEPTION — fake UI, hidden text, misleading formatting, suspicious sender vs display name
7. SPAM_COMMERCIAL — unsolicited commercial offer, bulk marketing

Respond ONLY with this exact JSON structure (no markdown, no extra text):
{"urgency":false,"financial_threat":false,"manipulation":false,"impersonation":false,"social_engineering":false,"visual_deception":false,"spam_commercial":false,"summary":"one sentence assessment"}"""


@dataclass
class SenderIntelResult:
    vt_domain_malicious:      int       = 0
    vt_domain_total:          int       = 0
    vt_domain_categories:     list[str] = field(default_factory=list)
    vt_community_votes_mal:   int       = 0
    vt_community_comments_mal:int       = 0
    vt_malicious_files:       int       = 0
    vt_popularity_rank:       Optional[int] = None
    sender_ip:                Optional[str] = None
    abuse_confidence:         int       = 0
    abuse_reports:            int       = 0
    abuse_categories:         list[str] = field(default_factory=list)
    score_contribution:       int       = 0
    flags:  list[str]                   = field(default_factory=list)
    iocs:   list[str]                   = field(default_factory=list)
    errors: list[str]                   = field(default_factory=list)


@dataclass
class AIEmailAnalysis:
    urgency_detected:      bool = False
    financial_threat:      bool = False
    manipulation_detected: bool = False
    impersonation_signal:  bool = False
    social_engineering:    bool = False
    visual_deception:      bool = False
    spam_commercial:       bool = False
    summary:               str  = ""
    score_contribution:    int  = 0
    flags: list[str]            = field(default_factory=list)
    error: Optional[str]        = None


@dataclass
class EmailForensicsResult:
    score: int = 0
    display_name:     Optional[str] = None
    sender_address:   Optional[str] = None
    sender_domain:    Optional[str] = None
    reply_to:         Optional[str] = None
    return_path:      Optional[str] = None
    message_id:       Optional[str] = None
    subject:          Optional[str] = None
    all_emails_found: list[str]     = field(default_factory=list)
    spf_result:       Optional[str] = None
    dkim_result:      Optional[str] = None
    dmarc_result:     Optional[str] = None
    auth_failed:      bool          = False
    display_name_spoofing: bool     = False
    reply_to_hijack:       bool     = False
    brand_impersonated:    Optional[str] = None
    extracted_urls:    list[str] = field(default_factory=list)
    urgency_phrases:   list[str] = field(default_factory=list)
    authority_phrases: list[str] = field(default_factory=list)
    spam_signals:      list[str] = field(default_factory=list)
    ocr_text:          Optional[str] = None
    ocr_method:        Optional[str] = None
    sender_intel:      Optional[SenderIntelResult] = None
    ai_analysis:       Optional[AIEmailAnalysis]   = None
    flags:  list[str] = field(default_factory=list)
    iocs:   list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── OCR ───────────────────────────────────────────────────────────────────────

def _ocr_playwright(image_bytes: bytes) -> tuple[Optional[str], str]:
    # Size guard — reject oversized images before encoding
    if len(image_bytes) > MAX_IMAGE_BYTES:
        return None, f"image_too_large:{len(image_bytes)}"
    try:
        import base64
        from playwright.sync_api import sync_playwright
        b64 = base64.b64encode(image_bytes).decode()
        html = f'<html><body style="margin:0;background:white"><img src="data:image/png;base64,{b64}" style="max-width:100%"/></body></html>'
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox","--disable-gpu","--disable-dev-shm-usage"], headless=True)
            page = browser.new_page(viewport={"width":1400,"height":900})
            page.set_content(html)
            page.wait_for_timeout(800)
            text = page.inner_text("body") or ""
            browser.close()
            if len(text.strip()) > 20:
                return text.strip(), "playwright"
    except Exception:
        pass
    return None, "playwright_failed"


# ── Max image dimensions: prevent pixel bomb (1px PNG → 50000×50000) ──────
MAX_IMAGE_DIM   = 4096   # px per side
MAX_IMAGE_BYTES = 20_000_000  # 20MB raw bytes before decode


def _safe_open_image(image_bytes: bytes):
    """Open PIL image with size guard. Raises ValueError if too large."""
    from PIL import Image
    import io
    # PIL ImageFile.LOAD_TRUNCATED_IMAGES is off by default — keep it off
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_DIM * MAX_IMAGE_DIM  # built-in bomb guard
    img = Image.open(io.BytesIO(image_bytes))
    w, h = img.size
    if w > MAX_IMAGE_DIM or h > MAX_IMAGE_DIM:
        raise ValueError(
            f"Image too large ({w}×{h}px > {MAX_IMAGE_DIM}px limit) — "
            "possible pixel bomb or oversized upload"
        )
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise ValueError(
            f"Image file too large ({len(image_bytes):,} bytes > {MAX_IMAGE_BYTES:,} limit)"
        )
    return img.convert("RGB")


def _ocr_easyocr(image_bytes: bytes) -> tuple[Optional[str], str]:
    try:
        import easyocr, numpy as np
        img = _safe_open_image(image_bytes)
        reader = easyocr.Reader(["en"], gpu=False, verbose=False)
        results = reader.readtext(np.array(img), detail=0, paragraph=True)
        text = "\n".join(results)
        return (text, "easyocr") if text else (None, "easyocr_empty")
    except ImportError:
        return None, "easyocr_not_installed"
    except Exception:
        return None, "easyocr_error"


def _ocr_ollama_vision(image_bytes: bytes) -> tuple[Optional[str], str]:
    # Size guard before base64 encoding (prevents memory spike)
    if len(image_bytes) > MAX_IMAGE_BYTES:
        return None, f"image_too_large:{len(image_bytes)}"
    try:
        import ollama, base64
        b64 = base64.b64encode(image_bytes).decode()
        response = ollama.chat(
            model="llava",
            messages=[{"role":"user","content":"Extract ALL text from this email screenshot exactly as shown. Include From/To/Subject headers and full body. Return only the text.","images":[b64]}],
            options={"temperature":0.0,"num_predict":1500},
        )
        text = response["message"]["content"]
        return (text, "ollama_llava") if text else (None, "ollama_empty")
    except Exception:
        return None, "ollama_unavailable"


def extract_text_from_image(image_bytes: bytes) -> tuple[Optional[str], str]:
    for fn in [_ocr_easyocr, _ocr_playwright, _ocr_ollama_vision]:
        text, method = fn(image_bytes)
        if text and len(text.strip()) > 15:
            return text, method
    return None, "all_ocr_failed"


# ── Email extraction ──────────────────────────────────────────────────────────

def _extract_all_emails(text: str) -> list[str]:
    pattern = re.compile(r"[a-zA-Z0-9._%+\-]+\s*@\s*[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)
    bracket = re.compile(r"<([^>]+@[^>]+)>")
    found: set[str] = set()
    for m in pattern.finditer(text):
        addr = re.sub(r"\s+","",m.group()).lower()
        if len(addr) < 100: found.add(addr)
    for m in bracket.finditer(text):
        addr = re.sub(r"\s+","",m.group(1)).lower()
        if "@" in addr: found.add(addr)
    return sorted(found)[:10]


def _extract_sender_from_ocr(text: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Find sender from OCR text when no formal headers exist."""
    # Pattern: Display Name <email> or (email)
    m = re.search(r"([A-Za-z\s]{2,40})\s*[<\(]\s*([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\s*[>\)]", text)
    if m:
        email = re.sub(r"\s+","",m.group(2)).lower()
        return m.group(1).strip(), email, email.split("@")[-1]

    # Pattern: From: ... line
    m = re.search(r"(?:from|sender)\s*[:;]\s*(.+)", text, re.IGNORECASE|re.MULTILINE)
    if m:
        emails = _extract_all_emails(m.group(1))
        if emails:
            return None, emails[0], emails[0].split("@")[-1]

    # First email in first 20 lines
    for line in text.split("\n")[:20]:
        emails = _extract_all_emails(line)
        if emails:
            return None, emails[0], emails[0].split("@")[-1]

    return None, None, None


def _parse_from_header(s: str) -> tuple[Optional[str], Optional[str]]:
    if not s: return None, None
    m = re.match(r'^"?([^"<>]+)"?\s*<([^>]+)>$', s.strip())
    if m: return m.group(1).strip(), m.group(2).strip().lower()
    m = re.match(r'^<([^>]+)>$', s.strip())
    if m: return None, m.group(1).strip().lower()
    if "@" in s: return None, s.strip().lower()
    return s.strip(), None


def _extract_domain(email: str) -> Optional[str]:
    return email.split("@")[-1].lower() if "@" in email else None


# ── VT + AbuseIPDB Sender Intel ───────────────────────────────────────────────

def _vt_sender(domain: str, vt_key: str, intel: SenderIntelResult) -> None:
    h = {"x-apikey": vt_key, "Accept": "application/json"}

    # Domain scan
    try:
        r = requests.get(f"{VT_BASE}/domains/{domain}", headers=h, timeout=TIMEOUT)
        if r.status_code == 200:
            attrs = r.json().get("data",{}).get("attributes",{})
            stats = attrs.get("last_analysis_stats",{})
            intel.vt_domain_malicious  = stats.get("malicious", 0)
            intel.vt_domain_total      = sum(stats.values()) if stats else 0
            intel.vt_domain_categories = list(set(attrs.get("categories",{}).values()))[:6]
            total_votes = attrs.get("total_votes", {})
            intel.vt_community_votes_mal = total_votes.get("malicious", 0)
            popularity = attrs.get("popularity_ranks", {})
            if popularity:
                intel.vt_popularity_rank = min(v.get("rank",999999) for v in popularity.values())

            if intel.vt_domain_malicious >= 5:
                intel.flags.append(f"🔴 VT Sender Domain: {intel.vt_domain_malicious}/{intel.vt_domain_total} engines MALICIOUS")
                intel.iocs.append(f"VT_SENDER_DOMAIN_MALICIOUS:{domain}")
            elif intel.vt_domain_malicious >= 2:
                intel.flags.append(f"🟠 VT Sender Domain: {intel.vt_domain_malicious} malicious detections")
            elif intel.vt_domain_malicious == 1:
                intel.flags.append(f"🟡 VT Sender Domain: 1 engine flagged")
            else:
                intel.flags.append(f"✅ VT Sender Domain '{domain}': Clean ({intel.vt_domain_total} engines)")

            danger_cats = [c for c in intel.vt_domain_categories if c.lower() in {"phishing","malware","spam","malicious","scam"}]
            if danger_cats:
                intel.flags.append(f"🏷 VT Categories: {', '.join(danger_cats)}")
                intel.iocs.append(f"VT_DOMAIN_CATEGORY:{','.join(danger_cats)}")

            if intel.vt_popularity_rank and intel.vt_popularity_rank <= 10000:
                intel.flags.append(f"📊 Popular domain (rank #{intel.vt_popularity_rank}) — likely legitimate")
    except Exception as e:
        intel.errors.append(f"VT domain error: {e}")

    # Community votes
    try:
        r = requests.get(f"{VT_BASE}/domains/{domain}/votes", headers=h, params={"limit":30}, timeout=TIMEOUT)
        if r.status_code == 200:
            votes = r.json().get("data",[])
            mal_v = sum(1 for v in votes if v.get("attributes",{}).get("verdict")=="malicious")
            harm_v = sum(1 for v in votes if v.get("attributes",{}).get("verdict")=="harmless")
            if mal_v > intel.vt_community_votes_mal:
                intel.vt_community_votes_mal = mal_v
            if mal_v >= 2:
                intel.flags.append(f"👎 VT Community: {mal_v} users voted sender domain MALICIOUS ({harm_v} harmless)")
                intel.iocs.append(f"VT_SENDER_COMMUNITY_VOTES:{mal_v}")
            elif harm_v >= 3 and mal_v == 0:
                intel.flags.append(f"👍 VT Community: {harm_v} users voted harmless")
    except Exception as e:
        intel.errors.append(f"VT votes error: {e}")

    # Comments NLP
    try:
        r = requests.get(f"{VT_BASE}/domains/{domain}/comments", headers=h, params={"limit":10}, timeout=TIMEOUT)
        if r.status_code == 200:
            comments = r.json().get("data",[])
            mal_comments = []
            for c in comments:
                txt = c.get("attributes",{}).get("text","").lower()
                mal_hits = [kw for kw in _VT_MAL_KW if kw in txt]
                ben_hits = [kw for kw in _VT_BENIGN_KW if kw in txt]
                if len(mal_hits) >= 2 and not ben_hits:
                    intel.vt_community_comments_mal += 1
                    mal_comments.append(txt[:100])
            if mal_comments:
                intel.flags.append(f"💬 VT Comments: {len(mal_comments)} malicious comment(s) about sender domain")
                for i, s in enumerate(mal_comments[:2]):
                    intel.flags.append(f'   Comment {i+1}: "{s.strip()}…"')
                intel.iocs.append("VT_SENDER_COMMENTS_MALICIOUS")
            elif comments:
                intel.flags.append(f"💬 VT Comments: {len(comments)} comment(s), no malicious signals")
            else:
                intel.flags.append("💬 VT Comments: No comments for this sender domain")
    except Exception as e:
        intel.errors.append(f"VT comments error: {e}")

    # Related files
    try:
        r = requests.get(f"{VT_BASE}/domains/{domain}/communicating_files", headers=h, params={"limit":10}, timeout=TIMEOUT)
        if r.status_code == 200:
            items = r.json().get("data",[])
            mal = sum(1 for i in items if i.get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0)>=3)
            intel.vt_malicious_files = mal
            if mal > 0:
                intel.flags.append(f"🔗 VT Relations: {mal}/{len(items)} communicating files MALICIOUS")
                intel.iocs.append(f"VT_SENDER_MALICIOUS_FILES:{mal}")
            elif items:
                intel.flags.append(f"🔗 VT Relations: {len(items)} related files, none malicious")
    except Exception as e:
        intel.errors.append(f"VT relations error: {e}")


def _abuseipdb_sender(domain: str, abuse_key: str, intel: SenderIntelResult) -> None:
    CATS = {3:"Fraud Orders",4:"DDoS Attack",5:"FTP Brute-Force",7:"Phishing",
            9:"Open Proxy",10:"Web Spam",11:"Email Spam",14:"Port Scan",
            15:"Hacking",16:"SQL Injection",18:"Brute-Force",21:"Web App Attack",22:"SSH Attack"}
    try:
        ip = socket.gethostbyname(domain)
        intel.sender_ip = ip
    except Exception:
        intel.errors.append(f"Cannot resolve '{domain}' to IP")
        return
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": abuse_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json().get("data",{})
            intel.abuse_confidence = data.get("abuseConfidenceScore", 0)
            intel.abuse_reports    = data.get("totalReports", 0)
            all_cat_ids: set[int] = set()
            for report in (data.get("reports") or [])[:20]:
                for cid in (report.get("categories") or []):
                    all_cat_ids.add(cid)
            intel.abuse_categories = [CATS.get(cid, f"Cat {cid}") for cid in sorted(all_cat_ids)]

            if intel.abuse_confidence >= 70:
                intel.flags.append(f"🔴 AbuseIPDB Sender IP ({ip}): {intel.abuse_confidence}% confidence, {intel.abuse_reports} reports")
                intel.iocs.append(f"ABUSIVE_SENDER_IP:{ip}")
            elif intel.abuse_confidence >= 40:
                intel.flags.append(f"🟠 AbuseIPDB Sender IP ({ip}): {intel.abuse_confidence}% confidence")
            elif intel.abuse_reports > 0:
                intel.flags.append(f"AbuseIPDB Sender IP ({ip}): {intel.abuse_reports} historical reports")
            else:
                intel.flags.append(f"✅ AbuseIPDB Sender IP ({ip}): No abuse history")

            if intel.abuse_categories:
                intel.flags.append(f"📋 Abuse Categories: {', '.join(intel.abuse_categories[:5])}")
                if any("spam" in c.lower() or "phish" in c.lower() for c in intel.abuse_categories):
                    intel.iocs.append(f"SENDER_ABUSE_CATEGORY:{','.join(intel.abuse_categories[:3])}")
    except Exception as e:
        intel.errors.append(f"AbuseIPDB error: {e}")


def check_sender_intelligence(domain, email, vt_key, abuse_key) -> SenderIntelResult:
    intel = SenderIntelResult()
    if vt_key:
        _vt_sender(domain, vt_key, intel)
    else:
        intel.errors.append("VT key not set — add VIRUSTOTAL_API_KEY to .env")
    if abuse_key:
        _abuseipdb_sender(domain, abuse_key, intel)
    else:
        intel.errors.append("AbuseIPDB key not set — add ABUSEIPDB_API_KEY to .env")

    score = 0
    if intel.vt_domain_malicious >= 5:   score += 30
    elif intel.vt_domain_malicious >= 2: score += 18
    elif intel.vt_domain_malicious == 1: score += 8
    score += min(intel.vt_community_votes_mal * 5,    15)
    score += min(intel.vt_community_comments_mal * 8, 15)
    score += min(intel.vt_malicious_files * 10,       20)
    if intel.abuse_confidence >= 70:   score += 25
    elif intel.abuse_confidence >= 40: score += 15
    elif intel.abuse_reports > 0:      score += 5
    if intel.vt_popularity_rank and intel.vt_popularity_rank <= 10000:
        score = max(score - 15, 0)
    intel.score_contribution = min(score, 40)
    return intel


# ── AI Analysis ───────────────────────────────────────────────────────────────

def _analyze_email_ai(text: str) -> AIEmailAnalysis:
    result = AIEmailAnalysis()
    try:
        import ollama
        # Try faster models first
        for model in ["phi3:mini", "llama3.2", "llama3", "mistral"]:
            try:
                response = ollama.chat(
                    model=model,
                    messages=[
                        {"role":"system","content":_AI_EMAIL_SYSTEM},
                        {"role":"user","content":f"Email to analyze:\n\n---\n{text[:4000]}\n---"},
                    ],
                    options={"temperature":0.05,"num_predict":512},
                )
                raw = response["message"]["content"]
                clean = re.sub(r"```(?:json)?","",raw).strip()
                m = re.search(r"\{.*\}", clean, re.DOTALL)
                if not m: continue
                parsed = json.loads(m.group())

                result.urgency_detected      = bool(parsed.get("urgency",False))
                result.financial_threat      = bool(parsed.get("financial_threat",False))
                result.manipulation_detected = bool(parsed.get("manipulation",False))
                result.impersonation_signal  = bool(parsed.get("impersonation",False))
                result.social_engineering    = bool(parsed.get("social_engineering",False))
                result.visual_deception      = bool(parsed.get("visual_deception",False))
                result.spam_commercial       = bool(parsed.get("spam_commercial",False))
                result.summary               = str(parsed.get("summary",""))

                score = 0
                if result.urgency_detected:      score += 15; result.flags.append("🤖 AI: Urgency/pressure tactics")
                if result.financial_threat:      score += 12; result.flags.append("🤖 AI: Financial threat/lure")
                if result.manipulation_detected: score += 12; result.flags.append("🤖 AI: Psychological manipulation")
                if result.impersonation_signal:  score += 15; result.flags.append("🤖 AI: Impersonation detected")
                if result.social_engineering:    score += 12; result.flags.append("🤖 AI: Social engineering tactics")
                if result.visual_deception:      score += 12; result.flags.append("🤖 AI: Visual deception/formatting tricks")
                if result.spam_commercial:       score += 12; result.flags.append("🤖 AI: Unsolicited commercial email (spam)")
                if result.summary:
                    result.flags.append(f"🤖 AI Summary: {result.summary}")

                result.score_contribution = min(score, 40)

                # ── Minimum score floors ──────────────────────────────────
                # Spam + manipulation/social engineering → minimum MEDIUM
                if result.spam_commercial and (result.manipulation_detected or result.social_engineering):
                    if result.score_contribution < 30:
                        result.score_contribution = 30
                        result.flags.append(
                            "⚠️ AI Override: Spam + manipulation confirmed → score floor MEDIUM"
                        )

                # Manipulation + social engineering birlikdə → minimum MEDIUM
                if result.manipulation_detected and result.social_engineering:
                    if result.score_contribution < 28:
                        result.score_contribution = 28
                        result.flags.append(
                            "⚠️ AI Override: Manipulation + social engineering → score floor raised"
                        )

                # 3+ siqnal birlikdə → minimum HIGH floor
                ai_signal_count = sum([
                    result.urgency_detected,
                    result.financial_threat,
                    result.manipulation_detected,
                    result.impersonation_signal,
                    result.social_engineering,
                    result.visual_deception,
                    result.spam_commercial,
                ])
                if ai_signal_count >= 3:
                    if result.score_contribution < 35:
                        result.score_contribution = 35
                        result.flags.append(
                            f"🔴 AI Override: {ai_signal_count} threat signals confirmed → score floor HIGH"
                        )

                return result  # success
            except Exception:
                continue

        result.error = "All Ollama models failed — heuristics only"
    except ImportError:
        result.error = "Ollama not installed"
    return result


# ── Heuristic analysis ────────────────────────────────────────────────────────

def _heuristic_analysis(text: str, result: EmailForensicsResult) -> None:
    tl = text.lower()
    for pat in URGENCY_PATTERNS:
        m = re.search(pat, tl)
        if m:
            result.urgency_phrases.append(tl[max(0,m.start()-5):m.end()+20].strip()[:80])
    for pat in AUTHORITY_PATTERNS:
        m = re.search(pat, tl)
        if m:
            result.authority_phrases.append(tl[max(0,m.start()-5):m.end()+20].strip()[:80])
    for pat in SPAM_PATTERNS:
        m = re.search(pat, tl)
        if m:
            result.spam_signals.append(tl[max(0,m.start()-5):m.end()+20].strip()[:80])

    if result.urgency_phrases:
        result.score += min(len(result.urgency_phrases)*5,15)
        result.flags.append(f"Urgency patterns: '{result.urgency_phrases[0][:60]}'")
    if result.authority_phrases:
        result.score += min(len(result.authority_phrases)*5,15)
        result.flags.append(f"Authority language: '{result.authority_phrases[0][:60]}'")
    if result.spam_signals:
        result.score += min(len(result.spam_signals)*3,10)
        result.flags.append(f"Commercial spam signals: {len(result.spam_signals)} pattern(s) — '{result.spam_signals[0][:60]}'")


def _check_auth(text: str, result: EmailForensicsResult) -> None:
    def _get(h): m=re.search(rf"{h}=(\w+)",text,re.IGNORECASE); return m.group(1).lower() if m else None
    result.spf_result   = _get("spf")
    result.dkim_result  = _get("dkim")
    result.dmarc_result = _get("dmarc")
    failures = []
    if result.spf_result   in ("fail","softfail"): failures.append(f"SPF={result.spf_result}")
    if result.dkim_result  == "fail":              failures.append("DKIM=fail")
    if result.dmarc_result == "fail":              failures.append("DMARC=fail")
    if len(failures) >= 2:
        result.auth_failed = True; result.score += 20
        result.flags.append(f"Auth failures: {', '.join(failures)} — email likely spoofed")
        result.iocs.append(f"AUTH_FAIL:{'+'.join(failures)}")
    elif failures:
        result.score += 8
        result.flags.append(f"Partial auth failure: {failures[0]}")


def _detect_impersonation(dn, sd, result: EmailForensicsResult) -> None:
    if not dn: return
    dn_l = dn.lower(); sd_l = (sd or "").lower()
    for brand, legit in KNOWN_BRANDS.items():
        if brand in dn_l and not any(sd_l==ld or sd_l.endswith("."+ld) for ld in legit):
            result.display_name_spoofing = True
            result.brand_impersonated    = brand.title()
            result.score += 35
            result.flags.append(f"IMPERSONATION: Claims '{brand.title()}' but sent from '{sd or 'unknown'}'")
            result.iocs.append(f"EMAIL_IMPERSONATION:{brand.upper()}")
            break


def _detect_reply_hijack(sender, reply_to, result: EmailForensicsResult) -> None:
    if not reply_to or not sender: return
    fd = _extract_domain(sender) or ""
    rd = _extract_domain(reply_to) or ""
    def _base(d):
        try:
            import tldextract; ext=tldextract.extract(d); return f"{ext.domain}.{ext.suffix}" if ext.domain else d
        except: return d
    if _base(fd) != _base(rd) and rd:
        result.reply_to_hijack = True; result.score += 20
        result.flags.append(f"Reply-To hijack: From '{fd}' → Reply-To '{rd}'")
        result.iocs.append(f"REPLY_TO_HIJACK:{rd}")


# ── Main entry ────────────────────────────────────────────────────────────────

def analyze_email(
    text: Optional[str] = None,
    image_bytes: Optional[bytes] = None,
    vt_api_key: Optional[str] = None,
    abuse_api_key: Optional[str] = None,
) -> EmailForensicsResult:
    """Full email forensic pipeline: OCR → Sender extraction → VT+AbuseIPDB → AI → Score."""
    vt_api_key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY")
    abuse_api_key = abuse_api_key or os.getenv("ABUSEIPDB_API_KEY")
    result = EmailForensicsResult()

    # Step 1: OCR
    if image_bytes:
        ocr_text, method = extract_text_from_image(image_bytes)
        result.ocr_text = ocr_text; result.ocr_method = method
        if ocr_text:
            result.flags.append(f"📷 OCR via {method} ({len(ocr_text)} chars)")
            text = ((text or "") + "\n" + ocr_text).strip()
        else:
            result.errors.append(f"OCR failed ({method})")

    if not text:
        result.errors.append("No email text or image provided"); return result

    # Step 2: Extract all emails
    result.all_emails_found = _extract_all_emails(text)

    # Step 3: Parse headers or extract from OCR
    from_m = re.search(r"^From:\s*(.+)$", text, re.MULTILINE|re.IGNORECASE)
    if from_m:
        result.display_name, result.sender_address = _parse_from_header(from_m.group(1))
        result.sender_domain = _extract_domain(result.sender_address or "")
    else:
        dn, addr, domain = _extract_sender_from_ocr(text)
        result.display_name = dn; result.sender_address = addr; result.sender_domain = domain

    if not result.sender_address and result.all_emails_found:
        result.sender_address = result.all_emails_found[0]
        result.sender_domain  = _extract_domain(result.sender_address)

    if result.sender_address:
        result.iocs.append(f"EMAIL_SENDER:{result.sender_address}")
        result.flags.append(f"📧 Sender: {result.sender_address}")
    if result.display_name:
        result.flags.append(f"📛 Display name: {result.display_name}")
    if len(result.all_emails_found) > 1:
        extras = result.all_emails_found[1:]
        result.flags.append(f"📧 Additional addresses: {', '.join(extras[:4])}")
        for e in extras: result.iocs.append(f"EMAIL_ADDRESS:{e}")

    subj_m = re.search(r"^Subject:\s*(.+)$", text, re.MULTILINE|re.IGNORECASE)
    if subj_m: result.subject = subj_m.group(1).strip()
    else:
        subj_ocr = re.search(r"(?:subject|re:|fwd:)\s*[:\-]?\s*(.{5,80})", text, re.IGNORECASE)
        if subj_ocr: result.subject = subj_ocr.group(1).strip()

    rt_m = re.search(r"^Reply-To:\s*(.+)$", text, re.MULTILINE|re.IGNORECASE)
    if rt_m: _, result.reply_to = _parse_from_header(rt_m.group(1))

    rp_m = re.search(r"^Return-Path:\s*<([^>]+)>", text, re.MULTILINE|re.IGNORECASE)
    if rp_m: result.return_path = rp_m.group(1).strip().lower()

    # Step 4: Authentication
    _check_auth(text, result)

    # Step 5: Sender VT + AbuseIPDB
    if result.sender_domain:
        result.flags.append(f"🔍 Checking '{result.sender_domain}' on VT + AbuseIPDB…")
        intel = check_sender_intelligence(result.sender_domain, result.sender_address or "", vt_api_key, abuse_api_key)
        result.sender_intel = intel
        result.score       += intel.score_contribution
        result.flags.extend(intel.flags)
        result.iocs.extend(intel.iocs)
        result.errors.extend(intel.errors)
    else:
        result.flags.append("⚠ Sender domain not found — skipping VT/AbuseIPDB")

    # Step 6: AI analysis (7 signals)
    ai = _analyze_email_ai(text)
    result.ai_analysis = ai

    # ── Screenshot mode: AI is the primary signal source ─────────────
    # When input is an image (no headers, no sender domain), VT/AbuseIPDB
    # contribute 0. Without a boost the final score understates the risk
    # even when AI detects clear threat signals.
    # Solution: raise the AI score cap from 40 → 70 when:
    #   (a) input came from OCR (image_bytes was provided), AND
    #   (b) sender domain was not found (no VT/AbuseIPDB contribution)
    is_screenshot_mode = bool(image_bytes and not result.sender_domain)
    if is_screenshot_mode and ai.score_contribution > 0:
        # Re-compute raw score without the 40-cap, then apply 70-cap
        ai_signals = sum([
            ai.urgency_detected,
            ai.financial_threat,
            ai.manipulation_detected,
            ai.impersonation_signal,
            ai.social_engineering,
            ai.visual_deception,
            ai.spam_commercial,
        ])
        raw = (
            (15 if ai.urgency_detected      else 0) +
            (12 if ai.financial_threat      else 0) +
            (12 if ai.manipulation_detected else 0) +
            (15 if ai.impersonation_signal  else 0) +
            (12 if ai.social_engineering    else 0) +
            (12 if ai.visual_deception      else 0) +
            (12 if ai.spam_commercial       else 0)
        )
        boosted = min(raw, 70)
        if boosted > ai.score_contribution:
            result.flags.append(
                f"📷 Screenshot mode: AI score boosted {ai.score_contribution}→{boosted} "
                f"(no headers/domain available, {ai_signals} AI signal(s) detected)"
            )
            ai.score_contribution = boosted

    result.score += ai.score_contribution
    result.flags.extend(ai.flags)
    if ai.error: result.errors.append(f"AI: {ai.error}")

    # Step 7: Heuristics
    _heuristic_analysis(text, result)

    # Step 8: Impersonation + Reply-To
    _detect_impersonation(result.display_name, result.sender_domain, result)
    _detect_reply_hijack(result.sender_address, result.reply_to, result)

    # Step 9: URLs
    urls = re.findall(r"https?://[^\s<>\"')]+", text, re.IGNORECASE)
    result.extracted_urls = list(set(u.rstrip(".,;)") for u in urls))[:20]
    if result.extracted_urls:
        result.flags.append(f"🔗 {len(result.extracted_urls)} URL(s) extracted")
        for u in result.extracted_urls[:3]:
            result.iocs.append(f"EMAIL_URL:{u[:80]}")

    # Return-Path mismatch
    if result.return_path and result.sender_address:
        rp_d = _extract_domain(result.return_path) or ""
        sd_d = result.sender_domain or ""
        if rp_d and sd_d and rp_d != sd_d:
            result.score += 10
            result.flags.append(f"Return-Path mismatch: '{rp_d}' vs sender '{sd_d}'")

    if not result.flags:
        result.flags.append("Email forensics: No threat indicators detected")

    result.score = min(result.score, 100)
    return result