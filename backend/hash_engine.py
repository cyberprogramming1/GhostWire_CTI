"""
utils/hash_engine.py
--------------------
File & Hash Analysis Engine — GhostWire CTI v6.

Capabilities:
  • SHA-256 / MD5 / SHA-1 hash → VirusTotal file reputation
  • File upload → compute hash → VT lookup
  • File metadata extraction:
      - PDF: author, creator tool, creation date
      - Office (docx/xlsx): author, last modified, macro detection
      - PE (exe/dll): compile timestamp, imphash, section entropy
  • Weaponized document indicators:
      - Macro presence (VBA/XLM)
      - High section entropy (packed/encrypted PE)
      - Suspicious embedded objects
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Optional, BinaryIO

import requests

import logging
logger = logging.getLogger(__name__)

TIMEOUT = 10

VT_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class HashAnalysisResult:
    """Full result from file/hash analysis engine."""
    score: int = 0

    # Hash info
    sha256: Optional[str]       = None
    md5:    Optional[str]       = None
    sha1:   Optional[str]       = None
    file_type: Optional[str]    = None
    file_size: Optional[int]    = None     # bytes

    # VirusTotal
    vt_malicious: int           = 0
    vt_suspicious: int          = 0
    vt_harmless: int            = 0
    vt_total: int               = 0
    vt_family: Optional[str]    = None    # Detected malware family
    vt_tags: list[str]          = field(default_factory=list)

    # Document metadata
    author: Optional[str]       = None
    creator_tool: Optional[str] = None
    creation_date: Optional[str]= None
    last_modified: Optional[str]= None
    page_count: Optional[int]   = None

    # Weaponization indicators
    has_macros: bool            = False
    has_embedded_objects: bool  = False
    has_auto_open: bool         = False    # AutoOpen / AutoExec macros
    high_entropy_sections: list[str] = field(default_factory=list)
    suspicious_imports: list[str]    = field(default_factory=list)

    flags: list[str]            = field(default_factory=list)
    iocs: list[str]             = field(default_factory=list)
    errors: list[str]           = field(default_factory=list)


# ── Hash utilities ────────────────────────────────────────────────────────────

def _compute_hashes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.sha256(data).hexdigest(),
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
    )


def _normalise_hash(h: str) -> tuple[str, str]:
    """Return (hash_value, hash_type) for a user-supplied hash string."""
    h = h.strip().lower()
    if len(h) == 64 and re.fullmatch(r"[0-9a-f]+", h):
        return h, "sha256"
    if len(h) == 40 and re.fullmatch(r"[0-9a-f]+", h):
        return h, "sha1"
    if len(h) == 32 and re.fullmatch(r"[0-9a-f]+", h):
        return h, "md5"
    return h, "unknown"


# ── VirusTotal file lookup ────────────────────────────────────────────────────

def _vt_file_lookup(sha256: str, api_key: str) -> dict:
    try:
        r = requests.get(
            f"{VT_BASE}/files/{sha256}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"error": "Hash not found in VirusTotal database"}
        return r.json() if r.status_code == 200 else {"error": f"VT HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _parse_vt_file(data: dict, result: HashAnalysisResult) -> None:
    if "error" in data:
        result.errors.append(f"VirusTotal: {data['error']}")
        return

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    result.vt_malicious  = stats.get("malicious", 0)
    result.vt_suspicious = stats.get("suspicious", 0)
    result.vt_harmless   = stats.get("harmless", 0)
    result.vt_total      = sum(stats.values()) if stats else 0
    result.file_type     = attrs.get("type_description") or attrs.get("type_tag")
    result.vt_tags       = attrs.get("tags", [])[:8]

    # Malware family detection
    names = attrs.get("popular_threat_classification", {})
    family = names.get("suggested_threat_label")
    result.vt_family = family

    if result.vt_malicious >= 20:
        result.score += 50
        result.flags.append(
            f"VT FILE: {result.vt_malicious}/{result.vt_total} engines MALICIOUS 🔴"
        )
        result.iocs.append(f"MALICIOUS_HASH:{result.sha256}")
    elif result.vt_malicious >= 5:
        result.score += 35
        result.flags.append(f"VT FILE: {result.vt_malicious} malicious detections")
    elif result.vt_malicious >= 1:
        result.score += 20
        result.flags.append(f"VT FILE: {result.vt_malicious} engine(s) flagged file")
    elif result.vt_total > 0:
        result.flags.append(f"VT FILE: Clean ({result.vt_harmless}/{result.vt_total} engines)")

    if result.vt_family:
        result.score += 15
        result.flags.append(f"Malware family: {result.vt_family}")
        result.iocs.append(f"MALWARE_FAMILY:{result.vt_family}")

    if "macro" in result.vt_tags or "document" in result.vt_tags:
        result.has_macros = True
        result.flags.append("VT tags indicate macro-enabled document")


# ── PDF metadata extraction ───────────────────────────────────────────────────

def _extract_pdf_metadata(data: bytes, result: HashAnalysisResult) -> None:
    """
    Extract PDF metadata without external dependencies.
    Uses raw byte-level parsing of the PDF info dictionary.
    """
    try:
        text = data[:65536].decode("latin-1", errors="ignore")

        def _pdf_string(key: str) -> Optional[str]:
            m = re.search(rf"/{key}\s*\(([^)]*)\)", text)
            if m:
                return m.group(1).strip()
            # Also handle hex strings
            m = re.search(rf"/{key}\s*<([0-9a-fA-F]+)>", text)
            if m:
                try:
                    return bytes.fromhex(m.group(1)).decode("utf-16-be", errors="ignore").strip()
                except Exception:
                    pass
            return None

        result.author       = _pdf_string("Author")
        result.creator_tool = _pdf_string("Creator") or _pdf_string("Producer")
        result.creation_date= _pdf_string("CreationDate")
        result.last_modified= _pdf_string("ModDate")

        # Page count
        pages = re.findall(r"/Type\s*/Page[^s]", text)
        result.page_count = len(pages) if pages else None

        # JavaScript in PDF — weaponized indicator
        if "/JavaScript" in text or "/JS" in text:
            result.score += 20
            result.flags.append("PDF contains JavaScript — potential exploit vector")
            result.iocs.append("PDF_JAVASCRIPT")

        # Embedded file streams
        if "/EmbeddedFile" in text or "/FileSpec" in text:
            result.has_embedded_objects = True
            result.score += 10
            result.flags.append("PDF contains embedded file objects")

        # Launch actions (opens external processes)
        if "/Launch" in text:
            result.score += 25
            result.flags.append("PDF contains /Launch action — executes external commands 🚨")
            result.iocs.append("PDF_LAUNCH_ACTION")

        # OpenAction (runs on open)
        if "/OpenAction" in text and ("/JavaScript" in text or "/Launch" in text):
            result.has_auto_open = True
            result.score += 15
            result.flags.append("PDF auto-executes action on open — weaponized document")

        # Suspicious creator tools used in phishing kits
        phish_tools = ["msfvenom", "msfpayload", "metasploit", "empire", "cobaltstrike"]
        ct = (result.creator_tool or "").lower()
        for tool in phish_tools:
            if tool in ct:
                result.score += 30
                result.flags.append(f"Creator tool '{result.creator_tool}' is a known attack framework")
                result.iocs.append(f"MALWARE_TOOL:{result.creator_tool}")

    except Exception as e:
        result.errors.append(f"PDF metadata extraction: {e}")


# ── PDF text content extraction ───────────────────────────────────────────────

def _extract_pdf_text(data: bytes) -> str:
    """
    Extract readable text from PDF for NLP / manipulation analysis.

    Strategy (no external deps required):
      1. Try pypdf (if installed) — best quality
      2. Fallback: raw stream extraction via regex — works on most simple PDFs
    Returns extracted text (up to 8000 chars).
    """
    # ── Method 1: pypdf ───────────────────────────────────────────────
    try:
        import io
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        pages_text: list[str] = []
        for page in reader.pages[:10]:          # max 10 pages
            try:
                t = page.extract_text() or ""
                pages_text.append(t)
            except Exception:
                pass
        combined = "\n".join(pages_text).strip()
        if combined:
            return combined[:8000]
    except ImportError:
        pass
    except Exception:
        pass

    # ── Method 2: raw stream regex (fallback) ─────────────────────────
    try:
        raw = data.decode("latin-1", errors="ignore")
        # Extract text between BT (Begin Text) and ET (End Text) operators
        bt_blocks = re.findall(r"BT(.*?)ET", raw, re.DOTALL)
        tokens: list[str] = []
        for block in bt_blocks[:50]:
            # Tj / TJ operators carry text
            found = re.findall(r"\(([^)]{1,300})\)\s*T[jJ]", block)
            tokens.extend(found)
            found2 = re.findall(r"\[([^\]]{1,300})\]\s*TJ", block)
            for f in found2:
                sub = re.findall(r"\(([^)]*)\)", f)
                tokens.extend(sub)
        text = " ".join(t for t in tokens if t.strip())
        if text:
            return text[:8000]
    except Exception:
        pass

    return ""


# ── Content NLP analysis (shared for PDF + Office) ───────────────────────────

def _analyze_content_nlp(text: str, result: HashAnalysisResult) -> None:
    """
    Run heuristic NLP on extracted document text.
    Detects: urgency, financial threats, credential harvesting,
    impersonation, manipulation tactics.
    Optionally calls Ollama if available.
    """
    if not text or len(text.strip()) < 30:
        return

    text_lower = text.lower()

    # ── Pattern libraries ─────────────────────────────────────────────
    URGENCY_PATTERNS = [
        r"act\s+(immediately|now|urgently|fast)",
        r"within\s+\d+\s+(hours?|days?|minutes?)",
        r"your\s+account\s+(has\s+been|will\s+be|is)\s+(suspended|locked|closed|compromised)",
        r"(last|final)\s+(warning|notice|reminder|chance)",
        r"expire[sd]?\s+(in|within|today|soon)",
        r"unusual\s+(sign.?in|activity|login|access)",
        r"verify\s+(your\s+)?(account|identity|information|email)\s+(now|immediately)",
        r"limited\s+time",
        r"(click|tap)\s+(here|below|link)\s+(now|immediately)",
    ]

    FINANCIAL_PATTERNS = [
        r"(credit|debit)\s+card",
        r"bank\s+(account|transfer|details)",
        r"(payment|invoice|tax|refund|reward)\s+(pending|required|due|overdue)",
        r"(send|transfer|wire)\s+\$?\d+",
        r"cryptocurrency|bitcoin|ethereum|crypto\s+wallet",
        r"prize|winner|lottery|inheritance",
        r"irs|tax\s+(authority|office|return)",
    ]

    CREDENTIAL_PATTERNS = [
        r"(enter|confirm|reset|update)\s+(your\s+)?(password|pin|credentials)",
        r"(login|sign\s*in)\s+(to\s+)?(verify|confirm|access)",
        r"(username|email)\s+and\s+password",
        r"click\s+(here|below|link)\s+to\s+(verify|confirm|access|login)",
        r"your\s+(account|profile)\s+(information|details)\s+(required|needed)",
    ]

    IMPERSONATION_PATTERNS = [
        r"(paypal|apple|google|microsoft|amazon|netflix|facebook|instagram)",
        r"(bank\s+of\s+america|chase|wells\s+fargo|citibank|hsbc|barclays)",
        r"(irs|hmrc|medicare|social\s+security|government)",
        r"(dhl|fedex|ups|usps)\s+(delivery|package|shipment)",
        r"(technical|customer)\s+(support|service|team)",
    ]

    urgency_hits     = [p for p in URGENCY_PATTERNS     if re.search(p, text_lower)]
    financial_hits   = [p for p in FINANCIAL_PATTERNS   if re.search(p, text_lower)]
    credential_hits  = [p for p in CREDENTIAL_PATTERNS  if re.search(p, text_lower)]
    impersonation_hits = [p for p in IMPERSONATION_PATTERNS if re.search(p, text_lower)]

    # ── Scoring ───────────────────────────────────────────────────────
    if urgency_hits:
        pts = min(len(urgency_hits) * 8, 20)
        result.score += pts
        result.flags.append(
            f"📢 CONTENT: Urgency language detected ({len(urgency_hits)} patterns) "
            f"— pressure tactics to force immediate action"
        )

    if financial_hits:
        pts = min(len(financial_hits) * 6, 15)
        result.score += pts
        result.flags.append(
            f"💰 CONTENT: Financial threat/lure language "
            f"({len(financial_hits)} patterns)"
        )

    if credential_hits:
        pts = min(len(credential_hits) * 8, 20)
        result.score += pts
        result.flags.append(
            f"🔑 CONTENT: Credential harvesting language "
            f"({len(credential_hits)} patterns) — targets login/password input"
        )
        result.iocs.append("CONTENT_CREDENTIAL_HARVEST")

    if impersonation_hits:
        pts = min(len(impersonation_hits) * 5, 15)
        result.score += pts
        result.flags.append(
            f"🎭 CONTENT: Brand impersonation language detected "
            f"({len(impersonation_hits)} brand references)"
        )
        result.iocs.append("CONTENT_IMPERSONATION")

    # ── Ollama deep analysis (if available) ──────────────────────────
    try:
        from backend.ai_analyzer import analyze_text
        ai = analyze_text(text[:3000])
        if not ai.error:
            ai_signals: list[str] = []

            if ai.urgency_detected:
                result.flags.append("🤖 AI (Ollama): Urgency/pressure tactics confirmed")
                ai_signals.append("urgency")
            if ai.financial_threat_detected:
                result.flags.append("🤖 AI (Ollama): Financial threat language confirmed")
                ai_signals.append("financial")
            if ai.manipulation_detected:
                result.flags.append("🤖 AI (Ollama): Psychological manipulation tactics confirmed")
                ai_signals.append("manipulation")
            if ai.summary:
                result.flags.append(f"🤖 AI Summary: {ai.summary}")

            # Base AI score
            result.score += min(ai.score, 20)

            # ── Minimum score floors based on AI signals ──────────────
            # Urgency + Manipulation birlikdə → minimum MEDIUM
            if "urgency" in ai_signals and "manipulation" in ai_signals:
                if result.score < 40:
                    result.flags.append(
                        "⚠️ AI Override: Urgency + Manipulation confirmed → score floor MEDIUM (40)"
                    )
                    result.score = 40

            # Bütün 3 siqnal → minimum HIGH
            if len(ai_signals) >= 3:
                if result.score < 60:
                    result.flags.append(
                        "🔴 AI Override: Full manipulation profile (urgency+financial+manipulation) → score floor HIGH (60)"
                    )
                    result.score = 60

            # Urgency + heuristic pattern-lər birlikdə → floor 40
            heuristic_count = sum([
                bool(urgency_hits),
                bool(financial_hits),
                bool(credential_hits),
                bool(impersonation_hits),
            ])
            if "urgency" in ai_signals and heuristic_count >= 2:
                if result.score < 45:
                    result.flags.append(
                        "⚠️ AI + Heuristic Override: Multiple social engineering signals → score floor 45"
                    )
                    result.score = 45

    except Exception:
        pass  # Ollama not running — heuristics still work


# ── Office (OOXML) metadata extraction ────────────────────────────────────────

def _extract_office_metadata(data: bytes, result: HashAnalysisResult) -> None:
    """
    Extract metadata from Office Open XML files (.docx, .xlsx, .pptx).
    These are ZIP archives containing XML files.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            namelist = zf.namelist()

            # Core properties (author, dates)
            if "docProps/core.xml" in namelist:
                core = zf.read("docProps/core.xml").decode("utf-8", errors="ignore")
                def _xml_val(tag: str) -> Optional[str]:
                    m = re.search(rf"<[^>]*:{tag}[^>]*>([^<]+)<", core)
                    return m.group(1).strip() if m else None

                result.author        = _xml_val("creator") or _xml_val("lastModifiedBy")
                result.creation_date = _xml_val("created")
                result.last_modified = _xml_val("modified")

            # App properties (creator tool)
            if "docProps/app.xml" in namelist:
                app = zf.read("docProps/app.xml").decode("utf-8", errors="ignore")
                m = re.search(r"<Application>([^<]+)</Application>", app)
                if m:
                    result.creator_tool = m.group(1).strip()

            # Macro detection — VBA project present
            vba_files = [n for n in namelist if "vbaProject" in n or n.endswith(".bin")]
            if vba_files:
                result.has_macros = True
                result.score += 20
                result.flags.append(
                    f"VBA macro project found: {vba_files[0]} — potential malware vector"
                )
                result.iocs.append("OFFICE_MACRO")

                # Check for AutoOpen / AutoExec inside VBA binary
                try:
                    vba_data = zf.read(vba_files[0]).decode("latin-1", errors="ignore")
                    auto_triggers = ["AutoOpen", "AutoExec", "Auto_Open",
                                     "AutoClose", "Document_Open", "Workbook_Open"]
                    found_auto = [t for t in auto_triggers if t in vba_data]
                    if found_auto:
                        result.has_auto_open = True
                        result.score += 20
                        result.flags.append(
                            f"Auto-execute macro triggers found: {', '.join(found_auto)} 🚨"
                        )
                        result.iocs.append(f"MACRO_AUTO_EXEC:{found_auto[0]}")
                except Exception:
                    pass

            # Embedded OLE objects
            ole_files = [n for n in namelist if n.startswith("word/embeddings/")
                         or n.startswith("xl/embeddings/")]
            if ole_files:
                result.has_embedded_objects = True
                result.score += 10
                result.flags.append(
                    f"{len(ole_files)} embedded object(s) in document — "
                    f"possible OLE exploit or dropper"
                )

    except zipfile.BadZipFile:
        result.errors.append("Not a valid Office Open XML / ZIP archive")
    except Exception as e:
        result.errors.append(f"Office metadata extraction: {e}")


# ── PE (Windows executable) analysis ─────────────────────────────────────────

_PE_SUSPICIOUS_IMPORTS = [
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "SetWindowsHookEx", "GetAsyncKeyState",   # keylogger
    "InternetOpenUrl", "WinHttpConnect",       # C2 comms
    "CryptEncrypt", "CryptAcquireContext",     # ransomware
    "RegSetValueEx", "RegCreateKeyEx",         # persistence
    "ShellExecute", "WinExec", "CreateProcess",
]


def _extract_pe_metadata(data: bytes, result: HashAnalysisResult) -> None:
    """
    Basic PE header parsing without external libraries.
    Extracts compile timestamp, imports, section entropy.
    """
    try:
        if data[:2] != b"MZ":
            return

        # PE offset
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return

        # Compile timestamp
        ts = struct.unpack_from("<I", data, pe_offset + 8)[0]
        import datetime
        try:
            compile_dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            result.creation_date = compile_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            # Epoch 0 or very old timestamp = suspicious
            if ts == 0 or compile_dt.year < 2000:
                result.score += 8
                result.flags.append(
                    f"PE compile timestamp is zeroed/invalid ({result.creation_date}) — "
                    f"possible timestamp stomping"
                )
        except Exception:
            pass

        # Section entropy (detect packing/encryption)
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        section_table_offset = pe_offset + 24 + opt_header_size

        def _shannon_entropy(b: bytes) -> float:
            import math
            if not b:
                return 0.0
            freq: dict[int, int] = {}
            for byte in b:
                freq[byte] = freq.get(byte, 0) + 1
            n = len(b)
            return -sum((c/n) * math.log2(c/n) for c in freq.values())

        for i in range(min(num_sections, 16)):
            off = section_table_offset + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
            raw_size   = struct.unpack_from("<I", data, off + 16)[0]
            raw_offset = struct.unpack_from("<I", data, off + 20)[0]
            section_data = data[raw_offset:raw_offset + raw_size]
            ent = _shannon_entropy(section_data)
            if ent > 7.0:
                result.high_entropy_sections.append(f"{name}(H={ent:.2f})")

        if result.high_entropy_sections:
            result.score += 15
            result.flags.append(
                f"High-entropy PE sections: {', '.join(result.high_entropy_sections)} — "
                f"packed or encrypted binary (evasion technique)"
            )
            result.iocs.append("PE_HIGH_ENTROPY_SECTIONS")

        # Import scan (string search — no full PE parsing)
        text = data.decode("latin-1", errors="ignore")
        found_imports = [fn for fn in _PE_SUSPICIOUS_IMPORTS if fn in text]
        if found_imports:
            result.suspicious_imports = found_imports
            result.score += len(found_imports) * 3
            result.flags.append(
                f"Suspicious PE imports: {', '.join(found_imports[:6])}"
            )
            result.iocs.append(f"SUSPICIOUS_IMPORTS:{len(found_imports)}")

    except Exception as e:
        result.errors.append(f"PE analysis: {e}")


# ── Main ─────────────────────────────────────────────────────────────────────

def analyze_hash(
    hash_or_data: str | bytes,
    vt_api_key: Optional[str] = None,
    filename: Optional[str] = None,
) -> HashAnalysisResult:
    """
    Analyse a file hash string or raw file bytes.

    Args:
        hash_or_data: Either a hex hash string (SHA256/MD5/SHA1)
                      or raw file bytes from an upload.
        vt_api_key:   VirusTotal API key (optional).
        filename:     Original filename hint for type detection.

    Returns:
        HashAnalysisResult with score, metadata, and IOCs.
    """
    result = HashAnalysisResult()

    # ── Determine if input is a hash string or file bytes ────────────
    if isinstance(hash_or_data, str):
        h_val, h_type = _normalise_hash(hash_or_data)
        if h_type == "unknown":
            result.errors.append("Unrecognised hash format — provide SHA256/SHA1/MD5")
            return result
        result.sha256 = h_val if h_type == "sha256" else None
        result.md5    = h_val if h_type == "md5"    else None
        result.sha1   = h_val if h_type == "sha1"   else None

        # For non-SHA256 hashes, VT still accepts them
        if vt_api_key:
            vt_data = _vt_file_lookup(h_val, vt_api_key)
            _parse_vt_file(vt_data, result)
        else:
            result.errors.append("VirusTotal API key not configured — hash lookup skipped")
        return result

    # ── File bytes path ───────────────────────────────────────────────
    data: bytes = hash_or_data
    result.file_size = len(data)
    result.sha256, result.md5, result.sha1 = _compute_hashes(data)
    result.iocs.append(f"SHA256:{result.sha256}")

    # ── VT lookup by computed hash ────────────────────────────────────
    if vt_api_key:
        vt_data = _vt_file_lookup(result.sha256, vt_api_key)
        _parse_vt_file(vt_data, result)
    else:
        result.errors.append("VirusTotal API key not configured — cloud lookup skipped")

    # ── File type detection & metadata extraction ─────────────────────
    sig = data[:4]

    if data[:4] == b"%PDF":
        result.file_type = "PDF Document"
        _extract_pdf_metadata(data, result)
        # ── Content NLP ───────────────────────────────────────────────
        pdf_text = _extract_pdf_text(data)
        if pdf_text:
            result.flags.append(f"📄 PDF text extracted ({len(pdf_text)} chars) — running NLP analysis…")
            _analyze_content_nlp(pdf_text, result)
        else:
            result.flags.append("📄 PDF: no readable text found (scanned/image-only or encrypted)")
    elif data[:2] == b"MZ":
        result.file_type = "Windows Executable (PE)"
        _extract_pe_metadata(data, result)

    elif data[:4] == b"PK\x03\x04":
        # ZIP-based: Office OOXML or plain ZIP
        ext = (filename or "").lower().split(".")[-1]
        type_map = {
            "docx": "Word Document", "xlsx": "Excel Workbook",
            "pptx": "PowerPoint", "xlsm": "Excel Macro-Enabled",
            "docm": "Word Macro-Enabled",
        }
        result.file_type = type_map.get(ext, "Office/ZIP Archive")

        # ── SECURITY: ZIP bomb pre-check before any extraction ────────
        _zip_is_bomb = False
        _UNCOMPRESSED_CAP = 100_000_000  # 100 MB
        try:
            import zipfile as _zf_check, io as _io_check
            with _zf_check.ZipFile(_io_check.BytesIO(data)) as _zf:
                _entries = _zf.infolist()
                _total_uncomp = sum(e.file_size for e in _entries)
                _total_comp   = sum(e.compress_size for e in _entries)
                _ratio = _total_uncomp / max(len(data), 1)

                if _total_uncomp > _UNCOMPRESSED_CAP:
                    _zip_is_bomb = True
                    result.flags.append(
                        f"⛔ ZIP BOMB: declared {_total_uncomp//1_000_000}MB uncompressed "
                        f"(>{_UNCOMPRESSED_CAP//1_000_000}MB cap) — extraction blocked"
                    )
                    result.score = min(result.score + 40, 100)
                elif _ratio > 100:
                    _zip_is_bomb = True
                    result.flags.append(
                        f"⛔ ZIP BOMB: {_ratio:.0f}:1 compression ratio — extraction blocked"
                    )
                    result.score = min(result.score + 40, 100)
                elif _total_uncomp == 0 and _total_comp > 0:
                    result.flags.append(
                        "⚠️ ZIP metadata anomaly: file_size=0 with real data — "
                        "possible metadata spoofing to bypass ZIP bomb detection"
                    )
                    result.score = min(result.score + 15, 100)

                # Nested archive detection
                _nested = [e.filename for e in _entries
                           if e.filename.lower().endswith((".zip",".gz",".tar",".7z",".rar"))]
                if _nested:
                    result.flags.append(
                        f"⚠️ NESTED ARCHIVES: {len(_nested)} archive(s) inside — "
                        "possible Matryoshka bomb"
                    )
                    result.score = min(result.score + 20, 100)
        except Exception:
            pass

        if _zip_is_bomb:
            result.flags.append("Content extraction SKIPPED due to ZIP bomb detection.")
        else:
            _extract_office_metadata(data, result)
            # ── Content NLP for Office files ──────────────────────────────
            try:
                import zipfile, io
                office_text_parts: list[str] = []
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for name in zf.namelist():
                        if name.endswith('.xml') and 'word/document' in name or 'xl/sharedStrings' in name:
                            raw_xml = zf.read(name).decode('utf-8', errors='ignore')
                            import re as _re
                            plain = _re.sub(r'<[^>]+>', ' ', raw_xml)
                            plain = _re.sub(r'\s+', ' ', plain).strip()
                            if plain:
                                office_text_parts.append(plain[:2000])
                office_text = ' '.join(office_text_parts)[:6000]
                if office_text:
                    result.flags.append(f"📄 Office content extracted ({len(office_text)} chars) — running NLP analysis…")
                    _analyze_content_nlp(office_text, result)
            except Exception as _e:
                result.errors.append(f"Office content extraction: {_e}")

    elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        # OLE2 (legacy Office: .doc, .xls, .ppt)
        result.file_type = "Legacy Office Document (OLE2)"
        result.score += 10
        result.flags.append(
            "Legacy Office format (OLE2) — higher risk of embedded macros/exploits"
        )
        # Check for macro indicators
        text = data.decode("latin-1", errors="ignore")
        if "VBA" in text or "AutoOpen" in text:
            result.has_macros = True
            result.score += 15
            result.flags.append("VBA macro signatures found in OLE2 document")
            result.iocs.append("OLE2_MACRO")

    else:
        result.file_type = "Unknown/Binary"

    # ── Metadata anomaly checks ───────────────────────────────────────
    if result.author:
        # Check for known threat actor tools creating the doc
        suspicious_authors = ["admin", "user", "test", "unknown", "exploit"]
        if result.author.lower() in suspicious_authors:
            result.score += 5
            result.flags.append(
                f"Generic/suspicious document author: '{result.author}'"
            )

    if not result.flags:
        result.flags.append("File analysis: No malicious indicators found")

    result.score = min(result.score, 100)
    return result
