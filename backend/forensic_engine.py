"""
utils/forensic_engine.py
------------------------
Deep File Forensic Analysis Engine — GhostWire CTI v6 v4

Implements all 5 analysis dimensions:

  1. Static & Metadata Analysis   — ExifTool-style anomaly detection
     • Timestamps (future, epoch-0, mismatched)
     • MIME vs extension mismatch
     • Author/creator anomalies
     • Overlay data / trailing bytes / NTFS ADS markers

  2. Internal Content Inspection  — structural + NLP
     • PDF action tree (/JS /OpenAction /EmbeddedFiles /Launch)
     • VBA macro extraction + intent analysis
     • PowerShell / Shellcode pattern matching
     • Steganography markers (LSB, appended ZIP, polyglot)
     • ZIP bomb detection (compression ratio)

  3. AI NLP Script Analysis       — Ollama LLM
     • Reads extracted code/text
     • Judges intent vs benign baseline
     • Attributes malware family from behavioural language
     • Explains "clean container" discrepancy

  4. Container Discrepancy Logic  — why hash ≠ container scan
     • Dormant trigger detection
     • Environment-keying patterns
     • Sandbox evasion signatures

  5. VirusTotal Engine Divergence — why CrowdStrike flags but others don't
     • Engine-specific heuristic analysis
     • Community notes parsing
     • C2 domain / IP extraction from file strings

Output: ForensicReport dataclass consumed by the UI renderer.
"""

from __future__ import annotations

import hashlib
import io
import math
import os
import re
import struct
import zipfile
import datetime
from dataclasses import dataclass, field
from typing import Optional

import logging
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MetadataAnomaly:
    field:       str
    value:       str
    severity:    str   # LOW / MEDIUM / HIGH / CRITICAL
    description: str


@dataclass
class EmbeddedObject:
    obj_type:    str   # JS / VBA / PowerShell / Shellcode / EmbeddedFile / OLE
    location:    str   # where found (PDF stream N, ZIP entry, etc.)
    size_bytes:  int
    entropy:     float
    preview:     str   # first 200 chars of extracted text
    intent_label:str   # BENIGN / SUSPICIOUS / MALICIOUS
    is_obfuscated: bool = False
    auto_exec:   bool  = False


@dataclass
class C2Indicator:
    indicator:   str   # domain / IP / URL
    ioc_type:    str   # DOMAIN / IP / URL / DGA_PATTERN
    context:     str   # where found in the file
    confidence:  str   # LOW / MEDIUM / HIGH


@dataclass
class ForensicReport:
    """Complete deep forensic report for a file."""

    # ── Hashes ────────────────────────────────────────────────────────
    sha256:       Optional[str] = None
    md5:          Optional[str] = None
    sha1:         Optional[str] = None
    file_size:    int           = 0
    file_type:    str           = "Unknown"
    mime_type:    Optional[str] = None

    # ── Metadata anomalies ────────────────────────────────────────────
    metadata_anomalies: list[MetadataAnomaly] = field(default_factory=list)
    has_overlay_data:   bool = False
    overlay_size:       int  = 0
    has_trailing_bytes: bool = False
    mime_mismatch:      bool = False
    timestamp_anomaly:  bool = False

    # ── Structural findings ───────────────────────────────────────────
    embedded_objects:   list[EmbeddedObject] = field(default_factory=list)
    has_macros:         bool = False
    has_auto_exec:      bool = False
    has_javascript:     bool = False
    has_shellcode:      bool = False
    has_powershell:     bool = False
    has_embedded_files: bool = False
    is_polyglot:        bool = False          # valid as two file types simultaneously
    compression_ratio:  Optional[float] = None  # for ZIP bomb detection
    is_zip_bomb:        bool = False

    # ── Container discrepancy ─────────────────────────────────────────
    discrepancy_reason: Optional[str] = None
    evasion_techniques: list[str]     = field(default_factory=list)
    is_dormant:         bool = False
    environment_keyed:  bool = False

    # ── AI NLP analysis ───────────────────────────────────────────────
    nlp_intent_label:   str           = "UNKNOWN"   # BENIGN / SUSPICIOUS / MALICIOUS
    nlp_summary:        str           = ""
    nlp_malware_family: Optional[str] = None
    nlp_execution_flow: str           = ""
    nlp_engine_used:    str           = ""

    # ── C2 / Infrastructure ───────────────────────────────────────────
    c2_indicators:      list[C2Indicator] = field(default_factory=list)
    extracted_domains:  list[str]         = field(default_factory=list)
    extracted_ips:      list[str]         = field(default_factory=list)
    extracted_urls:     list[str]         = field(default_factory=list)
    has_dga_pattern:    bool              = False

    # ── VT engine divergence ──────────────────────────────────────────
    vt_malicious:       int           = 0
    vt_suspicious:      int           = 0
    vt_harmless:        int           = 0
    vt_total:           int           = 0
    vt_family:          Optional[str] = None
    vt_tags:            list[str]     = field(default_factory=list)
    engine_divergence_reason: str     = ""

    # ── Verdict ───────────────────────────────────────────────────────
    executive_summary:  str  = ""
    final_verdict:      str  = "UNKNOWN"   # TRUE_POSITIVE / FALSE_POSITIVE / UNKNOWN
    risk_score:         int  = 0
    confidence:         int  = 0
    threat_level:       str  = "UNKNOWN"   # SAFE / LOW / MEDIUM / HIGH / CRITICAL

    flags:  list[str] = field(default_factory=list)
    iocs:   list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Constants & patterns
# ─────────────────────────────────────────────────────────────────────────────

# Known dangerous strings across file types
POWERSHELL_PATTERNS = [
    r"powershell\s*[-/]",
    r"Invoke-Expression",  r"IEX\s*\(",
    r"DownloadString",     r"DownloadFile",
    r"Net\.WebClient",     r"Start-Process",
    r"EncodedCommand",     r"-enc\s+[A-Za-z0-9+/=]{20,}",
    r"bypass\s+-exec",     r"Hidden\s+-NonInteractive",
    r"FromBase64String",   r"System\.Reflection\.Assembly",
    r"Invoke-Mimikatz",    r"Invoke-Shellcode",
    r"Add-MpPreference",   r"Set-MpPreference",  # AV disable
]

SHELLCODE_PATTERNS = [
    r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}",   # long hex byte strings
    r"%u[0-9a-fA-F]{4}(%u[0-9a-fA-F]{4}){8,}",        # unicode shellcode
    r"VirtualAlloc",  r"VirtualProtect",  r"CreateThread",
    r"WriteProcessMemory",  r"NtUnmapViewOfSection",
    r"RtlMoveMemory",  r"WinExec",
]

JS_OBFUSCATION_PATTERNS = [
    r"eval\s*\(",
    r"unescape\s*\(",
    r"String\.fromCharCode\s*\(",
    r"window\[.{1,30}\]\s*\(",
    r"\\u[0-9a-fA-F]{4}",
    r"atob\s*\(",
    r"decodeURIComponent\s*\(",
]

VBA_DANGEROUS = [
    "Shell",  "CreateObject",  "WScript",  "Environ",
    "AutoOpen",  "AutoExec",  "Document_Open",  "Workbook_Open",
    "MSXML2.XMLHTTP",  "ADODB.Stream",  "WScript.Shell",
    "PowerShell",  "cmd.exe",  "regsvr32",  "mshta",
    "certutil",  "bitsadmin",  "msiexec",
]

# C2 / network extraction
DOMAIN_RE  = re.compile(
    r"(?:https?://|['\"])([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+\.[a-zA-Z]{2,})"
    r"(?:/[^\s'\"<>]*)?", re.IGNORECASE
)
IP_RE      = re.compile(
    r"(?<![.\d])(\d{1,3}(?:\.\d{1,3}){3})(?![.\d])"
)
URL_RE     = re.compile(r"https?://[^\s'\"<>\x00-\x1f]{8,}", re.IGNORECASE)

# DGA pattern: long random-looking lowercase domains
DGA_RE     = re.compile(r"[a-z]{8,20}\.(ru|cn|tk|ml|ga|xyz|top|cc|su|pw)\b")

# Known benign / system domains to filter from C2 extraction
WHITELIST_DOMAINS = {
    "microsoft.com", "windows.com", "adobe.com", "apple.com",
    "google.com", "googleapis.com", "gstatic.com", "w3.org",
    "schema.org", "openxmlformats.org", "purl.org",
    "ns.adobe.com", "dublincore.org", "xmlsoap.org",
}

# Known malware family signatures (string patterns in code)
FAMILY_SIGNATURES: dict[str, list[str]] = {
    "GootLoader":     ["gootloader", "JScript", "wscript.sleep", "ActiveXObject"],
    "Emotet":         ["emotet", "C:\\Users\\Public", "cmd /c", "regsvr32 /s"],
    "Cobalt Strike":  ["cobaltstrike", "beacon", "stageless", "sleep_mask", "malleable"],
    "IcedID":         ["icedid", "bokbot", "PhotoDirector"],
    "QakBot":         ["qakbot", "quakbot", "Obama", "BB", "Biden"],
    "Ursnif":         ["ursnif", "gozi", "isfb"],
    "AgentTesla":     ["AgentTesla", "SMTP_From", "537a3c"],
    "AsyncRAT":       ["AsyncClient", "AsyncRAT", "pastebin.com/raw"],
    "njRAT":          ["njRAT", "njq8", "VBS_Backdoor"],
    "Powersploit":    ["PowerSploit", "Invoke-ReflectivePEInjection", "Invoke-Shellcode"],
    "Metasploit":     ["meterpreter", "metasploit", "Msf::Payload"],
}

# Sandbox evasion signatures
EVASION_PATTERNS: dict[str, str] = {
    r"sleep\s*\(\s*[5-9]\d{3,}":            "Long sleep call (sandbox timeout evasion)",
    r"GetTickCount\(\)":                      "Tick count check (VM/sandbox detection)",
    r"IsDebuggerPresent":                     "Debugger presence check (anti-analysis)",
    r"GetSystemInfo|cpuid":                   "CPU info check (VM detection)",
    r"vmware|virtualbox|vbox|qemu|sandbox":   "Explicit hypervisor string check",
    r"SbieDll\.dll|SandboxieDll":             "Sandboxie detection",
    r"GetUserName.*?Administrator":           "Admin username check (targeted)",
    r"CheckRemoteDebuggerPresent":            "Remote debugger detection",
    r"NtQueryInformationProcess":             "Anti-debug NtQueryInformationProcess",
    r"PROCESSOR_ARCHITECTURE.*?x86":         "Architecture check (32-bit sandbox bypass)",
    r"GetForegroundWindow\(\).*?0":          "Foreground window check (user presence)",
    r"GetCursorPos.*?mouse":                 "Mouse movement check (sandbox bypass)",
    r"RegOpenKey.*?SYSTEM\\\\CurrentControlSet\\\\Enum\\\\IDE": "Physical disk check",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _hashes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.sha256(data).hexdigest(),
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
    )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    pattern = re.compile(rb"[ -~]{%d,}" % min_len)
    return [m.group().decode("ascii", errors="replace") for m in pattern.finditer(data)]


def _parse_date(raw: str) -> Optional[datetime.datetime]:
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y:%m:%d %H:%M:%S",
        "D:%Y%m%d%H%M%S",
        "%Y%m%d%H%M%S",
    ]
    raw = raw.strip().rstrip("Z'").lstrip("D:")
    for fmt in formats:
        try:
            return datetime.datetime.strptime(raw[:len(fmt)], fmt)
        except Exception:
            continue
    return None


def _check_date_anomaly(date_str: str, field_name: str) -> Optional[MetadataAnomaly]:
    dt = _parse_date(date_str)
    if not dt:
        return None
    now  = datetime.datetime.now()
    year = dt.year

    if year > now.year + 1:
        return MetadataAnomaly(
            field=field_name, value=date_str, severity="HIGH",
            description=f"Future timestamp ({year}) — timestamp stomping to evade file-age detection"
        )
    if year < 1995:
        return MetadataAnomaly(
            field=field_name, value=date_str, severity="HIGH",
            description=f"Implausibly old timestamp ({year}) — epoch-0 or deliberate obfuscation"
        )
    if year < 2000:
        return MetadataAnomaly(
            field=field_name, value=date_str, severity="MEDIUM",
            description=f"Suspicious old timestamp ({year}) — possible timestamp manipulation"
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 1. Static metadata analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_metadata(data: bytes, filename: str, report: ForensicReport) -> None:
    """Detect metadata anomalies: timestamps, MIME mismatches, overlays."""

    ext  = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    sig4 = data[:4]
    sig8 = data[:8]

    # ── Magic byte vs extension mismatch ──────────────────────────────
    MAGIC_MAP: dict[bytes, tuple[str, str]] = {
        b"%PDF":               ("pdf",  "application/pdf"),
        b"PK\x03\x04":        ("zip",  "application/zip"),
        b"MZ":                 ("exe",  "application/x-msdownload"),
        b"\xd0\xcf\x11\xe0":  ("doc",  "application/msword"),
        b"\x1f\x8b":          ("gz",   "application/gzip"),
        b"Rar!":               ("rar",  "application/x-rar"),
        b"\x7fELF":            ("elf",  "application/x-elf"),
        b"MSCF":               ("cab",  "application/cab"),
    }

    detected_ext, detected_mime = None, None
    for magic, (m_ext, m_mime) in MAGIC_MAP.items():
        if data[:len(magic)] == magic:
            detected_ext  = m_ext
            detected_mime = m_mime
            break

    report.mime_type = detected_mime

    if detected_ext and ext and ext != detected_ext:
        # Common legitimate combo: .docx is a ZIP
        benign_combos = {("zip", "docx"), ("zip", "xlsx"), ("zip", "pptx"),
                          ("zip", "odt"), ("zip", "jar")}
        if (detected_ext, ext) not in benign_combos:
            report.mime_mismatch = True
            report.metadata_anomalies.append(MetadataAnomaly(
                field="MIME/Extension",
                value=f"Magic={detected_ext} vs Extension=.{ext}",
                severity="HIGH",
                description=(
                    f"File magic bytes indicate '{detected_ext}' but extension is '.{ext}'. "
                    f"Classic masquerading technique — file may be a '{detected_ext}' "
                    f"disguised as a '{ext}' to bypass extension-based filters."
                )
            ))
            report.flags.append(
                f"MIME mismatch: file is {detected_ext.upper()} disguised as .{ext.upper()}"
            )
            report.iocs.append(f"MIME_MISMATCH:{detected_ext}→{ext}")

    # ── Overlay data detection ─────────────────────────────────────────
    # For PDF: check if data continues after %%EOF
    if sig4 == b"%PDF":
        eof_pos = data.rfind(b"%%EOF")
        if eof_pos != -1:
            trailing = data[eof_pos + 5:].strip()
            if len(trailing) > 20:
                report.has_overlay_data   = True
                report.has_trailing_bytes = True
                report.overlay_size       = len(trailing)
                report.metadata_anomalies.append(MetadataAnomaly(
                    field="PDF Overlay",
                    value=f"{report.overlay_size} bytes after %%EOF",
                    severity="CRITICAL",
                    description=(
                        f"{report.overlay_size} bytes of data exist after PDF %%EOF marker. "
                        "PDF readers ignore this — attackers append payloads here (ZIP, PE, shellcode). "
                        "This is a hallmark of polyglot PDF/ZIP attacks (e.g., GootLoader)."
                    )
                ))
                report.flags.append(
                    f"OVERLAY DATA: {report.overlay_size}B after %%EOF — hidden payload suspected"
                )
                report.iocs.append("PDF_OVERLAY_DATA")

                # Check if overlay is a valid ZIP (polyglot)
                if trailing[:4] == b"PK\x03\x04":
                    report.is_polyglot = True
                    report.metadata_anomalies.append(MetadataAnomaly(
                        field="Polyglot File",
                        value="PDF/ZIP polyglot",
                        severity="CRITICAL",
                        description=(
                            "File is simultaneously a valid PDF AND a valid ZIP archive. "
                            "PDF readers open the document portion; ZIP extractors reveal "
                            "the hidden payload. Used by GootLoader and similar malware."
                        )
                    ))
                    report.flags.append("POLYGLOT FILE: valid PDF and ZIP simultaneously")
                    report.iocs.append("POLYGLOT_PDF_ZIP")

    # ── ZIP bomb detection (SECURITY HARDENED v6) ───────────────────
    # Three attack vectors addressed:
    #   1. Classic ratio bomb  — ratio > 100:1 via metadata
    #   2. Absolute size bomb  — uncompressed > 100MB hard cap
    #   3. Fake metadata bomb  — header claims 0 bytes; we use compress_size
    #      as a cross-check since that value must be accurate for extraction
    #   4. Nested ZIP (Matryoshka) — infolist() only sees layer-1;
    #      we flag any entry whose name ends in .zip/.gz for manual review
    if sig4 == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                entries      = zf.infolist()
                compressed   = len(data)

                # Use compress_size (actual compressed bytes) as secondary check
                total_compress_size   = sum(e.compress_size for e in entries)
                # file_size is metadata — can be spoofed; treat as advisory only
                total_file_size       = sum(e.file_size for e in entries)

                # Absolute uncompressed size guard (100 MB hard cap)
                UNCOMPRESSED_HARD_CAP = 100_000_000   # 100 MB
                if total_file_size > UNCOMPRESSED_HARD_CAP:
                    report.is_zip_bomb = True
                    report.metadata_anomalies.append(MetadataAnomaly(
                        field="ZIP Bomb (Absolute Size)",
                        value=f"Declared uncompressed size: {total_file_size:,} bytes",
                        severity="CRITICAL",
                        description=(
                            f"ZIP declares {total_file_size:,} bytes uncompressed "
                            f"(>{UNCOMPRESSED_HARD_CAP//1_000_000} MB hard cap). "
                            "Extraction would exhaust system memory/disk."
                        )
                    ))
                    report.flags.append(
                        f"ZIP BOMB (size): declared {total_file_size//1_000_000}MB uncompressed"
                    )
                    report.iocs.append("ZIP_BOMB:ABSOLUTE_SIZE")

                # Ratio check (using both declared and compress_size for cross-validation)
                if compressed > 0 and not report.is_zip_bomb:
                    ratio_declared  = total_file_size   / compressed
                    ratio_actual    = total_compress_size / max(compressed, 1)
                    report.compression_ratio = round(ratio_declared, 1)

                    if ratio_declared > 100:
                        report.is_zip_bomb = True
                        report.metadata_anomalies.append(MetadataAnomaly(
                            field="ZIP Bomb (Ratio)",
                            value=f"Compression ratio {ratio_declared:.0f}:1",
                            severity="CRITICAL",
                            description=(
                                f"ZIP compression ratio of {ratio_declared:.0f}:1 indicates a "
                                "decompression bomb. Designed to exhaust system resources."
                            )
                        ))
                        report.flags.append(f"ZIP BOMB: {ratio_declared:.0f}:1 compression ratio")
                        report.iocs.append(f"ZIP_BOMB:{ratio_declared:.0f}x")

                    # Metadata spoofing detection: if declared size differs wildly
                    # from compress_size in a suspicious direction
                    elif total_file_size == 0 and total_compress_size > 0:
                        report.metadata_anomalies.append(MetadataAnomaly(
                            field="ZIP Metadata Anomaly",
                            value="file_size=0 but compress_size>0",
                            severity="HIGH",
                            description=(
                                "ZIP entries declare 0 uncompressed size but have compressed data. "
                                "This may indicate metadata spoofing to bypass ratio-based ZIP bomb "
                                "detection — the actual decompressed size is unknown without extraction."
                            )
                        ))
                        report.flags.append("ZIP metadata spoofing: file_size=0 with real data")
                        report.iocs.append("ZIP_METADATA_SPOOF")

                # Nested ZIP detection (Matryoshka / recursive bomb)
                nested = [
                    e.filename for e in entries
                    if e.filename.lower().endswith((".zip", ".gz", ".tar", ".7z", ".rar"))
                ]
                if nested:
                    report.metadata_anomalies.append(MetadataAnomaly(
                        field="Nested Archives",
                        value=f"{len(nested)} archive(s) inside ZIP: {nested[:3]}",
                        severity="HIGH",
                        description=(
                            f"ZIP contains {len(nested)} nested archive(s) "
                            f"({', '.join(nested[:3])}). Recursive extraction (Matryoshka/42.zip "
                            "style) can bypass single-layer ratio checks and exhaust resources. "
                            "Do NOT extract without a recursive depth/size-limited tool."
                        )
                    ))
                    report.flags.append(
                        f"NESTED ARCHIVES: {len(nested)} archive(s) inside — possible Matryoshka bomb"
                    )
                    report.iocs.append(f"NESTED_ARCHIVES:{len(nested)}")

        except Exception:
            pass

    # ── File size anomaly ──────────────────────────────────────────────
    if report.file_size > 50_000_000:
        report.metadata_anomalies.append(MetadataAnomaly(
            field="File Size",
            value=f"{report.file_size:,} bytes",
            severity="MEDIUM",
            description="Very large file — may contain embedded payload padded to evade size-based filters."
        ))


# ─────────────────────────────────────────────────────────────────────────────
# 2a. PDF forensics
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_pdf(data: bytes, report: ForensicReport) -> list[str]:
    """Deep PDF structure analysis. Returns extracted text corpus."""
    text   = data.decode("latin-1", errors="ignore")
    corpus = []

    # ── PDF action tree ────────────────────────────────────────────────
    pdf_dangerous = {
        "/JS":            ("JavaScript",       "CRITICAL", "Executes JavaScript on document open"),
        "/JavaScript":    ("JavaScript",       "CRITICAL", "JavaScript action object"),
        "/OpenAction":    ("Auto-Execute",     "HIGH",     "Action runs automatically when PDF opens"),
        "/AA":            ("Additional Action","HIGH",     "Triggers on page view/close/keystroke"),
        "/Launch":        ("Launch Action",    "CRITICAL", "Launches external process or file"),
        "/EmbeddedFiles": ("Embedded File",    "HIGH",     "File embedded within PDF stream"),
        "/EmbeddedFile":  ("Embedded File",    "HIGH",     "Embedded file object"),
        "/RichMedia":     ("Rich Media",       "MEDIUM",   "Flash/video — exploit surface"),
        "/XFA":           ("XFA Form",         "MEDIUM",   "XML Forms Architecture — complex attack surface"),
        "/AcroForm":      ("Acro Form",        "LOW",      "Interactive form (can trigger JS on submit)"),
        "/URI":           ("URI Action",       "MEDIUM",   "External URL action"),
        "/SubmitForm":    ("Form Submit",      "MEDIUM",   "Submits data to external server"),
        "/ImportData":    ("Import Data",      "HIGH",     "Imports data from external source"),
    }

    found_actions = []
    for key, (label, sev, desc) in pdf_dangerous.items():
        if key in text:
            count = text.count(key)
            found_actions.append(f"{key}({count}×)")
            report.metadata_anomalies.append(MetadataAnomaly(
                field=f"PDF {label}", value=f"{key} × {count}", severity=sev,
                description=desc
            ))
            if key in ("/JS", "/JavaScript"):
                report.has_javascript = True
                report.flags.append(f"PDF JavaScript: {key} found {count}× in document")
                report.iocs.append(f"PDF_{key.strip('/')}")
            if key == "/Launch":
                report.flags.append("PDF /Launch action — executes arbitrary OS commands")
                report.iocs.append("PDF_LAUNCH_ACTION")
            if key == "/OpenAction":
                report.has_auto_exec = True
                report.flags.append("PDF /OpenAction — payload triggers on document open")
            if key in ("/EmbeddedFiles", "/EmbeddedFile"):
                report.has_embedded_files = True

    if found_actions:
        report.flags.append(f"PDF dangerous actions: {', '.join(found_actions)}")

    # ── Suspicious JavaScript extraction ──────────────────────────────
    js_blocks = re.findall(
        r"(?:/JS|/JavaScript)\s*\(([^)]{10,})\)", text, re.DOTALL
    ) + re.findall(
        r"stream\s*\n(.*?)\nendstream", text, re.DOTALL
    )
    for block in js_blocks[:3]:
        corpus.append(block[:2000])

    # ── Metadata extraction ────────────────────────────────────────────
    def _pdf_val(key: str) -> Optional[str]:
        m = re.search(rf"/{key}\s*\(([^)]*)\)", text)
        if m:
            return m.group(1).strip()
        m = re.search(rf"/{key}\s*<([0-9a-fA-F]+)>", text)
        if m:
            try:
                return bytes.fromhex(m.group(1)).decode("utf-16-be", errors="ignore").strip()
            except Exception:
                pass
        return None

    author   = _pdf_val("Author")
    creator  = _pdf_val("Creator") or _pdf_val("Producer")
    created  = _pdf_val("CreationDate")
    modified = _pdf_val("ModDate")

    if author:
        if author.lower() in {"admin", "user", "test", "unknown", "document"}:
            report.metadata_anomalies.append(MetadataAnomaly(
                field="Author", value=author, severity="MEDIUM",
                description=f"Generic author name '{author}' — documents mass-produced by phishing kits often use placeholder names"
            ))

    if created:
        anomaly = _check_date_anomaly(created, "CreationDate")
        if anomaly:
            report.timestamp_anomaly = True
            report.metadata_anomalies.append(anomaly)
            report.flags.append(f"Timestamp anomaly: {anomaly.description}")

    # ── Phishing kit creator tools ─────────────────────────────────────
    kit_tools = [
        "msfvenom", "metasploit", "empire", "cobalt", "cobaltstrike",
        "pdfkit 0.8", "fpdf 1.6",   # old versions often in phishing kits
        "reportlab 1", "wkhtmltopdf 0.",
    ]
    for tool in kit_tools:
        if creator and tool in creator.lower():
            report.metadata_anomalies.append(MetadataAnomaly(
                field="Creator Tool", value=creator, severity="CRITICAL",
                description=f"Creator tool '{creator}' is a known attack framework component"
            ))
            report.flags.append(f"Malware tool in creator: {creator}")
            report.iocs.append(f"CREATOR_TOOL:{creator}")

    # ── Encryption ────────────────────────────────────────────────────
    if "/Encrypt" in text:
        report.evasion_techniques.append(
            "PDF encryption used — AV engines cannot inspect encrypted stream content"
        )
        report.flags.append("PDF is encrypted — stream content hidden from static scanners")

    # ── Object count anomaly ──────────────────────────────────────────
    obj_count = len(re.findall(r"\d+ \d+ obj", text))
    if obj_count > 500:
        report.evasion_techniques.append(
            f"Excessive PDF objects ({obj_count}) — object confusion / obfuscation technique"
        )

    return corpus


# ─────────────────────────────────────────────────────────────────────────────
# 2b. Office / OOXML forensics
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_office(data: bytes, filename: str, report: ForensicReport) -> list[str]:
    """Analyse Office OOXML (ZIP-based) and legacy OLE2 documents."""
    corpus = []

    if data[:4] == b"PK\x03\x04":
        # ── SECURITY: Hard-stop if ZIP bomb was already detected ───────
        # Without this guard, is_zip_bomb=True is set but ZipFile still
        # opens and reads the content, defeating the detection entirely.
        if report.is_zip_bomb:
            report.flags.append(
                "⛔ Office content extraction BLOCKED — ZIP bomb detected. "
                "File will NOT be decompressed."
            )
            return corpus

        # ── OOXML ─────────────────────────────────────────────────────
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()

                # VBA macro detection
                vba_files = [n for n in names if "vbaProject" in n or n.endswith(".bin")]
                if vba_files:
                    report.has_macros = True
                    for vf in vba_files:
                        try:
                            vba_raw  = zf.read(vf)
                            vba_text = vba_raw.decode("latin-1", errors="ignore")
                            corpus.append(vba_text[:3000])

                            # Auto-exec triggers
                            auto_triggers = [
                                "AutoOpen", "AutoExec", "Auto_Open",
                                "Document_Open", "Workbook_Open",
                                "AutoClose", "Document_Close",
                            ]
                            found_triggers = [t for t in auto_triggers if t in vba_text]
                            if found_triggers:
                                report.has_auto_exec = True
                                report.flags.append(
                                    f"VBA auto-execute triggers: {', '.join(found_triggers)}"
                                )
                                report.iocs.append(f"VBA_AUTO_EXEC:{found_triggers[0]}")

                            # Dangerous VBA calls
                            found_dangerous = [k for k in VBA_DANGEROUS if k in vba_text]
                            if found_dangerous:
                                report.flags.append(
                                    f"Dangerous VBA calls: {', '.join(found_dangerous[:6])}"
                                )
                                report.iocs.append("VBA_DANGEROUS_CALLS")

                            # PowerShell in VBA
                            if re.search(r"powershell|cmd\.exe|wscript|cscript",
                                         vba_text, re.IGNORECASE):
                                report.has_powershell = True
                                report.flags.append("PowerShell/Shell execution inside VBA macro")
                                report.iocs.append("VBA_SHELL_EXEC")

                            # Obfuscation: string concatenation, Chr() spam
                            chr_count = vba_text.lower().count("chr(")
                            if chr_count > 20:
                                report.metadata_anomalies.append(MetadataAnomaly(
                                    field="VBA Obfuscation",
                                    value=f"Chr() called {chr_count}×",
                                    severity="HIGH",
                                    description=(
                                        f"VBA uses Chr() {chr_count} times to assemble strings "
                                        "character-by-character — classic obfuscation to hide "
                                        "URLs, commands, or shellcode from static scanners."
                                    )
                                ))
                                report.evasion_techniques.append(
                                    f"VBA string obfuscation via Chr() × {chr_count}"
                                )

                        except Exception as e:
                            report.errors.append(f"VBA parse error: {e}")

                # Embedded OLE objects
                ole_objects = [n for n in names if "embeddings" in n.lower()]
                if ole_objects:
                    report.has_embedded_files = True
                    report.flags.append(
                        f"{len(ole_objects)} OLE embedded object(s): {', '.join(ole_objects[:3])}"
                    )

                # Metadata from core.xml
                if "docProps/core.xml" in names:
                    core = zf.read("docProps/core.xml").decode("utf-8", errors="ignore")
                    for tag in ["creator", "lastModifiedBy"]:
                        m = re.search(rf"<[^>]*:{tag}[^>]*>([^<]+)<", core)
                        if m:
                            author = m.group(1).strip()
                            if author.lower() in {"admin", "user", "test", "administrator"}:
                                report.metadata_anomalies.append(MetadataAnomaly(
                                    field=tag, value=author, severity="MEDIUM",
                                    description=f"Generic author '{author}' — phishing kit placeholder"
                                ))
                    # Check dates
                    for tag in ["created", "modified"]:
                        m = re.search(rf"<[^>]*:{tag}[^>]*>([^<]+)<", core)
                        if m:
                            anomaly = _check_date_anomaly(m.group(1), tag)
                            if anomaly:
                                report.timestamp_anomaly = True
                                report.metadata_anomalies.append(anomaly)

        except zipfile.BadZipFile:
            report.errors.append("File has ZIP header but is corrupt/truncated")

    elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        # ── Legacy OLE2 (doc, xls, ppt) ──────────────────────────────
        report.has_macros = True
        text = data.decode("latin-1", errors="ignore")
        corpus.append(text[:4000])

        report.metadata_anomalies.append(MetadataAnomaly(
            field="Format",
            value="Legacy OLE2 (BIFF/DOC/XLS)",
            severity="MEDIUM",
            description=(
                "Legacy Office format. Modern Office uses OOXML. "
                "Legacy formats are preferred by malware as they support "
                "macros without the 'Enable Macros' prompt in older Office versions."
            )
        ))

        found_triggers = [t for t in ["AutoOpen", "AutoExec", "Document_Open"] if t in text]
        if found_triggers:
            report.has_auto_exec = True
            report.flags.append(f"OLE2 auto-exec: {', '.join(found_triggers)}")

    return corpus


# ─────────────────────────────────────────────────────────────────────────────
# 2c. PE (Windows executable) forensics
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_pe(data: bytes, report: ForensicReport) -> list[str]:
    """PE header + import analysis."""
    corpus = []
    text   = data.decode("latin-1", errors="ignore")
    corpus.append(text[:4000])

    if data[:2] != b"MZ":
        return corpus

    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return corpus

        # Timestamp
        ts = struct.unpack_from("<I", data, pe_offset + 8)[0]
        if ts != 0:
            dt = datetime.datetime.utcfromtimestamp(ts)
            anomaly = _check_date_anomaly(dt.strftime("%Y-%m-%d %H:%M:%S"), "PE Compile Timestamp")
            if anomaly:
                report.timestamp_anomaly = True
                report.metadata_anomalies.append(anomaly)
        else:
            report.metadata_anomalies.append(MetadataAnomaly(
                field="PE Compile Timestamp",
                value="0 (zeroed)",
                severity="HIGH",
                description="Compile timestamp is zeroed — timestamp stomping to defeat AV heuristics"
            ))
            report.evasion_techniques.append("PE timestamp stomping (zeroed compile time)")

        # Section entropy
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        opt_size     = struct.unpack_from("<H", data, pe_offset + 20)[0]
        sec_offset   = pe_offset + 24 + opt_size

        for i in range(min(num_sections, 16)):
            off = sec_offset + i * 40
            if off + 40 > len(data):
                break
            name     = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            raw_size = struct.unpack_from("<I", data, off + 16)[0]
            raw_off  = struct.unpack_from("<I", data, off + 20)[0]
            sec_data = data[raw_off:raw_off + raw_size]
            ent      = _entropy(sec_data)

            if ent > 7.2:
                report.metadata_anomalies.append(MetadataAnomaly(
                    field=f"PE Section {name}",
                    value=f"Entropy={ent:.2f}",
                    severity="HIGH",
                    description=(
                        f"Section '{name}' has entropy {ent:.2f}/8.0 — "
                        "indicates packed, encrypted, or compressed code. "
                        "Packers/crypters are used to defeat signature-based AV."
                    )
                ))
                report.flags.append(f"High-entropy PE section '{name}' (H={ent:.2f}) — packed/encrypted")
                report.iocs.append(f"PE_PACKED_SECTION:{name}")
                report.evasion_techniques.append(f"PE packing/encryption in section {name} (entropy {ent:.2f})")

    except Exception as e:
        report.errors.append(f"PE parse error: {e}")

    return corpus


# ─────────────────────────────────────────────────────────────────────────────
# 2d. Universal pattern scanning
# ─────────────────────────────────────────────────────────────────────────────

def _scan_patterns(corpus: list[str], report: ForensicReport) -> None:
    """Scan all extracted text for dangerous code patterns."""
    full_text = "\n".join(corpus)

    # PowerShell
    for pat in POWERSHELL_PATTERNS:
        if re.search(pat, full_text, re.IGNORECASE):
            report.has_powershell = True
            match = re.search(pat, full_text, re.IGNORECASE)
            if match:
                snippet = full_text[max(0, match.start()-20):match.end()+40].strip()
                report.flags.append(f"PowerShell pattern: {pat[:40]} → …{snippet[:60]}…")
                report.iocs.append(f"PS_PATTERN:{pat[:30]}")
            break

    # Shellcode
    for pat in SHELLCODE_PATTERNS:
        if re.search(pat, full_text, re.IGNORECASE):
            report.has_shellcode = True
            report.flags.append(f"Shellcode pattern detected: {pat[:50]}")
            report.iocs.append("SHELLCODE_PATTERN")
            break

    # JS obfuscation
    for pat in JS_OBFUSCATION_PATTERNS:
        if re.search(pat, full_text, re.IGNORECASE):
            if not report.has_javascript:
                report.has_javascript = True
            report.evasion_techniques.append(f"JS obfuscation: {pat[:40]}")
            break

    # Sandbox evasion
    for pat, desc in EVASION_PATTERNS.items():
        if re.search(pat, full_text, re.IGNORECASE):
            report.environment_keyed = True
            report.evasion_techniques.append(desc)
            report.flags.append(f"Sandbox evasion: {desc}")

    # Malware family attribution (static signatures)
    for family, sigs in FAMILY_SIGNATURES.items():
        matched = [s for s in sigs if s.lower() in full_text.lower()]
        if len(matched) >= 2:
            report.nlp_malware_family = family
            report.flags.append(
                f"Malware family signature match: {family} "
                f"({', '.join(matched[:3])})"
            )
            report.iocs.append(f"FAMILY:{family}")
            break


# ─────────────────────────────────────────────────────────────────────────────
# 3. C2 / network indicator extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_network_indicators(data: bytes, report: ForensicReport) -> None:
    """Extract domains, IPs, URLs from file strings."""
    strings = _extract_strings(data, min_len=8)
    full    = "\n".join(strings)

    # URLs first (most specific)
    for m in URL_RE.finditer(full):
        url = m.group().rstrip(".,;)")
        if len(url) < 200:
            report.extracted_urls.append(url)

    # Domains
    for m in DOMAIN_RE.finditer(full):
        domain = m.group(1).lower()
        # Filter system/benign domains
        parts  = domain.split(".")
        root   = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        if root not in WHITELIST_DOMAINS and len(domain) > 5:
            report.extracted_domains.append(domain)

    # IPs (filter private ranges)
    for m in IP_RE.finditer(full):
        ip = m.group(1)
        parts = [int(x) for x in ip.split(".")]
        if parts[0] not in {10, 127, 169, 172, 192}:  # rough private filter
            report.extracted_ips.append(ip)

    # DGA pattern detection
    dga_hits = DGA_RE.findall(full)
    if len(dga_hits) >= 3:
        report.has_dga_pattern = True
        report.flags.append(
            f"DGA pattern detected: {len(dga_hits)} random-looking domains "
            f"with high-abuse TLDs ({', '.join(set(dga_hits[:4]))})"
        )
        report.iocs.append(f"DGA_DOMAINS:{len(dga_hits)}")

    # Deduplicate
    report.extracted_domains = list(dict.fromkeys(report.extracted_domains))[:20]
    report.extracted_ips     = list(dict.fromkeys(report.extracted_ips))[:10]
    report.extracted_urls    = list(dict.fromkeys(report.extracted_urls))[:10]

    # Build C2Indicator objects for suspicious findings
    for domain in report.extracted_domains[:5]:
        report.c2_indicators.append(C2Indicator(
            indicator=domain, ioc_type="DOMAIN",
            context="Extracted from file strings",
            confidence="MEDIUM" if any(
                tld in domain for tld in [".tk",".ml",".ga",".xyz",".ru",".cn"]
            ) else "LOW"
        ))

    for ip in report.extracted_ips[:3]:
        report.c2_indicators.append(C2Indicator(
            indicator=ip, ioc_type="IP",
            context="Hardcoded IP in file",
            confidence="HIGH"
        ))


# ─────────────────────────────────────────────────────────────────────────────
# 4. Container discrepancy analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_discrepancy(report: ForensicReport) -> None:
    """
    Determine why the file might appear clean in a container but
    malicious as a standalone hash.
    """
    reasons: list[str] = []

    if report.is_polyglot:
        reasons.append(
            "POLYGLOT ATTACK: The file is simultaneously a valid PDF and a valid ZIP. "
            "PDF scanners see a PDF and scan the document portion (which is clean). "
            "Hash-based scanners flag the entire file byte sequence. "
            "The malicious payload is in the ZIP portion, extracted by the OS or a second tool."
        )
        report.is_dormant = True

    if report.has_overlay_data:
        reasons.append(
            "OVERLAY PAYLOAD: Data exists after the PDF %%EOF marker. "
            "AV tools that parse the PDF structure stop at %%EOF and report clean. "
            "The hash covers the entire file including the hidden overlay. "
            "The overlay is only processed when a secondary tool (unzip, script) acts on it."
        )

    if report.environment_keyed:
        reasons.append(
            "ENVIRONMENT KEYING: The embedded code checks for specific OS conditions "
            "(debugger presence, username, screen resolution, tick count) before executing. "
            "In a sandbox, these checks fail → payload stays dormant → sandbox reports clean. "
            "On a real user machine, conditions pass → payload executes."
        )
        report.is_dormant = True

    if report.evasion_techniques and "sleep" in str(report.evasion_techniques).lower():
        reasons.append(
            "SANDBOX TIMEOUT EVASION: Long sleep() calls cause the malware to wait longer "
            "than the sandbox's analysis window. Sandbox reports no malicious activity. "
            "On real systems, the user leaves the file open long enough for payload activation."
        )

    if report.has_javascript and "/Encrypt" in str(report.metadata_anomalies):
        reasons.append(
            "ENCRYPTED STREAM EVASION: JavaScript is inside an encrypted PDF stream. "
            "Static scanners cannot read encrypted content → report clean. "
            "Hash of the encrypted file differs from hash of the decrypted version → VT miss."
        )

    if report.has_macros and not report.has_auto_exec:
        reasons.append(
            "USER-TRIGGERED DORMANCY: VBA macros are present but only execute when the user "
            "enables macros (clicks 'Enable Content'). Automated sandbox analysis may "
            "not simulate this interaction → sandbox reports no malicious behavior. "
            "Hash includes the macro code → behavioural engines flag it."
        )
        report.is_dormant = True

    if not reasons:
        reasons.append(
            "SIGNATURE MISMATCH: The file's specific byte sequence matches a known "
            "malicious hash in threat intelligence databases (hash-based detection), "
            "but the container's structural parsing may miss embedded logic if "
            "the parser doesn't fully reconstruct the malicious context."
        )

    report.discrepancy_reason = "\n\n".join(reasons)


# ─────────────────────────────────────────────────────────────────────────────
# 5. AI NLP analysis via Ollama
# ─────────────────────────────────────────────────────────────────────────────

_NLP_SYSTEM = """You are a senior malware analyst and reverse engineer at a Tier-1 SOC.
You have received extracted text/code from a suspicious file for deep NLP analysis.

Analyse the provided code/text and produce a structured JSON response ONLY:
{
  "intent_label": "BENIGN" | "SUSPICIOUS" | "MALICIOUS",
  "malware_family": "<family name or null>",
  "execution_flow": "<one paragraph: how does this progress from delivery to execution>",
  "key_indicators": ["<indicator 1>", "<indicator 2>", ...],
  "engine_divergence": "<why would CrowdStrike/SentinelOne flag this but weaker engines miss it>",
  "summary": "<2-3 sentence executive summary>"
}

Be specific. Reference actual strings or patterns you observe. If the code is benign, explain why."""


def _ai_nlp_analysis(corpus: list[str], filename: str, ollama_model: str = "phi3:mini") -> dict:
    """Send extracted code/text to Ollama for NLP-driven intent analysis."""
    if not corpus:
        return {}

    content = "\n\n---\n\n".join(corpus[:3])[:4000]
    prompt  = (
        f"File: {filename}\n\n"
        f"Extracted content for analysis:\n\n{content}\n\n"
        "Provide your forensic analysis as JSON."
    )

    try:
        import ollama
        import json
        import re as re2

        response = ollama.chat(
            model=ollama_model,
            messages=[
                {"role": "system", "content": _NLP_SYSTEM},
                {"role": "user",   "content": prompt},
            ],
            options={"temperature": 0.05, "num_predict": 800},
        )
        raw = response["message"]["content"]
        # Extract JSON
        m = re2.search(r"\{.*\}", raw, re2.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception as e:
        return {"error": str(e)}

    return {}


# ─────────────────────────────────────────────────────────────────────────────
# 6. VirusTotal deep-dive
# ─────────────────────────────────────────────────────────────────────────────

def _vt_deep_lookup(sha256: str, api_key: str) -> dict:
    import requests as req
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        r = req.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers, timeout=12
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return {"not_found": True}
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _parse_vt_deep(vt_data: dict, report: ForensicReport) -> None:
    if not vt_data or "not_found" in vt_data or "error" in vt_data:
        if "error" in (vt_data or {}):
            report.errors.append(f"VirusTotal: {vt_data['error']}")
        elif "not_found" in (vt_data or {}):
            report.errors.append("Hash not in VirusTotal — first submission or very new file")
        return

    attrs  = vt_data.get("data", {}).get("attributes", {})
    stats  = attrs.get("last_analysis_stats", {})
    report.vt_malicious  = stats.get("malicious", 0)
    report.vt_suspicious = stats.get("suspicious", 0)
    report.vt_harmless   = stats.get("harmless", 0)
    report.vt_total      = sum(stats.values()) if stats else 0
    report.vt_tags       = attrs.get("tags", [])[:10]

    family_info = attrs.get("popular_threat_classification", {})
    if family_info:
        report.vt_family = family_info.get("suggested_threat_label")

    # Engine divergence analysis
    results = attrs.get("last_analysis_results", {})
    flagging_engines  = [e for e, v in results.items() if v.get("category") == "malicious"]
    clean_engines     = [e for e, v in results.items() if v.get("category") == "harmless"]

    tier1 = ["CrowdStrike", "SentinelOne", "Kaspersky", "ESET", "Sophos",
              "Bitdefender", "Carbon Black", "Cybereason"]
    tier1_flagging = [e for e in flagging_engines if any(t in e for t in tier1)]

    if tier1_flagging and report.vt_malicious < report.vt_total * 0.5:
        report.engine_divergence_reason = (
            f"TIER-1 DIVERGENCE: {', '.join(tier1_flagging[:3])} flag this file, "
            f"but only {report.vt_malicious}/{report.vt_total} engines agree. "
            f"This pattern is typical of: (1) new/zero-day malware that only advanced "
            f"behavioural engines detect via heuristics, (2) packed/obfuscated payloads "
            f"where signature engines see the packer (clean) not the payload (malicious), "
            f"(3) environment-keyed malware that only activates in specific conditions — "
            f"simpler sandbox engines report clean because the payload never fires."
        )
    elif report.vt_malicious == 0 and report.vt_total > 0:
        report.engine_divergence_reason = (
            "CLEAN HASH: All VT engines report clean. If the file was flagged elsewhere, "
            "it may be: (1) a false positive from a custom YARA rule, "
            "(2) a newly created variant not yet in VT, "
            "(3) the hash computed from a modified version of the file."
        )
    elif report.vt_malicious >= 20:
        report.engine_divergence_reason = (
            f"BROAD CONSENSUS: {report.vt_malicious}/{report.vt_total} engines agree — "
            "this is a well-known malicious file with established signatures. "
            "The 'clean' appearance in a container is definitely evasion, not a false positive."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 7. Final scoring & verdict
# ─────────────────────────────────────────────────────────────────────────────

def _compute_verdict(report: ForensicReport) -> None:
    score = 0

    # VT score
    if report.vt_malicious >= 20: score += 50
    elif report.vt_malicious >= 5:  score += 35
    elif report.vt_malicious >= 1:  score += 20

    # Structural findings
    if report.is_polyglot:          score += 30
    if report.has_overlay_data:     score += 25
    if report.has_auto_exec:        score += 20
    if report.has_shellcode:        score += 25
    if report.has_macros:           score += 10
    if report.has_javascript:       score += 10
    if report.has_powershell:       score += 15
    if report.mime_mismatch:        score += 15
    if report.timestamp_anomaly:    score += 8
    if report.is_zip_bomb:          score += 20
    if report.environment_keyed:    score += 15
    if report.has_dga_pattern:      score += 15
    if report.evasion_techniques:   score += min(len(report.evasion_techniques) * 5, 20)

    # NLP verdict
    if report.nlp_intent_label == "MALICIOUS":  score += 20
    elif report.nlp_intent_label == "SUSPICIOUS": score += 10

    report.risk_score = min(score, 100)

    # Threat level
    if report.risk_score >= 80: report.threat_level = "CRITICAL"
    elif report.risk_score >= 60: report.threat_level = "HIGH"
    elif report.risk_score >= 35: report.threat_level = "MEDIUM"
    elif report.risk_score >= 15: report.threat_level = "LOW"
    else: report.threat_level = "SAFE"

    # True / False positive verdict
    strong_positives = sum([
        report.vt_malicious >= 5,
        report.has_auto_exec,
        report.has_shellcode,
        report.is_polyglot,
        report.has_overlay_data,
        report.has_powershell and report.has_macros,
        report.nlp_intent_label == "MALICIOUS",
    ])

    if strong_positives >= 3:
        report.final_verdict = "TRUE_POSITIVE"
        report.confidence = 90
    elif strong_positives >= 2:
        report.final_verdict = "TRUE_POSITIVE"
        report.confidence = 72
    elif strong_positives == 1:
        report.final_verdict = "LIKELY_MALICIOUS"
        report.confidence = 55
    elif report.risk_score < 15 and report.vt_malicious == 0:
        report.final_verdict = "LIKELY_FALSE_POSITIVE"
        report.confidence = 65
    else:
        report.final_verdict = "INCONCLUSIVE"
        report.confidence = 40

    # Executive summary
    report.executive_summary = (
        f"File '{report.file_type}' (SHA-256: {(report.sha256 or 'N/A')[:16]}…) "
        f"scored {report.risk_score}/100 [{report.threat_level}]. "
        f"Verdict: {report.final_verdict} (confidence {report.confidence}%). "
    )
    if report.nlp_malware_family or report.vt_family:
        family = report.nlp_malware_family or report.vt_family
        report.executive_summary += f"Attributed to {family} malware family. "
    if report.evasion_techniques:
        report.executive_summary += (
            f"{len(report.evasion_techniques)} evasion technique(s) identified: "
            f"{report.evasion_techniques[0][:80]}."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def deep_forensic_analysis(
    data:          bytes,
    filename:      str          = "unknown",
    vt_api_key:    Optional[str] = None,
    ollama_model:  str           = "phi3:mini",
) -> ForensicReport:
    """
    Run complete multi-layer forensic analysis on file bytes.

    Args:
        data:         Raw file bytes.
        filename:     Original filename (used for extension/MIME checks).
        vt_api_key:   VirusTotal API key for cloud hash lookup.
        ollama_model: Ollama model for NLP analysis.

    Returns:
        ForensicReport with all findings populated.
    """
    report           = ForensicReport()
    report.file_size = len(data)
    report.sha256, report.md5, report.sha1 = _hashes(data)

    # Detect file type
    sig4 = data[:4]
    if sig4 == b"%PDF":
        report.file_type = "PDF Document"
    elif data[:2] == b"MZ":
        report.file_type = "Windows Executable (PE)"
    elif sig4 == b"PK\x03\x04":
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        report.file_type = {
            "docx": "Word Document (OOXML)",
            "xlsx": "Excel Workbook (OOXML)",
            "pptx": "PowerPoint (OOXML)",
            "xlsm": "Excel Macro-Enabled",
            "docm": "Word Macro-Enabled",
        }.get(ext, "ZIP Archive / OOXML")
    elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        report.file_type = "Legacy Office Document (OLE2)"
    elif data[:4] == b"Rar!":
        report.file_type = "RAR Archive"
    else:
        report.file_type = "Unknown/Binary"

    corpus: list[str] = []

    # ── 1. Metadata analysis ──────────────────────────────────────────
    _analyse_metadata(data, filename, report)

    # ── 2. Content inspection ─────────────────────────────────────────
    # SECURITY: If ZIP bomb detected in metadata phase, skip ALL content
    # extraction to prevent decompression. Score is already set.
    if report.is_zip_bomb:
        report.flags.append(
            "⛔ Content extraction SKIPPED — ZIP bomb detected in metadata phase."
        )
        # Skip to scoring — bomb flag contributes +20 pts already
    elif "PDF" in report.file_type:
        corpus.extend(_analyse_pdf(data, report))
    elif "Office" in report.file_type or "Word" in report.file_type \
            or "Excel" in report.file_type or "ZIP" in report.file_type \
            or "PowerPoint" in report.file_type:
        corpus.extend(_analyse_office(data, filename, report))
    elif "PE" in report.file_type or "Executable" in report.file_type:
        corpus.extend(_analyse_pe(data, report))
    else:
        # Generic: extract all strings
        corpus.append(data.decode("latin-1", errors="ignore")[:5000])

    # ── 3. Pattern scanning ───────────────────────────────────────────
    _scan_patterns(corpus, report)

    # ── 4. Network indicator extraction ──────────────────────────────
    _extract_network_indicators(data, report)

    # ── 5. Container discrepancy ──────────────────────────────────────
    _analyse_discrepancy(report)

    # ── 6. AI NLP analysis ───────────────────────────────────────────
    if corpus:
        nlp = _ai_nlp_analysis(corpus, filename, ollama_model)
        if nlp and "intent_label" in nlp:
            report.nlp_intent_label   = nlp.get("intent_label", "UNKNOWN")
            report.nlp_summary        = nlp.get("summary", "")
            report.nlp_execution_flow = nlp.get("execution_flow", "")
            report.nlp_engine_used    = ollama_model
            if nlp.get("malware_family") and not report.nlp_malware_family:
                report.nlp_malware_family = nlp.get("malware_family")
            if nlp.get("engine_divergence"):
                report.engine_divergence_reason = (
                    report.engine_divergence_reason + "\n\n" + nlp["engine_divergence"]
                ).strip()
            for ind in nlp.get("key_indicators", [])[:5]:
                report.flags.append(f"AI: {ind}")
        elif "error" in (nlp or {}):
            report.errors.append(f"AI NLP: {nlp['error']}")

    # ── 7. VirusTotal deep lookup ─────────────────────────────────────
    if vt_api_key and report.sha256:
        vt_data = _vt_deep_lookup(report.sha256, vt_api_key)
        _parse_vt_deep(vt_data, report)

    # ── 8. Score + verdict ────────────────────────────────────────────
    _compute_verdict(report)

    # Populate IOC list
    report.iocs = list(dict.fromkeys(report.iocs))
    if report.sha256:
        report.iocs.insert(0, f"SHA256:{report.sha256[:16]}…")

    return report
