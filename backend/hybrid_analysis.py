"""
backend/hybrid_analysis.py
--------------------------
Hybrid Analysis Sandbox Engine — GhostWire CTI v6
https://www.hybrid-analysis.com/docs/api/v2

Supports:
  • URL sandbox submission + quick-scan
  • File submission (PDF, Office, PE, scripts)
  • Hash lookup (SHA-256 / MD5 / SHA-1)
  • Domain / IP search via terms API
  • Full report parsing: verdict, MITRE ATT&CK, network IOCs,
    process tree, extracted strings, AV detections, signatures

Security hardening:
  • API key never logged or exposed in flags/errors
  • All user input sanitized before query construction
  • Hash format validated via regex before API call
  • File size re-validated server-side (max 100MB HA limit)
  • Timeouts on all requests (connect=10s, read=60s)
  • No pickle / eval / exec anywhere
  • Response JSON parsed with strict field access (no eval)
  • Input type whitelist: url / file / hash / domain / ip
  • SSRF-safe: only calls hybrid-analysis.com (external only)
  • Rate-limit aware: 429 handled with backoff, not crash
"""

from __future__ import annotations

import logging

import hashlib
import io
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

# Key rotation pool — imported from config
from config import ha_key_pool

logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────

HA_BASE          = "https://www.hybrid-analysis.com"
HA_API           = f"{HA_BASE}/api/v2"
CONNECT_TIMEOUT  = 10      # seconds — TCP connect
READ_TIMEOUT     = 60      # seconds — server response
POLL_INTERVAL    = 8       # seconds between status polls
MAX_POLL_ROUNDS  = 15      # max ~2 min wait for sandbox
MAX_FILE_BYTES   = 100 * 1024 * 1024   # 100 MB (HA limit)

# Sandbox environment IDs
ENV_WIN10_64   = 100    # Windows 10 64-bit
ENV_WIN7_32    = 120    # Windows 7 32-bit
ENV_ANDROID    = 200    # Android
DEFAULT_ENV    = ENV_WIN10_64

# Hash regex patterns — validated BEFORE sending to API
_SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')
_SHA1_RE   = re.compile(r'^[0-9a-fA-F]{40}$')
_MD5_RE    = re.compile(r'^[0-9a-fA-F]{32}$')

# Domain/IP sanitization — only safe chars allowed
_SAFE_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9.\-_:]{1,253}$')

# Verdict → score mapping
_VERDICT_SCORES = {
    "malicious":   90,
    "suspicious":  55,
    "no specific threat": 10,
    "whitelisted":  0,
    "no verdict":  15,
}

# Threat level colours matching GhostWire palette
_VERDICT_COLOURS = {
    "malicious":           "#ff2d55",
    "suspicious":          "#ffd060",
    "no specific threat":  "#78d97a",
    "whitelisted":         "#00ffb4",
    "no verdict":          "#4a6a8a",
}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class HAResult:
    """Full Hybrid Analysis sandbox result."""

    # Status
    submitted:     bool          = False   # True if API accepted submission
    completed:     bool          = False   # True if report is ready
    job_id:        Optional[str] = None
    sha256:        Optional[str] = None
    analysis_id:   Optional[str] = None
    environment:   str           = "Windows 10 64-bit"

    # Verdict
    verdict:       str           = "no verdict"   # malicious / suspicious / etc.
    verdict_score: int           = 0              # 0–100
    threat_score:  Optional[int] = None           # HA's own 0–100
    threat_level:  int           = 0              # 0=no threat, 1=suspicious, 2=malicious
    av_detect:     int           = 0              # % AV detections
    vx_family:     Optional[str] = None           # malware family name

    # Summary
    analysis_start: Optional[str] = None
    duration_ms:    Optional[int] = None
    submit_url:     Optional[str] = None   # link back to HA report

    # Network IOCs
    contacted_hosts: list[str] = field(default_factory=list)
    dns_requests:    list[str] = field(default_factory=list)
    http_requests:   list[str] = field(default_factory=list)
    compromised_hosts: list[str] = field(default_factory=list)

    # Behavioral
    processes:       list[str] = field(default_factory=list)   # spawned processes
    signatures:      list[str] = field(default_factory=list)   # matched signatures
    extracted_files: list[str] = field(default_factory=list)
    mutexes:         list[str] = field(default_factory=list)
    registry_keys:   list[str] = field(default_factory=list)

    # MITRE ATT&CK
    mitre_attcks:    list[dict] = field(default_factory=list)
    # Each: {"tactic": "TA0001", "technique": "T1566", "name": "Phishing"}

    # AV detections (top hits)
    av_detections:   list[dict] = field(default_factory=list)
    # Each: {"engine": "Windows Defender", "result": "Trojan:Win32/..."}

    # Tags assigned by HA
    tags:            list[str] = field(default_factory=list)

    # Extracted strings / IOCs
    extracted_strings: list[str] = field(default_factory=list)

    # Flags for UI
    flags:   list[str] = field(default_factory=list)
    iocs:    list[str] = field(default_factory=list)
    errors:  list[str] = field(default_factory=list)

    # Polling state
    status:  str = "pending"   # pending / running / error / done


# ── Internal helpers ──────────────────────────────────────────────────────────

def _headers(api_key: str) -> dict:
    """Build request headers. Key never appears in logs/errors."""
    return {
        "api-key":      api_key,
        "User-Agent":   "GhostWire-CTI/5.0",
        "Accept":       "application/json",
    }


def _safe_get(
    url: str,
    api_key: str,
    params: Optional[dict] = None,
    result: Optional[HAResult] = None,
) -> Optional[dict]:
    """
    GET with timeout + error handling.
    Returns parsed JSON or None. Never raises.
    On 429 the used key is put in cooldown via ha_key_pool.
    """
    try:
        r = requests.get(
            url,
            headers=_headers(api_key),
            params=params,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        )
        if r.status_code == 429:
            ha_key_pool.mark_rate_limited(api_key)   # put key in cooldown
            if result:
                result.errors.append("Hybrid Analysis: rate limit hit (429) — retry later")
            return None
        if r.status_code == 401:
            if result:
                result.errors.append("Hybrid Analysis: invalid API key (401)")
            return None
        if r.status_code == 404:
            if result:
                result.errors.append("Hybrid Analysis: HTTP 404 — resource not found in database")
            return None
        if not r.ok:
            if result:
                result.errors.append(f"Hybrid Analysis: HTTP {r.status_code}")
            return None
        return r.json()
    except requests.exceptions.Timeout:
        if result:
            result.errors.append("Hybrid Analysis: request timed out")
        return None
    except Exception as e:
        if result:
            # Never expose API key in error message
            msg = str(e).replace(api_key, "***")
            result.errors.append(f"Hybrid Analysis: {msg[:120]}")
        return None


def _safe_post(
    url: str,
    api_key: str,
    data: Optional[dict] = None,
    files: Optional[dict] = None,
    json_body: Optional[dict] = None,
    result: Optional[HAResult] = None,
) -> Optional[dict]:
    """POST with timeout + error handling.
    On 429 the used key is put in cooldown via ha_key_pool.
    """
    try:
        r = requests.post(
            url,
            headers=_headers(api_key),
            data=data,
            files=files,
            json=json_body,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        )
        if r.status_code == 429:
            ha_key_pool.mark_rate_limited(api_key)   # put key in cooldown
            if result:
                result.errors.append("Hybrid Analysis: rate limit (429) — 5 submissions/hr max")
            return None
        if r.status_code == 401:
            if result:
                result.errors.append("Hybrid Analysis: invalid API key (401)")
            return None
        if r.status_code == 404:
            if result:
                result.errors.append("Hybrid Analysis: HTTP 404 — resource not found")
            return None
        if r.status_code == 400:
            try:
                body = r.json()
                msg  = body.get("message") or body.get("error") or "Bad request"
            except Exception:
                msg = "Bad request (400)"
            if result:
                result.errors.append(f"Hybrid Analysis: {msg[:120]}")
            return None
        if not r.ok:
            if result:
                result.errors.append(f"Hybrid Analysis: HTTP {r.status_code}")
            return None
        return r.json()
    except requests.exceptions.Timeout:
        if result:
            result.errors.append("Hybrid Analysis: submission timed out")
        return None
    except Exception as e:
        if result:
            msg = str(e).replace(api_key, "***")
            result.errors.append(f"Hybrid Analysis: {msg[:120]}")
        return None


def _validate_hash(h: str) -> Optional[str]:
    """
    Validate and normalize a hash string.
    Returns 'sha256' / 'sha1' / 'md5' or None if invalid.
    Prevents injection via hash field.
    """
    h = h.strip().lower()
    if _SHA256_RE.match(h):
        return "sha256"
    if _SHA1_RE.match(h):
        return "sha1"
    if _MD5_RE.match(h):
        return "md5"
    return None


def _sanitize_domain(d: str) -> Optional[str]:
    """
    Sanitize domain / IP for use in HA search API.
    Returns None if unsafe.
    """
    d = d.strip().lower()
    # Strip leading 'www.' prefix only — lstrip('www.') is wrong as it strips
    # individual characters (w, o, r, l, d → 'ld.com' from 'world.com')
    if d.startswith("www."):
        d = d[4:]
    if not d or not _SAFE_DOMAIN_RE.match(d):
        return None
    if len(d) > 253:
        return None
    return d


def _env_name(env_id: int) -> str:
    return {
        100: "Windows 10 64-bit",
        120: "Windows 7 32-bit",
        200: "Android",
    }.get(env_id, f"Environment {env_id}")


# ── Report parser ─────────────────────────────────────────────────────────────

def _parse_report(data: dict, result: HAResult) -> None:
    """
    Parse a HA /report/{id}/summary or /overview/{hash} response
    into the HAResult dataclass. Strict field access — no eval.
    """
    result.completed    = True
    result.status       = "done"

    verdict_raw         = str(data.get("verdict") or "no verdict").lower()
    result.verdict      = verdict_raw
    result.verdict_score = _VERDICT_SCORES.get(verdict_raw, 15)
    result.threat_score = data.get("threat_score")
    result.threat_level = int(data.get("threat_level") or 0)
    result.av_detect    = int(data.get("av_detect") or 0)
    result.vx_family    = data.get("vx_family") or None
    result.sha256       = data.get("sha256") or result.sha256
    result.analysis_start = data.get("analysis_start_time")
    result.duration_ms  = data.get("total_network_connections")   # reused field if ms unavailable

    if result.sha256:
        result.submit_url = f"{HA_BASE}/sample/{result.sha256}"

    # Tags
    result.tags = [str(t) for t in (data.get("tags") or [])[:20]]

    # ── Network IOCs ──────────────────────────────────────────────────
    hosts = data.get("hosts") or []
    result.contacted_hosts = [str(h)[:80] for h in hosts[:30]]

    domains = data.get("domains") or []
    result.dns_requests = [str(d)[:80] for d in domains[:30]]

    # HTTP requests
    http_reqs = data.get("extracted_urls") or []
    result.http_requests = [str(u)[:120] for u in http_reqs[:20]]

    compromised = data.get("compromised_hosts") or []
    result.compromised_hosts = [str(c)[:80] for c in compromised[:20]]

    # ── Behavioral ────────────────────────────────────────────────────
    procs = data.get("processes") or []
    result.processes = [
        str(p.get("name") or p.get("cmd") or "")[:80]
        for p in procs[:20]
        if isinstance(p, dict)
    ]

    sigs = data.get("signatures") or []
    result.signatures = [
        str(s.get("name") or s.get("threat_level_human") or "")[:100]
        for s in sigs[:30]
        if isinstance(s, dict)
    ]

    files = data.get("extracted_files") or []
    result.extracted_files = [
        str(f.get("name") or f.get("file_path") or "")[:80]
        for f in files[:15]
        if isinstance(f, dict)
    ]

    mutexes = data.get("mutants") or []
    result.mutexes = [str(m)[:80] for m in mutexes[:15]]

    regs = data.get("registry") or []
    result.registry_keys = [
        str(r.get("key") or r)[:120]
        for r in regs[:15]
    ]

    # ── MITRE ATT&CK ─────────────────────────────────────────────────
    mitre_raw = data.get("mitre_attcks") or []
    for entry in mitre_raw[:40]:
        if not isinstance(entry, dict):
            continue
        result.mitre_attcks.append({
            "tactic":    str(entry.get("tactic") or "")[:20],
            "technique": str(entry.get("technique") or "")[:20],
            "name":      str(entry.get("attck_id_wiki") or entry.get("name") or "")[:60],
        })

    # ── AV detections ─────────────────────────────────────────────────
    av_raw = data.get("scanners") or data.get("av_results") or []
    for av in av_raw[:40]:
        if not isinstance(av, dict):
            continue
        result_str = av.get("result") or av.get("threat_found") or ""
        if result_str:
            result.av_detections.append({
                "engine": str(av.get("name") or av.get("engine") or "Unknown")[:40],
                "result": str(result_str)[:80],
            })

    # ── IOCs ──────────────────────────────────────────────────────────
    if result.verdict == "malicious":
        result.iocs.append(f"HA:VERDICT:MALICIOUS")
    if result.vx_family:
        result.iocs.append(f"MALWARE:{result.vx_family.upper()}")
    for host in result.contacted_hosts[:5]:
        result.iocs.append(f"C2:{host}")
    for dom in result.dns_requests[:5]:
        result.iocs.append(f"DNS:{dom}")

    # ── Flags ─────────────────────────────────────────────────────────
    v_colour = _VERDICT_COLOURS.get(result.verdict, "#4a6a8a")
    result.flags.append(
        f"🧪 Hybrid Analysis Verdict: {result.verdict.upper()} "
        f"(threat_score={result.threat_score or '—'}, "
        f"av_detect={result.av_detect}%)"
    )

    if result.vx_family:
        result.flags.append(f"☠️ Malware Family: {result.vx_family}")

    if result.signatures:
        result.flags.append(
            f"⚡ {len(result.signatures)} behavioral signature(s) matched"
        )

    if result.contacted_hosts:
        result.flags.append(
            f"🌐 {len(result.contacted_hosts)} host(s) contacted during execution"
        )

    if result.compromised_hosts:
        result.flags.append(
            f"🚨 {len(result.compromised_hosts)} compromised host(s) identified"
        )

    if result.mitre_attcks:
        tactics = list({m["tactic"] for m in result.mitre_attcks})[:5]
        result.flags.append(
            f"⚔️ MITRE ATT&CK: {len(result.mitre_attcks)} technique(s) — "
            f"tactics: {', '.join(tactics)}"
        )

    if result.av_detect >= 50:
        result.flags.append(
            f"🔴 HIGH AV Detection Rate: {result.av_detect}% of engines flagged"
        )
    elif result.av_detect >= 20:
        result.flags.append(
            f"🟡 Moderate AV Detection: {result.av_detect}%"
        )


# ── Poll for report completion ────────────────────────────────────────────────

def _poll_report(
    job_id: str,
    api_key: str,
    result: HAResult,
) -> None:
    """
    Poll HA for report completion. Blocks up to MAX_POLL_ROUNDS x POLL_INTERVAL.
    Updates result in-place.

    HA API v2 behaviour:
      /report/{job_id}/summary returns 404 while sandbox is still running
      (job not yet committed to DB). This is EXPECTED — not a real error.
      state field values: IN_QUEUE / IN_PROGRESS / SUCCESS / ERROR
    """
    report_url = f"{HA_API}/report/{job_id}/summary"

    for attempt in range(MAX_POLL_ROUNDS):
        time.sleep(POLL_INTERVAL)

        # Clear transient 404 "not ready yet" errors from previous poll attempts.
        result.errors = [
            e for e in result.errors
            if "404" not in e and "resource not found" not in e.lower()
        ]

        data = _safe_get(report_url, api_key, result=result)
        if data is None:
            # 404 = still processing; other errors are retried up to MAX_POLL_ROUNDS
            result.status = "running"
            continue

        state = str(data.get("state") or data.get("status") or "").upper()

        if state in ("SUCCESS", "FINISHED", "DONE", ""):
            if data.get("verdict") is not None or data.get("threat_level") is not None:
                _parse_report(data, result)
                return
            result.status = "running"
            continue
        elif state in ("ERROR", "FAILED"):
            result.errors.append(
                f"Hybrid Analysis: sandbox job {job_id[:20]} failed"
            )
            result.status = "error"
            return
        elif state in ("IN_QUEUE", "INQUEUE", "RUNNING", "IN_PROGRESS"):
            result.status = "running"
            continue

    # Timeout — remove residual 404 noise before surfacing timeout message
    result.errors = [
        e for e in result.errors
        if "404" not in e and "resource not found" not in e.lower()
    ]
    result.errors.append(
        f"Hybrid Analysis: report not ready after "
        f"{MAX_POLL_ROUNDS * POLL_INTERVAL}s — check HA portal manually"
    )
    result.status = "timeout"


# ── Public API functions ──────────────────────────────────────────────────────

def analyze_url_ha(
    url:     str,
    api_key: str,
    env_id:  int = DEFAULT_ENV,
) -> HAResult:
    """
    Submit a URL to Hybrid Analysis sandbox for full behavioral analysis.
    Polls until report is ready (up to ~2 min).

    Uses ha_key_pool for automatic key rotation on 429.
    api_key is the caller-supplied key; if the pool has additional keys
    they will be tried automatically on rate-limit.

    Security:
      • URL validated for http/https scheme before submission
      • No SSRF risk — only sends URL string to external HA API
      • Does NOT fetch the URL locally
    """
    result = HAResult()
    result.environment = _env_name(env_id)

    # Resolve active key — pool takes priority if it has keys loaded
    active_key = ha_key_pool.get() if ha_key_pool.available else api_key
    if not active_key:
        result.errors.append("Hybrid Analysis API key not configured")
        return result

    # Validate URL scheme — only http/https accepted
    url_stripped = url.strip()
    if not url_stripped.lower().startswith(("http://", "https://")):
        url_stripped = "http://" + url_stripped

    if not re.match(r'^https?://', url_stripped, re.IGNORECASE):
        result.errors.append("Hybrid Analysis: invalid URL scheme — only http/https accepted")
        return result

    if len(url_stripped) > 2048:
        result.errors.append("Hybrid Analysis: URL too long (max 2048 chars)")
        return result

    # ── Step 1: Quick scan first (fast, ~10s) ────────────────────────
    # HA API v2 /quick-scan/url accepts 'url' + 'scan_type' (both required).
    # We use a dedicated result object so any 400/404 from quick-scan
    # does NOT pollute the errors shown to the user for the main submission.
    # NOTE: quick-scan frequently returns 404 for unknown URLs — this is
    # EXPECTED behaviour (URL not in HA cache yet). Never surface this 404
    # to the user; it is not a real error — full sandbox submit follows.
    _qs_result = HAResult()
    quick_data = _safe_post(
        f"{HA_API}/quick-scan/url",
        active_key,
        data={
            "url":       url_stripped,
            "scan_type": "all",          # required by HA API v2
        },
        result=_qs_result,   # errors written here, never to the main result
    )
    # Silently discard quick-scan errors — they must NOT reach the UI
    _qs_result.errors.clear()

    if quick_data:
        result.submitted = True
        # Quick scan gives immediate verdict from static checks
        verdict_raw = str(quick_data.get("verdict") or "no verdict").lower()
        if verdict_raw != "no verdict":
            result.verdict       = verdict_raw
            result.verdict_score = _VERDICT_SCORES.get(verdict_raw, 15)

        # Extract quick-scan IOCs
        for scanner in (quick_data.get("scanners") or []):
            if not isinstance(scanner, dict):
                continue
            threat = scanner.get("result") or scanner.get("threat_found") or ""
            if threat:
                result.av_detections.append({
                    "engine": str(scanner.get("name") or "Scanner")[:40],
                    "result": str(threat)[:80],
                })
        result.flags.append(
            f"🔍 Quick scan complete — {len(result.av_detections)} scanner(s) triggered"
        )
    # Quick-scan failures are non-fatal — suppress errors, full submit continues

    # ── Step 2: Full sandbox submission ──────────────────────────────
    # On 429, pool will have rotated active_key into cooldown; try next key.
    submit_key = ha_key_pool.get() if ha_key_pool.available else active_key
    submit_data = _safe_post(
        f"{HA_API}/submit/url",
        submit_key,
        data={
            "url":            url_stripped,
            "environment_id": str(env_id),
        },
        result=result,
    )

    if not submit_data:
        # If full submit failed, return quick-scan result at minimum
        if result.submitted:
            result.completed = True
            result.status    = "done"
            result.flags.append(
                "⚠️ Full sandbox submission failed — quick scan result only"
            )
        return result

    result.submitted  = True
    result.job_id     = submit_data.get("job_id") or submit_data.get("id")
    result.sha256     = submit_data.get("sha256")
    result.analysis_id = submit_data.get("analysis_id")

    if not result.job_id:
        # ── Restricted account fallback ───────────────────────────────
        # Free HA accounts with "Restricted" auth level cannot submit URLs
        # for full sandbox detonation — only quick-scan is available.
        # If quick-scan already ran and gave us results, surface those.
        # Otherwise show a clear, actionable message.
        if result.submitted and result.av_detections:
            result.completed = True
            result.status    = "done"
            result.flags.append(
                "ℹ️ Quick scan result only — full sandbox detonation requires "
                "a higher HA auth level. Upgrade your HA account or use the "
                "Hash tab to look up known samples."
            )
        else:
            result.errors.append(
                "Hybrid Analysis: URL sandbox submission failed. "
                "Your HA account auth level is 'Restricted' — full URL detonation "
                "requires an upgraded account. Try: (1) Hash tab for known samples, "
                "(2) Upgrade HA account at hybrid-analysis.com."
            )
            result.status = "error"
        return result

    result.flags.append(
        f"✅ URL submitted to sandbox (env: {result.environment}, "
        f"job_id: {result.job_id[:16]}…)"
    )

    # ── Step 3: Poll for report ───────────────────────────────────────
    _poll_report(result.job_id, submit_key, result)
    return result


def analyze_file_ha(
    file_bytes: bytes,
    filename:   str,
    api_key:    str,
    env_id:     int = DEFAULT_ENV,
) -> HAResult:
    """
    Submit a file to Hybrid Analysis sandbox.

    Security:
      • File size re-validated (max 100MB)
      • Filename sanitized — path traversal prevented
      • File bytes sent as multipart/form-data (no exec)
    """
    result = HAResult()
    result.environment = _env_name(env_id)

    if not api_key:
        result.errors.append("Hybrid Analysis API key not configured")
        return result

    # Size check
    if len(file_bytes) > MAX_FILE_BYTES:
        result.errors.append(
            f"Hybrid Analysis: file too large "
            f"({len(file_bytes) // 1024 // 1024}MB, max 100MB)"
        )
        return result

    if not file_bytes:
        result.errors.append("Hybrid Analysis: empty file")
        return result

    # Sanitize filename — strip path components, limit length
    safe_name = re.sub(r'[^\w.\-]', '_', filename.split('/')[-1].split('\\')[-1])[:128]
    if not safe_name:
        safe_name = "sample.bin"

    # Compute SHA-256 for submit_url construction
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    result.sha256 = sha256

    # Submit file
    submit_data = _safe_post(
        f"{HA_API}/submit/file",
        api_key,
        data={"environment_id": str(env_id)},
        files={"file": (safe_name, io.BytesIO(file_bytes), "application/octet-stream")},
        result=result,
    )

    if not submit_data:
        # Try hash lookup as fallback — file may already be known
        return analyze_hash_ha(sha256, api_key)

    result.submitted  = True
    result.job_id     = submit_data.get("job_id") or submit_data.get("id")
    result.sha256     = submit_data.get("sha256") or sha256
    result.analysis_id = submit_data.get("analysis_id")
    result.submit_url  = f"{HA_BASE}/sample/{result.sha256}"

    result.flags.append(
        f"✅ File submitted: {safe_name} "
        f"({len(file_bytes) // 1024}KB, env: {result.environment})"
    )

    if not result.job_id:
        # No job_id means already known — check hash
        result.flags.append("ℹ️ File already analyzed — fetching cached report")
        cached = analyze_hash_ha(result.sha256, api_key)
        if cached.completed:
            return cached
        result.errors.append("Hybrid Analysis: no job_id and no cached report")
        return result

    _poll_report(result.job_id, api_key, result)
    return result


def analyze_hash_ha(
    hash_str: str,
    api_key:  str,
) -> HAResult:
    """
    Look up a file hash in Hybrid Analysis database.
    Supports SHA-256 (best), MD5, SHA-1.

    Security:
      • Hash validated via strict regex before API call
      • Prevents any injection via hash field
    """
    result = HAResult()

    if not api_key:
        result.errors.append("Hybrid Analysis API key not configured")
        return result

    hash_str = hash_str.strip().lower()
    hash_type = _validate_hash(hash_str)

    if hash_type is None:
        result.errors.append(
            "Hybrid Analysis: invalid hash format — "
            "expected SHA-256 (64), MD5 (32), or SHA-1 (40) hex chars"
        )
        return result

    # SHA-256: use /overview endpoint for richest data
    if hash_type == "sha256":
        # Clear any 404 error added by _safe_get before we check the result
        # so we can replace it with a cleaner user-facing message
        pre_error_count = len(result.errors)
        data = _safe_get(
            f"{HA_API}/overview/{hash_str}",
            api_key,
            result=result,
        )
        if data:
            result.sha256   = hash_str
            result.submitted = True
            _parse_report(data, result)
            result.flags.insert(0, f"🔎 Hash lookup: SHA-256 found in HA database")
            return result
        # /overview returned nothing — either 404 (hash unknown) or another error.
        # Trim any generic 404 error and replace with a cleaner message, then skip
        # the search/hash fallback (which would also fail and add confusing errors).
        result.errors = result.errors[:pre_error_count]
        result.errors.append(
            f"Hybrid Analysis: SHA256 {hash_str[:16]}… not found in database"
        )
        return result

    # MD5/SHA-1 or fallback: use search/hash
    search_data = _safe_post(
        f"{HA_API}/search/hash",
        api_key,
        data={"hash": hash_str},
        result=result,
    )

    if not search_data:
        result.errors.append(
            f"Hybrid Analysis: {hash_type.upper()} {hash_str[:16]}… not found in database"
        )
        return result

    # search/hash returns a list of results
    results_list = search_data if isinstance(search_data, list) else [search_data]

    if not results_list:
        result.flags.append(f"ℹ️ Hash not found in Hybrid Analysis database")
        return result

    # Use the most recent / highest threat result
    best = max(
        results_list,
        key=lambda x: (x.get("threat_level") or 0, x.get("threat_score") or 0),
        default=results_list[0],
    )

    result.submitted = True
    result.sha256    = best.get("sha256") or hash_str
    _parse_report(best, result)
    result.flags.insert(0, f"🔎 Hash lookup: {hash_type.upper()} found — {len(results_list)} report(s)")
    return result


def analyze_domain_ip_ha(
    target:  str,
    api_key: str,
) -> HAResult:
    """
    Search Hybrid Analysis for samples associated with a domain or IP.
    Uses /search/terms endpoint.

    Security:
      • Target sanitized via strict regex
      • No SSRF — sends string to HA API only
    """
    result = HAResult()

    if not api_key:
        result.errors.append("Hybrid Analysis API key not configured")
        return result

    safe_target = _sanitize_domain(target)
    if not safe_target:
        result.errors.append(
            "Hybrid Analysis: invalid domain/IP format — "
            "only alphanumeric, dots, hyphens allowed"
        )
        return result

    # Determine if IP or domain for field selection
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', safe_target))
    field = "host" if is_ip else "domain"

    pre_error_count = len(result.errors)
    search_data = _safe_post(
        f"{HA_API}/search/terms",
        api_key,
        data={field: safe_target},
        result=result,
    )

    if not search_data:
        # 404 from /search/terms means HA has no samples for this target — not an API error.
        # Replace any HTTP 404 error written by _safe_post with an informational flag.
        result.errors = result.errors[:pre_error_count]
        result.flags.append(
            f"ℹ️ No Hybrid Analysis results for {safe_target} — "
            f"this {'IP' if is_ip else 'domain'} has not been observed in any analyzed samples"
        )
        result.status = "done"
        result.completed = True
        return result

    results_list = (
        search_data.get("result") or
        search_data if isinstance(search_data, list) else
        []
    )

    if not results_list:
        result.flags.append(
            f"ℹ️ No samples associated with {safe_target} in HA database"
        )
        return result

    result.submitted = True
    result.flags.append(
        f"🌐 Found {len(results_list)} sample(s) associated with {safe_target}"
    )

    # Aggregate intelligence from all results
    malicious_count   = 0
    suspicious_count  = 0
    families: set[str] = set()
    all_sigs: set[str] = set()
    all_mitre: list[dict] = []

    for entry in results_list[:20]:
        if not isinstance(entry, dict):
            continue
        v = str(entry.get("verdict") or "").lower()
        if v == "malicious":
            malicious_count += 1
        elif v == "suspicious":
            suspicious_count += 1
        fam = entry.get("vx_family")
        if fam:
            families.add(str(fam))

        # Collect signatures
        for sig in (entry.get("signatures") or []):
            if isinstance(sig, dict):
                n = sig.get("name") or ""
                if n:
                    all_sigs.add(str(n)[:80])

        # Collect MITRE
        for m in (entry.get("mitre_attcks") or []):
            if isinstance(m, dict):
                all_mitre.append({
                    "tactic":    str(m.get("tactic") or "")[:20],
                    "technique": str(m.get("technique") or "")[:20],
                    "name":      str(m.get("attck_id_wiki") or m.get("name") or "")[:60],
                })

    result.signatures   = list(all_sigs)[:30]
    result.mitre_attcks = all_mitre[:40]

    # Determine aggregate verdict
    total = len(results_list)
    if malicious_count >= max(1, total // 2):
        result.verdict       = "malicious"
        result.verdict_score = 90
        result.iocs.append(f"HA:DOMAIN_MALICIOUS:{safe_target}")
    elif malicious_count > 0 or suspicious_count > 0:
        result.verdict       = "suspicious"
        result.verdict_score = 55
        result.iocs.append(f"HA:DOMAIN_SUSPICIOUS:{safe_target}")
    else:
        result.verdict       = "no specific threat"
        result.verdict_score = 10

    result.completed = True
    result.status    = "done"

    if families:
        result.vx_family = ", ".join(sorted(families)[:3])
        result.iocs.append(f"MALWARE:{result.vx_family.upper()}")

    result.flags.append(
        f"🧪 HA Domain/IP Search: {malicious_count} malicious, "
        f"{suspicious_count} suspicious out of {total} sample(s)"
    )
    if families:
        result.flags.append(f"☠️ Associated malware families: {', '.join(sorted(families))}")
    if result.signatures:
        result.flags.append(f"⚡ {len(result.signatures)} behavioral signature(s) across samples")

    return result
