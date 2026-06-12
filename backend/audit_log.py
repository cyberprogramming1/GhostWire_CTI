

from __future__ import annotations

import json
import logging
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import streamlit as st

from config import defang_url

logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_LOG_DIR  = Path.home() / ".ghostwire"
_DEFAULT_LOG_FILE = _DEFAULT_LOG_DIR / "audit.jsonl"

_MAX_LOG_SIZE_MB = 50    # 50MB-dən böyük olsa rotate et
_MAX_TARGET_LEN  = 80    # target string maksimum uzunluğu (privacy)


# ── Session tracking ──────────────────────────────────────────────────────────

def _get_session_id() -> str:
    """
    Streamlit session-a unikal ID ver.
    Hər brauzer tab-ı / restart yeni session ID alır.
    session_state-də saxlanır — session boyu sabit qalır.
    """
    if "ghostwire_session_id" not in st.session_state:
        st.session_state["ghostwire_session_id"] = str(uuid.uuid4())[:8]
    return st.session_state["ghostwire_session_id"]


def _get_request_seq() -> int:
    """
    Session daxilində sorğu sayğacı — neçənci analiz olduğunu izləyir.
    Rate limit kontekstində faydalı: seq artıq çox sürətlidirsə xəbərdarlıq.
    """
    if "ghostwire_req_seq" not in st.session_state:
        st.session_state["ghostwire_req_seq"] = 0
    st.session_state["ghostwire_req_seq"] += 1
    return st.session_state["ghostwire_req_seq"]


def _get_hostname() -> str:
    """
    Analiz edən maşının hostname-i.
    Open-source / local istifadə — kim analiz etdi sualına cavab verir.
    Fail olsa 'unknown' qaytarır.
    """
    try:
        return socket.gethostname()[:40]
    except Exception:
        return "unknown"


# ── Log path ──────────────────────────────────────────────────────────────────

def _get_log_path() -> Path:
    custom = os.environ.get("GHOSTWIRE_LOG_PATH")
    if custom:
        return Path(custom)
    return _DEFAULT_LOG_FILE


def _ensure_log_dir(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)


def _rotate_if_needed(log_path: Path) -> None:
    """Rotate log if > MAX_LOG_SIZE_MB."""
    try:
        if log_path.exists() and log_path.stat().st_size > _MAX_LOG_SIZE_MB * 1_000_000:
            rotated = log_path.with_suffix(
                f".{datetime.now(tz=timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"
            )
            log_path.rename(rotated)
    except Exception:
        pass


# ── Main log function ─────────────────────────────────────────────────────────

def log_analysis(
    pipeline:          str,
    target:            str,
    score:             int             = 0,
    verdict:           str             = "",
    threat_level:      str             = "",
    engines_triggered: Optional[list] = None,
    ioc_count:         int             = 0,
    duration_secs:     Optional[float] = None,
    error:             Optional[str]   = None,
) -> None:
    """
    Append one audit entry to the local JSONL log.

    Log entry fields (v6.1):
      ts            — UTC timestamp (ISO 8601)
      session_id    — Streamlit session unikal ID (8 char)
      request_seq   — Session daxilində neçənci sorğu
      hostname      — Analiz edən maşının adı
      pipeline      — url / hash / email / ip / sandbox
      target        — Defanged + truncated (hxxps://, [.])
      score         — 0-100 risk skoru
      verdict       — Threat level string
      threat_level  — SAFE / LOW / MEDIUM / HIGH / CRITICAL
      engines       — Hansı engine-lər trigger oldu
      ioc_count     — Tapılan IOC sayı
      duration_secs — Analiz müddəti (saniyə)
      error         — Xəta mesajı (varsa)

    Targets are defanged before writing — audit log-da heç vaxt
    canlı, kliklenebilir URL olmur (SIEM export təhlükəsizliyi).

    Never raises — logging failure heç vaxt pipeline-ı dayandırmır.
    """
    try:
        log_path = _get_log_path()
        _ensure_log_dir(log_path)
        _rotate_if_needed(log_path)

        # Target defang + truncate
        safe_target = defang_url(str(target))[:_MAX_TARGET_LEN]

        entry = {
            "ts":            datetime.now(tz=timezone.utc).isoformat(),
            "session_id":    _get_session_id(),       # Kim — session ID
            "request_seq":   _get_request_seq(),      # Neçənci sorğu
            "hostname":      _get_hostname(),          # Hansı maşın
            "pipeline":      pipeline,
            "target":        safe_target,
            "score":         score,
            "verdict":       verdict,
            "threat_level":  threat_level,
            "engines":       engines_triggered or [],
            "ioc_count":     ioc_count,
            "duration_secs": round(duration_secs, 2) if duration_secs else None,
            "error":         str(error)[:200] if error else None,
        }

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    except Exception:
        pass  # Silently fail — logging heç vaxt app-ı crash etməməlidir


# ── Read helpers ──────────────────────────────────────────────────────────────

def get_recent_logs(n: int = 50) -> list[dict]:
    """Return the last n audit entries (newest first)."""
    try:
        log_path = _get_log_path()
        if not log_path.exists():
            return []
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        entries = []
        for line in reversed(lines[-n:]):
            try:
                entries.append(json.loads(line))
            except Exception:
                continue
        return entries
    except Exception:
        return []


def get_log_path_str() -> str:
    return str(_get_log_path())


def get_threat_level_counts(limit: int = 200) -> dict[str, int]:
    """
    Return counts of each threat level from the last `limit` audit entries.
    Always returns all 5 levels — missing ones default to 0.
    Order is fixed: CRITICAL → HIGH → MEDIUM → LOW → SAFE.
    Never raises — returns all-zero dict on any error.
    """
    counts: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH":     0,
        "MEDIUM":   0,
        "LOW":      0,
        "SAFE":     0,
    }
    try:
        log_path = _get_log_path()
        if not log_path.exists():
            return counts
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        for line in lines[-limit:]:
            try:
                entry = json.loads(line)
                level = str(entry.get("threat_level", "")).upper().strip()
                if level in counts:
                    counts[level] += 1
            except Exception:
                continue
    except Exception:
        pass
    return counts
