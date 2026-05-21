"""
backend/audit_log.py
--------------------
Audit Logging — GhostWire CTI v6.1

Writes structured audit entries to a local JSONL file.
Each analysis request is logged with:
  - timestamp (UTC)
  - pipeline type (url/file/email/ip)
  - target (URL, filename, IP — defanged + truncated)
  - verdict + score
  - engines triggered
  - analysis duration

Security:
  - Targets are DEFANGED before logging (hxxps://, [.] notation)
    so audit logs cannot contain accidental clickable live URLs that
    SIEM tools, log viewers, or email clients might auto-resolve.
  - Targets are truncated to 80 chars.
  - Log is written locally only — never sent anywhere.

Usage:
    from backend.audit_log import log_analysis
    log_analysis(pipeline="url", target="http://evil.com", score=87, ...)
"""

from __future__ import annotations

import logging

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import defang_url

logger = logging.getLogger(__name__)



# Default log path — can be overridden via GHOSTWIRE_LOG_PATH env var
_DEFAULT_LOG_DIR  = Path.home() / ".ghostwire"
_DEFAULT_LOG_FILE = _DEFAULT_LOG_DIR / "audit.jsonl"

_MAX_LOG_SIZE_MB  = 50   # rotate when log exceeds 50MB
_MAX_TARGET_LEN   = 80   # truncate target strings for privacy


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
        pass  # Never crash the app due to logging failure


def log_analysis(
    pipeline:          str,
    target:            str,
    score:             int              = 0,
    verdict:           str              = "",
    threat_level:      str              = "",
    engines_triggered: Optional[list]  = None,
    ioc_count:         int              = 0,
    duration_secs:     Optional[float]  = None,
    error:             Optional[str]    = None,
) -> None:
    """
    Append one audit entry to the local JSONL log.

    Targets are defanged (hxxps://, [.] notation) before writing so
    audit logs never contain live, clickable URLs.

    Never raises — logging failures are silently swallowed so they
    cannot interrupt the analysis pipeline.
    """
    try:
        log_path = _get_log_path()
        _ensure_log_dir(log_path)
        _rotate_if_needed(log_path)

        # Defang the target before logging — prevents accidental live URL
        # in SIEM exports, email reports, or log viewer auto-linking.
        safe_target = defang_url(str(target))[:_MAX_TARGET_LEN]

        entry = {
            "ts":               datetime.now(tz=timezone.utc).isoformat(),
            "pipeline":         pipeline,
            "target":           safe_target,          # defanged + truncated
            "score":            score,
            "verdict":          verdict,
            "threat_level":     threat_level,
            "engines":          engines_triggered or [],
            "ioc_count":        ioc_count,
            "duration_secs":    round(duration_secs, 2) if duration_secs else None,
            "error":            str(error)[:200] if error else None,
        }

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    except Exception:
        pass  # Silently fail — logging must never crash the app


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
