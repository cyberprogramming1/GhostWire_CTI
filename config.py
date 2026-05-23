"""
config.py
---------
GhostWire CTI v6 — Configuration loader.
"""

from __future__ import annotations

import os
import re
import threading
from pathlib import Path

# Load .env file if present (development convenience)
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path, override=False)
except ImportError:
    pass  # python-dotenv optional; env vars still read from os.environ


# ── URL Defanging ─────────────────────────────────────────────────────────────

def defang_url(url: str) -> str:
    """
    Convert a live URL into a non-clickable defanged format for safe logging.
    Examples:
        https://evil.com/payload  →  hxxps://evil[.]com/payload
        http://malware.ru/drop    →  hxxp://malware[.]ru/drop
        ftp://bad.actor/          →  fxp://bad[.]actor/

    The scheme is mangled (https→hxxps, http→hxxp, ftp→fxp) and every
    dot in the hostname is wrapped in brackets so the string cannot be
    accidentally clicked or resolved by log viewers, email clients, or SIEMs.
    """
    if not url:
        return url
    url = str(url).strip()

    # Mangle scheme: https → hxxps, http → hxxp, ftp → fxp
    url = re.sub(r'^https', 'hxxps', url, flags=re.IGNORECASE)
    url = re.sub(r'^http(?!s)',  'hxxp',  url, flags=re.IGNORECASE)
    url = re.sub(r'^ftp',   'fxp',   url, flags=re.IGNORECASE)

    # Split off scheme://  then wrap dots in hostname only
    # hostname ends at first / ? or # after the authority
    match = re.match(r'([a-z+\-]+://)?([^/?#]*)(.*)', url, re.IGNORECASE)
    if match:
        scheme    = match.group(1) or ''
        authority = match.group(2)     # host[:port]
        rest      = match.group(3)
        authority = authority.replace('.', '[.]')
        url = scheme + authority + rest

    return url


# ── HA API Key Rotator ────────────────────────────────────────────────────────

class _HAKeyRotator:
    """
    Thread-safe round-robin key pool for Hybrid Analysis API.

    Supports multiple keys defined as:
        HYBRID_ANALYSIS_API_KEY=key1
        HYBRID_ANALYSIS_API_KEY_2=key2
        HYBRID_ANALYSIS_API_KEY_3=key3

    On 429 (rate-limit), call mark_rate_limited(key) to skip that key
    for COOLDOWN_SECS seconds before it re-enters rotation.
    """

    COOLDOWN_SECS = 65   # 1 minute + buffer; HA free tier resets per minute

    def __init__(self) -> None:
        self._lock     = threading.Lock()
        self._keys: list[str] = []
        self._index    = 0
        self._cooldown: dict[str, float] = {}   # key → cooldown-until timestamp
        self._load()

    def _load(self) -> None:
        """Collect all HYBRID_ANALYSIS_API_KEY[_N] env vars."""
        import time as _time
        keys: list[str] = []
        primary = os.environ.get("HYBRID_ANALYSIS_API_KEY", "").strip()
        if primary:
            keys.append(primary)
        for i in range(2, 11):   # _2 … _10
            extra = os.environ.get(f"HYBRID_ANALYSIS_API_KEY_{i}", "").strip()
            if extra:
                keys.append(extra)
        # deduplicate preserving order
        seen: set[str] = set()
        self._keys = [k for k in keys if k not in seen and not seen.add(k)]  # type: ignore[func-returns-value]

    def get(self) -> str:
        """Return next available key. Returns empty string if pool is empty."""
        import time as _time
        with self._lock:
            if not self._keys:
                return ""
            now = _time.monotonic()
            # Try each key starting from current index
            for _ in range(len(self._keys)):
                key = self._keys[self._index % len(self._keys)]
                self._index += 1
                if now >= self._cooldown.get(key, 0):
                    return key
            # All keys cooling down — return least-recently-cooled one anyway
            return self._keys[(self._index - 1) % len(self._keys)]

    def mark_rate_limited(self, key: str) -> None:
        """Put key in cooldown after receiving a 429 response."""
        import time as _time
        with self._lock:
            self._cooldown[key] = _time.monotonic() + self.COOLDOWN_SECS

    @property
    def count(self) -> int:
        return len(self._keys)

    @property
    def available(self) -> bool:
        return bool(self._keys)


# Global singleton — imported by hybrid_analysis.py
ha_key_pool = _HAKeyRotator()


# ── Main Config ───────────────────────────────────────────────────────────────

class _Config:
    """Read-only configuration container. All values from environment only."""

    __slots__ = (
        "VIRUSTOTAL_API_KEY",
        "ABUSEIPDB_API_KEY",
        "SHODAN_API_KEY",
        "GREYNOISE_API_KEY",
        "URLHAUS_API_KEY",
        "OTX_API_KEY",
        "HYBRID_ANALYSIS_API_KEY",
        "OLLAMA_BASE_URL",
        "OLLAMA_MODEL",
        "SANDBOX_MAX_BYTES",
        "REQUEST_TIMEOUT",
        "GHOSTWIRE_LOG_PATH",
        "DEBUG",
    )

    def __init__(self) -> None:
        self.VIRUSTOTAL_API_KEY      = os.environ.get("VIRUSTOTAL_API_KEY",      "")
        self.ABUSEIPDB_API_KEY       = os.environ.get("ABUSEIPDB_API_KEY",       "")
        self.SHODAN_API_KEY          = os.environ.get("SHODAN_API_KEY",          "")
        self.GREYNOISE_API_KEY       = os.environ.get("GREYNOISE_API_KEY",       "")
        self.URLHAUS_API_KEY         = os.environ.get("URLHAUS_API_KEY",         "")
        self.OTX_API_KEY              = os.environ.get("OTX_API_KEY",              "")
        # Primary key — use ha_key_pool.get() for rotation-aware access
        self.HYBRID_ANALYSIS_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
        self.OLLAMA_BASE_URL         = os.environ.get("OLLAMA_BASE_URL",         "http://localhost:11434")
        self.OLLAMA_MODEL            = os.environ.get("OLLAMA_MODEL",            "phi3:mini")
        self.SANDBOX_MAX_BYTES       = int(os.environ.get("SANDBOX_MAX_BYTES",   "524288"))
        self.REQUEST_TIMEOUT         = int(os.environ.get("REQUEST_TIMEOUT",     "8"))
        self.GHOSTWIRE_LOG_PATH      = os.environ.get("GHOSTWIRE_LOG_PATH",      "")
        self.DEBUG                   = os.environ.get("DEBUG", "false").lower() == "true"

    def __setattr__(self, name: str, value: object) -> None:
        # Allow setting during __init__ only
        if name in self.__slots__:
            object.__setattr__(self, name, value)
        else:
            raise AttributeError(f"Config has no attribute '{name}'")


cfg = _Config()
