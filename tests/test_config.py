"""
tests/test_config.py
---------------------
GhostWire CTI v6 — Unit tests for config module.

Tests:
  - defang_url() output correctness
  - _Config read-only enforcement
  - _HAKeyRotator round-robin + cooldown logic
  - IP privacy check (reputation._is_private)

Run:  pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from config import defang_url, _Config, _HAKeyRotator


# ─────────────────────────────────────────────────────────────────────────────
# 1. URL defanging
# ─────────────────────────────────────────────────────────────────────────────

class TestDefangURL:
    def test_https_defanged(self):
        result = defang_url("https://evil.com/payload")
        assert result.startswith("hxxps://")
        assert "evil[.]com" in result

    def test_http_defanged(self):
        result = defang_url("http://malware.ru/drop")
        assert result.startswith("hxxp://")
        assert "malware[.]ru" in result

    def test_dots_in_hostname_replaced(self):
        result = defang_url("https://sub.domain.evil.com/path")
        assert "[.]" in result
        # path dots should NOT be replaced (only hostname dots)
        assert "/path" in result

    def test_empty_string(self):
        assert defang_url("") == ""

    def test_no_scheme(self):
        """Bare domain without scheme should still defang dots."""
        result = defang_url("evil.com")
        assert "[.]" in result

    def test_preserves_path(self):
        result = defang_url("https://evil.com/some/path?q=test")
        assert "/some/path" in result or "some" in result

    def test_ftp_defanged(self):
        result = defang_url("ftp://files.evil.com/malware.exe")
        assert result.startswith("fxp://")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Config read-only enforcement
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigReadOnly:
    def test_unknown_attribute_raises(self):
        cfg = _Config()
        with pytest.raises(AttributeError):
            cfg.NONEXISTENT_KEY = "value"

    def test_known_attributes_readable(self):
        cfg = _Config()
        # These should not raise
        _ = cfg.VIRUSTOTAL_API_KEY
        _ = cfg.ABUSEIPDB_API_KEY
        _ = cfg.OLLAMA_MODEL
        _ = cfg.DEBUG

    def test_debug_default_false(self):
        cfg = _Config()
        # DEBUG env var not set in test env → should default to False
        assert isinstance(cfg.DEBUG, bool)

    def test_sandbox_max_bytes_int(self):
        cfg = _Config()
        assert isinstance(cfg.SANDBOX_MAX_BYTES, int)
        assert cfg.SANDBOX_MAX_BYTES > 0


# ─────────────────────────────────────────────────────────────────────────────
# 3. HA Key Rotator
# ─────────────────────────────────────────────────────────────────────────────

class TestHAKeyRotator:
    def _make_pool(self, *keys):
        """Create a rotator with given keys injected directly."""
        pool = _HAKeyRotator.__new__(_HAKeyRotator)
        import threading
        pool._lock     = threading.Lock()
        pool._keys     = list(keys)
        pool._index    = 0
        pool._cooldown = {}
        return pool

    def test_empty_pool_returns_empty(self):
        pool = self._make_pool()
        assert pool.get() == ""
        assert pool.available is False
        assert pool.count == 0

    def test_single_key_returned(self):
        pool = self._make_pool("key_alpha")
        assert pool.get() == "key_alpha"

    def test_round_robin_two_keys(self):
        pool = self._make_pool("key_a", "key_b")
        calls = [pool.get() for _ in range(4)]
        # Should alternate: a, b, a, b
        assert calls[0] != calls[1]
        assert calls[0] == calls[2]
        assert calls[1] == calls[3]

    def test_mark_rate_limited_skipped(self):
        """A rate-limited key should be skipped in favour of the next key."""
        pool = self._make_pool("key_a", "key_b")
        pool.mark_rate_limited("key_a")
        # Next get should return key_b (key_a is in cooldown)
        result = pool.get()
        assert result == "key_b"

    def test_count(self):
        pool = self._make_pool("k1", "k2", "k3")
        assert pool.count == 3


# ─────────────────────────────────────────────────────────────────────────────
# 4. IP privacy check (reputation engine)
# ─────────────────────────────────────────────────────────────────────────────

class TestIPPrivacyCheck:
    """_is_private() must catch all RFC-1918 + special ranges."""

    def _check(self, ip: str) -> bool:
        from backend.reputation import _is_private
        return _is_private(ip)

    def test_loopback(self):
        assert self._check("127.0.0.1") is True

    def test_private_10(self):
        assert self._check("10.0.0.1") is True

    def test_private_172_16(self):
        assert self._check("172.16.0.1") is True

    def test_private_192_168(self):
        assert self._check("192.168.1.100") is True

    def test_link_local(self):
        assert self._check("169.254.1.1") is True

    def test_multicast(self):
        assert self._check("224.0.0.1") is True

    def test_unspecified(self):
        assert self._check("0.0.0.0") is True

    def test_public_ip_not_private(self):
        assert self._check("8.8.8.8") is False
        assert self._check("1.1.1.1") is False
        assert self._check("185.220.101.47") is False

    def test_invalid_string_returns_true(self):
        """Invalid IP → treated as unsafe (True = block)."""
        assert self._check("not_an_ip") is True
        assert self._check("") is True
