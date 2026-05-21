"""
tests/test_hash_validation.py
------------------------------
GhostWire CTI v6 — Unit tests for hash format validation.

Tests the _validate_hash() function in backend/hybrid_analysis.py
which guards against injection via the hash input field.

Run:  pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from backend.hybrid_analysis import _validate_hash


class TestHashValidation:
    # ── Valid hashes ──────────────────────────────────────────────────

    def test_valid_md5(self):
        result = _validate_hash("44d88612fea8a8f36de82e1278abb02f")
        assert result == "md5"

    def test_valid_md5_uppercase(self):
        result = _validate_hash("44D88612FEA8A8F36DE82E1278ABB02F")
        assert result == "md5"

    def test_valid_sha1(self):
        result = _validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert result == "sha1"

    def test_valid_sha256(self):
        result = _validate_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result == "sha256"

    def test_valid_sha256_mixed_case(self):
        result = _validate_hash(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        )
        assert result == "sha256"

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace should be stripped before validation."""
        result = _validate_hash("  44d88612fea8a8f36de82e1278abb02f  ")
        assert result == "md5"

    # ── Invalid hashes ────────────────────────────────────────────────

    def test_empty_string(self):
        assert _validate_hash("") is None

    def test_too_short(self):
        assert _validate_hash("44d88612") is None

    def test_too_long(self):
        assert _validate_hash("a" * 65) is None

    def test_non_hex_characters(self):
        """Contains 'g' which is not valid hex."""
        assert _validate_hash("44d88612fea8a8f36de82e1278abb02g") is None

    def test_injection_attempt_semicolon(self):
        """SQL/shell injection attempt."""
        assert _validate_hash("44d88612'; DROP TABLE hashes; --") is None

    def test_injection_attempt_path(self):
        """Path traversal in hash field."""
        assert _validate_hash("../../../etc/passwd") is None

    def test_correct_length_wrong_chars(self):
        """32 chars but contains non-hex."""
        assert _validate_hash("44d88612fea8a8f36de82e1278abb0ZZ") is None

    def test_sha256_minus_one_char(self):
        """63 chars — one short of SHA-256."""
        assert _validate_hash("e" * 63) is None

    def test_sha256_plus_one_char(self):
        """65 chars — one too many for SHA-256."""
        assert _validate_hash("e" * 65) is None


class TestHashSanitizeDomain:
    """Test domain/IP sanitization for HA search API."""
    from backend.hybrid_analysis import _sanitize_domain

    def test_valid_domain(self):
        from backend.hybrid_analysis import _sanitize_domain
        result = _sanitize_domain("evil.com")
        assert result == "evil.com"

    def test_strips_www(self):
        from backend.hybrid_analysis import _sanitize_domain
        result = _sanitize_domain("www.evil.com")
        assert result == "evil.com"

    def test_valid_ip(self):
        from backend.hybrid_analysis import _sanitize_domain
        result = _sanitize_domain("185.220.101.47")
        assert result == "185.220.101.47"

    def test_injection_blocked(self):
        from backend.hybrid_analysis import _sanitize_domain
        result = _sanitize_domain("evil.com'; DROP TABLE--")
        assert result is None

    def test_too_long_blocked(self):
        from backend.hybrid_analysis import _sanitize_domain
        result = _sanitize_domain("a" * 254 + ".com")
        assert result is None

    def test_path_traversal_blocked(self):
        from backend.hybrid_analysis import _sanitize_domain
        result = _sanitize_domain("../../../etc")
        assert result is None
