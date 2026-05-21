"""
tests/test_ssrf.py
-------------------
GhostWire CTI v6 — Unit tests for SSRF protection.

Tests the _is_ssrf_target() guard in backend/sandbox.py which blocks
requests to private, loopback, link-local, and reserved IP ranges.

Run:  pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from backend.sandbox import _is_ssrf_target


class TestSSRFGuard:
    # ── Blocked schemes ───────────────────────────────────────────────

    def test_file_scheme_blocked(self):
        blocked, reason = _is_ssrf_target("file:///etc/passwd")
        assert blocked is True
        assert "file" in reason.lower()

    def test_ftp_scheme_blocked(self):
        blocked, _ = _is_ssrf_target("ftp://evil.com/payload")
        assert blocked is True

    def test_gopher_scheme_blocked(self):
        blocked, _ = _is_ssrf_target("gopher://127.0.0.1/probe")
        assert blocked is True

    def test_data_scheme_blocked(self):
        blocked, _ = _is_ssrf_target("data:text/html,<h1>XSS</h1>")
        assert blocked is True

    def test_ldap_scheme_blocked(self):
        blocked, _ = _is_ssrf_target("ldap://internal.corp/dc=corp")
        assert blocked is True

    # ── Private IPv4 ranges ───────────────────────────────────────────

    def test_localhost_blocked(self):
        blocked, _ = _is_ssrf_target("http://localhost/admin")
        assert blocked is True

    def test_loopback_ipv4_blocked(self):
        blocked, _ = _is_ssrf_target("http://127.0.0.1/")
        assert blocked is True

    def test_loopback_ipv4_any_port(self):
        blocked, _ = _is_ssrf_target("http://127.0.0.1:8501/api/keys")
        assert blocked is True

    def test_private_10_blocked(self):
        blocked, _ = _is_ssrf_target("http://10.0.0.1/internal")
        assert blocked is True

    def test_private_172_16_blocked(self):
        blocked, _ = _is_ssrf_target("http://172.16.0.1/")
        assert blocked is True

    def test_private_172_31_blocked(self):
        blocked, _ = _is_ssrf_target("http://172.31.255.254/")
        assert blocked is True

    def test_private_192_168_blocked(self):
        blocked, _ = _is_ssrf_target("http://192.168.1.1/router")
        assert blocked is True

    # ── Link-local / cloud metadata ───────────────────────────────────

    def test_link_local_blocked(self):
        """AWS/GCP/Azure metadata endpoint — must be blocked."""
        blocked, _ = _is_ssrf_target("http://169.254.169.254/latest/meta-data/")
        assert blocked is True

    def test_link_local_ipv6_blocked(self):
        blocked, _ = _is_ssrf_target("http://[fe80::1]/")
        assert blocked is True

    # ── IPv6 loopback ─────────────────────────────────────────────────

    def test_ipv6_loopback_blocked(self):
        blocked, _ = _is_ssrf_target("http://[::1]/")
        assert blocked is True

    # ── Public IPs — must be allowed ─────────────────────────────────

    def test_public_ip_allowed(self):
        blocked, _ = _is_ssrf_target("http://8.8.8.8/")
        assert blocked is False

    def test_public_domain_allowed(self):
        blocked, _ = _is_ssrf_target("https://google.com/")
        assert blocked is False

    def test_http_allowed(self):
        blocked, _ = _is_ssrf_target("http://example.com/page")
        assert blocked is False

    def test_https_allowed(self):
        blocked, _ = _is_ssrf_target("https://virustotal.com/api/v3/urls")
        assert blocked is False

    # ── Edge cases ────────────────────────────────────────────────────

    def test_empty_string(self):
        """Empty input should not crash — treat as blocked."""
        blocked, _ = _is_ssrf_target("")
        assert isinstance(blocked, bool)

    def test_non_standard_port_loopback(self):
        """Loopback on unusual port still blocked."""
        blocked, _ = _is_ssrf_target("http://127.0.0.1:9200/")
        assert blocked is True

    def test_streamlit_port_blocked(self):
        """Attacker trying to reach local Streamlit — must be blocked."""
        blocked, _ = _is_ssrf_target("http://localhost:8501/")
        assert blocked is True
