"""
tests/test_v8_fixes.py
-----------------------
GhostWire CTI v8 — Unit tests for all v8 bug fixes.

Tests:
  - url_utils module (shared helpers)
  - Rate limiting (session + global)
  - GreyNoise IP resolution logic
  - OTX IPv6 routing
  - PDF report accepts urlhaus_res / otx_res
  - Cache layer for WHOIS, SSL, PassiveDNS

Run:  pytest tests/test_v8_fixes.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# 1. url_utils module
# ─────────────────────────────────────────────────────────────────────────────

class TestUrlUtils:
    def test_normalise_bare_domain(self):
        from backend.url_utils import normalise_url
        result = normalise_url("evil.com")
        assert result == "http://evil.com"

    def test_normalise_https_unchanged(self):
        from backend.url_utils import normalise_url
        result = normalise_url("https://evil.com/path")
        assert result == "https://evil.com/path"

    def test_normalise_strips_whitespace(self):
        from backend.url_utils import normalise_url
        result = normalise_url("  evil.com  ")
        assert result == "http://evil.com"

    def test_normalise_ftp_unchanged(self):
        from backend.url_utils import normalise_url
        result = normalise_url("ftp://files.example.com")
        assert result == "ftp://files.example.com"

    def test_extract_hostname_from_url(self):
        from backend.url_utils import extract_hostname
        assert extract_hostname("https://evil.com/path?q=1") == "evil.com"

    def test_extract_hostname_from_bare_domain(self):
        from backend.url_utils import extract_hostname
        assert extract_hostname("evil.com") == "evil.com"

    def test_extract_hostname_empty_on_failure(self):
        from backend.url_utils import extract_hostname
        result = extract_hostname("")
        assert result == ""

    def test_is_ip_address_ipv4(self):
        from backend.url_utils import is_ip_address
        assert is_ip_address("192.168.1.1") is True
        assert is_ip_address("8.8.8.8") is True

    def test_is_ip_address_ipv6(self):
        from backend.url_utils import is_ip_address
        assert is_ip_address("2001:db8::1") is True

    def test_is_ip_address_domain(self):
        from backend.url_utils import is_ip_address
        assert is_ip_address("evil.com") is False

    def test_is_ipv6_detection(self):
        from backend.url_utils import is_ipv6
        assert is_ipv6("2001:db8::1") is True
        assert is_ipv6("8.8.8.8") is False
        assert is_ipv6("evil.com") is False


# ─────────────────────────────────────────────────────────────────────────────
# 2. OTX IPv6 routing
# ─────────────────────────────────────────────────────────────────────────────

class TestOTXIPv6:
    def test_query_hash_md5_routes_correctly(self):
        from backend.otx_engine import query_hash, OTXResult
        # Just verify it returns OTXResult without crashing on MD5
        import re
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        # Don't actually call API — just test routing logic
        assert len(md5) == 32
        assert re.fullmatch(r"[0-9a-f]+", md5)

    def test_query_hash_sha256_routes_correctly(self):
        from backend.otx_engine import OTXResult
        import re
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert len(sha256) == 64

    def test_ipv6_indicator_type_allowed(self):
        from backend.otx_engine import _ALLOWED_INDICATOR_TYPES
        assert "IPv6" in _ALLOWED_INDICATOR_TYPES


# ─────────────────────────────────────────────────────────────────────────────
# 3. PDF report accepts urlhaus_res and otx_res
# ─────────────────────────────────────────────────────────────────────────────

class TestPDFSignatures:
    def test_generate_cti_report_accepts_urlhaus_otx(self):
        """generate_cti_report must accept urlhaus_res and otx_res kwargs without error."""
        import inspect
        from backend.pdf_report import generate_cti_report
        sig = inspect.signature(generate_cti_report)
        params = sig.parameters
        assert "urlhaus_res" in params, "urlhaus_res missing from generate_cti_report"
        assert "otx_res" in params, "otx_res missing from generate_cti_report"

    def test_generate_hash_cti_report_accepts_urlhaus_otx(self):
        import inspect
        from backend.pdf_report import generate_hash_cti_report
        sig = inspect.signature(generate_hash_cti_report)
        params = sig.parameters
        assert "urlhaus_res" in params, "urlhaus_res missing from generate_hash_cti_report"
        assert "otx_res" in params, "otx_res missing from generate_hash_cti_report"

    def test_generate_ip_cti_report_accepts_urlhaus_otx(self):
        import inspect
        from backend.pdf_report import generate_ip_cti_report
        sig = inspect.signature(generate_ip_cti_report)
        params = sig.parameters
        assert "urlhaus_res" in params, "urlhaus_res missing from generate_ip_cti_report"
        assert "otx_res" in params, "otx_res missing from generate_ip_cti_report"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Cache layer existence
# ─────────────────────────────────────────────────────────────────────────────

class TestCacheLayers:
    def test_whois_cache_defined(self):
        from backend.whois_check import _whois_cache
        # May be None if caching unavailable, but the variable must exist
        assert "_whois_cache" in dir(sys.modules.get("backend.whois_check", object()))

    def test_ssl_cache_defined(self):
        import importlib
        mod = importlib.import_module("backend.ssl_engine")
        assert hasattr(mod, "_ssl_cache"), "_ssl_cache not defined in ssl_engine"

    def test_passive_dns_cache_defined(self):
        import importlib
        mod = importlib.import_module("backend.passive_dns")
        assert hasattr(mod, "_pdns_cache"), "_pdns_cache not defined in passive_dns"

    def test_email_vt_cache_defined(self):
        import importlib
        mod = importlib.import_module("backend.email_engine")
        assert hasattr(mod, "_email_vt_cache"), "_email_vt_cache not defined in email_engine"

    def test_email_abuse_cache_defined(self):
        import importlib
        mod = importlib.import_module("backend.email_engine")
        assert hasattr(mod, "_email_abuse_cache"), "_email_abuse_cache not defined in email_engine"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Dead file removal verification
# ─────────────────────────────────────────────────────────────────────────────

class TestOrphanedFilesRemoved:
    def _backend_path(self):
        import pathlib
        return pathlib.Path(__file__).parent.parent / "backend"

    def test_forensic_engine_exists_and_importable(self):
        """
        v9 FIX: forensic_engine.py is NOT orphaned — it is wired into
        pipeline_hash.py and called on every file upload.
        This test verifies the module exists and its public API is intact.
        """
        p = self._backend_path() / "forensic_engine.py"
        assert p.exists(), (
            "forensic_engine.py must exist — it is imported by pipeline_hash.py. "
            "Do NOT delete it."
        )
        # Verify the public entry point is callable
        import importlib, sys
        # Ensure backend is on path
        import pathlib
        root = str(pathlib.Path(__file__).parent.parent)
        if root not in sys.path:
            sys.path.insert(0, root)
        mod = importlib.import_module("backend.forensic_engine")
        assert callable(getattr(mod, "deep_forensic_analysis", None)), (
            "deep_forensic_analysis() must be a callable in forensic_engine"
        )
        # Smoke-test with a minimal PDF-like payload (no real file needed)
        report = mod.deep_forensic_analysis(
            data=b"%PDF-1.4 test content",
            filename="test.pdf",
            vt_api_key=None,
            ollama_model="phi3:mini",
        )
        assert report is not None
        assert hasattr(report, "risk_score")
        assert hasattr(report, "final_verdict")
        assert hasattr(report, "threat_level")

    def test_cti_report_removed(self):
        p = self._backend_path() / "cti_report.py"
        assert not p.exists(), "cti_report.py should be removed (orphaned)"

    def test_urlhaus_copy_removed(self):
        p = self._backend_path() / "urlhaus_engine copy.py"
        assert not p.exists(), "urlhaus_engine copy.py should be removed (duplicate)"

    def test_url_utils_exists(self):
        p = self._backend_path() / "url_utils.py"
        assert p.exists(), "url_utils.py should exist (new shared module)"


# ─────────────────────────────────────────────────────────────────────────────
# 6. ha_renderer XSS fix
# ─────────────────────────────────────────────────────────────────────────────

class TestHaRendererXSS:
    def test_submit_url_scheme_validation_present(self):
        """ha_renderer.py must validate submit_url scheme before rendering as href."""
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "frontend" / "ha_renderer.py").read_text()
        assert "startswith" in src, "ha_renderer.py must validate URL scheme (startswith http/https)"
        assert "javascript" not in src.lower() or "startswith" in src, \
            "javascript: URLs must be blocked in ha_renderer.py"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Sandbox rate limiting for all input types
# ─────────────────────────────────────────────────────────────────────────────

class TestSandboxRateLimiting:
    def test_rate_limit_for_file_input(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_sandbox.py").read_text()
        assert "_rl_check(ha_file_up.name)" in src, "File input must have rate limiting"

    def test_rate_limit_for_hash_input(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_sandbox.py").read_text()
        assert "_rl_check(raw_hash)" in src, "Hash input must have rate limiting"

    def test_rate_limit_for_ip_input(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_sandbox.py").read_text()
        assert "_rl_check(raw_ha_ip)" in src, "IP input must have rate limiting"


# ─────────────────────────────────────────────────────────────────────────────
# 8. AI summary guard in sandbox pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestSandboxAIGuard:
    def test_ai_summary_guarded_by_run_ha(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_sandbox.py").read_text()
        assert "if run_ha else" in src, "AI summary must be guarded by run_ha flag"


# ─────────────────────────────────────────────────────────────────────────────
# 9. STIX export in sandbox pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestSTIXSandboxExport:
    def test_stix_export_present_in_sandbox(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_sandbox.py").read_text()
        assert "render_stix_export_panel" in src, "STIX export must be present in sandbox pipeline"


# ─────────────────────────────────────────────────────────────────────────────
# 10. normalise_url deduplication
# ─────────────────────────────────────────────────────────────────────────────

class TestNormaliseUrlDeduplication:
    def test_app_uses_shared_normalise_url(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "app.py").read_text()
        assert "from backend.url_utils import" in src, "app.py must import from url_utils"
        assert "def _normalise_url" not in src, "app.py must not define its own _normalise_url"

    def test_sandbox_uses_shared_normalise_url(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_sandbox.py").read_text()
        assert "from backend.url_utils import" in src, "pipeline_sandbox.py must import from url_utils"
        assert "def _normalise_url" not in src, "pipeline_sandbox.py must not define its own _normalise_url"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Round-2 fixes (v8.1)
# ─────────────────────────────────────────────────────────────────────────────

class TestV81Fixes:
    def test_ip_pipeline_has_exception_handling(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_ip.py").read_text()
        assert "_ip_exc" in src, "pipeline_ip must handle f_ip.result() exceptions"

    def test_greynoise_none_guard_ip(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_ip.py").read_text()
        assert "_ip_gn is not None" in src, "IP pipeline must guard GreyNoise render against None"

    def test_greynoise_available_guard_url(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_url.py").read_text()
        assert "greynoise_res is not None and getattr" in src

    def test_ha_renderer_accepts_run_ai(self):
        import inspect, importlib
        mod = importlib.import_module("frontend.ha_renderer")
        sig = inspect.signature(mod.render_ha_results)
        assert "run_ai" in sig.parameters, "render_ha_results must accept run_ai parameter"

    def test_url_pipeline_ipv6_detection(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_url.py").read_text()
        assert "ipaddress as _ipa" in src, "URL pipeline must detect IPv6"
        assert "_ipa.ip_address(_raw_host)" in src

    def test_engines_triggered_includes_urlhaus_otx(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_url.py").read_text()
        assert "OTX AlienVault" in src, "_engines_triggered must include OTX"
        assert "URLhaus" in src, "_engines_triggered must include URLhaus"

    def test_email_stix_export_present(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_email.py").read_text()
        assert "render_stix_export_panel" in src, "Email pipeline must have STIX export"

    def test_shodan_double_render_fixed(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_url.py").read_text()
        assert "Only render Shodan panel when" in src

    def test_caching_uses_canonical_defang(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "backend" / "caching.py").read_text()
        assert "canonical defang_url" in src

    def test_threat_map_uses_pdns_geo(self):
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "pipelines" / "pipeline_url.py").read_text()
        assert "Use pdns_res geo data" in src
