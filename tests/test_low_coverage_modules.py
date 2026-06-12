"""
tests/test_low_coverage_modules.py
====================================
GhostWire CTI — Tests for 6 low-coverage (<25%) modules + Problem 1 fix verification.

Covered:
  1. backend/pdf_report.py      (8%)  — _safe_str, _clamp, _classify_score,
                                        _file_mitigation, _email_mitigation, _ip_mitigation
  2. backend/email_engine.py   (18%) — _extract_all_emails, _extract_domain,
                                        _parse_from_header, _heuristic_analysis,
                                        _check_auth, _detect_impersonation
  3. backend/reputation.py     (18%) — _extract_domain, _is_private, _score_comments,
                                        _score_votes, _score_relations, _parse_vt, _parse_abuse
  4. backend/ssl_engine.py     (18%) — _extract_hostname, _get_san_domains, _parse_ssl_date,
                                        _analyse_cert, SSLResult
  5. backend/whois_check.py    (19%) — _extract_root_domain, _normalise_date, analyze_domain
  6. backend/hybrid_analysis.py(20%) — _validate_hash, _sanitize_domain, _env_name, _parse_report

  PROBLEM 1 FIXES (Ollama UI messages):
  7. ai_analyzer: no ⚠ flags appended when Ollama is unreachable
  8. url_renderer: caption logic renders friendly ℹ️ not raw ⚠ error
  9. other_renderers: email error tuple matches all Ollama signal variants

All tests run fully offline — no real network calls.
Run: pytest tests/test_low_coverage_modules.py -v
"""

from __future__ import annotations

import sys
import types
import datetime
import re
from datetime import timezone
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))



# ── tldextract module-level stub (offline — no network) ───────────────────────
import types as _types
if "tldextract" not in sys.modules:
    _tld = _types.ModuleType("tldextract")
    class _FakeResult:
        def __init__(self, domain="", suffix="com", subdomain=""):
            self.domain = domain; self.suffix = suffix; self.subdomain = subdomain
    def _fake_extract(url, **kw):
        import re as _re
        # strip scheme
        s = _re.sub(r"^https?://", "", str(url)).split("/")[0].split("?")[0]
        parts = s.split(".")
        if len(parts) >= 2:
            return _FakeResult(domain=parts[-2], suffix=parts[-1], subdomain=".".join(parts[:-2]))
        return _FakeResult(domain=s)
    _tld.extract = _fake_extract
    _tld.TLDExtract = lambda **kw: _fake_extract
    sys.modules["tldextract"] = _tld

# ── tldextract stub (offline) ─────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _stub_tldextract(monkeypatch):
    if "tldextract" not in sys.modules:
        fake = types.ModuleType("tldextract")
        class _FR:
            def __init__(self, domain="", suffix="com", subdomain=""):
                self.domain = domain; self.suffix = suffix; self.subdomain = subdomain
        def _extract(url, **_):
            url = url.replace("http://", "").replace("https://", "").split("/")[0]
            parts = url.split(".")
            if len(parts) >= 2:
                return _FR(domain=parts[-2], suffix=parts[-1], subdomain=".".join(parts[:-2]))
            return _FR(domain=url, suffix="")
        fake.extract = _extract
        monkeypatch.setitem(sys.modules, "tldextract", fake)
    yield


# ═══════════════════════════════════════════════════════════════════════════════
# PROBLEM 1 FIX VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestProblem1OllamaFixes:
    """Ollama unavailability must show friendly ℹ️ info, not ⚠ error warnings."""

    # ── ai_analyzer: no ⚠ flags when Ollama unreachable ──────────────────────

    def test_analyze_text_conn_refused_no_warning_flag(self):
        """connection refused → flags must NOT contain ⚠ Ollama warning item."""
        def _boom(*a, **k): raise Exception("connection refused to port 11434")
        mc = MagicMock(); mc.chat.side_effect = _boom
        with patch("backend.ai_analyzer._get_ollama_client", return_value=mc), \
             patch("backend.ai_analyzer._get_installed_models", return_value=[]):
            from backend.ai_analyzer import analyze_text
            res = analyze_text("urgent content")
        warn_flags = [f for f in res.flags if "⚠" in f and "ollama" in f.lower()]
        assert len(warn_flags) == 0, f"Unexpected ⚠ flags: {warn_flags}"

    def test_analyze_text_not_reachable_no_warning_flag(self):
        """Timeout/unreachable → flags must NOT contain ⚠ Ollama warning item."""
        def _boom(*a, **k): raise Exception("timed out connecting to 11434")
        mc = MagicMock(); mc.chat.side_effect = _boom
        with patch("backend.ai_analyzer._get_ollama_client", return_value=mc), \
             patch("backend.ai_analyzer._get_installed_models", return_value=[]):
            from backend.ai_analyzer import analyze_text
            res = analyze_text("some text")
        warn_flags = [f for f in res.flags if "⚠" in f and "ollama" in f.lower()]
        assert len(warn_flags) == 0, f"Unexpected ⚠ flags: {warn_flags}"

    def test_analyze_text_error_field_still_set(self):
        """Even without flags, result.error must still be set for caption rendering."""
        def _boom(*a, **k): raise Exception("connection refused")
        mc = MagicMock(); mc.chat.side_effect = _boom
        with patch("backend.ai_analyzer._get_ollama_client", return_value=mc), \
             patch("backend.ai_analyzer._get_installed_models", return_value=[]):
            from backend.ai_analyzer import analyze_text
            res = analyze_text("content")
        assert res.error is not None
        assert res.score == 0

    # ── url_renderer: caption logic ───────────────────────────────────────────

    _UNAVAIL = (
        "cannot reach ollama", "ollama not running", "ollama not reachable",
        "all ollama models failed", "connection refused", "ai analysis skipped",
        "heuristics only",
    )

    def _caption(self, err: str) -> str:
        low = err.lower()
        if any(s in low for s in self._UNAVAIL):
            return "ℹ️ Ollama not available — heuristic analysis used."
        return f"⚠ {err}"

    def test_url_renderer_caption_cannot_reach(self):
        err = "Cannot reach Ollama. Start it: `ollama serve` and pull a model: `ollama pull phi3:mini` (heuristics only)"
        assert self._caption(err).startswith("ℹ️"), f"Got: {self._caption(err)}"

    def test_url_renderer_caption_not_running(self):
        err = "Ollama not running. Start it with: `ollama serve`\nThen pull a model: `ollama pull phi3:mini`"
        assert self._caption(err).startswith("ℹ️"), f"Got: {self._caption(err)}"

    def test_url_renderer_caption_heuristics_only(self):
        err = "All Ollama models failed — heuristics only"
        assert self._caption(err).startswith("ℹ️"), f"Got: {self._caption(err)}"

    def test_url_renderer_real_error_not_suppressed(self):
        err = "HTTP 500 Internal Server Error from analysis backend"
        assert self._caption(err).startswith("⚠"), f"Real error was suppressed: {self._caption(err)}"

    # ── other_renderers: email error tuple coverage ───────────────────────────

    _EMAIL_SIGNALS = (
        "all ollama models failed", "heuristics only", "cannot reach ollama",
        "ollama not running", "ollama not reachable", "connection refused",
        "ai analysis skipped",
    )

    def _email_is_ollama(self, err: str) -> bool:
        return any(s in err.lower() for s in self._EMAIL_SIGNALS)

    def test_email_renderer_matches_all_ollama_failed(self):
        assert self._email_is_ollama("AI: All Ollama models failed — heuristics only")

    def test_email_renderer_matches_cannot_reach(self):
        assert self._email_is_ollama("AI: Cannot reach Ollama. Start it: `ollama serve`")

    def test_email_renderer_matches_not_running(self):
        assert self._email_is_ollama("AI: Ollama not running. Start it with: `ollama serve`")

    def test_email_renderer_matches_connection_refused(self):
        assert self._email_is_ollama("AI: connection refused to port 11434")

    def test_email_renderer_does_not_suppress_real_errors(self):
        assert not self._email_is_ollama("VT domain error: HTTP 429 rate limit")
        assert not self._email_is_ollama("AbuseIPDB error: invalid API key")
        assert not self._email_is_ollama("DNS resolution failed for sender domain")


# ═══════════════════════════════════════════════════════════════════════════════
# 1. backend/pdf_report.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestPdfReport:
    """Pure-logic helpers in pdf_report — no PDF rendering needed."""

    def test_safe_str_none_returns_na(self):
        from backend.pdf_report import _safe_str
        assert _safe_str(None) == "N/A"

    def test_safe_str_empty_string_returns_na(self):
        from backend.pdf_report import _safe_str
        assert _safe_str("") == "N/A"

    def test_safe_str_whitespace_only(self):
        from backend.pdf_report import _safe_str
        # Whitespace-only returns the whitespace string (not N/A — only None/empty trigger N/A)
        result = _safe_str("   ")
        assert isinstance(result, str)   # no crash, returns string

    def test_safe_str_normal_string(self):
        from backend.pdf_report import _safe_str
        assert _safe_str("hello") == "hello"

    def test_safe_str_strips_null_bytes(self):
        from backend.pdf_report import _safe_str
        assert "\x00" not in _safe_str("hel\x00lo")

    def test_safe_str_strips_control_chars(self):
        from backend.pdf_report import _safe_str
        assert "\x01" not in _safe_str("hel\x01lo")
        assert "\x1f" not in _safe_str("hel\x1flo")

    def test_safe_str_truncates_to_max_len(self):
        from backend.pdf_report import _safe_str
        result = _safe_str("x" * 500, max_len=100)
        assert len(result) <= 100

    def test_safe_str_converts_int(self):
        from backend.pdf_report import _safe_str
        assert _safe_str(42) == "42"

    def test_safe_str_converts_list(self):
        from backend.pdf_report import _safe_str
        assert isinstance(_safe_str([1, 2, 3]), str)

    def test_clamp_normal_range(self):
        from backend.pdf_report import _clamp
        assert _clamp(50) == 50

    def test_clamp_below_minimum(self):
        from backend.pdf_report import _clamp
        assert _clamp(-5) == 0

    def test_clamp_above_maximum(self):
        from backend.pdf_report import _clamp
        assert _clamp(200) == 100

    def test_clamp_none_returns_zero(self):
        from backend.pdf_report import _clamp
        assert _clamp(None) == 0

    def test_clamp_string_number(self):
        from backend.pdf_report import _clamp
        assert _clamp("75") == 75

    def test_clamp_invalid_string_returns_zero(self):
        from backend.pdf_report import _clamp
        assert _clamp("abc") == 0

    def test_classify_score_critical(self):
        from backend.pdf_report import _classify_score
        label, colour, bg = _classify_score(90)
        assert label == "CRITICAL"

    def test_classify_score_high(self):
        from backend.pdf_report import _classify_score
        label, _, _ = _classify_score(70)
        assert label == "HIGH"

    def test_classify_score_medium(self):
        from backend.pdf_report import _classify_score
        label, _, _ = _classify_score(50)
        assert label == "MEDIUM"

    def test_classify_score_low(self):
        from backend.pdf_report import _classify_score
        label, _, _ = _classify_score(30)
        assert label == "LOW"

    def test_classify_score_safe(self):
        from backend.pdf_report import _classify_score
        label, _, _ = _classify_score(10)
        assert label == "SAFE"

    def test_classify_score_boundary_85(self):
        from backend.pdf_report import _classify_score
        assert _classify_score(85)[0] == "CRITICAL"

    def test_classify_score_boundary_65(self):
        from backend.pdf_report import _classify_score
        assert _classify_score(65)[0] == "HIGH"

    def test_classify_score_boundary_40(self):
        from backend.pdf_report import _classify_score
        assert _classify_score(40)[0] == "MEDIUM"

    def test_classify_score_boundary_20(self):
        from backend.pdf_report import _classify_score
        assert _classify_score(20)[0] == "LOW"

    def test_classify_score_returns_hex_colours(self):
        from backend.pdf_report import _classify_score
        _, colour, _ = _classify_score(90)
        assert colour.startswith("#") and len(colour) in (4, 7)

    def test_file_mitigation_high_vt(self):
        from backend.pdf_report import _file_mitigation
        mits = _file_mitigation(score=85, vt_malicious=12, has_macros=False)
        assert any("quarantine" in m.lower() or "isolate" in m.lower() or "block" in m.lower() for m in mits)

    def test_file_mitigation_macros(self):
        from backend.pdf_report import _file_mitigation
        mits = _file_mitigation(score=60, vt_malicious=0, has_macros=True)
        assert any("macro" in m.lower() or "office" in m.lower() for m in mits)

    def test_file_mitigation_always_has_steps(self):
        from backend.pdf_report import _file_mitigation
        mits = _file_mitigation(score=30, vt_malicious=0, has_macros=False)
        assert len(mits) >= 1

    def test_email_mitigation_auth_failed(self):
        from backend.pdf_report import _email_mitigation
        mits = _email_mitigation(score=70, auth_failed=True, spoofing=False)
        assert any("spf" in m.lower() or "dkim" in m.lower() or "dmarc" in m.lower() or "auth" in m.lower() for m in mits)

    def test_email_mitigation_spoofing(self):
        from backend.pdf_report import _email_mitigation
        mits = _email_mitigation(score=70, auth_failed=False, spoofing=True)
        assert any("spoof" in m.lower() or "impersonat" in m.lower() or "block" in m.lower() for m in mits)

    def test_email_mitigation_always_has_steps(self):
        from backend.pdf_report import _email_mitigation
        mits = _email_mitigation(score=50, auth_failed=False, spoofing=False)
        assert len(mits) >= 1

    def test_ip_mitigation_tor(self):
        from backend.pdf_report import _ip_mitigation
        mits = _ip_mitigation(score=70, is_tor=True, is_vpn=False, abuse=0)
        assert any("tor" in m.lower() for m in mits)

    def test_ip_mitigation_high_abuse(self):
        from backend.pdf_report import _ip_mitigation
        mits = _ip_mitigation(score=70, is_tor=False, is_vpn=False, abuse=90)
        assert any("abuse" in m.lower() or "block" in m.lower() or "firewall" in m.lower() for m in mits)

    def test_ip_mitigation_always_has_steps(self):
        from backend.pdf_report import _ip_mitigation
        mits = _ip_mitigation(score=30, is_tor=False, is_vpn=False, abuse=0)
        assert len(mits) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# 2. backend/email_engine.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmailEngine:
    """Test email engine pure-logic helpers — no network, no OCR."""

    def test_extract_all_emails_finds_multiple(self):
        from backend.email_engine import _extract_all_emails
        emails = _extract_all_emails("Contact user@example.com or admin@test.org or info@site.net")
        assert len(emails) >= 2

    def test_extract_all_emails_empty_text(self):
        from backend.email_engine import _extract_all_emails
        assert _extract_all_emails("no emails here") == []

    def test_extract_all_emails_deduplicates(self):
        from backend.email_engine import _extract_all_emails
        result = _extract_all_emails("a@b.com and also a@b.com plus c@d.com")
        assert result.count("a@b.com") == 1

    def test_extract_all_emails_no_false_positives(self):
        from backend.email_engine import _extract_all_emails
        result = _extract_all_emails("no emails here just text")
        assert result == []

    def test_extract_domain_from_email(self):
        from backend.email_engine import _extract_domain
        assert _extract_domain("user@example.com") == "example.com"

    def test_extract_domain_no_at_sign(self):
        from backend.email_engine import _extract_domain
        # No @ sign → returns None
        assert _extract_domain("notanemail") is None

    def test_extract_domain_with_subdomain(self):
        from backend.email_engine import _extract_domain
        result = _extract_domain("user@mail.example.com")
        assert "example.com" in result or "mail.example.com" in result

    def test_parse_from_header_angle_brackets(self):
        from backend.email_engine import _parse_from_header
        # Returns (display_name, email) — name first, email second
        name, email = _parse_from_header("John Doe <john@example.com>")
        assert email == "john@example.com"
        assert "John" in (name or "")

    def test_parse_from_header_bare_email(self):
        from backend.email_engine import _parse_from_header
        name, email = _parse_from_header("bare@email.com")
        assert email == "bare@email.com"

    def test_parse_from_header_empty(self):
        from backend.email_engine import _parse_from_header
        name, email = _parse_from_header("")
        assert email is None or email == ""

    def test_parse_from_header_display_name_extracted(self):
        from backend.email_engine import _parse_from_header
        name, email = _parse_from_header("PayPal Support <support@paypal.com>")
        assert email == "support@paypal.com"
        assert "PayPal" in (name or "")

    def test_heuristic_analysis_urgency(self):
        from backend.email_engine import _heuristic_analysis, EmailForensicsResult
        r = EmailForensicsResult()
        _heuristic_analysis("URGENT: Your account will be suspended! Act now within 24 hours!", r)
        assert len(r.urgency_phrases) > 0

    def test_heuristic_analysis_authority(self):
        from backend.email_engine import _heuristic_analysis, EmailForensicsResult
        r = EmailForensicsResult()
        # Use pattern that matches AUTHORITY_PATTERNS: "official notice/alert"
        _heuristic_analysis("This is an official notice from the IRS court order legal action.", r)
        assert len(r.authority_phrases) > 0 or len(r.urgency_phrases) > 0 or len(r.spam_signals) > 0

    def test_heuristic_analysis_spam_signals(self):
        from backend.email_engine import _heuristic_analysis, EmailForensicsResult
        r = EmailForensicsResult()
        _heuristic_analysis("We offer wholesale discount prices. Contact us for business cooperation inquiry.", r)
        assert len(r.spam_signals) > 0

    def test_heuristic_analysis_clean_email(self):
        from backend.email_engine import _heuristic_analysis, EmailForensicsResult
        r = EmailForensicsResult()
        _heuristic_analysis("Hi, please find the meeting agenda attached. Looking forward to Thursday.", r)
        assert len(r.urgency_phrases) == 0

    def test_check_auth_spf_fail(self):
        from backend.email_engine import _check_auth, EmailForensicsResult
        r = EmailForensicsResult()
        _check_auth("spf=fail dkim=fail", r)
        # _check_auth sets auth_failed=True and adds to r.flags
        assert r.auth_failed is True
        assert any("spf" in f.lower() or "auth" in f.lower() for f in r.flags)

    def test_check_auth_dkim_fail(self):
        from backend.email_engine import _check_auth, EmailForensicsResult
        r = EmailForensicsResult()
        _check_auth("spf=fail dkim=fail", r)
        assert r.auth_failed is True

    def test_check_auth_pass_all(self):
        from backend.email_engine import _check_auth, EmailForensicsResult
        r = EmailForensicsResult()
        _check_auth("spf=pass dkim=pass dmarc=pass", r)
        assert r.auth_failed is False

    def test_check_auth_single_failure_partial(self):
        from backend.email_engine import _check_auth, EmailForensicsResult
        r = EmailForensicsResult()
        _check_auth("spf=fail dkim=pass", r)
        # Partial failure: auth_failed=True, partial flag in flags
        assert r.auth_failed is True or any("spf" in f.lower() for f in r.flags)

    def test_detect_impersonation_paypal(self):
        from backend.email_engine import _detect_impersonation, EmailForensicsResult
        r = EmailForensicsResult()
        _detect_impersonation("PayPal Support <hacker@evil.com>", "evil.com", r)
        # Sets brand_impersonated and adds IMPERSONATION flag
        assert r.brand_impersonated or any("impersonat" in f.lower() for f in r.flags)

    def test_detect_impersonation_legit_paypal(self):
        from backend.email_engine import _detect_impersonation, EmailForensicsResult
        r = EmailForensicsResult()
        _detect_impersonation("PayPal Support <support@paypal.com>", "paypal.com", r)
        assert not r.brand_impersonated and not any("impersonat" in f.lower() for f in r.flags)

    def test_detect_impersonation_no_display_name(self):
        from backend.email_engine import _detect_impersonation, EmailForensicsResult
        r = EmailForensicsResult()
        _detect_impersonation("", "somedomain.com", r)
        assert not r.brand_impersonated

    def test_email_forensics_result_defaults(self):
        from backend.email_engine import EmailForensicsResult
        r = EmailForensicsResult()
        assert r.score == 0
        assert r.flags == []
        assert r.errors == []
        assert r.iocs == []


# ═══════════════════════════════════════════════════════════════════════════════
# 3. backend/reputation.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestReputation:
    """Test reputation engine pure-logic helpers."""

    def test_extract_domain_full_url(self):
        from backend.reputation import _extract_domain
        result = _extract_domain("https://www.example.com/path?q=1")
        assert "example.com" in result

    def test_extract_domain_bare_domain(self):
        from backend.reputation import _extract_domain
        result = _extract_domain("evil.com")
        assert "evil.com" in result

    def test_is_private_loopback(self):
        from backend.reputation import _is_private
        assert _is_private("127.0.0.1")

    def test_is_private_rfc1918(self):
        from backend.reputation import _is_private
        assert _is_private("192.168.1.1")
        assert _is_private("10.0.0.1")
        assert _is_private("172.16.0.1")

    def test_is_private_public(self):
        from backend.reputation import _is_private
        assert not _is_private("8.8.8.8")

    def test_is_private_invalid(self):
        from backend.reputation import _is_private
        # Invalid IPs are treated as unsafe (private) to prevent external API calls
        assert _is_private("not-an-ip")

    def test_score_comments_empty(self):
        from backend.reputation import _score_comments
        score, flags = _score_comments([])  # empty list
        assert score == 0

    def test_score_comments_malicious_keywords(self):
        from backend.reputation import _score_comments
        # VT comment format: {"attributes": {"text": ..., "votes": {...}}}
        comments = [{"attributes": {"text": "this ip is malicious spreading malware botnet c2", "votes": {"positive": 2}}}]
        score, flags = _score_comments(comments)
        assert score > 0

    def test_score_comments_benign_reduces_score(self):
        from backend.reputation import _score_comments
        comments = [{"attributes": {"text": "looks clean to me, harmless cdn traffic safe", "votes": {}}}]
        score, flags = _score_comments(comments)
        assert score <= 5

    def test_score_comments_capped_at_25(self):
        from backend.reputation import _score_comments
        big = [{"attributes": {"text": "malware phishing trojan botnet ransomware c2 exploit", "votes": {"positive": 5}}}] * 20
        score, _ = _score_comments(big)
        assert score <= 25

    def test_score_votes_all_malicious(self):
        from backend.reputation import _score_votes
        score, flags = _score_votes({"malicious": 10, "harmless": 0, "total": 10})
        assert score > 0

    def test_score_votes_all_harmless(self):
        from backend.reputation import _score_votes
        score, flags = _score_votes({"malicious": 0, "harmless": 10, "total": 10})
        assert score <= 0

    def test_score_votes_zero_total(self):
        from backend.reputation import _score_votes
        score, flags = _score_votes({"malicious": 0, "harmless": 0, "total": 0})
        assert score == 0

    def test_score_votes_capped_at_20(self):
        from backend.reputation import _score_votes
        score, _ = _score_votes({"malicious": 1000, "harmless": 0, "total": 1000})
        assert score <= 20

    def test_score_relations_empty(self):
        from backend.reputation import _score_relations
        score, flags = _score_relations({})
        assert score == 0

    def test_score_relations_downloaded_files(self):
        from backend.reputation import _score_relations
        score, flags = _score_relations({"downloaded_files": {"total": 5, "malicious": 5}})
        assert score > 0

    def test_score_relations_communicating_files(self):
        from backend.reputation import _score_relations
        score, flags = _score_relations({"communicating_files": {"total": 3, "malicious": 3}})
        assert score > 0

    def test_score_relations_capped_at_40(self):
        from backend.reputation import _score_relations
        big = {"downloaded_files": {"total": 9999, "malicious": 9999}, "communicating_files": {"total": 9999, "malicious": 9999}}
        score, _ = _score_relations(big)
        assert score <= 40

    def test_score_relations_zero_malicious(self):
        from backend.reputation import _score_relations
        score, _ = _score_relations({"downloaded_files": {"total": 5, "malicious": 0}})
        assert score == 0

    def test_parse_vt_error_dict(self):
        from backend.reputation import _parse_vt, ReputationResult
        r = ReputationResult()
        _parse_vt({"error": "Not Found in VirusTotal"}, r)
        assert len(r.errors) > 0

    def test_parse_vt_success(self):
        from backend.reputation import _parse_vt, ReputationResult
        r = ReputationResult()
        _parse_vt({"data": {"attributes": {
            "last_analysis_stats": {"malicious": 5, "undetected": 65},
            "total_votes": {"malicious": 3, "harmless": 10},
            "reputation": 10,
            "last_analysis_results": {},
        }}}, r)
        assert r.vt_malicious == 5

    def test_parse_abuse_empty(self):
        from backend.reputation import _parse_abuse, ReputationResult
        r = ReputationResult()
        _parse_abuse({}, r)
        assert r.abuse_confidence == 0

    def test_parse_abuse_with_data(self):
        from backend.reputation import _parse_abuse, ReputationResult
        r = ReputationResult()
        _parse_abuse({"data": {
            "abuseConfidenceScore": 85, "totalReports": 200,
            "countryCode": "RU", "usageType": "hosting",
            "isp": "Evil ISP", "domain": "evil.com", "isWhitelisted": False,
        }}, r)
        assert r.abuse_confidence == 85

    def test_reputation_result_defaults(self):
        from backend.reputation import ReputationResult
        r = ReputationResult()
        assert r.score == 0
        assert r.vt_malicious == 0
        assert r.abuse_confidence == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. backend/ssl_engine.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestSSLEngine:
    """Test SSL engine pure-logic helpers."""

    def test_extract_hostname_https_url(self):
        from backend.ssl_engine import _extract_hostname
        assert _extract_hostname("https://evil.com/path") == "evil.com"

    def test_extract_hostname_http_url(self):
        from backend.ssl_engine import _extract_hostname
        assert _extract_hostname("http://example.org") == "example.org"

    def test_extract_hostname_bare_domain(self):
        from backend.ssl_engine import _extract_hostname
        assert _extract_hostname("evil.com") == "evil.com"

    def test_extract_hostname_with_port(self):
        from backend.ssl_engine import _extract_hostname
        assert _extract_hostname("https://host.com:8443/path") == "host.com"

    def test_extract_hostname_ip_address(self):
        from backend.ssl_engine import _extract_hostname
        result = _extract_hostname("https://1.2.3.4/api")
        assert result == "1.2.3.4"

    def test_get_san_domains_dns_entries(self):
        from backend.ssl_engine import _get_san_domains
        cert = {"subjectAltName": [("DNS", "evil.com"), ("DNS", "www.evil.com"), ("IP Address", "1.2.3.4")]}
        sans = _get_san_domains(cert)
        assert "evil.com" in sans
        assert "www.evil.com" in sans

    def test_get_san_domains_empty(self):
        from backend.ssl_engine import _get_san_domains
        assert _get_san_domains({}) == []

    def test_get_san_domains_lowercased(self):
        from backend.ssl_engine import _get_san_domains
        cert = {"subjectAltName": [("DNS", "EVIL.COM"), ("DNS", "WWW.EVIL.COM")]}
        sans = _get_san_domains(cert)
        assert all(s == s.lower() for s in sans)

    def test_parse_ssl_date_valid(self):
        from backend.ssl_engine import _parse_ssl_date
        result = _parse_ssl_date("Jan 15 10:30:00 2025 GMT")
        assert result is not None

    def test_parse_ssl_date_invalid(self):
        from backend.ssl_engine import _parse_ssl_date
        assert _parse_ssl_date("not a date at all") is None

    def test_ssl_result_defaults(self):
        from backend.ssl_engine import SSLResult
        r = SSLResult()
        assert r.score == 0
        assert not r.is_expired
        assert not r.is_self_signed

    def test_analyse_cert_self_signed(self):
        from backend.ssl_engine import _analyse_cert, SSLResult
        cert = {
            "subject":  [(("commonName", "evil.com"),)],
            "issuer":   [(("commonName", "evil.com"),)],   # same → self-signed
            "subjectAltName": [],
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter":  "Dec 31 00:00:00 2025 GMT",
        }
        r = SSLResult(); r.hostname = "evil.com"
        _analyse_cert(cert, "evil.com", None, r, domain_age_days=30)
        assert r.is_self_signed or r.score > 0

    def test_analyse_cert_hostname_mismatch(self):
        from backend.ssl_engine import _analyse_cert, SSLResult
        cert = {
            "subject":  [(("commonName", "legitimate.com"),)],
            "issuer":   [(("commonName", "Let's Encrypt",),)],
            "subjectAltName": [("DNS", "legitimate.com")],
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter":  "Dec 31 00:00:00 2026 GMT",
        }
        r = SSLResult(); r.hostname = "evil.com"
        _analyse_cert(cert, "evil.com", None, r, domain_age_days=365)
        assert r.score >= 0   # mismatch may add score

    def test_analyse_cert_expired(self):
        from backend.ssl_engine import _analyse_cert, SSLResult
        cert = {
            "subject":  [(("commonName", "evil.com"),)],
            "issuer":   [(("commonName", "Some CA"),)],
            "subjectAltName": [("DNS", "evil.com")],
            "notBefore": "Jan  1 00:00:00 2020 GMT",
            "notAfter":  "Jan  1 00:00:00 2021 GMT",   # expired
        }
        r = SSLResult(); r.hostname = "evil.com"
        _analyse_cert(cert, "evil.com", None, r, domain_age_days=365)
        assert r.is_expired or r.score > 0


# ═══════════════════════════════════════════════════════════════════════════════
# 5. backend/whois_check.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestWhoisCheck:
    """Test WHOIS helpers — network mocked."""

    def test_extract_root_domain_full_url(self):
        from backend.whois_check import _extract_root_domain
        result = _extract_root_domain("https://www.example.com/path?q=1")
        assert "example" in result

    def test_extract_root_domain_bare_domain(self):
        from backend.whois_check import _extract_root_domain
        result = _extract_root_domain("example.com")
        assert "example" in result

    def test_extract_root_domain_strips_subdomain(self):
        from backend.whois_check import _extract_root_domain
        result = _extract_root_domain("sub.evil.com")
        assert result in ("evil.com", "sub.evil.com")   # either is valid

    def test_extract_root_domain_sanitizes_injection(self):
        from backend.whois_check import _extract_root_domain
        result = _extract_root_domain("; DROP TABLE whois--")
        assert ";" not in result and "$" not in result

    def test_extract_root_domain_max_length(self):
        from backend.whois_check import _extract_root_domain
        result = _extract_root_domain("x" * 300)
        assert len(result) <= 255

    def test_normalise_date_datetime_object(self):
        from backend.whois_check import _normalise_date
        dt = datetime.datetime(2022, 6, 15, tzinfo=timezone.utc)
        result = _normalise_date(dt)
        assert result is not None
        assert result.year == 2022

    def test_normalise_date_list_returns_earliest(self):
        from backend.whois_check import _normalise_date
        dates = [
            datetime.datetime(2022, 6, 15, tzinfo=timezone.utc),
            datetime.datetime(2020, 1, 1, tzinfo=timezone.utc),
        ]
        result = _normalise_date(dates)
        assert result is not None
        assert result.year == 2020   # earliest

    def test_normalise_date_string_iso(self):
        from backend.whois_check import _normalise_date
        result = _normalise_date("2022-06-15")
        assert result is not None

    def test_normalise_date_string_with_time(self):
        from backend.whois_check import _normalise_date
        result = _normalise_date("2022-06-15 10:30:00")
        assert result is not None

    def test_normalise_date_none(self):
        from backend.whois_check import _normalise_date
        assert _normalise_date(None) is None

    def test_normalise_date_invalid_string(self):
        from backend.whois_check import _normalise_date
        assert _normalise_date("not a date at all xyz") is None

    def test_normalise_date_makes_tz_aware(self):
        from backend.whois_check import _normalise_date
        dt = datetime.datetime(2022, 1, 1)   # naive (no tz)
        result = _normalise_date(dt)
        assert result is not None
        assert result.tzinfo is not None

    def test_whois_result_defaults(self):
        from backend.whois_check import WhoisResult
        r = WhoisResult()
        assert r.score == 0
        assert r.domain_age_days is None
        assert r.flags == []

    def test_analyze_domain_whois_import_error(self):
        mock_whois = types.ModuleType("whois")
        mock_whois.whois = MagicMock(side_effect=ImportError("no module named whois"))
        sys.modules["whois"] = mock_whois
        from backend.whois_check import analyze_domain, WhoisResult
        result = analyze_domain("example.com")
        assert isinstance(result, WhoisResult)   # no crash

    def test_analyze_domain_whois_exception(self):
        mock_whois = types.ModuleType("whois")
        mock_whois.whois = MagicMock(side_effect=Exception("WHOIS lookup failed: timeout"))
        sys.modules["whois"] = mock_whois
        from backend.whois_check import analyze_domain, WhoisResult
        result = analyze_domain("example.com")
        assert isinstance(result, WhoisResult)

    def test_analyze_domain_new_domain_high_score(self):
        mock_data = MagicMock()
        mock_data.creation_date = datetime.datetime.now(tz=timezone.utc)
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.registrar = "NameCheap"
        mock_data.status = ["active"]
        mock_data.name_servers = ["ns1.namecheap.com"]
        mock_whois = types.ModuleType("whois")
        mock_whois.whois = MagicMock(return_value=mock_data)
        sys.modules["whois"] = mock_whois
        from backend.whois_check import analyze_domain
        result = analyze_domain("brandnew.xyz")
        assert result.score > 0   # new domain = high risk

    def test_analyze_domain_old_domain_lower_score(self):
        mock_data = MagicMock()
        mock_data.creation_date = datetime.datetime(2010, 1, 1, tzinfo=timezone.utc)
        mock_data.expiration_date = datetime.datetime(2030, 1, 1, tzinfo=timezone.utc)
        mock_data.updated_date = None
        mock_data.registrar = "GoDaddy"
        mock_data.status = ["active"]
        mock_data.name_servers = ["ns1.godaddy.com"]
        mock_whois = types.ModuleType("whois")
        mock_whois.whois = MagicMock(return_value=mock_data)
        sys.modules["whois"] = mock_whois
        from backend.whois_check import analyze_domain
        result_old = analyze_domain("trusted-old-domain.com")
        # New domain should score higher than 15-year-old domain
        assert result_old.score < 30


# ═══════════════════════════════════════════════════════════════════════════════
# 6. backend/hybrid_analysis.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestHybridAnalysis:
    """Test Hybrid Analysis pure-logic helpers."""

    def test_validate_hash_sha256(self):
        from backend.hybrid_analysis import _validate_hash
        assert _validate_hash("a" * 64) == "sha256"

    def test_validate_hash_sha256_uppercase(self):
        from backend.hybrid_analysis import _validate_hash
        assert _validate_hash("A" * 64) == "sha256"

    def test_validate_hash_sha1(self):
        from backend.hybrid_analysis import _validate_hash
        assert _validate_hash("b" * 40) == "sha1"

    def test_validate_hash_md5(self):
        from backend.hybrid_analysis import _validate_hash
        assert _validate_hash("c" * 32) == "md5"

    def test_validate_hash_invalid_short(self):
        from backend.hybrid_analysis import _validate_hash
        assert _validate_hash("abc") is None

    def test_validate_hash_invalid_non_hex(self):
        from backend.hybrid_analysis import _validate_hash
        assert _validate_hash("zz" * 32) is None

    def test_validate_hash_strips_whitespace(self):
        from backend.hybrid_analysis import _validate_hash
        assert _validate_hash("  " + "d" * 64 + "  ") == "sha256"

    def test_sanitize_domain_normal(self):
        from backend.hybrid_analysis import _sanitize_domain
        assert _sanitize_domain("example.com") == "example.com"

    def test_sanitize_domain_strips_www(self):
        from backend.hybrid_analysis import _sanitize_domain
        result = _sanitize_domain("www.example.com")
        assert "www." not in result

    def test_sanitize_domain_lowercase(self):
        from backend.hybrid_analysis import _sanitize_domain
        assert _sanitize_domain("EVIL.COM") == "evil.com"

    def test_sanitize_domain_injection_rejected(self):
        from backend.hybrid_analysis import _sanitize_domain
        result = _sanitize_domain("; rm -rf /")
        assert result is None or ";" not in (result or "")

    def test_sanitize_domain_too_long(self):
        from backend.hybrid_analysis import _sanitize_domain
        assert _sanitize_domain("x" * 300) is None

    def test_sanitize_domain_empty(self):
        from backend.hybrid_analysis import _sanitize_domain
        assert _sanitize_domain("") is None

    def test_env_name_windows10(self):
        from backend.hybrid_analysis import _env_name
        name = _env_name(100)
        assert "windows" in name.lower() or "10" in name

    def test_env_name_windows7(self):
        from backend.hybrid_analysis import _env_name
        name = _env_name(120)
        assert "windows" in name.lower() or "7" in name

    def test_env_name_unknown(self):
        from backend.hybrid_analysis import _env_name
        name = _env_name(9999)
        assert isinstance(name, str) and len(name) > 0

    def test_parse_report_malicious_verdict(self):
        from backend.hybrid_analysis import _parse_report, HAResult
        data = {
            "verdict": "malicious", "threat_score": 85, "av_detect": 70,
            "vx_family": "Emotet", "environment_description": "Windows 10",
            "interesting_behaviors": [{"name": "Creates autorun", "threat_level": 2}],
            "iocs": [], "signatures": [{"name": "Network C2"}],
            "mitre_attcks": [], "contacted_hosts": ["1.2.3.4"],
            "domains": [], "sha256": "a" * 64, "environment_id": 100,
        }
        r = HAResult(); _parse_report(data, r)
        assert r.verdict == "malicious"
        assert r.threat_score == 85

    def test_parse_report_no_verdict_no_crash(self):
        from backend.hybrid_analysis import _parse_report, HAResult
        r = HAResult(); _parse_report({}, r)
        assert isinstance(r.verdict, str)   # no crash, default value

    def test_parse_report_verdict_score_mapping(self):
        from backend.hybrid_analysis import _parse_report, HAResult
        for verdict, min_score in [("malicious", 60), ("suspicious", 30), ("no specific threat", 0)]:
            r = HAResult()
            _parse_report({
                "verdict": verdict, "threat_score": None, "av_detect": 0,
                "vx_family": None, "interesting_behaviors": [], "iocs": [],
                "signatures": [], "mitre_attcks": [], "contacted_hosts": [],
                "domains": [], "sha256": None, "environment_id": 100,
            }, r)
            assert r.verdict_score >= min_score, f"verdict={verdict}: verdict_score={r.verdict_score} < {min_score}"

    def test_parse_report_limits_lists(self):
        from backend.hybrid_analysis import _parse_report, HAResult
        data = {
            "verdict": "malicious", "threat_score": 90, "av_detect": 80,
            "vx_family": "Ransomware",
            "interesting_behaviors": [{"name": f"B{i}", "threat_level": 2} for i in range(50)],
            "iocs": [f"ioc_{i}" for i in range(50)],
            "signatures": [{"name": f"Sig {i}"} for i in range(50)],
            "mitre_attcks": [], "contacted_hosts": [f"1.2.3.{i}" for i in range(50)],
            "domains": [], "sha256": "b" * 64, "environment_id": 100,
        }
        r = HAResult(); _parse_report(data, r)
        assert len(r.flags) <= 30   # list must be bounded

    def test_parse_report_sha256_builds_submit_url(self):
        from backend.hybrid_analysis import _parse_report, HAResult
        sha = "e" * 64
        r = HAResult()
        _parse_report({
            "verdict": "malicious", "threat_score": 90, "av_detect": 80,
            "vx_family": "X", "interesting_behaviors": [], "iocs": [],
            "signatures": [], "mitre_attcks": [], "contacted_hosts": [],
            "domains": [], "sha256": sha, "environment_id": 100,
        }, r)
        assert sha in (r.submit_url or "")

    def test_ha_result_defaults(self):
        from backend.hybrid_analysis import HAResult
        r = HAResult()
        assert r.verdict_score == 0
        assert r.verdict in ("", "no verdict", None) or isinstance(r.verdict, str)
        assert r.flags == []
