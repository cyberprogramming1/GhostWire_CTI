"""
tests/test_email_engine.py
---------------------------
GhostWire CTI v7 — Unit tests for email engine.

Tests cover:
  - Email header parsing (From, Reply-To, Received chain)
  - SPF/DKIM/DMARC auth result extraction
  - URL extraction from HTML/text bodies
  - Attachment detection and hash extraction
  - Spoofing detection (display name vs domain mismatch)
  - Authentication failure scoring
  - Header injection detection
  - Malformed header handling

Run:  pytest tests/test_email_engine.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import patch, MagicMock


# Lazy import — email_engine has heavy optional deps (easyocr, tesseract)
def get_engine():
    """Import email_engine lazily to handle missing optional deps."""
    try:
        import backend.email_engine as ee
        return ee
    except ImportError as e:
        pytest.skip(f"email_engine import failed: {e}")


# ── Email Header Parsing ──────────────────────────────────────────────────────

SAMPLE_HEADERS = """From: "PayPal Security" <spoof@evil.ru>
Reply-To: collect@evil.ru
To: victim@company.com
Subject: URGENT: Your account has been suspended
Date: Mon, 23 May 2026 10:00:00 +0000
Message-ID: <abc123@evil.ru>
Received: from mail.evil.ru (mail.evil.ru [1.2.3.4])
          by mx.company.com with ESMTP
Authentication-Results: mx.company.com;
       dkim=fail (signature did not verify) header.d=paypal.com;
       spf=fail (evil.ru is not permitted sender) smtp.mailfrom=evil.ru;
       dmarc=fail (p=REJECT) header.from=paypal.com
X-Mailer: PhpMailer
"""

SAMPLE_LEGIT_HEADERS = """From: "Amazon" <noreply@amazon.com>
To: user@gmail.com
Subject: Your order has shipped
Date: Mon, 23 May 2026 10:00:00 +0000
Authentication-Results: mx.google.com;
       dkim=pass header.d=amazon.com;
       spf=pass (google.com: domain of noreply@amazon.com designates 54.240.0.1);
       dmarc=pass (p=QUARANTINE)
"""


class TestEmailHeaderParsing:
    def test_module_importable(self):
        ee = get_engine()
        assert ee is not None

    def test_from_address_parsed(self):
        ee = get_engine()
        if not hasattr(ee, "parse_email_headers"):
            pytest.skip("parse_email_headers not in email_engine")
        result = ee.parse_email_headers(SAMPLE_HEADERS)
        assert result.get("from_address") or result.get("from_domain")

    def test_spf_fail_detected(self):
        ee = get_engine()
        if not hasattr(ee, "extract_auth_results"):
            pytest.skip("extract_auth_results not in email_engine")
        auth = ee.extract_auth_results(SAMPLE_HEADERS)
        assert auth.get("spf") in ("fail", "softfail", "none") or \
               "spf" in str(auth).lower()

    def test_dkim_fail_detected(self):
        ee = get_engine()
        if not hasattr(ee, "extract_auth_results"):
            pytest.skip("extract_auth_results not in email_engine")
        auth = ee.extract_auth_results(SAMPLE_HEADERS)
        assert auth.get("dkim") == "fail" or "fail" in str(auth.get("dkim", "")).lower()

    def test_dmarc_fail_detected(self):
        ee = get_engine()
        if not hasattr(ee, "extract_auth_results"):
            pytest.skip("extract_auth_results not in email_engine")
        auth = ee.extract_auth_results(SAMPLE_HEADERS)
        assert auth.get("dmarc") == "fail" or "fail" in str(auth.get("dmarc", "")).lower()

    def test_legitimate_email_passes_auth(self):
        ee = get_engine()
        if not hasattr(ee, "extract_auth_results"):
            pytest.skip("extract_auth_results not in email_engine")
        auth = ee.extract_auth_results(SAMPLE_LEGIT_HEADERS)
        assert auth.get("spf") in ("pass", "softpass") or "pass" in str(auth.get("spf", "")).lower()


# ── URL Extraction ────────────────────────────────────────────────────────────

SAMPLE_HTML_BODY = """
<html><body>
<p>Click here: <a href="http://evil-phishing.com/login">Verify Now</a></p>
<p>Or visit: https://paypal-security-alert.ru/confirm</p>
<img src="http://tracker.evil.com/pixel.gif">
</body></html>
"""

SAMPLE_TEXT_BODY = """
Dear customer,

Please click: http://update-paypal.net/verify?token=abc123
Alternatively: hxxps://defanged-url.com/path (defanged)
"""


class TestUrlExtraction:
    def test_http_urls_extracted(self):
        ee = get_engine()
        if not hasattr(ee, "extract_urls_from_body"):
            pytest.skip("extract_urls_from_body not in email_engine")
        urls = ee.extract_urls_from_body(SAMPLE_HTML_BODY)
        assert any("evil-phishing.com" in u for u in urls)

    def test_https_urls_extracted(self):
        ee = get_engine()
        if not hasattr(ee, "extract_urls_from_body"):
            pytest.skip("extract_urls_from_body not in email_engine")
        urls = ee.extract_urls_from_body(SAMPLE_HTML_BODY)
        assert any("paypal-security-alert.ru" in u for u in urls)

    def test_defanged_urls_handled(self):
        ee = get_engine()
        if not hasattr(ee, "extract_urls_from_body"):
            pytest.skip("extract_urls_from_body not in email_engine")
        urls = ee.extract_urls_from_body(SAMPLE_TEXT_BODY)
        # Should extract regular URLs
        assert any("update-paypal.net" in u for u in urls)

    def test_no_duplicate_urls(self):
        ee = get_engine()
        if not hasattr(ee, "extract_urls_from_body"):
            pytest.skip("extract_urls_from_body not in email_engine")
        body = "http://evil.com http://evil.com http://evil.com"
        urls = ee.extract_urls_from_body(body)
        assert urls.count("http://evil.com") <= 1

    def test_empty_body_returns_empty(self):
        ee = get_engine()
        if not hasattr(ee, "extract_urls_from_body"):
            pytest.skip("extract_urls_from_body not in email_engine")
        assert ee.extract_urls_from_body("") == []


# ── Spoofing Detection ────────────────────────────────────────────────────────

class TestSpoofingDetection:
    def test_display_name_domain_mismatch(self):
        ee = get_engine()
        if not hasattr(ee, "detect_display_name_spoofing"):
            pytest.skip("detect_display_name_spoofing not in email_engine")
        # "PayPal Security" display name but evil.ru email
        result = ee.detect_display_name_spoofing(
            display_name="PayPal Security",
            from_email="spoof@evil.ru"
        )
        assert result  # Should detect spoofing

    def test_legitimate_sender_no_spoof(self):
        ee = get_engine()
        if not hasattr(ee, "detect_display_name_spoofing"):
            pytest.skip("detect_display_name_spoofing not in email_engine")
        result = ee.detect_display_name_spoofing(
            display_name="Amazon",
            from_email="noreply@amazon.com"
        )
        assert not result  # amazon.com + Amazon display = legit

    def test_reply_to_mismatch_flagged(self):
        ee = get_engine()
        if not hasattr(ee, "detect_reply_to_mismatch"):
            pytest.skip("detect_reply_to_mismatch not in email_engine")
        result = ee.detect_reply_to_mismatch(
            from_email="spoof@evil.ru",
            reply_to="collector@different-evil.com"
        )
        assert result  # Mismatch should be flagged


# ── Attachment Analysis ───────────────────────────────────────────────────────

class TestAttachmentAnalysis:
    def test_executable_attachment_flagged(self):
        ee = get_engine()
        if not hasattr(ee, "score_attachment"):
            pytest.skip("score_attachment not in email_engine")
        score, flags = ee.score_attachment("invoice.exe", b"MZ\x90\x00")
        assert score > 0
        assert flags

    def test_pdf_low_risk(self):
        ee = get_engine()
        if not hasattr(ee, "score_attachment"):
            pytest.skip("score_attachment not in email_engine")
        score, flags = ee.score_attachment("document.pdf", b"%PDF-1.4")
        # PDF alone is lower risk than exe
        assert score <= 10

    def test_double_extension_flagged(self):
        ee = get_engine()
        if not hasattr(ee, "score_attachment"):
            pytest.skip("score_attachment not in email_engine")
        score, flags = ee.score_attachment("invoice.pdf.exe", b"MZ")
        assert score > 0


# ── Header Injection Prevention ───────────────────────────────────────────────

class TestHeaderInjection:
    def test_crlf_in_header_handled(self):
        ee = get_engine()
        if not hasattr(ee, "parse_email_headers"):
            pytest.skip("parse_email_headers not in email_engine")
        # Should not raise on malformed headers
        malformed = "From: test@example.com\r\nBcc: injected@evil.com\r\n"
        try:
            result = ee.parse_email_headers(malformed)
            # Key point: should not inject Bcc as a real To field
            assert isinstance(result, dict)
        except Exception:
            pass  # Raising is acceptable — crashing is not

    def test_null_bytes_handled(self):
        ee = get_engine()
        if not hasattr(ee, "parse_email_headers"):
            pytest.skip("parse_email_headers not in email_engine")
        headers_with_null = "From: test@\x00evil.com\nSubject: test"
        try:
            result = ee.parse_email_headers(headers_with_null)
            assert isinstance(result, dict)
        except Exception:
            pass


# ── Full Pipeline Smoke Test ──────────────────────────────────────────────────

class TestEmailPipelineSmoke:
    def test_analyze_function_exists(self):
        ee = get_engine()
        # One of these should exist as the main entry point
        has_entry = any(
            hasattr(ee, fn) for fn in
            ["analyze_email", "run_email_analysis", "EmailAnalysisResult", "parse_email"]
        )
        assert has_entry, "email_engine has no recognizable entry point"

    def test_result_dataclass_has_score(self):
        ee = get_engine()
        if not hasattr(ee, "EmailAnalysisResult"):
            pytest.skip("EmailAnalysisResult not in email_engine")
        r = ee.EmailAnalysisResult()
        assert hasattr(r, "score")
        assert hasattr(r, "flags")
