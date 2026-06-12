

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from unittest.mock import patch, MagicMock
import pytest
from unittest.mock import patch, MagicMock
from backend.urlhaus_engine import (
    URLhausResult,
    _sanitize_lookup_value,
    _score_result,
    _post_urlhaus,
    query_url_host,
    query_hash,
    query_host,
    URLHAUS_API_BASE,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_result(**kwargs) -> URLhausResult:
    r = URLhausResult()
    for k, v in kwargs.items():
        setattr(r, k, v)
    return r


def _mock_post(status_code: int, json_data: dict):
    """Create a mock requests.post response."""
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = json_data
    m.content = b'{"dummy": true}'
    return m


# ── Sanitize ──────────────────────────────────────────────────────────────────

class TestSanitize:
    def test_strips_control_chars(self):
        assert "\r" not in _sanitize_lookup_value("foo\rbar")
        assert "\n" not in _sanitize_lookup_value("foo\nbar")
        assert "\t" not in _sanitize_lookup_value("foo\tbar")

    def test_truncates_at_max_len(self):
        assert len(_sanitize_lookup_value("a" * 600)) == 512

    def test_normal_url_preserved(self):
        url = "https://example.com/path?q=1"
        assert _sanitize_lookup_value(url) == url

    def test_empty_string(self):
        assert _sanitize_lookup_value("") == ""


# ── Endpoint Whitelist ────────────────────────────────────────────────────────

class TestEndpointWhitelist:
    def test_valid_endpoints_pass(self):
        for ep in ("url", "host", "payload"):
            with patch("requests.post") as mock_post:
                mock_post.return_value = _mock_post(200, {"query_status": "no_results"})
                result = _post_urlhaus(ep, {"url": "http://example.com"})
                assert "error" not in result or result.get("error") != "invalid_endpoint"

    def test_invalid_endpoint_blocked(self):
        result = _post_urlhaus("admin", {"x": "y"})
        assert result.get("error") == "invalid_endpoint"

    def test_path_traversal_blocked(self):
        result = _post_urlhaus("../admin", {"x": "y"})
        assert result.get("error") == "invalid_endpoint"

    def test_submit_endpoint_blocked(self):
        result = _post_urlhaus("submit", {"url": "http://evil.com"})
        assert result.get("error") == "invalid_endpoint"


# ── Score Result ──────────────────────────────────────────────────────────────

class TestScoreResult:
    def test_online_with_threat(self):
        r = _make_result(available=True, url_status="online", threat="malware_download")
        _score_result(r)
        assert r.score_contribution >= 25
        assert any("ACTIVE" in f or "online" in f.lower() for f in r.flags)

    def test_online_no_threat(self):
        r = _make_result(available=True, url_status="online")
        _score_result(r)
        assert r.score_contribution >= 18

    def test_offline_with_threat(self):
        r = _make_result(available=True, url_status="offline", threat="malware_download")
        _score_result(r)
        assert 5 <= r.score_contribution <= 15
        assert any("offline" in f.lower() or "Previously" in f for f in r.flags)

    def test_offline_no_threat_low_score(self):
        r = _make_result(available=True, url_status="offline")
        _score_result(r)
        assert r.score_contribution <= 6

    def test_host_urls_many(self):
        r = _make_result(available=True, urls_found=15)
        _score_result(r)
        assert r.score_contribution >= 18
        assert any("bulletproof" in f.lower() or "15" in f for f in r.flags)

    def test_host_urls_medium(self):
        r = _make_result(available=True, urls_found=7)
        _score_result(r)
        assert r.score_contribution >= 12

    def test_host_urls_threshold_3(self):
        r = _make_result(available=True, urls_found=3)
        _score_result(r)
        assert r.score_contribution >= 6

    def test_host_urls_below_threshold_no_score(self):
        r = _make_result(available=True, urls_found=2)
        _score_result(r)
        # 1-2 URLs suppressed (shared hosting FP)
        assert r.score_contribution == 0

    def test_signature_detected(self):
        r = _make_result(available=True, signature="Emotet")
        _score_result(r)
        assert r.score_contribution >= 20
        assert any("Emotet" in f for f in r.flags)

    def test_sha256_with_urls_no_sig(self):
        r = _make_result(
            available=True,
            sha256_hash="a" * 64,
            associated_urls=[{"url": "http://evil.com"}]
        )
        _score_result(r)
        assert r.score_contribution >= 15

    def test_clean_result_flag(self):
        r = _make_result(available=True)
        _score_result(r)
        assert any("Not found" in f for f in r.flags)

    def test_tags_without_corroboration_no_score(self):
        r = _make_result(available=True, tags=["exe", "ransomware"])
        _score_result(r)
        # Tags alone should not add score
        assert r.score_contribution == 0
        # But should appear as informational flag
        assert any("informational" in f.lower() or "Tags" in f for f in r.flags)

    def test_tags_with_corroboration_add_score(self):
        r = _make_result(
            available=True,
            url_status="online",
            threat="malware_download",
            tags=["exe", "ransomware", "dropper"]
        )
        _score_result(r)
        # Tags + online URL = score
        assert r.score_contribution > 28  # online(28) + tags

    def test_score_capped_at_30(self):
        r = _make_result(
            available=True,
            url_status="online", threat="malware_download",
            signature="Emotet", urls_found=20, tags=["exe", "ransomware"]
        )
        _score_result(r)
        assert r.score_contribution == 30


# ── Query URL Host ────────────────────────────────────────────────────────────

class TestQueryUrlHost:
    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_is_url_online(self, mock_post):
        mock_post.side_effect = [
            # URL lookup
            {"query_status": "is_url", "url_status": "online", "threat": "malware_download", "tags": []},
            # Host lookup
            {"query_status": "is_host", "urls": []},
        ]
        r = query_url_host("http://evil.com/malware.exe")
        assert r.available
        assert r.url_status == "online"
        assert r.threat == "malware_download"
        assert r.score_contribution > 0

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_no_results(self, mock_post):
        mock_post.return_value = {"query_status": "no_results"}
        r = query_url_host("http://clean.com")
        assert r.available
        assert r.url_status is None
        assert any("Not found" in f for f in r.flags)

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_ok_status_with_url_status_data(self, mock_post):
        """FIX #3 REGRESSION TEST: 'ok' status with url_status embedded should be parsed."""
        mock_post.side_effect = [
            # URL lookup returns "ok" but with url_status (some API versions)
            {
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["exe"],
            },
            # Host lookup
            {"query_status": "no_results"},
        ]
        r = query_url_host("http://evil.com/bad.exe")
        assert r.available
        assert r.url_status == "online"
        assert r.threat == "malware_download"

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_ok_status_without_url_status_is_clean(self, mock_post):
        """'ok' status without url_status field = clean (not in DB)."""
        mock_post.side_effect = [
            {"query_status": "ok"},
            {"query_status": "no_results"},
        ]
        r = query_url_host("http://clean.com")
        assert r.available
        assert r.url_status is None

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_invalid_url_format(self, mock_post):
        mock_post.return_value = {"query_status": "invalid_url"}
        r = query_url_host("not-a-url")
        assert not r.available
        assert any("invalid" in e.lower() or "rejected" in e.lower() for e in r.errors)

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_api_error_graceful(self, mock_post):
        mock_post.return_value = {"error": "timeout"}
        r = query_url_host("http://example.com")
        assert len(r.errors) > 0
        # Should not raise


# ── Query Hash ────────────────────────────────────────────────────────────────

class TestQueryHash:
    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_md5_routing(self, mock_post):
        mock_post.return_value = {"query_status": "no_results"}
        r = query_hash("a" * 32)
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][1].get("md5_hash") is not None

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_sha256_routing(self, mock_post):
        mock_post.return_value = {"query_status": "no_results"}
        r = query_hash("b" * 64)
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][1].get("sha256_hash") is not None

    def test_invalid_hash_length(self):
        r = query_hash("abc123")
        assert len(r.errors) > 0
        assert not r.available

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_is_payload_with_signature(self, mock_post):
        mock_post.return_value = {
            "query_status": "is_payload",
            "md5_hash": "a" * 32,
            "sha256_hash": "b" * 64,
            "file_type": "exe",
            "signature": "Emotet",
            "urls": [{"url": "http://x.com", "url_status": "online", "threat": "malware_download", "date_added": "2024-01-01"}],
        }
        r = query_hash("b" * 64)
        assert r.available
        assert r.signature == "Emotet"
        assert r.score_contribution >= 20

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_no_results_hash(self, mock_post):
        mock_post.return_value = {"query_status": "no_results"}
        r = query_hash("c" * 64)
        assert r.available
        assert any("Not found" in f for f in r.flags)


# ── Query Host ────────────────────────────────────────────────────────────────

class TestQueryHost:
    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_is_host_with_urls(self, mock_post):
        mock_post.return_value = {
            "query_status": "is_host",
            "urls": [
                {"url": f"http://evil.com/path{i}", "url_status": "online", "threat": "malware_download", "date_added": "2024-01-01"}
                for i in range(6)
            ],
        }
        r = query_host("evil.com")
        assert r.available
        assert r.urls_found == 6
        assert r.score_contribution > 0

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_no_results_host(self, mock_post):
        mock_post.return_value = {"query_status": "no_results"}
        r = query_host("clean.com")
        assert r.available
        assert any("Not found" in f for f in r.flags)

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_invalid_host(self, mock_post):
        mock_post.return_value = {"query_status": "invalid_host"}
        r = query_host("")
        assert not r.available

    @patch("backend.urlhaus_engine._post_urlhaus")
    def test_associated_urls_capped_at_5(self, mock_post):
        mock_post.return_value = {
            "query_status": "is_host",
            "urls": [
                {"url": f"http://x.com/{i}", "url_status": "online", "threat": "", "date_added": ""}
                for i in range(20)
            ],
        }
        r = query_host("x.com")
        assert len(r.associated_urls) <= 5
        assert r.urls_found == 20  # total count preserved


# ── Rate Limit Handling ───────────────────────────────────────────────────────

class TestRateLimit:
    # We patch _urlhaus_cache to None, effectively disabling the cache for these tests
    @patch("backend.urlhaus_engine._urlhaus_cache", new=None)
    @patch("requests.post")
    def test_429_returns_error(self, mock_post):
        m = MagicMock()
        m.status_code = 429
        mock_post.return_value = m
        
        result = _post_urlhaus("url", {"url": "http://x.com"})
        assert result.get("error") == "rate_limit"

    @patch("backend.urlhaus_engine._urlhaus_cache", new=None)
    @patch("requests.post")
    def test_timeout_returns_error(self, mock_post):
        import requests as req
        mock_post.side_effect = req.Timeout()
        
        result = _post_urlhaus("url", {"url": "http://x.com"})
        assert result.get("error") == "timeout"

    @patch("backend.urlhaus_engine._urlhaus_cache", new=None)
    @patch("requests.post")
    def test_large_response_rejected(self, mock_post):
        m = MagicMock()
        m.status_code = 200
        m.content = b"x" * 2_100_000  # > 2MB
        mock_post.return_value = m