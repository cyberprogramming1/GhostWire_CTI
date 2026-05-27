"""
tests/test_urlhaus_integration.py
-----------------------------------
"""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))

import backend.urlhaus_engine as ue


def mock_post(endpoint_responses: dict):
    """Factory: return a mock _post_urlhaus with preset responses."""
    def _mock(endpoint, payload):
        return endpoint_responses.get(endpoint, {"query_status": "no_results"})
    return _mock


class TestQueryUrlHost:

    def test_domain_with_online_urls_scores_high(self):
        responses = {
            "url":  {"query_status": "invalid_url"},
            "host": {"query_status": "is_host", "urls": [
                {"url_status": "online", "threat": "malware_download",
                 "url": "http://evil.com/a.exe", "date_added": "2026-01-01", "tags": ["exe"]},
                {"url_status": "online", "threat": "malware_download",
                 "url": "http://evil.com/b.dll", "date_added": "2026-01-01", "tags": ["dll"]},
            ]}
        }
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_url_host("evil.com")

        assert r.available
        assert r.url_status == "online"
        assert r.threat == "malware_download"
        assert r.urls_found == 2
        assert r.score_contribution > 0
        assert any("URLHAUS_ACTIVE" in ioc for ioc in r.iocs)

    def test_ip_with_online_urls(self):
        responses = {
            "url":  {"query_status": "invalid_url"},
            "host": {"query_status": "is_host", "urls": [
                {"url_status": "online", "threat": "malware_download",
                 "url": "http://1.2.3.4:8080/bin.sh", "date_added": "2026-01-01", "tags": []},
                {"url_status": "online", "threat": "malware_download",
                 "url": "http://1.2.3.4:8080/i", "date_added": "2026-01-01", "tags": []},
            ]}
        }
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_url_host("1.2.3.4")

        assert r.available
        assert r.url_status == "online"
        assert r.score_contribution >= 28  # online+threat = 28+

    def test_1_url_with_threat_not_suppressed(self):
        """1 URL should be scored when threat label is confirmed (FIX v7)."""
        responses = {
            "url":  {"query_status": "invalid_url"},
            "host": {"query_status": "is_host", "urls": [
                {"url_status": "offline", "threat": "malware_download",
                 "url": "http://orbitstride7.com/curl/abc", "date_added": "2026-01-01", "tags": []},
            ]}
        }
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_url_host("orbitstride7.com")

        assert r.available
        assert r.score_contribution > 0  # Was 0 before fix — suppressed by threshold
        assert r.urls_found == 1

    def test_offline_url_with_threat_scores_partial(self):
        responses = {
            "url":  {"query_status": "invalid_url"},
            "host": {"query_status": "is_host", "urls": [
                {"url_status": "offline", "threat": "malware_download",
                 "url": "http://old.evil.com/drop.exe", "date_added": "2025-01-01", "tags": []},
                {"url_status": "offline", "threat": "malware_download",
                 "url": "http://old.evil.com/c2.php", "date_added": "2025-01-01", "tags": []},
                {"url_status": "offline", "threat": "malware_download",
                 "url": "http://old.evil.com/bot.vbs", "date_added": "2025-01-01", "tags": []},
            ]}
        }
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_url_host("old.evil.com")

        assert r.available
        assert 0 < r.score_contribution < 30  # Offline = partial score

    def test_no_results_returns_clean(self):
        responses = {
            "url":  {"query_status": "no_results"},
            "host": {"query_status": "no_results"},
        }
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_url_host("clean.com")

        assert r.available
        assert r.score_contribution == 0
        assert any("Not found" in f for f in r.flags)

    def test_rate_limit_error_handled(self):
        def ratelimit(endpoint, payload):
            return {"error": "rate_limit", "message": "Rate limit hit"}

        with patch.object(ue, "_post_urlhaus", side_effect=ratelimit):
            r = ue.query_url_host("evil.com")

        assert not r.available
        assert any("rate" in e.lower() for e in r.errors)

    def test_tags_merged_from_host_urls(self):
        responses = {
            "url":  {"query_status": "invalid_url"},
            "host": {"query_status": "is_host", "urls": [
                {"url_status": "online", "threat": "malware_download",
                 "url": "http://a.com/x", "date_added": "2026-01-01",
                 "tags": ["exe", "trojan"]},
                {"url_status": "online", "threat": "malware_download",
                 "url": "http://a.com/y", "date_added": "2026-01-01",
                 "tags": ["ransomware"]},
            ]}
        }
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_url_host("a.com")

        assert "exe" in r.tags
        assert "trojan" in r.tags
        assert "ransomware" in r.tags


class TestQueryHash:

    def test_hash_found_scores_high(self):
        responses = {
            "payload": {
                "query_status": "is_payload",
                "md5_hash": "abc123" * 5 + "ab",
                "sha256_hash": "a" * 64,
                "file_type": "exe",
                "file_size": 102400,
                "signature": "Emotet",
                "virustotal": "https://virustotal.com/...",
                "urls": [
                    {"url": "http://evil.com/drop.exe", "url_status": "online",
                     "threat": "malware_download", "date_added": "2026-01-01", "tags": []}
                ]
            }
        }
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_hash("a" * 64)

        assert r.available
        assert r.signature == "Emotet"
        assert r.score_contribution >= 25  # Signature match = +25
        assert any("Emotet" in f for f in r.flags)

    def test_hash_not_found_clean(self):
        responses = {"payload": {"query_status": "no_results"}}
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_hash("b" * 64)

        assert r.available
        assert r.score_contribution == 0

    def test_invalid_hash_format(self):
        r = ue.query_hash("notahash")
        assert not r.available or len(r.errors) > 0


class TestQueryHost:

    def test_ip_with_multiple_urls(self):
        responses = {
            "host": {"query_status": "is_host", "urls": [
                {"url_status": "online", "threat": "malware_download",
                 "url": f"http://220.1.2.3/{i}", "date_added": "2026-01-01", "tags": []}
                for i in range(5)
            ]}
        }
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_host("220.1.2.3")

        assert r.available
        assert r.urls_found == 5
        assert r.score_contribution >= 14  # 5 URLs = +14

    def test_ip_not_in_db(self):
        responses = {"host": {"query_status": "no_results"}}
        with patch.object(ue, "_post_urlhaus", side_effect=mock_post(responses)):
            r = ue.query_host("8.8.8.8")

        assert r.available
        assert r.score_contribution == 0
