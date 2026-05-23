"""
tests/test_otx_engine.py
-------------------------
GhostWire CTI v7 — Unit tests for OTX (AlienVault) engine.

Tests cover:
  - OTXResult dataclass defaults
  - _parse_general: pulse_count, ATT&CK IDs, adversaries, malware families
  - _score_result: no pulses, low pulses + no VT, pulses + VT, high-profile actors
  - query_indicator: mocked API (200, 404, 401, timeout, no key)
  - Corroboration logic (OTX score fires only with VT confirmation)
  - MITRE ATT&CK ID validation (format check)
  - Keyless operation (API key optional — FIX #4 regression test)

Run:  pytest tests/test_otx_engine.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import patch, MagicMock
from backend.otx_engine import (
    OTXResult,
    _parse_general,
    _score_result,
    _sanitize,
    query_indicator,
    query_domain,
    query_ip,
    query_hash,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_pulse(name="Test Pulse", attack_ids=None, adversary="", tags=None):
    return {
        "name": name,
        "attack_ids": attack_ids or [],
        "adversary": adversary,
        "tags": tags or [],
        "targeted_countries": [],
        "industries": [],
    }


def _mock_response(status_code: int, json_data: dict = None):
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = json_data or {}
    m.content = b'{"ok": true}'
    return m


# ── Sanitize ──────────────────────────────────────────────────────────────────

class TestSanitize:
    def test_strips_newlines(self):
        assert "\n" not in _sanitize("foo\nbar")
        assert "\r" not in _sanitize("foo\rbar")

    def test_truncates(self):
        assert len(_sanitize("a" * 600)) == 512

    def test_normal_preserved(self):
        val = "example.com"
        assert _sanitize(val) == val


# ── Parse General ─────────────────────────────────────────────────────────────

class TestParseGeneral:
    def test_pulse_count(self):
        data = {"pulse_info": {"count": 5, "pulses": []}}
        r = OTXResult()
        _parse_general(data, r)
        assert r.pulse_count == 5

    def test_pulse_names(self):
        pulses = [_make_pulse(f"Pulse {i}") for i in range(7)]
        data = {"pulse_info": {"count": 7, "pulses": pulses}}
        r = OTXResult()
        _parse_general(data, r)
        assert len(r.pulse_names) <= 5
        assert "Pulse 0" in r.pulse_names

    def test_attack_ids_parsed(self):
        pulse = _make_pulse(attack_ids=["T1566", "T1059"])
        data = {"pulse_info": {"count": 1, "pulses": [pulse]}}
        r = OTXResult()
        _parse_general(data, r)
        assert "T1566" in r.attack_ids
        assert "T1059" in r.attack_ids

    def test_attack_id_format_validation(self):
        """Invalid ATT&CK IDs must be filtered out."""
        pulse = _make_pulse(attack_ids=["T1566", "INVALID", "T9999", "T1059.001"])
        data = {"pulse_info": {"count": 1, "pulses": [pulse]}}
        r = OTXResult()
        _parse_general(data, r)
        assert "INVALID" not in r.attack_ids
        assert "T1566" in r.attack_ids
        assert "T1059.001" in r.attack_ids

    def test_attack_ids_deduplicated(self):
        pulses = [_make_pulse(attack_ids=["T1566"]) for _ in range(5)]
        data = {"pulse_info": {"count": 5, "pulses": pulses}}
        r = OTXResult()
        _parse_general(data, r)
        assert r.attack_ids.count("T1566") == 1

    def test_adversary_parsed(self):
        pulse = _make_pulse(adversary="Lazarus Group")
        data = {"pulse_info": {"count": 1, "pulses": [pulse]}}
        r = OTXResult()
        _parse_general(data, r)
        assert "Lazarus Group" in r.adversaries

    def test_adversary_deduplicated(self):
        pulses = [_make_pulse(adversary="Lazarus Group") for _ in range(3)]
        data = {"pulse_info": {"count": 3, "pulses": pulses}}
        r = OTXResult()
        _parse_general(data, r)
        assert r.adversaries.count("Lazarus Group") == 1

    def test_malware_families_from_tags(self):
        pulse = _make_pulse(tags=["Emotet", "Banking Trojan"])
        data = {"pulse_info": {"count": 1, "pulses": [pulse]}}
        r = OTXResult()
        _parse_general(data, r)
        assert "Emotet" in r.malware_families

    def test_empty_pulse_info(self):
        data = {"pulse_info": {"count": 0, "pulses": []}}
        r = OTXResult()
        _parse_general(data, r)
        assert r.pulse_count == 0
        assert r.attack_ids == []

    def test_reputation_parsed(self):
        data = {"pulse_info": {"count": 0, "pulses": []}, "reputation": -75}
        r = OTXResult()
        _parse_general(data, r)
        assert r.reputation == -75


# ── Score Result ──────────────────────────────────────────────────────────────

class TestScoreResult:
    def test_no_pulses_zero_score(self):
        r = OTXResult(available=True, pulse_count=0)
        _score_result(r)
        assert r.score_contribution == 0
        assert any("No threat intel" in f or "not found" in f.lower() for f in r.flags)

    def test_not_available_no_score(self):
        r = OTXResult(available=False, pulse_count=0)
        _score_result(r)
        assert r.score_contribution == 0

    def test_low_pulses_no_vt_zero_score(self):
        """FP-SAFE: OTX alone without VT = 0 score."""
        r = OTXResult(available=True, pulse_count=5)
        _score_result(r, vt_malicious=0)
        assert r.score_contribution == 0
        assert any("stale" in f.lower() or "Context only" in f for f in r.flags)

    def test_high_pulses_with_vt_scores(self):
        r = OTXResult(available=True, pulse_count=12)
        _score_result(r, vt_malicious=5)
        assert r.score_contribution == 12

    def test_medium_pulses_with_vt_scores(self):
        r = OTXResult(available=True, pulse_count=5)
        _score_result(r, vt_malicious=3)
        assert r.score_contribution == 6

    def test_low_pulses_with_vt_no_score(self):
        """1-2 pulses even with VT = too noisy, context only."""
        r = OTXResult(available=True, pulse_count=2)
        _score_result(r, vt_malicious=3)
        assert r.score_contribution == 0

    def test_score_capped_at_15(self):
        r = OTXResult(
            available=True,
            pulse_count=100,
            attack_ids=["T1566", "T1059"],
            adversaries=["Lazarus Group"],
        )
        _score_result(r, vt_malicious=10)
        assert r.score_contribution <= 15

    def test_high_profile_actor_flagged(self):
        r = OTXResult(
            available=True,
            pulse_count=15,
            adversaries=["Lazarus Group"],
        )
        _score_result(r, vt_malicious=5)
        assert any("THREAT ACTOR" in f.upper() or "Lazarus" in f for f in r.flags)

    def test_mitre_attack_shown(self):
        r = OTXResult(
            available=True,
            pulse_count=5,
            attack_ids=["T1566", "T1059"],
            attack_tactics=["Phishing", "Execution"],
        )
        _score_result(r, vt_malicious=0)
        assert any("ATT&CK" in f or "T1566" in f for f in r.flags)

    def test_negative_reputation_flagged(self):
        r = OTXResult(available=True, pulse_count=3, reputation=-80)
        _score_result(r, vt_malicious=0)
        assert any("Reputation" in f or "-80" in f for f in r.flags)


# ── Query Indicator ───────────────────────────────────────────────────────────

class TestQueryIndicator:
    @patch("backend.otx_engine._get_indicator")
    def test_successful_lookup_with_pulses(self, mock_get):
        pulse = _make_pulse("Emotet Campaign", ["T1566"], "TA505")
        mock_get.return_value = {
            "pulse_info": {"count": 8, "pulses": [pulse] * 8}
        }
        with patch.dict(os.environ, {"OTX_API_KEY": "testkey"}):
            r = query_indicator("evil.com", "domain", vt_malicious=3)
        assert r.available
        assert r.pulse_count == 8

    @patch("backend.otx_engine._get_indicator")
    def test_404_not_found_is_clean(self, mock_get):
        mock_get.return_value = {"error": "not_found"}
        with patch.dict(os.environ, {"OTX_API_KEY": "testkey"}):
            r = query_indicator("clean.com", "domain")
        assert r.available
        assert any("not found" in f.lower() or "Indicator not found" in f for f in r.flags)

    @patch("backend.otx_engine._get_indicator")
    def test_401_unauthorized(self, mock_get):
        mock_get.return_value = {"error": "unauthorized"}
        with patch.dict(os.environ, {"OTX_API_KEY": "badkey"}):
            r = query_indicator("x.com", "domain")
        assert any("key" in e.lower() or "API" in e for e in r.errors)

    @patch("backend.otx_engine._get_indicator")
    def test_timeout_graceful(self, mock_get):
        mock_get.return_value = {"error": "timeout"}
        with patch.dict(os.environ, {"OTX_API_KEY": "testkey"}):
            r = query_indicator("x.com", "domain")
        assert any("timed out" in e.lower() or "timeout" in e.lower() for e in r.errors)

    def test_keyless_operation(self):
        """FIX #4 REGRESSION: no API key should not immediately return empty result."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OTX_API_KEY", None)
            with patch("backend.otx_engine._get_indicator") as mock_get:
                mock_get.return_value = {"pulse_info": {"count": 0, "pulses": []}}
                r = query_indicator("example.com", "domain")
                # Should have made the API call (not returned early)
                assert mock_get.called

    def test_invalid_indicator_type_rejected(self):
        r = query_indicator("evil.com", "INVALID_TYPE")
        assert len(r.errors) > 0

    @patch("backend.otx_engine._get_indicator")
    def test_rate_limit_error(self, mock_get):
        mock_get.return_value = {"error": "rate_limit"}
        with patch.dict(os.environ, {"OTX_API_KEY": "testkey"}):
            r = query_indicator("x.com", "domain")
        assert any("rate" in e.lower() for e in r.errors)


# ── Convenience Wrappers ──────────────────────────────────────────────────────

class TestConvenienceWrappers:
    @patch("backend.otx_engine.query_indicator")
    def test_query_domain_passes_type(self, mock_qi):
        mock_qi.return_value = OTXResult()
        query_domain("test.com", vt_malicious=2)
        assert mock_qi.call_args[0][1] == "domain"

    @patch("backend.otx_engine.query_indicator")
    def test_query_ip_passes_ipv4(self, mock_qi):
        mock_qi.return_value = OTXResult()
        query_ip("1.2.3.4")
        assert mock_qi.call_args[0][1] == "IPv4"

    @patch("backend.otx_engine.query_indicator")
    def test_query_hash_md5(self, mock_qi):
        mock_qi.return_value = OTXResult()
        query_hash("a" * 32)
        assert mock_qi.call_args[0][1] == "FileHash-MD5"

    @patch("backend.otx_engine.query_indicator")
    def test_query_hash_sha256(self, mock_qi):
        mock_qi.return_value = OTXResult()
        query_hash("b" * 64)
        assert mock_qi.call_args[0][1] == "FileHash-SHA256"

    def test_query_hash_invalid_returns_error(self):
        r = query_hash("not-a-hash")
        assert len(r.errors) > 0
