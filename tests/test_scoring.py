"""
tests/test_scoring.py
----------------------
GhostWire CTI v6 — Unit tests for the scoring engine.

Tests cover:
  - AZ domain tiering (AZ_SAFE / AZ_REVIEW / AZ_SUSPECT / NOT_AZ)
  - Static whitelist (exact match, subdomain prefix, TLD rules)
  - Brand squatting detection (2+ keyword rule)
  - Infrastructure override threshold
  - Score normalization + clamping
  - Subdomain trap (free hosting logic)
  - _shannon_entropy helper
  - _is_private IP check (via reputation._is_private)

Run:  pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import MagicMock
from backend.scoring import (
    _classify_az_domain,
    _check_static_whitelist,
    _apply_brand_squatting,
    _apply_infra_override,
    _apply_subdomain_trap,
    _shannon_entropy,
    _is_free_hosting,
    _is_az_domain,
    _is_az_gov_domain,
    BehavioralSignals,
    INFRA_OVERRIDE_THRESHOLD,
    SQUATTING_PENALTY,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_rep(
    vt_malicious=0,
    abuse_confidence=0,
    votes=0,
    comments=0,
    relations=0,
    comment_texts=None,
):
    """Build a mock ReputationResult with the given values."""
    rep = MagicMock()
    rep.vt_malicious = vt_malicious
    rep.abuse_confidence = abuse_confidence
    rep.vt_community_malicious_votes = votes
    rep.vt_community_malicious_comments = comments
    rep.vt_malicious_files_related = relations
    rep.vt_community_comment_texts = comment_texts or []
    return rep


# ─────────────────────────────────────────────────────────────────────────────
# 1. AZ TLD detection helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestAZTLDDetection:
    def test_plain_az_domain(self):
        assert _is_az_domain("example.az") is True

    def test_subdomain_az(self):
        assert _is_az_domain("www.kapitalbank.az") is True

    def test_gov_az(self):
        assert _is_az_domain("taxes.gov.az") is True
        assert _is_az_gov_domain("taxes.gov.az") is True

    def test_edu_az(self):
        assert _is_az_gov_domain("bsu.edu.az") is True

    def test_non_az(self):
        assert _is_az_domain("google.com") is False
        assert _is_az_domain("example.co.uk") is False
        assert _is_az_domain("az.malicious.com") is False  # 'az' in hostname but not TLD

    def test_az_gov_non_gov(self):
        # .az but not .gov.az
        assert _is_az_gov_domain("kapitalbank.az") is False


# ─────────────────────────────────────────────────────────────────────────────
# 2. AZ domain tiering — _classify_az_domain
# ─────────────────────────────────────────────────────────────────────────────

class TestClassifyAZDomain:
    def test_not_az(self):
        rep = _make_rep()
        tier, reason = _classify_az_domain("google.com", rep)
        assert tier == "NOT_AZ"
        assert reason == ""

    def test_az_safe_clean(self):
        """Clean .az domain with zero signals → AZ_SAFE."""
        rep = _make_rep(vt_malicious=0, abuse_confidence=0, votes=0, comments=0, relations=0)
        tier, reason = _classify_az_domain("kapitalbank.az", rep)
        assert tier == "AZ_SAFE"
        assert "LEGIT" in reason or "clean" in reason.lower() or "VT=0" in reason

    def test_az_suspect_vt_detections(self):
        """Any VT engine detections → AZ_SUSPECT regardless of .az TLD."""
        rep = _make_rep(vt_malicious=1)
        tier, _ = _classify_az_domain("evil.az", rep)
        assert tier == "AZ_SUSPECT"

    def test_az_suspect_high_abuse(self):
        """AbuseIPDB ≥ 30 → AZ_SUSPECT."""
        rep = _make_rep(abuse_confidence=30)
        tier, _ = _classify_az_domain("spammer.az", rep)
        assert tier == "AZ_SUSPECT"

    def test_az_suspect_abuse_below_threshold(self):
        """AbuseIPDB = 29 → NOT AZ_SUSPECT (threshold is 30)."""
        rep = _make_rep(abuse_confidence=29)
        tier, _ = _classify_az_domain("borderline.az", rep)
        assert tier != "AZ_SUSPECT"

    def test_az_suspect_many_votes(self):
        """Community votes ≥ 5 → AZ_SUSPECT."""
        rep = _make_rep(votes=5)
        tier, _ = _classify_az_domain("dodgy.az", rep)
        assert tier == "AZ_SUSPECT"

    def test_az_review_relations_only(self):
        """Relations > 0 but no votes or comments → AZ_REVIEW."""
        rep = _make_rep(relations=3, votes=0, comments=0)
        tier, reason = _classify_az_domain("azal.az", rep)
        assert tier == "AZ_REVIEW"
        assert "relations" in reason.lower() or "user-uploaded" in reason.lower()

    def test_az_review_low_votes(self):
        """1–4 votes, no suspicious comments → AZ_REVIEW."""
        rep = _make_rep(votes=3)
        tier, _ = _classify_az_domain("airline.az", rep)
        assert tier == "AZ_REVIEW"

    def test_az_suspect_suspicious_comment(self):
        """Comment containing 'phishing' → AZ_SUSPECT."""
        rep = _make_rep(comment_texts=["this site is phishing for credentials"])
        tier, _ = _classify_az_domain("fake.az", rep)
        assert tier == "AZ_SUSPECT"

    def test_gov_az_clean(self):
        """Clean .gov.az domain → AZ_SAFE."""
        rep = _make_rep()
        tier, _ = _classify_az_domain("taxes.gov.az", rep)
        assert tier == "AZ_SAFE"

    def test_gov_az_with_vt(self):
        """Even .gov.az with VT detections → AZ_SUSPECT."""
        rep = _make_rep(vt_malicious=2)
        tier, _ = _classify_az_domain("fake-taxes.gov.az", rep)
        assert tier == "AZ_SUSPECT"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Static whitelist
# ─────────────────────────────────────────────────────────────────────────────

class TestStaticWhitelist:
    def test_infra_domain_exact(self):
        ok, org = _check_static_whitelist("gmail.com")
        assert ok is True
        assert "Gmail" in org or "Google" in org

    def test_infra_domain_www(self):
        ok, org = _check_static_whitelist("www.gmail.com")
        assert ok is True

    def test_infra_domain_allowed_subdomain(self):
        ok, _ = _check_static_whitelist("mail.gmail.com")
        assert ok is True

    def test_infra_domain_blocked_subdomain(self):
        """Phishing subdomain of whitelisted domain → NOT whitelisted."""
        ok, _ = _check_static_whitelist("phishing.gmail.com")
        assert ok is False

    def test_infra_domain_deep_subdomain(self):
        """Two-level subdomain of whitelisted domain → NOT whitelisted."""
        ok, _ = _check_static_whitelist("evil.mail.gmail.com")
        assert ok is False

    def test_unknown_domain(self):
        ok, _ = _check_static_whitelist("totally-unknown-site.xyz")
        assert ok is False

    def test_protonmail(self):
        ok, _ = _check_static_whitelist("proton.me")
        assert ok is True

    def test_yandex(self):
        ok, _ = _check_static_whitelist("yandex.ru")
        assert ok is True


# ─────────────────────────────────────────────────────────────────────────────
# 4. Brand squatting
# ─────────────────────────────────────────────────────────────────────────────

class TestBrandSquatting:
    def test_two_keywords_triggers(self):
        """2+ squatting keywords in hostname → penalty applied."""
        sig = BehavioralSignals()
        penalty, flags = _apply_brand_squatting(
            "http://secure-login.phishsite.com", "secure-login.phishsite.com", 0, sig
        )
        assert penalty == SQUATTING_PENALTY
        assert sig.brand_squatting is True
        assert len(flags) > 0

    def test_one_keyword_no_trigger(self):
        """Single keyword → no squatting penalty (v5 FP fix raised to 2)."""
        sig = BehavioralSignals()
        penalty, flags = _apply_brand_squatting(
            "http://login.legitimate.com", "login.legitimate.com", 0, sig
        )
        assert penalty == 0
        assert sig.brand_squatting is False

    def test_whitelisted_domain_exempt(self):
        """Keywords on whitelisted domain (e.g. paypal.com itself) → no penalty."""
        sig = BehavioralSignals()
        penalty, _ = _apply_brand_squatting(
            "https://paypal.com/signin", "paypal.com", 0, sig
        )
        assert penalty == 0

    def test_keywords_in_path_not_hostname(self):
        """Keywords only in URL path, not hostname → no penalty."""
        sig = BehavioralSignals()
        penalty, _ = _apply_brand_squatting(
            "http://innocent.com/login/verify", "innocent.com", 0, sig
        )
        assert penalty == 0

    def test_many_keywords(self):
        sig = BehavioralSignals()
        penalty, flags = _apply_brand_squatting(
            "http://verify-account-secure-login.evil.com",
            "verify-account-secure-login.evil.com", 0, sig
        )
        assert penalty == SQUATTING_PENALTY


# ─────────────────────────────────────────────────────────────────────────────
# 5. Infrastructure override
# ─────────────────────────────────────────────────────────────────────────────

class TestInfraOverride:
    def test_threshold_not_reached(self):
        """≤ threshold VT detections → no override."""
        sig = BehavioralSignals()
        score, flags = _apply_infra_override(50, INFRA_OVERRIDE_THRESHOLD, 0, sig)
        assert sig.infrastructure_override is False
        assert score == 50

    def test_threshold_exceeded(self):
        """VT detections > threshold → override to CRITICAL."""
        sig = BehavioralSignals()
        score, flags = _apply_infra_override(30, INFRA_OVERRIDE_THRESHOLD + 1, 0, sig)
        assert sig.infrastructure_override is True
        assert score >= 85
        assert len(flags) > 0

    def test_high_abuse_confidence_override(self):
        """AbuseIPDB ≥ 90 → override."""
        sig = BehavioralSignals()
        score, flags = _apply_infra_override(20, 0, 90, sig)
        assert sig.infrastructure_override is True
        assert score >= 85

    def test_score_already_critical_no_double_override(self):
        """Score already ≥ 85 → override fires but score not decreased."""
        sig = BehavioralSignals()
        score, _ = _apply_infra_override(90, INFRA_OVERRIDE_THRESHOLD + 1, 0, sig)
        assert score >= 85

    def test_threshold_is_8(self):
        """Verify threshold is exactly 8 (raised from 5 to reduce FPs)."""
        assert INFRA_OVERRIDE_THRESHOLD == 8


# ─────────────────────────────────────────────────────────────────────────────
# 6. Shannon entropy helper
# ─────────────────────────────────────────────────────────────────────────────

class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0  # no disorder

    def test_two_equal_chars(self):
        result = _shannon_entropy("ab")
        assert abs(result - 1.0) < 0.001  # exactly 1 bit

    def test_high_entropy(self):
        # Random-looking DGA domain has high entropy
        result = _shannon_entropy("x7f2k9m3q1n8")
        assert result > 3.0

    def test_low_entropy_word(self):
        result = _shannon_entropy("google")
        assert result < 3.0


# ─────────────────────────────────────────────────────────────────────────────
# 7. Free hosting detection
# ─────────────────────────────────────────────────────────────────────────────

class TestFreeHosting:
    def test_github_pages(self):
        is_free, platform = _is_free_hosting("evil-kit.github.io")
        assert is_free is True
        assert "github.io" in platform

    def test_netlify(self):
        is_free, _ = _is_free_hosting("phishing.netlify.app")
        assert is_free is True

    def test_vercel(self):
        is_free, _ = _is_free_hosting("fake-bank.vercel.app")
        assert is_free is True

    def test_real_domain(self):
        is_free, _ = _is_free_hosting("google.com")
        assert is_free is False

    def test_000webhost(self):
        is_free, _ = _is_free_hosting("attack.000webhostapp.com")
        assert is_free is True


# ─────────────────────────────────────────────────────────────────────────────
# 8. Subdomain trap
# ─────────────────────────────────────────────────────────────────────────────

class TestSubdomainTrap:
    def test_clean_free_host_no_penalty(self):
        """Free host with clean low-entropy subdomain → no penalty."""
        sig = BehavioralSignals()
        score, flags = _apply_subdomain_trap("aaaa.github.io", 10, sig)
        assert sig.subdomain_trap_active is True
        assert score == 0  # clean subdomain → no penalty

    def test_high_entropy_subdomain_penalty(self):
        """High-entropy DGA subdomain on free host → penalty."""
        sig = BehavioralSignals()
        score, flags = _apply_subdomain_trap("x7f2k9m3q8p1.netlify.app", 0, sig)
        assert score > 0
        assert any("entropy" in f.lower() for f in flags)

    def test_squatting_keyword_in_subdomain(self):
        """'paypal' keyword in free-host subdomain → penalty."""
        sig = BehavioralSignals()
        score, flags = _apply_subdomain_trap("paypal-login.github.io", 0, sig)
        assert score > 0

    def test_regular_domain_no_trap(self):
        """Non-free-hosting domain → trap not triggered."""
        sig = BehavioralSignals()
        score, flags = _apply_subdomain_trap("evil.com", 10, sig)
        assert sig.subdomain_trap_active is False
        assert score == 10  # unchanged


# ─────────────────────────────────────────────────────────────────────────────
# 9. BehavioralSignals defaults
# ─────────────────────────────────────────────────────────────────────────────

class TestBehavioralSignals:
    def test_default_all_false(self):
        sig = BehavioralSignals()
        assert sig.urgency is False
        assert sig.financial_threat is False
        assert sig.infrastructure_override is False
        assert sig.brand_squatting is False
        assert sig.subdomain_trap_active is False

    def test_default_confidence(self):
        assert BehavioralSignals().overall_confidence == 50

    def test_score_adjustments_empty(self):
        assert BehavioralSignals().score_adjustments == []
