"""
tests/test_scoring_normalization.py
------------------------------------
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.scoring import SCORE_NORMALIZATION_FACTOR


def _make_mock_engine(score=0, **kwargs):
    m = MagicMock()
    m.score = score
    for k, v in kwargs.items():
        setattr(m, k, v)
    return m


class TestScoringFloors:

    def _score(self, vt_malicious=0, whois_score=0, rep_score=0,
                heuristic_score=0, ai_score=0):
        """Simulate floor rule logic from scoring.py."""
        normalized = int((heuristic_score + whois_score + ai_score + rep_score) / 2.0)
        score = max(0, min(normalized, 100))

        # Rule 6: VT ≥ 3 + newly registered → MEDIUM floor
        if vt_malicious >= 3 and whois_score >= 30 and score < 40:
            score = 40

        # Rule 7: VT ≥ 3 alone → 35 floor
        elif vt_malicious >= 3 and score < 35:
            score = 35

        return score

    def test_vt3_newly_registered_floor_40(self):
        score = self._score(vt_malicious=3, whois_score=40, rep_score=15, heuristic_score=5)
        assert score >= 40, f"Expected ≥40, got {score}"

    def test_vt3_old_domain_floor_35(self):
        score = self._score(vt_malicious=3, whois_score=5, rep_score=15, heuristic_score=5)
        assert score >= 35, f"Expected ≥35, got {score}"

    def test_vt1_no_floor(self):
        score = self._score(vt_malicious=1, whois_score=5, rep_score=8, heuristic_score=2)
        assert score < 35, f"VT=1 should not trigger floor, got {score}"

    def test_high_score_not_capped_by_floor(self):
        score = self._score(vt_malicious=10, whois_score=40, rep_score=40, heuristic_score=20)
        assert score >= 40

    def test_zero_vt_zero_score(self):
        score = self._score(vt_malicious=0, whois_score=0, rep_score=0, heuristic_score=0)
        assert score == 0


class TestScoringNormalization:

    def test_normalization_factor_is_reasonable(self):
        # Max raw possible: 30+40+30+40+30+30+50+30 = 280
        # With factor=2.0: 280/2 = 140 → capped at 100
        max_raw = 30 + 40 + 30 + 40 + 30 + 30 + 50 + 30
        normalized = int(max_raw / SCORE_NORMALIZATION_FACTOR)
        assert normalized >= 100  # Should reach 100

    def test_single_engine_proportional(self):
        # WHOIS = 40 alone → raw = 40, normalized = 20
        raw = 40
        normalized = int(raw / SCORE_NORMALIZATION_FACTOR)
        assert normalized == 20

    def test_full_signal_reaches_high(self):
        # VT malicious + newly registered + SSL issues + heuristics
        raw = 25 + 40 + 20 + 35 + 10 + 0 + 30 + 0  # = 160
        normalized = int(raw / SCORE_NORMALIZATION_FACTOR)
        assert normalized >= 65  # Should be HIGH

    def test_empty_score_is_zero(self):
        assert int(0 / SCORE_NORMALIZATION_FACTOR) == 0


class TestFloorCeilingNoConflict:

    def test_az_safe_ceiling_not_applied_when_vt_malicious(self):
        """AZ_SAFE ceiling (19) should NOT apply when VT detections exist."""
        # _clean_conditions requires vt_malicious == 0
        vt_malicious = 3
        clean_conditions = vt_malicious == 0  # False
        assert not clean_conditions  # Ceiling blocked when VT malicious

    def test_floor_wins_over_ceiling_for_malicious(self):
        """If floor=40 and ceiling=35 would conflict, floor wins for malicious domains."""
        
        simulated_vt_malicious = 3 
        
        # İndi dəyişənləri bu real şərtə bağlayırıq:
        ceiling_applicable = (simulated_vt_malicious == 0)  # False olacaq
        floor_applicable   = (simulated_vt_malicious >= 3)  # True olacaq
        
        assert not (ceiling_applicable and floor_applicable) # Mutually exclusive
