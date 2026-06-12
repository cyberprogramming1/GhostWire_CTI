"""
tests/test_audit_log.py
-----------------------
Unit tests for backend/audit_log.py to achieve high test coverage.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# 1. Streamlit mock-laşdırılması (st.session_state-in test zamanı mövcud olması üçün)
sys.modules["streamlit"] = MagicMock()
import streamlit as st

from backend.audit_log import (
    _get_session_id,
    _get_request_seq,
    _get_hostname,
    _get_log_path,
    _ensure_log_dir,
    _rotate_if_needed,
    log_analysis,
    get_recent_logs,
    get_log_path_str
)


@pytest.fixture(autouse=True)
def setup_streamlit_session():
    """Hər testdən əvvəl st.session_state-i sıfırlayır."""
    st.session_state = {}
    yield
    st.session_state = {}


def test_get_session_id():
    """Session ID yaradılmasını və sabit qalmasını yoxlayır."""
    assert "ghostwire_session_id" not in st.session_state
    
    id1 = _get_session_id()
    assert len(id1) == 8
    assert st.session_state["ghostwire_session_id"] == id1
    
    # İkinci çağırışda eyni ID qayıtmalıdır
    id2 = _get_session_id()
    assert id1 == id2


def test_get_request_seq():
    """Sorğu sayğacının hər çağırışda 1 vahid artmasını yoxlayır."""
    assert _get_request_seq() == 1
    assert _get_request_seq() == 2
    assert _get_request_seq() == 3
    assert st.session_state["ghostwire_req_seq"] == 3


def test_get_hostname_success():
    """Hostname-in uğurla oxunmasını yoxlayır."""
    with patch("socket.gethostname", return_value="GhostWire-Server-Node-01"):
        hostname = _get_hostname()
        assert hostname == "GhostWire-Server-Node-01"


def test_get_hostname_failure():
    """Socket xəta verdikdə funksiyanın 'unknown' qaytarmasını yoxlayır."""
    with patch("socket.gethostname", side_effect=Exception("Socket error")):
        hostname = _get_hostname()
        assert hostname == "unknown"


def test_get_log_path_default():
    """Xüsusi mühit dəyişəni olmadıqda default yolun götürülməsini yoxlayır."""
    with patch.dict(os.environ, {}, clear=True):
        path = _get_log_path()
        assert ".ghostwire" in str(path)


def test_get_log_path_custom():
    """GHOSTWIRE_LOG_PATH təyin edildikdə həmin yolun götürülməsini yoxlayır."""
    custom_path = "/tmp/custom_audit.jsonl"
    with patch.dict(os.environ, {"GHOSTWIRE_LOG_PATH": custom_path}):
        path = _get_log_path()
        assert path == Path(custom_path)


def test_ensure_log_dir():
    """Qovluğun yaradılma funksiyasının düzgün çağırılmasını yoxlayır."""
    mock_path = MagicMock()
    _ensure_log_dir(mock_path)
    mock_path.parent.mkdir.assert_called_once_with(parents=True, exist_ok=True)


def test_rotate_if_needed_no_rotate():
    """Log faylının ölçüsü kiçik olduqda (məsələn, rotation lazım olmadıqda) yoxlanış."""
    mock_path = MagicMock()
    mock_path.exists.return_value = True
    # Ölçünü kiçik qoyuruq: 5MB (Limit 50MB-dır)
    mock_path.stat.return_value.st_size = 5 * 1_000_000
    
    _rotate_if_needed(mock_path)
    mock_path.rename.assert_not_called()


def test_rotate_if_needed_trigger_rotate():
    """Log faylı 50MB-ı keçdikdə adının dəyişdirilməsini (rotate) yoxlayır."""
    mock_path = MagicMock()
    mock_path.exists.return_value = True
    # Ölçünü böyük qoyuruq: 60MB
    mock_path.stat.return_value.st_size = 60 * 1_000_000
    
    # with_suffix metodunun yeni yol qaytarmasını simulyasiya edirik
    mock_rotated_path = MagicMock()
    mock_path.with_suffix.return_value = mock_rotated_path
    
    _rotate_if_needed(mock_path)
    mock_path.rename.assert_called_once_with(mock_rotated_path)


def test_rotate_if_needed_exception_handling():
    """Rotation zamanı xəta baş verərsə funksiyanın çökməməsini yoxlayır."""
    mock_path = MagicMock()
    mock_path.exists.side_effect = Exception("Disk error")
    
    # Heç bir xəta (Exception) çölə sıçramamalıdır, silently fail olmalıdır
    _rotate_if_needed(mock_path)


def test_log_analysis_success(tmp_path):
    """log_analysis funksiyasının uğurla JSONL sətirləri yazmasını yoxlayır."""
    test_file = tmp_path / "test_audit.jsonl"
    
    with patch.dict(os.environ, {"GHOSTWIRE_LOG_PATH": str(test_file)}), \
         patch("backend.audit_log._get_hostname", return_value="test-host"), \
         patch("config.defang_url", return_value="hxxps://malicious[.]com"):
         
        log_analysis(
            pipeline="url",
            target="https://malicious.com",
            score=85,
            verdict="Suspicious Infrastructure",
            threat_level="HIGH",
            engines_triggered=["Shodan", "GreyNoise"],
            ioc_count=2,
            duration_secs=1.456,
            error=None
        )
        
    assert test_file.exists()
    content = test_file.read_text(encoding="utf-8").strip()
    data = json.loads(content)
    
    assert data["pipeline"] == "url"
    assert data["target"] == "hxxps://malicious[.]com"
    assert data["score"] == 85
    assert data["threat_level"] == "HIGH"
    assert data["hostname"] == "test-host"
    assert data["engines"] == ["Shodan", "GreyNoise"]
    assert data["duration_secs"] == 1.46  # round(x, 2) yoxlanışı


def test_log_analysis_exception_handling():
    """log_analysis daxilində kritik xəta yarandıqda proqramın crash olmamasını yoxlayır."""
    with patch("backend.audit_log._get_log_path", side_effect=Exception("Fatal OS Error")):
        # Bu çağırış heç bir halda proqramı çökdürməməlidir (Never raises prinsipi)
        log_analysis(pipeline="ip", target="1.1.1.1")


def test_get_recent_logs_empty():
    """Fayl mövcud olmadıqda get_recent_logs-un boş siyahı qaytarmasını yoxlayır."""
    with patch("backend.audit_log._get_log_path") as mock_path:
        mock_path.return_value.exists.return_value = False
        assert get_recent_logs() == []


def test_get_recent_logs_parsing(tmp_path):
    """Yazılmış loqların düzgün parse edilib tərs ardıcıllıqla oxunmasını yoxlayır."""
    test_file = tmp_path / "read_audit.jsonl"
    
    entry1 = {"pipeline": "ip", "target": "1.1.1.1"}
    entry2 = {"pipeline": "hash", "target": "e3b0c442"}
    entry3 = {"invalid_json": ...} # xarab sətir
    
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(entry1) + "\n")
        f.write("corrupted json string\n")  # xətalı json parsing yoxlanışı üçün
        f.write(json.dumps(entry2) + "\n")
        
    with patch.dict(os.environ, {"GHOSTWIRE_LOG_PATH": str(test_file)}):
        logs = get_recent_logs(n=10)
        
    assert len(logs) == 2
    # Ən son yazılan ən birinci gəlməlidir (reversed)
    assert logs[0]["pipeline"] == "hash"
    assert logs[1]["pipeline"] == "ip"


def test_get_recent_logs_exception():
    """get_recent_logs işləyərkən gözlənilməz xəta olarsa [] qaytarmasını yoxlayır."""
    with patch("backend.audit_log._get_log_path", side_effect=Exception("Read failure")):
        assert get_recent_logs() == []


def test_get_log_path_str():
    """get_log_path_str funksiyasının düzgün string qaytarmasını yoxlayır."""
    with patch("backend.audit_log._get_log_path") as mock_path:
        mock_path.return_value = Path("/tmp/audit.jsonl")
        
        # os.path.normpath sayəsində Windows-da backslash, Linux-da slash avtomatik tənzimlənir
        import os
        assert os.path.normpath(get_log_path_str()) == os.path.normpath("/tmp/audit.jsonl")