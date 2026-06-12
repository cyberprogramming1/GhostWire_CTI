import pytest
from unittest.mock import patch, MagicMock
from backend.ssl_engine import _analyze_ssl_uncached

# ── Mocking SSL Sertifikatı ──────────────────────────────────────────────────

MOCK_CERT = {
    "issuer": ((("commonName", "Fake CA"),),),
    "subject": ((("commonName", "example.com"),),),
    "notBefore": "May 30 00:00:00 2026 GMT",
    "notAfter": "May 30 23:59:59 2027 GMT",
}

# ── Testlər ─────────────────────────────────────────────────────────────────

@patch("backend.ssl_engine.ssl.create_default_context")
@patch("backend.ssl_engine.socket.create_connection")
def test_analyze_ssl_success(mock_socket, mock_ssl_ctx):
    mock_sock = MagicMock()
    mock_socket.return_value = mock_sock
    
    mock_ctx = MagicMock()
    mock_ssl_ctx.return_value = mock_ctx
    
    mock_secure_sock = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_secure_sock
    mock_secure_sock.getpeercert.return_value = MOCK_CERT

    result = _analyze_ssl_uncached("example.com")

    # Düzəliş: 'issuer' yox, 'issuer_cn' istifadə edirik
    assert result.issuer_cn == "Fake CA"
    mock_socket.assert_called_once()

@patch("backend.ssl_engine.ssl.create_default_context")
@patch("backend.ssl_engine.socket.create_connection")
def test_analyze_ssl_connection_timeout(mock_socket, mock_ssl_ctx):
    mock_socket.side_effect = TimeoutError("Connection timed out")

    result = _analyze_ssl_uncached("timeout-site.com")
    
    # Düzəliş: Connection zamanı sertifikat alınmadığı üçün issuer_cn None olmalıdır
    assert result.issuer_cn is None
    assert "SSL handshake timed out" in str(result.errors)

@patch("backend.ssl_engine.ssl.create_default_context")
@patch("backend.ssl_engine.socket.create_connection")
def test_analyze_ssl_invalid_cert(mock_socket, mock_ssl_ctx):
    mock_sock = MagicMock()
    mock_socket.return_value = mock_sock
    mock_ctx = MagicMock()
    mock_ssl_ctx.return_value = mock_ctx
    mock_secure_sock = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_secure_sock
    
    # Boş sertifikat (getpeercert boş dict qaytarırsa)
    mock_secure_sock.getpeercert.return_value = {} 

    result = _analyze_ssl_uncached("bad-site.com")
    
    # Düzəliş: Əgər sertifikat boşdursa, issuer_cn boş string ("") olur
    assert result.issuer_cn == ""