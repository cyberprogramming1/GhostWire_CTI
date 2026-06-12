import pytest
from unittest.mock import patch, MagicMock
from backend.screenshot_engine import capture_screenshot

# ── 1. SSRF Guard Testləri ───────────────────────────────────────────────────

@patch("backend.screenshot_engine._is_ssrf_target")
def test_capture_screenshot_ssrf_blocked(mock_ssrf):
    # SSRF bloklanıb, funksiya None qaytarmalıdır
    mock_ssrf.return_value = (True, "Blocked by SSRF")
    
    result = capture_screenshot("http://internal-server.local")
    assert result is None
    mock_ssrf.assert_called_once()

# ── 2. Playwright İmport Testləri ────────────────────────────────────────────

@patch("backend.screenshot_engine._is_ssrf_target")
def test_capture_screenshot_playwright_not_installed(mock_ssrf):
    # SSRF yoxlaması keçdi
    mock_ssrf.return_value = (False, "")
    
    # Playwright-ı sistemdə yoxmuş kimi simulyasiya edirik (ImportError)
    with patch.dict("sys.modules", {"playwright.sync_api": None}):
        # Bu hissə funksiyanın daxilindəki ImportError-u tetikləyəcək
        result = capture_screenshot("https://example.com")
        assert result is None

# ── 3. Uğurlu Ssenari Testi ─────────────────────────────────────────────────

@patch("backend.screenshot_engine._is_ssrf_target")
@patch("playwright.sync_api.sync_playwright")
def test_capture_screenshot_success(mock_playwright, mock_ssrf):
    mock_ssrf.return_value = (False, "")
    
    # Mocking Playwright strukturu: p -> browser -> context -> page
    mock_p = MagicMock()
    mock_playwright.return_value.__enter__.return_value = mock_p
    
    mock_browser = mock_p.chromium.launch.return_value
    mock_context = mock_browser.new_context.return_value
    mock_page = mock_context.new_page.return_value
    
    # Ekran görüntüsü baytları
    fake_bytes = b"fake_png_data"
    mock_page.screenshot.return_value = fake_bytes
    
    # Testi işə sal
    result = capture_screenshot("https://example.com")
    
    assert result == fake_bytes
    mock_page.goto.assert_called_once()
    mock_browser.close.assert_called_once()

# ── 4. Exception (Timeout) Testləri ─────────────────────────────────────────

@patch("backend.screenshot_engine._is_ssrf_target")
@patch("playwright.sync_api.sync_playwright")
def test_capture_screenshot_timeout_handling(mock_playwright, mock_ssrf):
    mock_ssrf.return_value = (False, "")
    
    # Playwright timeout-u tetikləyirik
    mock_p = MagicMock()
    mock_playwright.return_value.__enter__.return_value = mock_p
    mock_page = mock_p.chromium.launch.return_value.new_context.return_value.new_page.return_value
    
    # page.goto-nun timeout atmasını simulyasiya edirik
    from playwright.sync_api import TimeoutError as PWTimeout
    mock_page.goto.side_effect = PWTimeout("Navigation Timeout")
    mock_page.screenshot.return_value = b"timeout_image"
    
    # Timeout olsa belə, funksiya tutub davam etməlidir (kodda 'pass' yazılıb)
    result = capture_screenshot("https://slow-site.com")
    
    assert result == b"timeout_image"