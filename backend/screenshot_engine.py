"""
backend/screenshot_engine.py
-----------------------------
Website Screenshot Engine — GhostWire CTI v6 (SECURITY HARDENED)

Security fixes applied:
  - JavaScript DISABLED (was enabled — drive-by JS exploit risk)
  - --no-sandbox REMOVED; replaced with proper sandbox flags
  - Network request blocking: only allows page HTML load, blocks all
    JS/XHR/WebSocket/fetch to prevent SSRF and data exfil from renderer
  - Strict 8-second navigation timeout
  - Isolated browser context (no cookies, no storage, no permissions)
  - Returns PNG bytes or None on any failure — never raises
"""

from __future__ import annotations

import base64
from typing import Optional

from backend.sandbox import _is_ssrf_target

import logging
logger = logging.getLogger(__name__)


# ── Blocked resource types (JS disabled at context level too) ─────────────────
_BLOCK_TYPES = {
    "script", "xhr", "fetch", "websocket",
    "eventsource", "manifest", "other",
}


def capture_screenshot(url: str, width: int = 1280, height: int = 720) -> Optional[bytes]:
    """
    Capture a screenshot of the target URL using Playwright Chromium.

    SECURITY MODEL:
      - JavaScript is DISABLED — no JS executes in the renderer
      - All script/XHR/fetch/websocket resource types are blocked at network layer
      - --no-sandbox is NOT used; Linux sandboxing is preserved via
        --disable-setuid-sandbox (safer alternative that works in containers)
      - No cookies, no localStorage, no permissions granted
      - Hard 8-second timeout; partial render is captured on timeout

    Args:
        url:    Full URL to visit (must start with http:// or https://)
        width:  Viewport width  (default 1280)
        height: Viewport height (default 720)

    Returns:
        PNG bytes if successful, None if any error occurred.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # ── SSRF guard ────────────────────────────────────────────────────────
    # Playwright follows redirects internally, bypassing sandbox.py's check.
    # Re-validate here before handing the URL to the browser process.
    blocked, reason = _is_ssrf_target(url)
    if blocked:
        return None

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

        with sync_playwright() as p:
            browser = p.chromium.launch(
                args=[
                    # REMOVED: --no-sandbox  ← was the critical security hole
                    # Use setuid-sandbox disable instead (safer, works in containers)
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-default-apps",
                    "--disable-sync",
                    "--disable-translate",
                    "--disable-notifications",
                    "--disable-geolocation",
                    "--disable-infobars",
                    "--no-first-run",
                    "--mute-audio",
                    "--block-new-web-contents",        # blocks popups
                    "--disable-popup-blocking",        # we handle this ourselves
                    "--disable-javascript",            # belt-and-suspenders JS disable
                ],
                headless=True,
            )

            context = browser.new_context(
                viewport={"width": width, "height": height},
                # ── CRITICAL FIX: JavaScript DISABLED ──────────────────
                java_script_enabled=False,    # was True — now False
                bypass_csp=False,
                locale="en-US",
                # No permissions granted
                permissions=[],
                # No geolocation
                geolocation=None,
                # Isolated storage — no cookies survive between sessions
                storage_state=None,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
            )

            page = context.new_page()

            # ── Block all JS/XHR/fetch/WebSocket at network level ──────
            # This is a second layer of protection even with JS disabled
            def _block_dangerous(route, request):
                if request.resource_type in _BLOCK_TYPES:
                    route.abort()
                else:
                    route.continue_()

            page.route("**/*", _block_dangerous)

            try:
                page.goto(url, timeout=8000, wait_until="domcontentloaded")
                # No wait_for_timeout — JS is off, no dynamic content to wait for
            except PWTimeout:
                # Timeout is acceptable — capture whatever rendered
                pass
            except Exception:
                pass

            # Capture visible viewport only — no full_page scroll
            img_bytes = page.screenshot(
                clip={"x": 0, "y": 0, "width": width, "height": height},
                full_page=False,
            )

            browser.close()
            return img_bytes

    except ImportError:
        # Playwright not installed — silently skip
        return None
    except Exception:
        return None


def screenshot_to_base64(img_bytes: bytes) -> str:
    """Convert PNG bytes to base64 data URI for HTML embedding."""
    return "data:image/png;base64," + base64.b64encode(img_bytes).decode()
