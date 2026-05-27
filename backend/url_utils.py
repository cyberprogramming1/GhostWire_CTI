"""
backend/url_utils.py
---------------------
Shared URL utility functions for GhostWire CTI.
Centralises helpers used across multiple pipelines to avoid duplication.
"""

from __future__ import annotations
import re
import ipaddress


def normalise_url(raw: str) -> str:
    """
    Ensure URL has an http:// scheme prefix.
    Used by pipeline_url, pipeline_sandbox, and app.py.
    FIX v8: Centralised to avoid drift between duplicate implementations.
    """
    raw = raw.strip()
    if raw and not raw.startswith(("http://", "https://", "ftp://")):
        return "http://" + raw
    return raw


def extract_hostname(url: str) -> str:
    """
    Extract bare hostname from a URL, domain, or IP address.
    Returns empty string on failure — never raises.
    """
    try:
        import urllib.parse as _up
        _url = url if "://" in url else "http://" + url
        parsed = _up.urlparse(_url)
        return (parsed.hostname or "").strip().lower()
    except Exception:
        return ""


def is_ip_address(host: str) -> bool:
    """Return True if host is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_ipv6(host: str) -> bool:
    """Return True if host is a valid IPv6 address."""
    try:
        addr = ipaddress.ip_address(host.strip("[]"))
        return isinstance(addr, ipaddress.IPv6Address)
    except ValueError:
        return False
