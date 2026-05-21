"""
tests/conftest.py
------------------
GhostWire CTI v6 — Pytest configuration and shared fixtures.

Ensures the project root is on sys.path so all backend imports work
without needing pip install -e .
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
