"""
backend/logging_config.py
--------------------------
GhostWire CTI v6 — Centralised logging configuration.

Call setup_logging() once at app startup (app.py imports it).
All backend modules use:
    import logging
    logger = logging.getLogger(__name__)

Log level is controlled by the DEBUG env var:
    DEBUG=false  (default) → WARNING level — only real problems logged
    DEBUG=true             → DEBUG level   — full engine telemetry

Log format: structured, timestamp + module + level + message.
Log output: stderr (Streamlit captures and shows it in terminal).

Security:
    - API keys are NEVER passed to logger — engines already mask them
    - Target URLs logged only at DEBUG level, truncated to 80 chars
    - No log file created here (audit JSONL handles persistent logging)
"""

from __future__ import annotations

import logging
import os
import sys


def setup_logging() -> None:
    """
    Configure root logger for GhostWire CTI.
    Safe to call multiple times — idempotent.
    """
    debug_mode = os.environ.get("DEBUG", "false").lower() == "true"
    level = logging.DEBUG if debug_mode else logging.WARNING

    # Only configure once — prevents duplicate handlers on Streamlit reruns
    root = logging.getLogger("ghostwire")
    if root.handlers:
        return

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False

    if debug_mode:
        root.debug("GhostWire CTI v6 — debug logging enabled")


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the 'ghostwire' namespace.
    Usage:  logger = get_logger(__name__)
    """
    return logging.getLogger(f"ghostwire.{name}")
