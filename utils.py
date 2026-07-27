"""
utils.py

Shared helper functions for PhishGuard: input sanitisation, validation,
logging setup, and small request helpers.
"""

import logging
import os

import bleach

MAX_INPUT_LENGTH = 5000
MIN_INPUT_LENGTH = 10


def sanitize_input(raw_text: str) -> str:
    """Strip any HTML/JS from user-submitted text and enforce a max length."""
    if not raw_text:
        return ""
    cleaned = bleach.clean(raw_text, tags=[], attributes={}, strip=True)
    return cleaned[:MAX_INPUT_LENGTH]


def validate_input(raw_text: str):
    """Validate sanitized input. Returns (is_valid, error_message)."""
    if not raw_text or not raw_text.strip():
        return False, "Please paste an email or message to analyze."
    if len(raw_text) > MAX_INPUT_LENGTH:
        return False, f"Input is too long. Please limit submissions to {MAX_INPUT_LENGTH} characters."
    if len(raw_text.strip()) < MIN_INPUT_LENGTH:
        return False, "Please paste a more complete email or message for accurate analysis."
    return True, None


def setup_logger(log_dir: str = "logs", name: str = "phishguard") -> logging.Logger:
    """
    Configure a simple file + console logger for scan activity.

    Only metadata (verdict, score, URL count) is ever logged - the actual
    pasted email content is never written to disk.
    """
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # already configured, e.g. on Flask's reloader re-import

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    file_handler = logging.FileHandler(os.path.join(log_dir, "phishguard.log"))
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


def get_client_ip(request) -> str:
    """Best-effort client IP resolution, preferring a forwarded header if present."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"
