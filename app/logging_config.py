"""Structured JSON logging with automatic secret redaction."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SECRET_PATTERNS = [
    re.compile(r"(password|passwd|pwd|secret|token|fernet_key|private_key|api_key)\s*[:=]\s*['\"]?([^\s,'\"\}]+)", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
]


def redact_secrets(text: str) -> str:
    """Redact potential secrets from log messages."""
    if not text:
        return text
    result = text
    result = _SECRET_PATTERNS[0].sub(r"\1=***REDACTED***", result)
    result = _SECRET_PATTERNS[1].sub("***REDACTED_PRIVATE_KEY***", result)
    return result


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_secrets(record.getMessage()),
            "module": record.module,
            "line": record.lineno,
        }
        if hasattr(record, "host"):
            payload["host"] = getattr(record, "host")
        if hasattr(record, "scan_id"):
            payload["scan_id"] = getattr(record, "scan_id")
        if record.exc_info:
            payload["exception"] = redact_secrets(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(log_level: str = "INFO", logs_dir: Path | None = None) -> None:
    """Configure root logger with structured JSON output."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    root.handlers.clear()

    formatter = JsonFormatter()

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    if logs_dir is not None:
        try:
            logs_dir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(logs_dir / "soc-monitor.log", encoding="utf-8")
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
        except OSError:
            # Fallback to stdout-only if directory is not writable (e.g., tests or non-root dev)
            pass

    # Silence noisy third-party loggers
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.INFO)
