"""Enterprise Security Event Logger for HNX26EPS01 Security Gateway.

Provides structured JSON logging with strict sanitization and redaction to prevent
credential leaks or sensitive legal document exposure in audit records.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Sensitive keys that must be completely redacted if encountered
REDACTED_KEYS = {
    "authorization",
    "cookie",
    "token",
    "secret",
    "key",
    "password",
    "private_key",
    "hmac_key",
    "access_token",
    "refresh_token",
    "client_secret",
}

# Regex to detect bearer tokens or sensitive credential patterns
BEARER_PATTERN = re.compile(r"Bearer\s+([A-Za-z0-9_\-\.]+)", re.IGNORECASE)


def sanitize_data(data: Any, depth: int = 0) -> Any:
    """Recursively sanitize sensitive data from dictionaries, lists, and strings.

    Ensures no passwords, secrets, full case documents, or authorization tokens
    are written to disk or logs.
    """
    if depth > 10:
        return "[MAX_DEPTH_EXCEEDED]"

    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if any(redacted in key_lower for redacted in REDACTED_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_data(v, depth + 1)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_data(item, depth + 1) for item in data]
    elif isinstance(data, str):
        # Redact Bearer tokens
        if "Bearer " in data:
            data = BEARER_PATTERN.sub("Bearer [REDACTED]", data)
        # Prevent oversized document logging
        if len(data) > 512:
            return data[:128] + f"... [TRUNCATED len={len(data)}]"
        return data
    elif isinstance(data, (int, float, bool)) or data is None:
        return data
    else:
        return str(data)


class SecurityJsonFormatter(logging.Formatter):
    """Formats security events into single-line machine-readable JSON."""

    def format(self, record: logging.LogRecord) -> str:
        base_event: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
        }

        # If custom attributes were attached
        if hasattr(record, "security_event"):
            event_data = getattr(record, "security_event")
            if isinstance(event_data, dict):
                base_event.update(sanitize_data(event_data))
        else:
            base_event["message"] = sanitize_data(record.getMessage())

        return json.dumps(base_event, separators=(",", ":"))


class SecurityLogger:
    """Singleton/Instance logger for all security events across gateway subsystems."""

    def __init__(self, log_file: Optional[str] = None, name: str = "security_gateway"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        formatter = SecurityJsonFormatter()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler if path provided
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def log_event(
        self,
        event: str,
        severity: str,
        action: str,
        source_ip: str = "127.0.0.1",
        client_id: str = "anonymous",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record an immutable, structured security audit event."""
        payload = {
            "event": event,
            "severity": severity.upper(),
            "source_ip": source_ip,
            "client_id": client_id,
            "action": action.upper(),
            "details": details or {},
        }

        log_level = {
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "HIGH": logging.WARNING,
            "CRITICAL": logging.CRITICAL,
        }.get(severity.upper(), logging.INFO)

        record = self.logger.makeRecord(
            self.logger.name,
            log_level,
            "(unknown)",
            0,
            event,
            (),
            None,
        )
        record.security_event = payload  # type: ignore[attr-defined]
        self.logger.handle(record)
        return payload


# Global shared instance
_global_logger: Optional[SecurityLogger] = None


def get_security_logger(log_file: Optional[str] = None) -> SecurityLogger:
    global _global_logger
    if _global_logger is None:
        _global_logger = SecurityLogger(log_file=log_file)
    return _global_logger
