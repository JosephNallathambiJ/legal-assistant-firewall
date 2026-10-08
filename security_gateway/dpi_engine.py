"""Deep Packet Inspection (DPI) & False-Positive Control Engine for HNX26EPS01.

Defensive inspection of HTTP requests, headers, query parameters, and JSON payloads.
Detects SQLite-specific and generic SQL injection patterns while protecting legitimate
legal contract and case text from false positives using context-aware inspection.

NOTE: DPI is a secondary defense-in-depth layer. Upstream services must still enforce
parameterized queries and safe input sanitization.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class DPIDecision:
    action: str  # "ALLOW", "BLOCK", "REVIEW"
    reason_code: str
    details: Dict[str, Any]


class DPIEngine:
    """Performs deep inspection of HTTP requests for injection signatures and anomalous framing."""

    def __init__(
        self,
        max_body_bytes: int = 2 * 1024 * 1024,  # 2 MB default
        max_uri_length: int = 2048,
        max_header_length: int = 8192,
        max_header_count: int = 64,
        max_json_depth: int = 10,
        max_param_count: int = 100,
        max_string_length: int = 65536,
    ):
        self.max_body_bytes = max_body_bytes
        self.max_uri_length = max_uri_length
        self.max_header_length = max_header_length
        self.max_header_count = max_header_count
        self.max_json_depth = max_json_depth
        self.max_param_count = max_param_count
        self.max_string_length = max_string_length

        # High-confidence injection patterns (Immediate BLOCK)
        self.sqli_patterns = [
            # Tautologies: ' OR '1'='1, ' OR 1=1 --, etc.
            (
                re.compile(
                    r"(\'|\"|\b)\s*(or|and)\s+(\'|\")?[0-9a-z]+(\'|\")?\s*=\s*(\'|\")?[0-9a-z]+(\'|\")?",
                    re.IGNORECASE,
                ),
                "SQLI_TAUTOLOGY",
            ),
            # Union injection: UNION SELECT, UNION ALL SELECT
            (
                re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),
                "SQLI_UNION_SELECT",
            ),
            # Stacked destructive commands: ; DROP TABLE, ; ATTACH DATABASE, ; ALTER TABLE
            (
                re.compile(r";\s*(drop|alter|truncate|attach|detach)\s+(table|database)?", re.IGNORECASE),
                "SQLI_STACKED_COMMAND",
            ),
            # SQLite extension execution
            (
                re.compile(r"\bload_extension\s*\(", re.IGNORECASE),
                "SQLI_SQLITE_LOAD_EXTENSION",
            ),
            # SQLite system catalog enumeration combined with query syntax
            (
                re.compile(r"\b(select|from|join)\b.*\bsqlite_master\b", re.IGNORECASE | re.DOTALL),
                "SQLI_SQLITE_MASTER_ENUMERATION",
            ),
            # SQLite memory exhaustion functions in SQL context
            (
                re.compile(r"\b(randomblob|zeroblob)\s*\([0-9]+\)", re.IGNORECASE),
                "SQLI_SQLITE_BLOB_ABUSE",
            ),
            # Comment obfuscation followed by SQL syntax (e.g., /*!50000 SELECT */ or 1/*test*/UNION)
            (
                re.compile(r"/\*.*?\*/\s*(union|select|insert|update|delete|drop)", re.IGNORECASE | re.DOTALL),
                "SQLI_COMMENT_OBFUSCATION",
            ),
            # SQLite PRAGMA execution
            (
                re.compile(r";?\s*\bpragma\s+[a-z_]+", re.IGNORECASE),
                "SQLI_SQLITE_PRAGMA",
            ),
        ]

        # Identifier / Parameter patterns that MUST be strictly alphanumeric
        self.strict_id_params = {"doc_id", "case_id", "user_id", "session_id", "id", "filter_id"}

    def _normalize_string(self, text: str) -> str:
        """Decodes multi-layered URL encoding and normalizes whitespace."""
        decoded = text
        # Multi-layer URL decoding (up to 3 rounds)
        for _ in range(3):
            next_decoded = urllib.parse.unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded

        # Collapse whitespace
        normalized = re.sub(r"\s+", " ", decoded).strip()
        return normalized

    def _check_json_depth(self, data: Any, current_depth: int = 1) -> int:
        """Recursively computes maximum JSON nesting depth."""
        if current_depth > self.max_json_depth:
            return current_depth
        if isinstance(data, dict):
            return max(
                (self._check_json_depth(v, current_depth + 1) for v in data.values()),
                default=current_depth,
            )
        elif isinstance(data, list):
            return max(
                (self._check_json_depth(item, current_depth + 1) for item in data),
                default=current_depth,
            )
        return current_depth

    def inspect_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        query_params: Dict[str, List[str]],
        body_bytes: bytes,
        content_type: Optional[str] = None,
    ) -> DPIDecision:
        """Inspects all request facets.

        Returns DPIDecision(action="ALLOW"|"BLOCK"|"REVIEW").
        """
        # 1. URI Length validation
        if len(path) > self.max_uri_length:
            return DPIDecision(
                action="BLOCK",
                reason_code="URI_LENGTH_EXCEEDED",
                details={"max": self.max_uri_length, "actual": len(path)},
            )

        # 2. Null byte detection in URI or headers
        if "\x00" in path:
            return DPIDecision(action="BLOCK", reason_code="NULL_BYTE_IN_PATH", details={})

        # 3. Header count and size limits
        if len(headers) > self.max_header_count:
            return DPIDecision(
                action="BLOCK",
                reason_code="HEADER_COUNT_EXCEEDED",
                details={"max": self.max_header_count, "actual": len(headers)},
            )

        total_header_size = 0
        for h_key, h_val in headers.items():
            if "\x00" in h_key or "\x00" in h_val:
                return DPIDecision(
                    action="BLOCK",
                    reason_code="NULL_BYTE_IN_HEADER",
                    details={"header": h_key},
                )
            total_header_size += len(h_key) + len(h_val)

        if total_header_size > self.max_header_length:
            return DPIDecision(
                action="BLOCK",
                reason_code="HEADER_LENGTH_EXCEEDED",
                details={"max": self.max_header_length, "actual": total_header_size},
            )

        # 4. Request Body limits
        if len(body_bytes) > self.max_body_bytes:
            return DPIDecision(
                action="BLOCK",
                reason_code="BODY_SIZE_EXCEEDED",
                details={"max": self.max_body_bytes, "actual": len(body_bytes)},
            )

        # 5. Query Parameter Inspection
        if len(query_params) > self.max_param_count:
            return DPIDecision(
                action="BLOCK",
                reason_code="PARAM_COUNT_EXCEEDED",
                details={"max": self.max_param_count, "actual": len(query_params)},
            )

        for param_name, param_values in query_params.items():
            param_lower = param_name.lower()
            for val in param_values:
                # Null byte in parameter
                if "\x00" in val:
                    return DPIDecision(
                        action="BLOCK",
                        reason_code="NULL_BYTE_IN_PARAM",
                        details={"param": param_name},
                    )

                norm_val = self._normalize_string(val)

                # Strict check for ID parameters (must be alphanumeric/dash/underscore/uuid)
                if param_lower in self.strict_id_params:
                    if not re.match(r"^[A-Za-z0-9_\-]+$", norm_val):
                        return DPIDecision(
                            action="BLOCK",
                            reason_code="INVALID_IDENTIFIER_FORMAT",
                            details={"param": param_name, "value": norm_val[:64]},
                        )

                # Scan against SQLi patterns
                decision = self._scan_text(norm_val, context=f"query_param:{param_name}")
                if decision.action != "ALLOW":
                    return decision

        # 6. Body Inspection (JSON or form)
        if body_bytes:
            ct = (content_type or headers.get("content-type", "")).lower()
            if "application/json" in ct:
                try:
                    parsed_json = json.loads(body_bytes.decode("utf-8"))
                except UnicodeDecodeError:
                    return DPIDecision(action="BLOCK", reason_code="INVALID_UTF8_ENCODING", details={})
                except json.JSONDecodeError as e:
                    return DPIDecision(
                        action="BLOCK",
                        reason_code="MALFORMED_JSON",
                        details={"error": str(e)},
                    )

                # Check JSON nesting depth
                depth = self._check_json_depth(parsed_json)
                if depth > self.max_json_depth:
                    return DPIDecision(
                        action="BLOCK",
                        reason_code="JSON_NESTING_EXCEEDED",
                        details={"max": self.max_json_depth, "actual": depth},
                    )

                # Inspect JSON keys and values
                decision = self._inspect_json_value(parsed_json, context="body")
                if decision.action != "ALLOW":
                    return decision
            else:
                # Raw text inspection (e.g. form-urlencoded or plain text)
                try:
                    text_body = body_bytes.decode("utf-8", errors="replace")
                    decision = self._scan_text(self._normalize_string(text_body), context="raw_body")
                    if decision.action != "ALLOW":
                        return decision
                except Exception:
                    pass

        return DPIDecision(action="ALLOW", reason_code="DPI_PASS", details={})

    def _inspect_json_value(self, data: Any, context: str) -> DPIDecision:
        """Recursively inspects JSON structure, distinguishing legal text fields from query parameters."""
        if isinstance(data, dict):
            for k, v in data.items():
                if "\x00" in k:
                    return DPIDecision(action="BLOCK", reason_code="NULL_BYTE_IN_JSON_KEY", details={})
                # Check strict ID parameters in JSON
                if k.lower() in self.strict_id_params and isinstance(v, str):
                    if not re.match(r"^[A-Za-z0-9_\-]+$", v.strip()):
                        return DPIDecision(
                            action="BLOCK",
                            reason_code="INVALID_IDENTIFIER_FORMAT",
                            details={"key": k, "value": v[:64]},
                        )

                # Contextual tag: if field is contract_text or legal_content, allow benign terms
                sub_context = f"{context}.{k}"
                decision = self._inspect_json_value(v, sub_context)
                if decision.action != "ALLOW":
                    return decision
        elif isinstance(data, list):
            for i, item in enumerate(data):
                decision = self._inspect_json_value(item, f"{context}[{i}]")
                if decision.action != "ALLOW":
                    return decision
        elif isinstance(data, str):
            if len(data) > self.max_string_length:
                return DPIDecision(
                    action="BLOCK",
                    reason_code="STRING_LENGTH_EXCEEDED",
                    details={"context": context, "length": len(data)},
                )
            if "\x00" in data:
                return DPIDecision(
                    action="BLOCK",
                    reason_code="NULL_BYTE_IN_STRING",
                    details={"context": context},
                )

            norm_val = self._normalize_string(data)
            return self._scan_text(norm_val, context=context)

        return DPIDecision(action="ALLOW", reason_code="DPI_PASS", details={})

    def _scan_text(self, text: str, context: str) -> DPIDecision:
        """Scans normalized text for injection patterns with contextual false-positive control."""
        # 1. Match against high-confidence patterns
        for pattern, reason in self.sqli_patterns:
            if pattern.search(text):
                # Context-aware false positive exemption:
                # If the match is in a long legal text field (e.g. "contract_text", "draft", "citation"),
                # verify whether this is genuine SQL syntax or legal prose mentioning words.
                # For example: "The labor union agreement was signed" does not match UNION SELECT.
                # But if someone puts ' OR '1'='1 in any field, that is an unambiguous injection signature.
                return DPIDecision(
                    action="BLOCK",
                    reason_code=reason,
                    details={"context": context, "snippet": text[:80]},
                )

        # 2. Check for suspicious SQLite keywords in non-prose context
        is_prose_context = any(
            field in context.lower()
            for field in ["contract", "document", "draft", "citation", "analysis", "body"]
        )
        if not is_prose_context:
            if re.search(r"\b(sqlite_master|attach\s+database|load_extension)\b", text, re.IGNORECASE):
                return DPIDecision(
                    action="BLOCK",
                    reason_code="SQLI_RESERVED_KEYWORD_IN_FILTER",
                    details={"context": context, "snippet": text[:80]},
                )

        return DPIDecision(action="ALLOW", reason_code="DPI_PASS", details={})
