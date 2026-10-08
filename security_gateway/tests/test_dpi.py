"""Deep Packet Inspection (DPI) & False-Positive Control Tests for HNX26EPS01 Gateway."""

import json
import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from dpi_engine import DPIEngine


@pytest.fixture
def dpi():
    return DPIEngine(
        max_body_bytes=1024 * 1024,
        max_uri_length=1024,
        max_json_depth=5,
    )


def test_sqlite_injections_blocked(dpi):
    attacks = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "1; DROP TABLE clients;",
        "UNION SELECT id, name FROM sqlite_master",
        "UNION ALL SELECT password, salt FROM users",
        "; ATTACH DATABASE '/tmp/injected.db' AS injected;",
        "load_extension('malicious.so')",
        "randomblob(100000000)",
        "zeroblob(500000)",
        "/*comment*/ UNION SELECT 1, 2",
    ]

    for attack in attacks:
        body = json.dumps({"search_query": attack}).encode("utf-8")
        dec = dpi.inspect_request(
            method="POST",
            path="/api/v1/legal/search",
            headers={"content-type": "application/json"},
            query_params={},
            body_bytes=body,
        )
        assert dec.action == "BLOCK", f"Attack payload bypassed DPI: {attack}"


def test_benign_legal_text_allowed(dpi):
    benign_samples = [
        "The trade union representative argued that clause 12 applies to collective bargaining.",
        "Under European Union data privacy directives, cross-border transfers require safeguards.",
        "The master service agreement between Plaintiff and Defendant was executed on May 10.",
        "Case review of Johnson v. State, 45 F.3d 112 (9th Cir. 1995).",
        "The plaintiff requested an extension of time to file the summary judgment response.",
    ]

    for text in benign_samples:
        body = json.dumps({"contract_content": text}).encode("utf-8")
        dec = dpi.inspect_request(
            method="POST",
            path="/api/v1/legal/review",
            headers={"content-type": "application/json"},
            query_params={},
            body_bytes=body,
        )
        assert dec.action == "ALLOW", f"Benign legal text falsely blocked: {text} ({dec.reason_code})"


def test_strict_identifier_validation(dpi):
    # Valid identifier
    body_valid = json.dumps({"doc_id": "doc_case_9988-A"}).encode("utf-8")
    dec_valid = dpi.inspect_request(
        method="POST",
        path="/api/v1/legal/query",
        headers={"content-type": "application/json"},
        query_params={},
        body_bytes=body_valid,
    )
    assert dec_valid.action == "ALLOW"

    # Malicious identifier with injection attempt
    body_invalid = json.dumps({"doc_id": "doc_123' OR 1=1"}).encode("utf-8")
    dec_invalid = dpi.inspect_request(
        method="POST",
        path="/api/v1/legal/query",
        headers={"content-type": "application/json"},
        query_params={},
        body_bytes=body_invalid,
    )
    assert dec_invalid.action == "BLOCK"


def test_json_nesting_depth_limit(dpi):
    # Construct JSON nested deeper than limit (depth > 5)
    nested = {"a": {"b": {"c": {"d": {"e": {"f": "too_deep"}}}}}}
    body = json.dumps(nested).encode("utf-8")

    dec = dpi.inspect_request(
        method="POST",
        path="/api/v1/legal/query",
        headers={"content-type": "application/json"},
        query_params={},
        body_bytes=body,
    )
    assert dec.action == "BLOCK"
    assert dec.reason_code == "JSON_NESTING_EXCEEDED"


def test_null_bytes_rejected(dpi):
    # Null byte in path
    dec_path = dpi.inspect_request(
        method="GET",
        path="/api/v1/documents/\x00secret",
        headers={},
        query_params={},
        body_bytes=b"",
    )
    assert dec_path.action == "BLOCK"
    assert dec_path.reason_code == "NULL_BYTE_IN_PATH"
