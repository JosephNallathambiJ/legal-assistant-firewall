"""Zero Trust Cryptographic Identity Context Tests for HNX26EPS01 Gateway."""

import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from core.identity import AnonymousPrincipal, AuthenticatedPrincipal, AuthenticationStrength


def test_authenticated_principal_attributes():
    principal = AuthenticatedPrincipal(
        principal_id="counsel_alice",
        role="ROLE_LEGAL_QUERY",
        client_certificate_id="client-001",
        certificate_fingerprint="AABBCC112233",
        token_id="tok-uuid-1",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=["legal.query", "legal.search"],
        auth_strength=AuthenticationStrength.MTLS_PLUS_TOKEN,
    )
    assert principal.principal_id == "counsel_alice"
    assert principal.role == "ROLE_LEGAL_QUERY"
    assert principal.has_scope("legal.query") is True
    assert principal.has_scope("admin.manage") is False
    assert principal.binds_to_certificate("aabbcc112233") is True
    assert principal.binds_to_certificate("DIFFERENT_FP") is False


def test_anonymous_principal_has_no_privileges():
    anon = AnonymousPrincipal(source_ip="192.168.1.50")
    assert anon.role == "ROLE_ANONYMOUS"
    assert anon.auth_strength == AuthenticationStrength.UNAUTHENTICATED
    assert anon.scopes == []
    assert anon.token_id == ""


def test_no_trust_elevation_from_client_metadata():
    """Verifies that principal properties are immutable and cannot be overridden by dict mutation."""
    principal = AuthenticatedPrincipal(
        principal_id="counsel_bob",
        role="ROLE_LEGAL_QUERY",
        client_certificate_id="client-002",
        certificate_fingerprint="112233445566",
        token_id="tok-uuid-2",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=["legal.query"],
    )
    with pytest.raises(AttributeError):
        principal.role = "ROLE_ADMIN"  # type: ignore[misc]
