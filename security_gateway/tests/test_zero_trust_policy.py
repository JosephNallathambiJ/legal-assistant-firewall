"""Zero Trust Policy Decision Point (PDP) Tests for HNX26EPS01 Gateway."""

import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from core.client_registry import ClientRegistration, DevicePosture
from core.identity import AuthenticatedPrincipal, AuthenticationStrength
from core.security_context import PostureState, RequestContext
from core.zero_trust_policy import ZeroTrustPolicyEngine


@pytest.fixture
def pdp():
    policy_path = BASE_DIR / "config" / "zero_trust_policy.yaml"
    return ZeroTrustPolicyEngine(config_path=str(policy_path))


@pytest.fixture
def compliant_client():
    return ClientRegistration(
        client_id="client-001",
        certificate_sha256="F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E",
        allowed_roles=["ROLE_LEGAL_QUERY", "ROLE_LEGAL_REVIEW", "ROLE_ADMIN"],
        allowed_scopes=["legal.query", "legal.search", "document.read", "case.review", "security.status"],
        enabled=True,
        device_posture=DevicePosture.COMPLIANT,
    )


def test_pdp_allows_authorized_legal_query(pdp, compliant_client):
    principal = AuthenticatedPrincipal(
        principal_id="counsel_jane",
        role="ROLE_LEGAL_QUERY",
        client_certificate_id="client-001",
        certificate_fingerprint="F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E",
        token_id="tok-1",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=["legal.query"],
    )
    ctx = RequestContext(
        request_id="req-1",
        timestamp="2026-10-08T15:00:00Z",
        principal=principal,
        resource="/api/v1/legal/query",
        action="QUERY",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=100,
        content_type="application/json",
        risk_score=10,
        posture=PostureState.HEALTHY,
        policy_version=pdp.policy_version,
    )

    decision = pdp.evaluate(ctx, client_reg=compliant_client, is_upstream_valid=True)
    assert decision.is_allowed() is True
    assert decision.decision == "ALLOW"
    assert decision.policy_id == "legal-query"


def test_pdp_denies_unregistered_client_device(pdp):
    principal = AuthenticatedPrincipal(
        principal_id="counsel_jane",
        role="ROLE_LEGAL_QUERY",
        client_certificate_id="unregistered",
        certificate_fingerprint="UNKNOWN_FINGERPRINT",
        token_id="tok-1",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=["legal.query"],
    )
    ctx = RequestContext(
        request_id="req-2",
        timestamp="2026-10-08T15:00:00Z",
        principal=principal,
        resource="/api/v1/legal/query",
        action="QUERY",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=100,
        content_type="application/json",
        risk_score=10,
        posture=PostureState.HEALTHY,
        policy_version=pdp.policy_version,
    )

    decision = pdp.evaluate(ctx, client_reg=None, is_upstream_valid=True)
    assert decision.is_allowed() is False
    assert decision.decision == "DENY"
    assert "DEVICE_NOT_REGISTERED" in decision.reason_codes


def test_pdp_denies_token_binding_mismatch(pdp, compliant_client):
    principal = AuthenticatedPrincipal(
        principal_id="stolen_token_user",
        role="ROLE_LEGAL_QUERY",
        client_certificate_id="client-001",
        certificate_fingerprint="DIFFERENT_CERT_FINGERPRINT",  # Does NOT match client_reg.certificate_sha256
        token_id="tok-stolen",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=["legal.query"],
    )
    ctx = RequestContext(
        request_id="req-3",
        timestamp="2026-10-08T15:00:00Z",
        principal=principal,
        resource="/api/v1/legal/query",
        action="QUERY",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=100,
        content_type="application/json",
        risk_score=20,
        posture=PostureState.HEALTHY,
        policy_version=pdp.policy_version,
    )

    decision = pdp.evaluate(ctx, client_reg=compliant_client, is_upstream_valid=True)
    assert decision.is_allowed() is False
    assert "TOKEN_BINDING_MISMATCH" in decision.reason_codes


def test_pdp_denies_unmapped_resource_by_default(pdp, compliant_client):
    principal = AuthenticatedPrincipal(
        principal_id="counsel_jane",
        role="ROLE_LEGAL_QUERY",
        client_certificate_id="client-001",
        certificate_fingerprint=compliant_client.certificate_sha256,
        token_id="tok-1",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=["legal.query"],
    )
    ctx = RequestContext(
        request_id="req-4",
        timestamp="2026-10-08T15:00:00Z",
        principal=principal,
        resource="/api/v1/unmapped/backdoor",
        action="QUERY",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=100,
        content_type="application/json",
        risk_score=10,
        posture=PostureState.HEALTHY,
        policy_version=pdp.policy_version,
    )

    decision = pdp.evaluate(ctx, client_reg=compliant_client, is_upstream_valid=True)
    assert decision.is_allowed() is False
    assert "POLICY_DEFAULT_DENY" in decision.reason_codes
