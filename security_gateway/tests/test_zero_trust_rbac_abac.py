"""Zero Trust RBAC + ABAC Contextual Attribute Tests for HNX26EPS01 Gateway."""

import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from core.client_registry import ClientRegistration, DevicePosture
from core.identity import AuthenticatedPrincipal
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


def test_abac_posture_restriction(pdp, compliant_client):
    """Case review policy rule requires HEALTHY posture. Under DEGRADED posture, it must be denied."""
    principal = AuthenticatedPrincipal(
        principal_id="reviewer_bob",
        role="ROLE_LEGAL_REVIEW",
        client_certificate_id="client-001",
        certificate_fingerprint=compliant_client.certificate_sha256,
        token_id="tok-rev-1",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=["case.review"],
    )

    # 1. Under HEALTHY posture -> ALLOW
    ctx_healthy = RequestContext(
        request_id="req-rev-1",
        timestamp="2026-10-08T15:00:00Z",
        principal=principal,
        resource="/api/v1/legal/review",
        action="REVIEW",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=150,
        content_type="application/json",
        risk_score=15,
        posture=PostureState.HEALTHY,
        policy_version=pdp.policy_version,
    )
    dec_healthy = pdp.evaluate(ctx_healthy, compliant_client, is_upstream_valid=True)
    assert dec_healthy.is_allowed() is True

    # 2. Under DEGRADED posture -> DENY
    ctx_degraded = RequestContext(
        request_id="req-rev-2",
        timestamp="2026-10-08T15:00:00Z",
        principal=principal,
        resource="/api/v1/legal/review",
        action="REVIEW",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=150,
        content_type="application/json",
        risk_score=15,
        posture=PostureState.DEGRADED,
        policy_version=pdp.policy_version,
    )
    dec_degraded = pdp.evaluate(ctx_degraded, compliant_client, is_upstream_valid=True)
    assert dec_degraded.is_allowed() is False
    assert "HOST_POSTURE_RESTRICTED" in dec_degraded.reason_codes


def test_abac_scope_enforcement(pdp, compliant_client):
    """Verifies that missing required scope prevents authorization despite valid role."""
    principal_no_scope = AuthenticatedPrincipal(
        principal_id="counsel_no_scope",
        role="ROLE_LEGAL_QUERY",
        client_certificate_id="client-001",
        certificate_fingerprint=compliant_client.certificate_sha256,
        token_id="tok-query-1",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=["other.scope"],  # Lacks "legal.query"
    )
    ctx = RequestContext(
        request_id="req-q-1",
        timestamp="2026-10-08T15:00:00Z",
        principal=principal_no_scope,
        resource="/api/v1/legal/query",
        action="QUERY",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=50,
        content_type="application/json",
        risk_score=10,
        posture=PostureState.HEALTHY,
        policy_version=pdp.policy_version,
    )
    decision = pdp.evaluate(ctx, compliant_client, is_upstream_valid=True)
    assert decision.is_allowed() is False
    assert "SCOPE_NOT_PERMITTED" in decision.reason_codes


def test_abac_step_up_authentication(pdp, compliant_client):
    """Verifies that elevated administrative endpoint requires step_up authentication."""
    # Principal without step_up_verified
    admin_regular = AuthenticatedPrincipal(
        principal_id="admin_dan",
        role="ROLE_ADMIN",
        client_certificate_id="client-001",
        certificate_fingerprint=compliant_client.certificate_sha256,
        token_id="tok-adm-1",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=[],
        step_up_verified=False,
    )
    ctx_unstepped = RequestContext(
        request_id="req-adm-1",
        timestamp="2026-10-08T15:00:00Z",
        principal=admin_regular,
        resource="/security/admin/configure",
        action="ADMIN",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=20,
        content_type="application/json",
        risk_score=10,
        posture=PostureState.HEALTHY,
        policy_version=pdp.policy_version,
    )
    dec_unstepped = pdp.evaluate(ctx_unstepped, compliant_client, is_upstream_valid=True)
    assert dec_unstepped.decision == "STEP_UP"
    assert "STEP_UP_AUTHENTICATION_REQUIRED" in dec_unstepped.reason_codes

    # Principal with step_up_verified -> ALLOW
    admin_stepped = AuthenticatedPrincipal(
        principal_id="admin_dan",
        role="ROLE_ADMIN",
        client_certificate_id="client-001",
        certificate_fingerprint=compliant_client.certificate_sha256,
        token_id="tok-adm-1",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=[],
        step_up_verified=True,
    )
    ctx_stepped = RequestContext(
        request_id="req-adm-2",
        timestamp="2026-10-08T15:00:00Z",
        principal=admin_stepped,
        resource="/security/admin/configure",
        action="ADMIN",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=20,
        content_type="application/json",
        risk_score=10,
        posture=PostureState.HEALTHY,
        policy_version=pdp.policy_version,
    )
    dec_stepped = pdp.evaluate(ctx_stepped, compliant_client, is_upstream_valid=True)
    assert dec_stepped.decision == "ALLOW"
