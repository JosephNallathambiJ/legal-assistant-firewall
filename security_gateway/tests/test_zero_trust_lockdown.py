"""Zero Trust Emergency Lockdown & Dynamic Deny Tests for HNX26EPS01 Gateway."""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from core.client_registry import ClientRegistration, DevicePosture
from core.identity import AuthenticatedPrincipal
from core.security_context import PostureState, RequestContext, SecurityPosture
from core.session_manager import SessionManager
from core.zero_trust_policy import ZeroTrustPolicyEngine
from incident_response import IncidentResponseManager


def test_lockdown_denies_all_requests_and_revokes_sessions(tmp_path):
    ir = IncidentResponseManager(state_dir=str(tmp_path))
    posture = SecurityPosture(gateway_state="READY")
    sm = SessionManager()

    # Active session
    principal = AuthenticatedPrincipal(
        principal_id="counsel_active",
        role="ROLE_LEGAL_QUERY",
        client_certificate_id="client-001",
        certificate_fingerprint="F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E",
        token_id="tok-active-1",
        token_issued_at=1700000000,
        token_expiry=1700000900,
        scopes=["legal.query"],
    )
    sess = sm.create_session(principal)
    assert sm.active_session_count() == 1

    policy_path = BASE_DIR / "config" / "zero_trust_policy.yaml"
    pdp = ZeroTrustPolicyEngine(config_path=str(policy_path))
    client_reg = ClientRegistration(
        client_id="client-001",
        certificate_sha256="F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E",
        allowed_roles=["ROLE_LEGAL_QUERY"],
        allowed_scopes=["legal.query"],
        enabled=True,
    )

    # 1. Trigger Emergency Lockdown
    ir.trigger_lockdown(reason="Critical tampering detected by watchdog", telemetry={"alert": True})
    posture.gateway_state = ir.current_state.value
    overall = posture.compute_overall_posture()
    assert overall == PostureState.LOCKDOWN

    # 2. Revalidate active session -> must be revoked
    valid, reason, _ = sm.validate_and_touch_session(
        session_id=sess.session_id,
        presented_certificate_fp="F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E",
        current_posture=overall,
    )
    assert valid is False
    assert sm.active_session_count() == 0

    # 3. PDP evaluates request during lockdown -> must be DENIED
    ctx = RequestContext(
        request_id="req-lockdown-1",
        timestamp="2026-10-08T15:00:00Z",
        principal=principal,
        resource="/api/v1/legal/query",
        action="QUERY",
        http_method="POST",
        source_ip="127.0.0.1",
        body_length=50,
        content_type="application/json",
        risk_score=10,
        posture=overall,
        policy_version=pdp.policy_version,
    )
    decision = pdp.evaluate(ctx, client_reg, is_upstream_valid=True)
    assert decision.is_allowed() is False
    assert "WATCHDOG_ALERT" in decision.reason_codes or "SECURITY_POSTURE_UNHEALTHY" in decision.reason_codes
