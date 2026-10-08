"""Zero Trust Session Security & Continuous Revalidation Tests."""

import time
import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from core.identity import AuthenticatedPrincipal
from core.security_context import PostureState
from core.session_manager import SessionManager


@pytest.fixture
def principal():
    return AuthenticatedPrincipal(
        principal_id="counsel_alice",
        role="ROLE_LEGAL_QUERY",
        client_certificate_id="client-001",
        certificate_fingerprint="AABBCC112233",
        token_id="tok-1",
        token_issued_at=int(time.time()),
        token_expiry=int(time.time()) + 900,
        scopes=["legal.query"],
    )


def test_session_lifecycle_and_continuous_revalidation(principal):
    sm = SessionManager(default_ttl_seconds=900, idle_timeout_seconds=60.0)
    session = sm.create_session(principal)
    assert sm.active_session_count() == 1

    # Immediate validation succeeds
    valid, reason, _ = sm.validate_and_touch_session(
        session_id=session.session_id,
        presented_certificate_fp="AABBCC112233",
        current_posture=PostureState.HEALTHY,
    )
    assert valid is True
    assert reason == "SESSION_VALID"


def test_session_revoked_on_certificate_mismatch(principal):
    sm = SessionManager()
    session = sm.create_session(principal)

    valid, reason, _ = sm.validate_and_touch_session(
        session_id=session.session_id,
        presented_certificate_fp="WRONG_FINGERPRINT",
        current_posture=PostureState.HEALTHY,
    )
    assert valid is False
    assert reason == "SESSION_CERTIFICATE_MISMATCH"
    assert sm.active_session_count() == 0


def test_session_revoked_on_host_lockdown(principal):
    sm = SessionManager()
    session = sm.create_session(principal)

    valid, reason, _ = sm.validate_and_touch_session(
        session_id=session.session_id,
        presented_certificate_fp="AABBCC112233",
        current_posture=PostureState.LOCKDOWN,
    )
    assert valid is False
    assert reason == "SESSION_REVOKED_HOST_COMPROMISED"
    assert sm.active_session_count() == 0


def test_session_idle_expiration(principal):
    sm = SessionManager(default_ttl_seconds=900, idle_timeout_seconds=0.1)
    session = sm.create_session(principal)

    time.sleep(0.15)
    valid, reason, _ = sm.validate_and_touch_session(
        session_id=session.session_id,
        presented_certificate_fp="AABBCC112233",
        current_posture=PostureState.HEALTHY,
    )
    assert valid is False
    assert reason == "SESSION_IDLE_TIMEOUT"
