"""Deterministic Request Risk Engine Tests for HNX26EPS01 Gateway."""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from core.risk_engine import RiskEngine, RiskLevel
from core.security_context import PostureState


def test_benign_request_low_risk():
    engine = RiskEngine()
    assessment = engine.assess_request(
        source_ip="127.0.0.1",
        is_authenticated=True,
        is_known_client=True,
        cert_binding_match=True,
        dpi_action="ALLOW",
        posture=PostureState.HEALTHY,
        body_length=256,
    )
    assert assessment.score <= 20
    assert assessment.level == RiskLevel.LOW
    assert len(assessment.factors) == 0


def test_dpi_block_escalates_risk():
    engine = RiskEngine()
    assessment = engine.assess_request(
        source_ip="127.0.0.1",
        is_authenticated=True,
        is_known_client=True,
        cert_binding_match=True,
        dpi_action="BLOCK",
        posture=PostureState.HEALTHY,
        body_length=256,
    )
    assert assessment.score >= 45
    assert assessment.level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
    assert any("DPI_INJECTION" in f for f in assessment.factors)


def test_host_compromise_triggers_critical_risk():
    engine = RiskEngine()
    assessment = engine.assess_request(
        source_ip="127.0.0.1",
        is_authenticated=True,
        is_known_client=True,
        cert_binding_match=True,
        dpi_action="ALLOW",
        posture=PostureState.COMPROMISED,
        body_length=256,
    )
    assert assessment.score >= 76
    assert assessment.level == RiskLevel.CRITICAL
    assert any("HOST_POSTURE_COMPROMISED" in f for f in assessment.factors)
