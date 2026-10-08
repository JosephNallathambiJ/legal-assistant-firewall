"""Zero Trust Client & Device Posture Registry Tests for HNX26EPS01 Gateway."""

import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from core.client_registry import ClientRegistration, ClientRegistry, DevicePosture


@pytest.fixture
def registry():
    reg = ClientRegistry()
    reg.register_client(
        ClientRegistration(
            client_id="client-001",
            certificate_sha256="F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E",
            allowed_roles=["ROLE_LEGAL_QUERY"],
            allowed_scopes=["legal.query", "legal.search"],
            enabled=True,
            device_posture=DevicePosture.COMPLIANT,
        )
    )
    return reg


def test_registered_compliant_device_authorized(registry):
    ok, reason, reg = registry.authorize_client(
        certificate_fingerprint="F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E",
        role="ROLE_LEGAL_QUERY",
        required_scope="legal.query",
    )
    assert ok is True
    assert reason == "DEVICE_AUTHORIZED"


def test_unregistered_device_denied(registry):
    ok, reason, reg = registry.authorize_client(
        certificate_fingerprint="0000000000000000000000000000000000000000000000000000000000000000",
        role="ROLE_LEGAL_QUERY",
    )
    assert ok is False
    assert reason == "DEVICE_NOT_REGISTERED"


def test_role_not_permitted_for_device(registry):
    ok, reason, reg = registry.authorize_client(
        certificate_fingerprint="F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E",
        role="ROLE_ADMIN",  # client-001 only allowed ROLE_LEGAL_QUERY
    )
    assert ok is False
    assert reason == "ROLE_NOT_PERMITTED_FOR_DEVICE"


def test_device_revocation(registry):
    fp = "F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E"
    revoked = registry.revoke_client(fp, reason="Stolen device reported")
    assert revoked is True

    ok, reason, _ = registry.authorize_client(certificate_fingerprint=fp, role="ROLE_LEGAL_QUERY")
    assert ok is False
    assert reason == "CERTIFICATE_REVOKED"
