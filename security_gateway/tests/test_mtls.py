"""Mutual TLS (mTLS) Authentication & Pinning Tests for HNX26EPS01 Gateway."""

import ssl
import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from tls_manager import CertificatePinMismatchError, TLSManager, TLSSecurityError


@pytest.fixture
def cert_paths():
    certs_dir = BASE_DIR / "certs"
    return {
        "server_crt": str(certs_dir / "server.crt"),
        "server_key": str(certs_dir / "server.key"),
        "ca_crt": str(certs_dir / "ca.crt"),
        "client_crt": str(certs_dir / "client.crt"),
        "client_key": str(certs_dir / "client.key"),
        "untrusted_client_crt": str(certs_dir / "untrusted_client.crt"),
    }


def test_mtls_configuration(cert_paths):
    """Verifies that mTLS configuration sets verify_mode to CERT_REQUIRED and loads CA."""
    mgr = TLSManager(
        server_cert_path=cert_paths["server_crt"],
        server_key_path=cert_paths["server_key"],
        ca_cert_path=cert_paths["ca_crt"],
        require_client_cert=True,
    )
    assert mgr.ssl_context.verify_mode == ssl.CERT_REQUIRED


def test_authorized_client_der_verification(cert_paths):
    """Verifies that authorized client certificate DER bytes are accepted."""
    mgr = TLSManager(
        server_cert_path=cert_paths["server_crt"],
        server_key_path=cert_paths["server_key"],
        ca_cert_path=cert_paths["ca_crt"],
        require_client_cert=True,
    )

    client_pem = Path(cert_paths["client_crt"]).read_bytes()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(client_pem)
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    info = mgr.verify_client_der_certificate(cert_der)
    assert "CN=client-legal-assistant" in info["subject"]
    assert "CN=HNX-Security-Root-CA" in info["issuer"]
    assert "fingerprint" in info
    assert "spki_pin" in info


def test_certificate_fingerprint_pinning_success(cert_paths):
    """Verifies that pinning succeeds when client fingerprint matches pinned allowlist."""
    client_pem = Path(cert_paths["client_crt"]).read_bytes()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(client_pem)
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    fp = TLSManager.compute_cert_fingerprint(cert_der)

    mgr = TLSManager(
        server_cert_path=cert_paths["server_cert_path" if "server_cert_path" in cert_paths else "server_crt"],
        server_key_path=cert_paths["server_key"],
        ca_cert_path=cert_paths["ca_crt"],
        require_client_cert=True,
        pinned_fingerprints=[fp],
    )
    info = mgr.verify_client_der_certificate(cert_der)
    assert info["fingerprint"] == fp


def test_certificate_fingerprint_pinning_mismatch(cert_paths):
    """Verifies that pinning fails when client fingerprint is not in allowlist."""
    client_pem = Path(cert_paths["client_crt"]).read_bytes()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(client_pem)
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    mgr = TLSManager(
        server_cert_path=cert_paths["server_crt"],
        server_key_path=cert_paths["server_key"],
        ca_cert_path=cert_paths["ca_crt"],
        require_client_cert=True,
        pinned_fingerprints=["0000000000000000000000000000000000000000000000000000000000000000"],
    )
    with pytest.raises(CertificatePinMismatchError):
        mgr.verify_client_der_certificate(cert_der)


def test_spki_public_key_pinning(cert_paths):
    """Verifies SubjectPublicKeyInfo (SPKI) pinning for rotation resilience."""
    client_pem = Path(cert_paths["client_crt"]).read_bytes()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(client_pem)
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    spki_hash = TLSManager.compute_spki_pin(cert_der)

    mgr = TLSManager(
        server_cert_path=cert_paths["server_crt"],
        server_key_path=cert_paths["server_key"],
        ca_cert_path=cert_paths["ca_crt"],
        require_client_cert=True,
        pinned_spki_hashes=[spki_hash],
    )
    info = mgr.verify_client_der_certificate(cert_der)
    assert info["spki_pin"] == spki_hash
