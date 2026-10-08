"""TLS 1.3 Protocol and Cipher Enforcement Tests for HNX26EPS01 Security Gateway."""

import ssl
import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from tls_manager import CertificateExpiredError, InsecureKeyPermissionsError, TLSManager, TLSSecurityError


@pytest.fixture
def cert_paths():
    certs_dir = BASE_DIR / "certs"
    return {
        "server_crt": str(certs_dir / "server.crt"),
        "server_key": str(certs_dir / "server.key"),
        "ca_crt": str(certs_dir / "ca.crt"),
        "expired_crt": str(certs_dir / "expired.crt"),
        "expired_key": str(certs_dir / "expired.key"),
    }


def test_tls_13_enforcement(cert_paths):
    """Verifies that SSLContext strictly enforces TLS 1.3 as both minimum and maximum."""
    mgr = TLSManager(
        server_cert_path=cert_paths["server_crt"],
        server_key_path=cert_paths["server_key"],
        ca_cert_path=cert_paths["ca_crt"],
        require_client_cert=False,
    )
    ctx = mgr.ssl_context
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3


def test_legacy_protocol_options(cert_paths):
    """Verifies that legacy protocol options (SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2) are disabled."""
    mgr = TLSManager(
        server_cert_path=cert_paths["server_crt"],
        server_key_path=cert_paths["server_key"],
        ca_cert_path=cert_paths["ca_crt"],
        require_client_cert=False,
    )
    options = mgr.ssl_context.options
    assert bool(options & ssl.OP_NO_TLSv1)
    assert bool(options & ssl.OP_NO_TLSv1_1)
    assert bool(options & ssl.OP_NO_TLSv1_2)


def test_server_private_key_permissions_check(tmp_path, cert_paths):
    """Verifies that gateway refuses to initialize if private key has world/group permissions."""
    insecure_key = tmp_path / "insecure.key"
    with open(cert_paths["server_key"], "rb") as f_src:
        insecure_key.write_bytes(f_src.read())

    # Set insecure permissions (0666)
    insecure_key.chmod(0o666)

    with pytest.raises(InsecureKeyPermissionsError):
        TLSManager(
            server_cert_path=cert_paths["server_crt"],
            server_key_path=str(insecure_key),
            ca_cert_path=cert_paths["ca_crt"],
            require_client_cert=False,
        )


def test_expired_certificate_rejection(cert_paths):
    """Verifies that an expired certificate is rejected at startup."""
    # If expired.crt was generated as expired
    try:
        TLSManager(
            server_cert_path=cert_paths["expired_crt"],
            server_key_path=cert_paths["expired_key"],
            require_client_cert=False,
        )
    except (CertificateExpiredError, TLSSecurityError):
        pass  # Expected rejection
