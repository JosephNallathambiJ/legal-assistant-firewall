"""Token-to-Certificate Cryptographic Binding Tests for HNX26EPS01 Gateway."""

import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from token_vault import TokenBindingMismatchError, TokenVault


def test_token_binding_verification_success():
    vault = TokenVault(secret_bytes=b"K" * 32)
    cert_fp = "AABBCCDDEEFF00112233445566778899"

    # Mint token cryptographically bound to client certificate fingerprint
    token = vault.create_token(
        subject="counsel_alice",
        role="ROLE_LEGAL_QUERY",
        bound_cert_fingerprint=cert_fp,
    )

    claims = vault.verify_token(token, expected_cert_fingerprint=cert_fp)
    assert claims.subject == "counsel_alice"
    assert claims.bound_cert_fingerprint == cert_fp


def test_token_binding_verification_mismatch_rejected():
    vault = TokenVault(secret_bytes=b"K" * 32)
    cert_fp_a = "AAAA0000AAAA0000AAAA0000AAAA0000"
    cert_fp_b = "BBBB1111BBBB1111BBBB1111BBBB1111"

    # Token minted for Cert A
    token = vault.create_token(
        subject="counsel_alice",
        role="ROLE_LEGAL_QUERY",
        bound_cert_fingerprint=cert_fp_a,
    )

    # Attacker tries to use token with Cert B
    with pytest.raises(TokenBindingMismatchError):
        vault.verify_token(token, expected_cert_fingerprint=cert_fp_b)
