"""HMAC-SHA256 Token Authentication & Security Tests for HNX26EPS01 Gateway."""

import sys
import time
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from token_vault import (
    InsecureKeyPermissionsError,
    TokenExpiredError,
    TokenReplayError,
    TokenTamperedError,
    TokenVault,
)


def test_token_creation_and_verification():
    vault = TokenVault(secret_bytes=b"0" * 32)
    token = vault.create_token(
        subject="legal_counsel_alice",
        role="ROLE_LEGAL_QUERY",
        scopes=["legal.query", "legal.search"],
        ttl_seconds=300,
    )
    claims = vault.verify_token(token)
    assert claims.subject == "legal_counsel_alice"
    assert claims.role == "ROLE_LEGAL_QUERY"
    assert "legal.query" in claims.scopes
    assert claims.expiry > int(time.time())


def test_expired_token_rejected():
    vault = TokenVault(secret_bytes=b"0" * 32)
    token = vault.create_token(
        subject="expired_user",
        role="ROLE_LEGAL_QUERY",
        ttl_seconds=-5,  # Already expired
    )
    with pytest.raises(TokenExpiredError):
        vault.verify_token(token)


def test_tampered_token_payload_rejected():
    vault = TokenVault(secret_bytes=b"0" * 32)
    token = vault.create_token(subject="user_1", role="ROLE_LEGAL_QUERY")
    parts = token.split(".")

    # Tamper with payload byte
    tampered_payload = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    with pytest.raises(TokenTamperedError):
        vault.verify_token(tampered_token)


def test_wrong_hmac_secret_rejected():
    vault1 = TokenVault(secret_bytes=b"1" * 32)
    vault2 = TokenVault(secret_bytes=b"2" * 32)

    token = vault1.create_token(subject="user_1", role="ROLE_LEGAL_QUERY")
    with pytest.raises(TokenTamperedError):
        vault2.verify_token(token)


def test_replay_attack_rejected():
    vault = TokenVault(secret_bytes=b"0" * 32)
    token = vault.create_token(subject="user_once", role="ROLE_LEGAL_QUERY")

    # First verification passes
    claims1 = vault.verify_token(token, enforce_replay_check=True)
    assert claims1.subject == "user_once"

    # Second verification fails due to replay
    with pytest.raises(TokenReplayError):
        vault.verify_token(token, enforce_replay_check=True)


def test_insecure_key_permissions_rejected(tmp_path):
    key_file = tmp_path / "insecure_secret.key"
    key_file.write_bytes(b"X" * 32)
    key_file.chmod(0o666)  # World readable/writable

    with pytest.raises(InsecureKeyPermissionsError):
        TokenVault(key_path=str(key_file))
