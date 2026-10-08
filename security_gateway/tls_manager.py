"""Cryptographic TLS 1.3 & Mutual TLS (mTLS) Manager for HNX26EPS01 Gateway.

Enforces:
- Strict TLS 1.3 minimum and maximum protocol configuration (rejection of TLS 1.0, 1.1, 1.2)
- Mutual TLS authentication (mandatory trusted CA-signed client certificates)
- Secure private key permission auditing (rejects world-readable/writable keys)
- Certificate validity and expiration verification
- SubjectPublicKeyInfo (SPKI) and certificate fingerprint pinning for MITM resistance
- Controlled certificate rotation support
"""

from __future__ import annotations

import hashlib
import os
import ssl
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class TLSSecurityError(Exception):
    """Base exception for all TLS and cryptographic security failures."""


class CertificateExpiredError(TLSSecurityError):
    """Raised when server or client certificate has expired."""


class CertificatePinMismatchError(TLSSecurityError):
    """Raised when client certificate or SPKI fingerprint does not match pinned allowlist."""


class InsecureKeyPermissionsError(TLSSecurityError):
    """Raised when private key permissions violate least-privilege rules."""


class TLSManager:
    """Configures and enforces TLS 1.3 and mTLS server context and client verification."""

    def __init__(
        self,
        server_cert_path: str,
        server_key_path: str,
        ca_cert_path: Optional[str] = None,
        require_client_cert: bool = True,
        pinned_fingerprints: Optional[List[str]] = None,
        pinned_spki_hashes: Optional[List[str]] = None,
    ):
        self.server_cert_path = Path(server_cert_path).resolve()
        self.server_key_path = Path(server_key_path).resolve()
        self.ca_cert_path = Path(ca_cert_path).resolve() if ca_cert_path else None
        self.require_client_cert = require_client_cert
        self.pinned_fingerprints: Set[str] = set(pinned_fingerprints or [])
        self.pinned_spki_hashes: Set[str] = set(pinned_spki_hashes or [])

        # Validate file existence and permissions
        self._validate_file_security()

        # Validate server certificate expiration
        self._validate_cert_expiry(self.server_cert_path, "Server certificate")
        if self.ca_cert_path:
            self._validate_cert_expiry(self.ca_cert_path, "CA certificate")

        # Build SSLContext
        self.ssl_context = self._create_ssl_context()

    def _validate_file_security(self) -> None:
        """Enforces strict owner-only file permissions (0600 or 0400) on private keys."""
        if not self.server_cert_path.exists():
            raise FileNotFoundError(f"Server certificate not found: {self.server_cert_path}")
        if not self.server_key_path.exists():
            raise FileNotFoundError(f"Server private key not found: {self.server_key_path}")

        key_stat = self.server_key_path.stat()
        mode = key_stat.st_mode
        # Reject if readable or writable by group or others (0o077)
        if bool(mode & (stat.S_IRWXG | stat.S_IRWXO)):
            raise InsecureKeyPermissionsError(
                f"FATAL: Server private key {self.server_key_path} has insecure permissions ({oct(mode)}). "
                f"Must be 0600 or 0400 (owner read-only/read-write)."
            )

        if self.require_client_cert:
            if not self.ca_cert_path or not self.ca_cert_path.exists():
                raise FileNotFoundError(f"mTLS is enabled but CA certificate was not found: {self.ca_cert_path}")

    def _validate_cert_expiry(self, cert_path: Path, label: str) -> None:
        """Parses certificate and verifies current time is within validity window."""
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data)
        now = datetime.now(timezone.utc)

        if now < cert.not_valid_before_utc:
            raise TLSSecurityError(f"{label} is not yet valid (valid from {cert.not_valid_before_utc})")
        if now > cert.not_valid_after_utc:
            raise CertificateExpiredError(f"{label} expired on {cert.not_valid_after_utc} (current: {now})")

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Creates a hardened SSLContext enforcing TLS 1.3 exclusively."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Enforce TLS 1.3 strictly
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Disable all legacy protocol versions and compression
        context.options |= (
            ssl.OP_NO_SSLv2
            | ssl.OP_NO_SSLv3
            | ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_NO_TLSv1_2
            | ssl.OP_NO_COMPRESSION
            | ssl.OP_SINGLE_DH_USE
            | ssl.OP_SINGLE_ECDH_USE
        )

        # Load server cert and private key
        context.load_cert_chain(certfile=str(self.server_cert_path), keyfile=str(self.server_key_path))

        # Configure Mutual TLS (mTLS)
        if self.require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
            assert self.ca_cert_path is not None
            context.load_verify_locations(cafile=str(self.ca_cert_path))
        else:
            context.verify_mode = ssl.CERT_NONE

        return context

    @staticmethod
    def compute_cert_fingerprint(cert_der: bytes) -> str:
        """Computes SHA-256 fingerprint of DER-encoded certificate."""
        return hashlib.sha256(cert_der).hexdigest().upper()

    @staticmethod
    def compute_spki_pin(cert_der: bytes) -> str:
        """Computes SHA-256 hash of SubjectPublicKeyInfo for resilient key pinning."""
        cert = x509.load_der_x509_certificate(cert_der)
        spki_der = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(spki_der).hexdigest().upper()

    def verify_client_der_certificate(self, cert_der: bytes) -> Dict[str, Any]:
        """Performs application-layer certificate checks (pinning, expiration, identity)."""
        cert = x509.load_der_x509_certificate(cert_der)
        now = datetime.now(timezone.utc)

        # Expiry check
        if now > cert.not_valid_after_utc:
            raise CertificateExpiredError(f"Client certificate expired on {cert.not_valid_after_utc}")
        if now < cert.not_valid_before_utc:
            raise TLSSecurityError(f"Client certificate not yet valid (valid from {cert.not_valid_before_utc})")

        cert_fp = self.compute_cert_fingerprint(cert_der)
        spki_pin = self.compute_spki_pin(cert_der)

        # Pinning verification if configured
        if self.pinned_fingerprints and cert_fp not in self.pinned_fingerprints:
            raise CertificatePinMismatchError(
                f"Client certificate fingerprint {cert_fp} does not match any pinned fingerprints"
            )

        if self.pinned_spki_hashes and spki_pin not in self.pinned_spki_hashes:
            raise CertificatePinMismatchError(
                f"Client SPKI pin {spki_pin} does not match any pinned SPKI hashes"
            )

        subject_cn = cert.subject.rfc4514_string()
        issuer_cn = cert.issuer.rfc4514_string()

        return {
            "subject": subject_cn,
            "issuer": issuer_cn,
            "fingerprint": cert_fp,
            "spki_pin": spki_pin,
            "serial_number": str(cert.serial_number),
            "valid_until": cert.not_valid_after_utc.isoformat(),
        }
