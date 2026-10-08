"""Zero Trust Client & Device Identity Registry for HNX26EPS01 Gateway.

Treats mTLS client certificates as device/client identity signals.
Validates certificate fingerprints against a declarative known-client registry.
Enforces default-deny for any unregistered or revoked client certificates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


class DevicePosture(str, Enum):
    COMPLIANT = "COMPLIANT"
    UNKNOWN = "UNKNOWN"
    NON_COMPLIANT = "NON_COMPLIANT"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class ClientRegistration:
    """Registered device identity and policy boundary."""

    client_id: str
    certificate_sha256: str
    allowed_roles: List[str]
    allowed_scopes: List[str]
    enabled: bool = True
    device_posture: DevicePosture = DevicePosture.COMPLIANT
    revoked: bool = False
    description: str = ""

    def is_valid_and_active(self) -> Tuple[bool, str]:
        if self.revoked:
            return False, "CERTIFICATE_REVOKED"
        if not self.enabled:
            return False, "DEVICE_DISABLED"
        if self.device_posture == DevicePosture.NON_COMPLIANT:
            return False, "DEVICE_NON_COMPLIANT"
        return True, "DEVICE_ACTIVE"


class ClientRegistry:
    """Manages known client device registrations and certificate authorizations."""

    def __init__(self, clients_dict: Optional[Dict[str, Any]] = None, config_path: Optional[str] = None):
        self._clients_by_fp: Dict[str, ClientRegistration] = {}
        self._clients_by_id: Dict[str, ClientRegistration] = {}

        if clients_dict:
            self._load_from_dict(clients_dict)
        elif config_path:
            self.load_from_file(config_path)

    def load_from_file(self, config_path: str) -> None:
        path = Path(config_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Client registry file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError("Client registry root must be a YAML dictionary")

        self._load_from_dict(data.get("clients", {}))

    def _load_from_dict(self, clients_data: Dict[str, Any]) -> None:
        self._clients_by_fp.clear()
        self._clients_by_id.clear()

        for c_id, meta in clients_data.items():
            if not isinstance(meta, dict):
                continue

            fp = str(meta.get("certificate_sha256", "")).strip().upper()
            if not fp:
                continue

            reg = ClientRegistration(
                client_id=c_id,
                certificate_sha256=fp,
                allowed_roles=list(meta.get("allowed_roles", [])),
                allowed_scopes=list(meta.get("allowed_scopes", [])),
                enabled=bool(meta.get("enabled", True)),
                device_posture=DevicePosture(meta.get("device_posture", DevicePosture.COMPLIANT.value)),
                revoked=bool(meta.get("revoked", False)),
                description=str(meta.get("description", "")),
            )

            self._clients_by_fp[fp] = reg
            self._clients_by_id[c_id] = reg

    def register_client(self, client: ClientRegistration) -> None:
        """Register a client device dynamically."""
        fp = client.certificate_sha256.upper()
        self._clients_by_fp[fp] = client
        self._clients_by_id[client.client_id] = client

    def revoke_client(self, client_id_or_fp: str, reason: str = "Operator revoked") -> bool:
        """Revokes a client device immediately."""
        key = client_id_or_fp.upper()
        reg = self._clients_by_fp.get(key) or self._clients_by_id.get(client_id_or_fp)
        if not reg:
            return False

        updated = ClientRegistration(
            client_id=reg.client_id,
            certificate_sha256=reg.certificate_sha256,
            allowed_roles=reg.allowed_roles,
            allowed_scopes=reg.allowed_scopes,
            enabled=False,
            device_posture=DevicePosture.REVOKED,
            revoked=True,
            description=f"{reg.description} (Revoked: {reason})",
        )
        self.register_client(updated)
        return True

    def lookup(self, certificate_fingerprint: str) -> Optional[ClientRegistration]:
        """Look up registered device by certificate SHA-256 fingerprint."""
        if not certificate_fingerprint:
            return None
        return self._clients_by_fp.get(certificate_fingerprint.strip().upper())

    def authorize_client(
        self,
        certificate_fingerprint: str,
        role: str,
        required_scope: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[ClientRegistration]]:
        """Validates if client certificate is known, compliant, and authorized for role/scope.

        Fails closed with explicit reason code.
        """
        reg = self.lookup(certificate_fingerprint)
        if not reg:
            return False, "DEVICE_NOT_REGISTERED", None

        is_active, status_reason = reg.is_valid_and_active()
        if not is_active:
            return False, status_reason, reg

        if role not in reg.allowed_roles:
            return False, "ROLE_NOT_PERMITTED_FOR_DEVICE", reg

        if required_scope and required_scope not in reg.allowed_scopes:
            return False, "SCOPE_NOT_PERMITTED_FOR_DEVICE", reg

        return True, "DEVICE_AUTHORIZED", reg

    def has_client(self, client_id_or_fp: str) -> bool:
        """Checks if a client ID or certificate fingerprint is registered."""
        return (client_id_or_fp in self._clients_by_id) or (client_id_or_fp.strip().upper() in self._clients_by_fp)

    def get_client(self, client_id_or_fp: str) -> Optional[ClientRegistration]:
        """Gets registered client by client ID or certificate fingerprint."""
        return self._clients_by_id.get(client_id_or_fp) or self._clients_by_fp.get(client_id_or_fp.strip().upper())

    def list_clients(self) -> List[ClientRegistration]:
        return list(self._clients_by_id.values())
