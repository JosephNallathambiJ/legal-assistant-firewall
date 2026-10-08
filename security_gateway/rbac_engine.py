"""Role-Based Access Control (RBAC) Engine for HNX26EPS01 Security Gateway.

Enforces least-privilege role boundaries before request normalization and forwarding.
Explicitly rejects shell execution, arbitrary code execution, raw socket access,
and filesystem modification attempts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml


class RBACError(Exception):
    """Base exception for RBAC failures."""


class RBACAccessDeniedError(RBACError):
    """Raised when an operation or role is unauthorized."""


class RBACConfigurationError(RBACError):
    """Raised when RBAC configuration is corrupted or invalid."""


# Hardcoded immutable system denylist - can NEVER be granted to any role
FORBIDDEN_OPERATIONS: Set[str] = {
    "shell.execute",
    "arbitrary.code.execution",
    "fs.write",
    "raw.socket",
    "process.spawn",
    "privilege.elevation",
    "system.admin",
}


@dataclass(frozen=True)
class RouteRule:
    method: str
    required_permission: str
    path: Optional[str] = None
    path_prefix: Optional[str] = None

    def matches(self, request_method: str, request_path: str) -> bool:
        if self.method != "*" and self.method.upper() != request_method.upper():
            return False
        if self.path and self.path == request_path:
            return True
        if self.path_prefix and request_path.startswith(self.path_prefix):
            return True
        return False


class RBACEngine:
    """Evaluates request authorization against configured role-permission matrices."""

    def __init__(self, config_path: Optional[str] = None, policy_dict: Optional[Dict[str, Any]] = None):
        self.roles: Dict[str, Set[str]] = {}
        self.rules: List[RouteRule] = []

        if policy_dict:
            self._load_from_dict(policy_dict)
        elif config_path:
            self.load_config(config_path)
        else:
            default_path = Path(__file__).parent / "config" / "rbac.yaml"
            if default_path.exists():
                self.load_config(str(default_path))
            else:
                raise RBACConfigurationError("No RBAC configuration provided or found at default path")

    def load_config(self, config_path: str) -> None:
        """Loads and strictly validates RBAC policy YAML file."""
        path = Path(config_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"RBAC config file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            raise RBACConfigurationError(f"Failed to parse RBAC YAML: {e}")

        if not isinstance(data, dict):
            raise RBACConfigurationError("RBAC configuration root must be a YAML dictionary")

        self._load_from_dict(data)

    def _load_from_dict(self, data: Dict[str, Any]) -> None:
        raw_roles = data.get("roles", {})
        if not isinstance(raw_roles, dict) or not raw_roles:
            raise RBACConfigurationError("RBAC configuration missing valid 'roles' section")

        self.roles.clear()
        for role_name, role_meta in raw_roles.items():
            if not isinstance(role_meta, dict):
                raise RBACConfigurationError(f"Invalid specification for role {role_name}")
            perms = set(role_meta.get("permissions", []))

            # Audit against hardcoded forbidden operations
            intersection = perms.intersection(FORBIDDEN_OPERATIONS)
            if intersection:
                raise RBACConfigurationError(
                    f"FATAL: Role {role_name} attempts to grant forbidden operations: {intersection}"
                )

            self.roles[role_name] = perms

        raw_routes = data.get("routes", [])
        if not isinstance(raw_routes, list):
            raise RBACConfigurationError("'routes' must be a list of route rules")

        self.rules.clear()
        for r in raw_routes:
            method = r.get("method", "GET").upper()
            perm = r.get("required_permission")
            if not perm:
                raise RBACConfigurationError(f"Route definition missing required_permission: {r}")
            self.rules.append(
                RouteRule(
                    method=method,
                    required_permission=perm,
                    path=r.get("path"),
                    path_prefix=r.get("path_prefix"),
                )
            )

    def authorize(self, role: str, method: str, path: str) -> bool:
        """Checks if a given role is authorized to perform method on path.

        Fails closed: Any unrecognized role, undefined route, or missing permission raises.
        """
        if not role or role not in self.roles:
            raise RBACAccessDeniedError(f"Role '{role}' is unrecognized or unassigned")

        role_permissions = self.roles[role]

        # Find matching route rule
        matching_rule: Optional[RouteRule] = None
        for rule in self.rules:
            if rule.matches(method, path):
                matching_rule = rule
                break

        if matching_rule is None:
            # Fail closed: unmapped routes are strictly prohibited
            raise RBACAccessDeniedError(f"No authorization rule defined for {method} {path} (deny by default)")

        req_perm = matching_rule.required_permission

        # Explicit absolute check
        if req_perm in FORBIDDEN_OPERATIONS:
            raise RBACAccessDeniedError(f"Action '{req_perm}' is explicitly forbidden for all roles")

        if req_perm not in role_permissions:
            raise RBACAccessDeniedError(
                f"Role '{role}' lacks required permission '{req_perm}' for {method} {path}"
            )

        return True

    def has_permission(self, role: str, permission: str) -> bool:
        """Query if a role contains a specific permission."""
        if permission in FORBIDDEN_OPERATIONS:
            return False
        return role in self.roles and permission in self.roles[role]
