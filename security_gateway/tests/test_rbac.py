"""Role-Based Access Control (RBAC) Tests for HNX26EPS01 Security Gateway."""

import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from rbac_engine import RBACAccessDeniedError, RBACConfigurationError, RBACEngine


@pytest.fixture
def rbac():
    config_path = BASE_DIR / "config" / "rbac.yaml"
    return RBACEngine(str(config_path))


def test_legal_query_role_permissions(rbac):
    # Query is allowed
    assert rbac.authorize("ROLE_LEGAL_QUERY", "POST", "/api/v1/legal/query") is True
    # Search is allowed
    assert rbac.authorize("ROLE_LEGAL_QUERY", "POST", "/api/v1/legal/search") is True
    # Document read is allowed
    assert rbac.authorize("ROLE_LEGAL_QUERY", "GET", "/api/v1/documents/case_123.pdf") is True

    # Case review is DENIED for query role
    with pytest.raises(RBACAccessDeniedError):
        rbac.authorize("ROLE_LEGAL_QUERY", "POST", "/api/v1/legal/review")

    # Security admin endpoints are DENIED
    with pytest.raises(RBACAccessDeniedError):
        rbac.authorize("ROLE_LEGAL_QUERY", "GET", "/security/status")


def test_legal_review_role_permissions(rbac):
    # Review role has all query capabilities plus case review
    assert rbac.authorize("ROLE_LEGAL_REVIEW", "POST", "/api/v1/legal/query") is True
    assert rbac.authorize("ROLE_LEGAL_REVIEW", "POST", "/api/v1/legal/review") is True


def test_admin_role_permissions(rbac):
    # Admin allowed for security status and audit
    assert rbac.authorize("ROLE_ADMIN", "GET", "/security/status") is True
    assert rbac.authorize("ROLE_ADMIN", "GET", "/security/audit") is True

    # Admin CANNOT access legal domain queries (least privilege)
    with pytest.raises(RBACAccessDeniedError):
        rbac.authorize("ROLE_ADMIN", "POST", "/api/v1/legal/query")


def test_unmapped_routes_fail_closed(rbac):
    """Verifies that any route not explicitly mapped is denied by default."""
    with pytest.raises(RBACAccessDeniedError):
        rbac.authorize("ROLE_LEGAL_QUERY", "GET", "/api/v1/unmapped")
    with pytest.raises(RBACAccessDeniedError):
        rbac.authorize("ROLE_ADMIN", "POST", "/etc/passwd")


def test_forbidden_operations_cannot_be_granted():
    """Verifies that hardcoded forbidden system operations (shell, exec) raise configuration error."""
    malicious_policy = {
        "roles": {
            "ROLE_SUPERUSER": {
                "permissions": ["shell.execute", "legal.query"]
            }
        },
        "routes": []
    }
    with pytest.raises(RBACConfigurationError):
        RBACEngine(policy_dict=malicious_policy)
