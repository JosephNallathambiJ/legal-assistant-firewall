#!/usr/bin/env bash
# ==============================================================================
# HNX26EPS01 Security Gateway — Automated Security Self-Test Suite
# Validates all defensive subsystems before production service activation.
# Fails closed if any mandatory check encounters an anomaly.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_PYTHON="${GATEWAY_DIR}/../.venv/bin/python3"
if [[ ! -f "${VENV_PYTHON}" ]]; then
    VENV_PYTHON="python3"
fi

TEST_STATUS=0

echo "=============================================================================="
echo "HNX26EPS01 SECURITY GATEWAY — PRE-FLIGHT COMPREHENSIVE SELF-TEST"
echo "=============================================================================="

# 1. Configuration Validation
echo -n "[*] [1/10] Checking Gateway & RBAC Configuration... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from config_loader import ConfigLoader
from rbac_engine import RBACEngine
ConfigLoader.load('${GATEWAY_DIR}/config/gateway.yaml', base_dir='${GATEWAY_DIR}')
RBACEngine('${GATEWAY_DIR}/config/rbac.yaml')
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 2. Firewall Rules Validation
echo -n "[*] [2/10] Checking Layer 3 nftables rules syntax... "
if "${GATEWAY_DIR}/scripts/setup_firewall.sh" check >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 3. TLS Certificate & Key Permissions Validation
echo -n "[*] [3/10] Checking TLS 1.3 / mTLS Certificates & Private Key permissions... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from tls_manager import TLSManager
TLSManager(
    server_cert_path='${GATEWAY_DIR}/certs/server.crt',
    server_key_path='${GATEWAY_DIR}/certs/server.key',
    ca_cert_path='${GATEWAY_DIR}/certs/ca.crt',
    require_client_cert=True,
)
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 4. Memory Hardening & Kernel Primitives Check
echo -n "[*] [4/10] Checking Memory Protection & prctl dumpability... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from memory_protection import harden_process_memory, SecureBuffer, create_anonymous_memfd
assert harden_process_memory() is True
with SecureBuffer(32) as b:
    b.write(b'x'*32)
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 5. Token Vault & HMAC Security Check
echo -n "[*] [5/10] Checking Token Vault (HMAC-SHA256 & Replay Cache)... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from token_vault import TokenVault
v = TokenVault(key_path='${GATEWAY_DIR}/config/token_secret.key')
t = v.create_token('test_sub', 'ROLE_LEGAL_QUERY')
c = v.verify_token(t)
assert c.subject == 'test_sub'
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 6. RBAC Engine Policy Enforcement Check
echo -n "[*] [6/10] Checking RBAC Engine least-privilege matrix... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from rbac_engine import RBACEngine, RBACAccessDeniedError
r = RBACEngine('${GATEWAY_DIR}/config/rbac.yaml')
assert r.authorize('ROLE_LEGAL_QUERY', 'POST', '/api/v1/legal/query') is True
try:
    r.authorize('ROLE_LEGAL_QUERY', 'POST', '/api/v1/legal/review')
    sys.exit(1)
except RBACAccessDeniedError:
    pass
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 7. DPI & False-Positive Control Check
echo -n "[*] [7/10] Checking DPI Engine (Anti-SQLi & False Positive resistance)... "
if ${VENV_PYTHON} -c "
import sys, json
sys.path.insert(0, '${GATEWAY_DIR}')
from dpi_engine import DPIEngine
dpi = DPIEngine()
# Test attack blocked
dec_attack = dpi.inspect_request('POST', '/api/v1/legal/query', {'content-type': 'application/json'}, {}, json.dumps({'q': \"' OR 1=1\"}).encode('utf-8'))
assert dec_attack.action == 'BLOCK'
# Test benign contract text allowed
dec_benign = dpi.inspect_request('POST', '/api/v1/legal/review', {'content-type': 'application/json'}, {}, json.dumps({'contract_text': 'Trade union collective agreement clause'}).encode('utf-8'))
assert dec_benign.action == 'ALLOW'
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 8. Cryptographic File Integrity Baseline Check
echo -n "[*] [8/10] Checking File Integrity Baseline (hashes.json)... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from integrity_monitor import IntegrityMonitor
m = IntegrityMonitor('${GATEWAY_DIR}/config/hashes.json', base_dir='${GATEWAY_DIR}')
passed, _ = m.verify_integrity()
assert passed is True
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 9. Anti-Tamper Watchdog Health Check
echo -n "[*] [9/10] Checking Anti-Tamper Watchdog inspection logic... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from anti_tamper_watchdog import AntiTamperWatchdog
w = AntiTamperWatchdog()
# Verify anti-debugging proc check does not crash
w.check_anti_debugging(1)
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 10. Zero Trust Policy Decision Point (PDP) Check
echo -n "[*] [10/14] Checking Zero Trust PDP & Declarative Policy... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from core.zero_trust_policy import ZeroTrustPolicyEngine
pdp = ZeroTrustPolicyEngine(config_path='${GATEWAY_DIR}/config/zero_trust_policy.yaml')
assert pdp.default_decision == 'DENY'
assert len(pdp.rules) >= 4
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 11. Zero Trust PEP & Client Registry Check
echo -n "[*] [11/14] Checking Client Device Registry & Posture Evaluation... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from core.client_registry import ClientRegistry, DevicePosture
reg = ClientRegistry(config_path='${GATEWAY_DIR}/config/zero_trust_policy.yaml')
assert reg.has_client('client-legal-assistant-001')
c = reg.get_client('client-legal-assistant-001')
assert c.device_posture == DevicePosture.COMPLIANT
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 12. Upstream Legal Assistant Workload Verification
echo -n "[*] [12/14] Checking Upstream Agentic Legal Assistant (FastAPI/Uvicorn)... "
if ${VENV_PYTHON} -c "
import sys, asyncio, httpx
sys.path.insert(0, '${GATEWAY_DIR}')
from upstream_legal_agent import app
async def verify_workload():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url='http://127.0.0.1:3000') as client:
        res = await client.get('/health')
        assert res.status_code == 200
        assert res.json()['workload_id'] == 'hnx26eps01-legal-agent'
asyncio.run(verify_workload())
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 13. Scapy Packet Inspector Check
echo -n "[*] [13/14] Checking Scapy Layer 3/4 Packet Anti-Reconnaissance Inspector... "
if ${VENV_PYTHON} -c "
import sys
sys.path.insert(0, '${GATEWAY_DIR}')
from packet_inspector import PacketInspector, PacketVerdict
pkt = PacketInspector.craft_adversarial_packet('XMAS')
res = PacketInspector.evaluate_tcp_packet(pkt, interface='eth0')
assert res.verdict == PacketVerdict.DROP
" >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

# 14. Run Full Automated Pytest Suite
echo -n "[*] [14/14] Running Comprehensive Gateway Pytest Suite... "
if ${VENV_PYTHON} -m pytest "${GATEWAY_DIR}/tests" -q >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    TEST_STATUS=1
fi

echo "=============================================================================="
if [[ "${TEST_STATUS}" -eq 0 ]]; then
    echo "SECURITY SELF-TEST: PASS"
    exit 0
else
    echo "SECURITY SELF-TEST: FAIL"
    exit 1
fi
