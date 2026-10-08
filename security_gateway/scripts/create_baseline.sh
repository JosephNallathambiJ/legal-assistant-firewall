#!/usr/bin/env bash
# ==============================================================================
# HNX26EPS01 Security Gateway — Baseline Creation Script
# Computes SHA-256 hashes of critical system assets into config/hashes.json
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[+] Creating cryptographic integrity baseline for HNX26EPS01 Gateway..."

python3 -c "
import sys
from pathlib import Path
gateway_dir = Path('${GATEWAY_DIR}').resolve()
sys.path.insert(0, str(gateway_dir))

from integrity_monitor import IntegrityMonitor

hashes_file = gateway_dir / 'config' / 'hashes.json'
monitor = IntegrityMonitor(str(hashes_file), base_dir=str(gateway_dir))

targets = [
    'config/gateway.yaml',
    'config/rbac.yaml',
    'certs/ca.crt',
    'certs/server.crt',
    'firewall_rules.nft',
    'gateway_proxy.py',
    'anti_tamper_watchdog.py',
    'integrity_monitor.py',
    'memory_protection.py',
    'token_vault.py',
    'rbac_engine.py',
    'dpi_engine.py',
    'tls_manager.py',
    'upstream_connector.py',
    'incident_response.py',
    'security_logger.py',
    'config_loader.py',
    'cli.py',
    'scripts/setup_firewall.sh',
    'scripts/generate_certificates.sh',
    'scripts/create_baseline.sh',
    'scripts/lockdown.sh',
    'scripts/security_self_test.sh',
    'config/zero_trust_policy.yaml',
    'core/identity.py',
    'core/client_registry.py',
    'core/security_context.py',
    'core/workload_identity.py',
    'core/session_manager.py',
    'core/risk_engine.py',
    'core/zero_trust_policy.py',
    'core/policy_enforcement.py',
    'upstream_legal_agent.py',
    'packet_inspector.py',
    'nfqueue_filter.py',
    'systemd/secure-gateway.service',
    'systemd/anti-tamper-watchdog.service'
]

baseline = monitor.create_baseline(targets)
print(f'[✓] Integrity baseline created successfully with {len(baseline[\"assets\"])} recorded assets.')
"

chmod 644 "${GATEWAY_DIR}/config/hashes.json"
echo "[✓] Saved to ${GATEWAY_DIR}/config/hashes.json"
