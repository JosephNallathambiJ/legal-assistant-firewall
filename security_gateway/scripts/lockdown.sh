#!/usr/bin/env bash
# ==============================================================================
# HNX26EPS01 Security Gateway — Emergency Lockdown Script
# Triggers emergency system isolation and fail-closed lockdown state.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

REASON="${1:-OPERATOR_MANUAL_LOCKDOWN: Operator initiated emergency isolation}"

echo "[!] INITIATING EMERGENCY LOCKDOWN FOR HNX26EPS01 GATEWAY..."

python3 -c "
import sys
from pathlib import Path
gateway_dir = Path('${GATEWAY_DIR}').resolve()
sys.path.insert(0, str(gateway_dir))

from incident_response import IncidentResponseManager

ir = IncidentResponseManager(state_dir=str(gateway_dir / 'logs'))
record = ir.trigger_lockdown(
    reason='${REASON}',
    telemetry={'invoked_by': 'operator_script', 'user': '$(whoami)'}
)
print(f'[✓] System transitioned to LOCKDOWN state.')
print(f'[✓] Incident recorded at {record.timestamp}')
"

echo "[✓] GATEWAY IS NOW LOCKED DOWN. Ingress traffic is refused and upstream is isolated."
echo "[i] To unlock after incident investigation: python3 cli.py unlock --confirm"
