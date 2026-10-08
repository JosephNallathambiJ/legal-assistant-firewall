"""Incident Response & Emergency Kill-Switch Subsystem for HNX26EPS01 Gateway.

Implements the Security State Machine and emergency isolation response:
1. Generates forensic incident audit records.
2. Transitions gateway state to LOCKDOWN.
3. Stops accepting incoming requests.
4. Gracefully terminates upstream legal assistant process (SIGTERM -> SIGKILL).
5. Persists lockdown state across restarts until explicit operator unlocking.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from security_logger import get_security_logger


class SecurityState(str, Enum):
    STARTING = "STARTING"
    SELF_TEST = "SELF_TEST"
    READY = "READY"
    DEGRADED = "DEGRADED"
    BLOCKING = "BLOCKING"
    LOCKDOWN = "LOCKDOWN"
    SHUTDOWN = "SHUTDOWN"


@dataclass(frozen=True)
class IncidentRecord:
    timestamp: str
    reason: str
    severity: str
    telemetry: Dict[str, Any]
    upstream_pid_terminated: Optional[int]


class IncidentResponseManager:
    """Controls gateway operational state and executes emergency lockdown workflows."""

    def __init__(self, state_dir: Optional[str] = None):
        self.state_dir = Path(state_dir or "security_gateway/logs").resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.lockdown_marker = self.state_dir / "LOCKDOWN.state"

        # If lockdown marker is present on disk, fail closed into LOCKDOWN
        if self.lockdown_marker.exists():
            self._current_state = SecurityState.LOCKDOWN
        else:
            self._current_state = SecurityState.STARTING

    @property
    def current_state(self) -> SecurityState:
        # Check if persistent marker was placed by another process (e.g. watchdog)
        if self.lockdown_marker.exists() and self._current_state != SecurityState.LOCKDOWN:
            self._current_state = SecurityState.LOCKDOWN
        return self._current_state

    def set_state(self, new_state: SecurityState) -> None:
        """Transitions state machine with fail-closed rules."""
        if self._current_state == SecurityState.LOCKDOWN and new_state != SecurityState.LOCKDOWN:
            raise RuntimeError("Cannot transition out of LOCKDOWN without explicit operator unlock")
        self._current_state = new_state

    def can_forward_requests(self) -> bool:
        """Only READY state is permitted to forward protected requests."""
        return self.current_state == SecurityState.READY

    def trigger_lockdown(
        self,
        reason: str,
        telemetry: Dict[str, Any],
        upstream_pid: Optional[int] = None,
    ) -> IncidentRecord:
        """Executes emergency isolation workflow.

        Fails closed: Terminating upstream process, persisting state, and blocking all ingress.
        """
        logger = get_security_logger()
        ts = datetime.now(timezone.utc).isoformat()
        terminated_pid: Optional[int] = None

        # 1. Terminate upstream process if specified
        if upstream_pid and upstream_pid > 1:
            try:
                os.kill(upstream_pid, signal.SIGTERM)
                terminated_pid = upstream_pid
                time.sleep(1.0)
                # Check if still running
                try:
                    os.kill(upstream_pid, 0)
                    # If still alive, escalate to SIGKILL
                    os.kill(upstream_pid, signal.SIGKILL)
                except OSError:
                    pass  # Process has terminated
            except Exception as e:
                telemetry["upstream_termination_error"] = str(e)

        # 2. Persist LOCKDOWN state to disk
        incident_data = {
            "timestamp": ts,
            "reason": reason,
            "severity": "CRITICAL",
            "telemetry": telemetry,
            "upstream_pid_terminated": terminated_pid,
        }

        with open(self.lockdown_marker, "w", encoding="utf-8") as f:
            json.dump(incident_data, f, indent=2)

        # 3. Write individual forensic report
        incident_file = self.state_dir / f"incident_{int(time.time())}.json"
        with open(incident_file, "w", encoding="utf-8") as f:
            json.dump(incident_data, f, indent=2)

        # 4. Set in-memory state
        self._current_state = SecurityState.LOCKDOWN

        # 5. Log structured audit event
        logger.log_event(
            event="EMERGENCY_LOCKDOWN_TRIGGERED",
            severity="CRITICAL",
            action="LOCKDOWN",
            details={
                "reason": reason,
                "incident_file": str(incident_file),
                "terminated_pid": terminated_pid,
            },
        )

        return IncidentRecord(
            timestamp=ts,
            reason=reason,
            severity="CRITICAL",
            telemetry=telemetry,
            upstream_pid_terminated=terminated_pid,
        )

    def unlock(self, confirmation_token: str) -> bool:
        """Operator-initiated recovery from LOCKDOWN state."""
        if confirmation_token != "CONFIRM_OPERATOR_UNLOCK":
            raise ValueError("Operator unlock requires confirmation token 'CONFIRM_OPERATOR_UNLOCK'")

        if self.lockdown_marker.exists():
            self.lockdown_marker.unlink()

        self._current_state = SecurityState.READY
        logger = get_security_logger()
        logger.log_event(
            event="OPERATOR_UNLOCK_EXECUTED",
            severity="WARNING",
            action="ALLOW",
            details={"unlocked_at": datetime.now(timezone.utc).isoformat()},
        )
        return True
