"""Anti-Tamper Watchdog and Emergency Kill-Switch Tests for HNX26EPS01 Gateway."""

import os
import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from anti_tamper_watchdog import AntiTamperWatchdog
from incident_response import IncidentResponseManager, SecurityState


def test_watchdog_test_mode_triggers_lockdown(tmp_path):
    """Verifies that WATCHDOG_TEST_MODE generates a CRITICAL event and triggers lockdown."""
    ir = IncidentResponseManager(state_dir=str(tmp_path))
    assert ir.current_state == SecurityState.STARTING

    watchdog = AntiTamperWatchdog(
        incident_manager=ir,
        test_mode=True,
    )

    events = watchdog.run_cycle()
    assert len(events) >= 1
    critical_events = [e for e in events if e.severity == "CRITICAL"]
    assert len(critical_events) >= 1

    # System must now be in LOCKDOWN state
    assert ir.current_state == SecurityState.LOCKDOWN
    assert not ir.can_forward_requests()
    assert (tmp_path / "LOCKDOWN.state").exists()


def test_incident_response_operator_unlock(tmp_path):
    """Verifies that exiting lockdown requires explicit confirmation token."""
    ir = IncidentResponseManager(state_dir=str(tmp_path))
    ir.trigger_lockdown(reason="Test lockdown", telemetry={"test": True})
    assert ir.current_state == SecurityState.LOCKDOWN

    # Attempting unlock without confirmation must fail
    with pytest.raises(ValueError):
        ir.unlock("wrong_token")

    # Correct unlock succeeds
    unlocked = ir.unlock("CONFIRM_OPERATOR_UNLOCK")
    assert unlocked is True
    assert ir.current_state == SecurityState.READY
    assert not (tmp_path / "LOCKDOWN.state").exists()


def test_anti_debugging_detection_with_mock_proc(tmp_path, monkeypatch):
    """Tests TracerPid detection logic using mocked /proc/<pid>/status."""
    import builtins
    import io

    pid = 99999
    real_open = builtins.open

    def mock_open(file, *args, **kwargs):
        if f"/proc/{pid}/status" in str(file):
            return io.StringIO("Name:\tprotected_bin\nTracerPid:\t1337\nUid:\t1000\t1000\n")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", lambda self: True if f"/proc/{pid}" in str(self) else Path.is_file(self) or Path.is_dir(self))
    monkeypatch.setattr(builtins, "open", mock_open)

    ir = IncidentResponseManager(state_dir=str(tmp_path))
    watchdog = AntiTamperWatchdog(monitored_pids=[pid], incident_manager=ir)
    ev = watchdog.check_anti_debugging(pid)

    assert ev is not None
    assert ev.severity == "CRITICAL"
    assert "TracerPid=1337" in ev.evidence
