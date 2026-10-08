"""Workload Identity Binding Engine for HNX26EPS01 Legal Assistant.

Verifies that the upstream listening process on 127.0.0.1:3000 matches the expected
workload identity (executable, UID, process attributes, and binary integrity).
Prevents forwarding to rogue or hijacked local sockets.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil


@dataclass
class WorkloadIdentitySpec:
    """Expected identity specification for the protected legal assistant service."""

    workload_id: str = "hnx26eps01-legal-agent"
    expected_host: str = "127.0.0.1"
    expected_port: int = 3000
    expected_uid: Optional[int] = None  # Current user by default
    expected_exe_names: List[str] = field(default_factory=lambda: ["python", "python3", "legal_agent"])
    expected_hash: Optional[str] = None
    allow_mock_in_test: bool = True


class WorkloadIdentityValidator:
    """Audits the process listening on the upstream loopback port."""

    def __init__(self, spec: Optional[WorkloadIdentitySpec] = None):
        self.spec = spec or WorkloadIdentitySpec()
        if self.spec.expected_uid is None:
            self.spec.expected_uid = os.getuid()

    def find_listening_pid(self, host: str, port: int) -> Optional[int]:
        """Finds PID listening on specified host and port using psutil."""
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    if conn.laddr.port == port:
                        # Validate address is loopback
                        if conn.laddr.ip in (host, "0.0.0.0", "127.0.0.1"):
                            return conn.pid
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        return None

    def verify_upstream_workload(
        self, host: str = "127.0.0.1", port: int = 3000
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Verifies that the process listening on 127.0.0.1:3000 matches expected workload identity."""
        pid = self.find_listening_pid(host, port)
        if pid is None:
            return False, "UPSTREAM_SOCKET_UNAVAILABLE", {"host": host, "port": port}

        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc_exe = proc.exe()
            proc_cmdline = " ".join(proc.cmdline())
            proc_uids = proc.uids()
            proc_uid = proc_uids.real if proc_uids else -1

            details = {
                "pid": pid,
                "name": proc_name,
                "exe": proc_exe,
                "uid": proc_uid,
                "cmdline": proc_cmdline[:128],
            }

            # 1. UID verification
            if self.spec.expected_uid is not None and proc_uid != self.spec.expected_uid:
                return False, "UPSTREAM_UID_MISMATCH", details

            # 2. Executable verification
            exe_matched = any(pattern in proc_name.lower() or pattern in proc_exe.lower() for pattern in self.spec.expected_exe_names)
            if not exe_matched:
                return False, "UPSTREAM_EXECUTABLE_MISMATCH", details

            # 3. Binary hash verification if configured
            if self.spec.expected_hash:
                exe_path = Path(proc_exe)
                if not exe_path.exists():
                    return False, "UPSTREAM_BINARY_MISSING", details
                current_hash = hashlib.sha256(exe_path.read_bytes()).hexdigest()
                if current_hash.lower() != self.spec.expected_hash.lower():
                    return False, "UPSTREAM_BINARY_HASH_MISMATCH", details

            return True, "WORKLOAD_VERIFIED", details

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return False, "UPSTREAM_PROCESS_ACCESS_DENIED", {"error": str(e), "pid": pid}
