"""Memory and Secret Protection Primitives for HNX26EPS01 Security Gateway.

Provides host-level memory hardening using Linux system calls:
- PR_SET_DUMPABLE: Disables core dumping and non-root ptrace attachment.
- RLIMIT_CORE: Restricts core dump size to 0 bytes.
- mlock / munlock: Locks sensitive cryptographic buffers into RAM, preventing swapping to disk.
- memfd_create: Anonymous RAM-backed file descriptor creation without filesystem persistence.
- explicit memory zeroing / wiping.

Realistic Security Boundary:
These primitives prevent accidental credential leakage into swap partitions, crash dumps,
and unprivileged process inspection. They do NOT protect against a kernel-level root exploit
or hypervisor-level inspection.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import resource
import sys
from typing import Optional

# Linux prctl Constants
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
SUID_DUMP_DISABLE = 0
MFD_CLOEXEC = 0x0001
SYS_memfd_create = 319  # x86_64 syscall number

# Load standard C library
_libc: Optional[ctypes.CDLL] = None
try:
    libc_name = ctypes.util.find_library("c")
    if libc_name:
        _libc = ctypes.CDLL(libc_name, use_errno=True)
    else:
        _libc = ctypes.CDLL(None, use_errno=True)
    if _libc and hasattr(_libc, "prctl"):
        _libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        _libc.prctl.restype = ctypes.c_int
except Exception:
    _libc = None


def harden_process_memory() -> bool:
    """Disables core dumps and process dumpability via prctl and setrlimit.

    Returns True if hardening applied successfully.
    """
    success = True

    # 1. Disable core dumps via RLIMIT_CORE
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        success = False

    # 2. Disable ptrace/dumpability via prctl(PR_SET_DUMPABLE, 0)
    if _libc is not None and hasattr(_libc, "prctl"):
        try:
            res = _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
            if res != 0:
                success = False
        except Exception:
            success = False

    return success


def wipe_memory(buf: bytearray | ctypes.Array) -> None:
    """Overwrite buffer contents with zeros using volatile zeroing."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, ctypes.Array):
        if _libc is not None and hasattr(_libc, "explicit_bzero"):
            _libc.explicit_bzero(ctypes.byref(buf), len(buf))
        else:
            ctypes.memset(ctypes.byref(buf), 0, len(buf))


class SecureBuffer:
    """RAM-locked memory buffer for cryptographic keys and session tokens.

    Locks pages with mlock() to prevent paging out to disk/swap.
    Automatically zeros out buffer upon exit or deletion.
    """

    def __init__(self, size: int):
        if size <= 0:
            raise ValueError("Buffer size must be positive")
        self.size = size
        self._buf = (ctypes.c_char * size)()
        self._is_locked = False
        self._addr = ctypes.addressof(self._buf)

        # Attempt mlock
        if _libc is not None and hasattr(_libc, "mlock"):
            try:
                res = _libc.mlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(self.size))
                if res == 0:
                    self._is_locked = True
            except Exception:
                self._is_locked = False

    @property
    def is_locked(self) -> bool:
        """Indicates if mlock succeeded (depends on RLIMIT_MEMLOCK)."""
        return self._is_locked

    def write(self, data: bytes) -> None:
        """Write bytes into secure buffer."""
        if len(data) > self.size:
            raise ValueError(f"Data size {len(data)} exceeds buffer capacity {self.size}")
        # Zero existing content
        self.wipe()
        ctypes.memmove(self._buf, data, len(data))

    def read(self) -> bytes:
        """Read bytes currently stored in secure buffer."""
        return bytes(self._buf)

    def wipe(self) -> None:
        """Securely zero memory."""
        wipe_memory(self._buf)

    def close(self) -> None:
        """Wipe memory and unlock pages."""
        self.wipe()
        if self._is_locked and _libc is not None and hasattr(_libc, "munlock"):
            try:
                _libc.munlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(self.size))
            except Exception:
                pass
            self._is_locked = False

    def __enter__(self) -> SecureBuffer:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


def create_anonymous_memfd(name: str = "sec_gateway_mem") -> int:
    """Create an anonymous in-memory file descriptor without disk persistence.

    Uses memfd_create syscall with MFD_CLOEXEC.
    """
    if _libc is None:
        raise OSError("C standard library is unavailable")

    name_bytes = name.encode("utf-8")
    if hasattr(_libc, "memfd_create"):
        fd = _libc.memfd_create(name_bytes, MFD_CLOEXEC)
    else:
        # Fallback to syscall
        fd = _libc.syscall(SYS_memfd_create, name_bytes, MFD_CLOEXEC)

    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"memfd_create failed: {os.strerror(err)}")
    return fd
