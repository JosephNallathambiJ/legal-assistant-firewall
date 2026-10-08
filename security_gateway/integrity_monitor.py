"""Cryptographic Host File & Asset Integrity Monitor for HNX26EPS01.

Computes and verifies SHA-256 baseline hashes and permission states for:
- Gateway Python source code (STATIC_IMMUTABLE)
- Configuration & RBAC policy files (STATIC_IMMUTABLE)
- Systemd service units & shell scripts (STATIC_IMMUTABLE)
- Cryptographic certificates & keys (ROTATABLE_PROTECTED)
- AI Model weights and assets (MODEL_WEIGHTS)

Classifies assets to prevent false alerts during planned rotation while failing
closed upon unapproved file modification or permission anomalies.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class AssetClassification(str, Enum):
    STATIC_IMMUTABLE = "STATIC_IMMUTABLE"
    ROTATABLE_PROTECTED = "ROTATABLE_PROTECTED"
    MODEL_WEIGHTS = "MODEL_WEIGHTS"
    DYNAMIC_STATE = "DYNAMIC_STATE"


@dataclass(frozen=True)
class IntegrityCheckResult:
    file_path: str
    status: str  # "PASS", "HASH_MISMATCH", "FILE_MISSING", "PERMISSION_ANOMALY"
    classification: str
    expected_hash: Optional[str]
    actual_hash: Optional[str]
    severity: str  # "INFO", "HIGH", "CRITICAL"
    details: Dict[str, Any]


class IntegrityMonitor:
    """Computes, stores, and audits cryptographic integrity baselines."""

    def __init__(self, hashes_path: str, base_dir: Optional[str] = None):
        self.hashes_path = Path(hashes_path).resolve()
        self.base_dir = Path(base_dir).resolve() if base_dir else self.hashes_path.parent.parent

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Computes SHA-256 hash of a file in streaming chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def classify_file(self, rel_path: str) -> AssetClassification:
        """Determines asset classification based on path semantics."""
        path_str = rel_path.lower()
        if "certs/" in path_str or "secret.key" in path_str:
            return AssetClassification.ROTATABLE_PROTECTED
        if "model" in path_str or path_str.endswith((".bin", ".safetensors", ".onnx", ".gguf")):
            return AssetClassification.MODEL_WEIGHTS
        if "logs/" in path_str or path_str.endswith(".log"):
            return AssetClassification.DYNAMIC_STATE
        return AssetClassification.STATIC_IMMUTABLE

    def create_baseline(self, targets: List[str]) -> Dict[str, Any]:
        """Scans targets, hashes files, and generates config/hashes.json baseline."""
        baseline: Dict[str, Any] = {
            "version": 1,
            "created_at": os.environ.get("SOURCE_DATE_EPOCH", "2026-10-08T15:00:00Z"),
            "assets": {},
        }

        for target in targets:
            target_path = (self.base_dir / target).resolve()
            if not target_path.exists():
                continue

            if target_path.is_file():
                self._record_file(target_path, baseline)
            elif target_path.is_dir():
                for root, _, files in os.walk(target_path):
                    for file in files:
                        p = Path(root) / file
                        # Skip temporary, git, or bytecode files
                        if p.suffix in (".pyc", ".pyo", ".tmp") or "__pycache__" in str(p):
                            continue
                        self._record_file(p, baseline)

        self.hashes_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.hashes_path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, sort_keys=True)

        return baseline

    def _record_file(self, file_path: Path, baseline: Dict[str, Any]) -> None:
        try:
            rel_path = str(file_path.relative_to(self.base_dir))
        except ValueError:
            rel_path = str(file_path)

        classification = self.classify_file(rel_path)
        if classification == AssetClassification.DYNAMIC_STATE:
            return

        file_stat = file_path.stat()
        file_hash = self.compute_sha256(file_path)

        baseline["assets"][rel_path] = {
            "sha256": file_hash,
            "size": file_stat.st_size,
            "mode": oct(file_stat.st_mode),
            "classification": classification.value,
        }

    def verify_integrity(self) -> Tuple[bool, List[IntegrityCheckResult]]:
        """Audits current filesystem assets against recorded baseline."""
        if not self.hashes_path.exists():
            return False, [
                IntegrityCheckResult(
                    file_path=str(self.hashes_path),
                    status="FILE_MISSING",
                    classification=AssetClassification.STATIC_IMMUTABLE.value,
                    expected_hash=None,
                    actual_hash=None,
                    severity="CRITICAL",
                    details={"error": "Hashes baseline file does not exist"},
                )
            ]

        try:
            with open(self.hashes_path, "r", encoding="utf-8") as f:
                baseline_data = json.load(f)
        except Exception as e:
            return False, [
                IntegrityCheckResult(
                    file_path=str(self.hashes_path),
                    status="CORRUPTED",
                    classification=AssetClassification.STATIC_IMMUTABLE.value,
                    expected_hash=None,
                    actual_hash=None,
                    severity="CRITICAL",
                    details={"error": f"Failed to parse hashes baseline: {e}"},
                )
            ]

        assets = baseline_data.get("assets", {})
        results: List[IntegrityCheckResult] = []
        all_passed = True

        for rel_path, meta in assets.items():
            expected_hash = meta.get("sha256")
            classification = meta.get("classification", AssetClassification.STATIC_IMMUTABLE.value)
            full_path = self.base_dir / rel_path

            if not full_path.exists():
                all_passed = False
                results.append(
                    IntegrityCheckResult(
                        file_path=rel_path,
                        status="FILE_MISSING",
                        classification=classification,
                        expected_hash=expected_hash,
                        actual_hash=None,
                        severity="CRITICAL",
                        details={"error": "File was deleted or relocated"},
                    )
                )
                continue

            # Verify permissions (reject world-writable files)
            file_stat = full_path.stat()
            if bool(file_stat.st_mode & stat.S_IWOTH):
                all_passed = False
                results.append(
                    IntegrityCheckResult(
                        file_path=rel_path,
                        status="PERMISSION_ANOMALY",
                        classification=classification,
                        expected_hash=expected_hash,
                        actual_hash=None,
                        severity="HIGH",
                        details={"mode": oct(file_stat.st_mode), "error": "File is world-writable"},
                    )
                )

            # Compute and compare hash
            current_hash = self.compute_sha256(full_path)
            if current_hash != expected_hash:
                all_passed = False
                severity = "CRITICAL" if classification in (
                    AssetClassification.STATIC_IMMUTABLE.value,
                    AssetClassification.MODEL_WEIGHTS.value,
                ) else "HIGH"

                results.append(
                    IntegrityCheckResult(
                        file_path=rel_path,
                        status="HASH_MISMATCH",
                        classification=classification,
                        expected_hash=expected_hash,
                        actual_hash=current_hash,
                        severity=severity,
                        details={"expected": expected_hash, "actual": current_hash},
                    )
                )
            else:
                results.append(
                    IntegrityCheckResult(
                        file_path=rel_path,
                        status="PASS",
                        classification=classification,
                        expected_hash=expected_hash,
                        actual_hash=current_hash,
                        severity="INFO",
                        details={},
                    )
                )

        return all_passed, results
