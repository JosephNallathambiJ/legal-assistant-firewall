"""Cryptographic File & Asset Integrity Verification Tests for HNX26EPS01 Gateway."""

import json
import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from integrity_monitor import AssetClassification, IntegrityMonitor


def test_baseline_creation_and_clean_verification(tmp_path):
    # Setup mock assets
    file_a = tmp_path / "gateway_proxy.py"
    file_a.write_text("print('clean proxy')")

    file_b = tmp_path / "config" / "gateway.yaml"
    file_b.parent.mkdir(parents=True, exist_ok=True)
    file_b.write_text("listener: 127.0.0.1")

    hashes_file = tmp_path / "config" / "hashes.json"

    monitor = IntegrityMonitor(str(hashes_file), base_dir=str(tmp_path))
    baseline = monitor.create_baseline(["gateway_proxy.py", "config/gateway.yaml"])

    assert len(baseline["assets"]) == 2

    # Verification should pass cleanly
    passed, results = monitor.verify_integrity()
    assert passed is True
    assert all(r.status == "PASS" for r in results)


def test_tampered_file_detection(tmp_path):
    file_a = tmp_path / "gateway_proxy.py"
    file_a.write_text("print('original')")
    hashes_file = tmp_path / "config" / "hashes.json"

    monitor = IntegrityMonitor(str(hashes_file), base_dir=str(tmp_path))
    monitor.create_baseline(["gateway_proxy.py"])

    # Tamper with file
    file_a.write_text("print('tampered backdoor')")

    passed, results = monitor.verify_integrity()
    assert passed is False
    mismatch = [r for r in results if r.status == "HASH_MISMATCH"]
    assert len(mismatch) == 1
    assert mismatch[0].severity == "CRITICAL"
    assert mismatch[0].classification == AssetClassification.STATIC_IMMUTABLE.value


def test_deleted_asset_detection(tmp_path):
    file_a = tmp_path / "config" / "rbac.yaml"
    file_a.parent.mkdir(parents=True, exist_ok=True)
    file_a.write_text("roles: {}")
    hashes_file = tmp_path / "config" / "hashes.json"

    monitor = IntegrityMonitor(str(hashes_file), base_dir=str(tmp_path))
    monitor.create_baseline(["config/rbac.yaml"])

    # Delete asset
    file_a.unlink()

    passed, results = monitor.verify_integrity()
    assert passed is False
    missing = [r for r in results if r.status == "FILE_MISSING"]
    assert len(missing) == 1
    assert missing[0].severity == "CRITICAL"
