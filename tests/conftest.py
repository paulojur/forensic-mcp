"""Shared pytest fixtures for forensic-mcp tests."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest


@pytest.fixture()
def evidence_dir(tmp_path: Path) -> Path:
    """Create an isolated directory for read-only forensic evidence fixtures."""
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    return ev_dir


@pytest.fixture()
def audit_log_path(tmp_path: Path) -> Path:
    """Return an audit log path strictly outside evidence_dir."""
    return tmp_path / "audit" / "audit.jsonl"


@pytest.fixture()
def small_sample_file(evidence_dir: Path) -> Path:
    """Create a small deterministic read-only file for hash verification."""
    sample = evidence_dir / "sample_artifact.bin"
    sample.write_bytes(b"forensic-mcp-deterministic-evidence-payload-2026\n")
    sample.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    return sample


@pytest.fixture()
def small_dd_image(evidence_dir: Path) -> Path:
    """Create a small deterministic 64 KiB raw .dd disk image fixture (read-only)."""
    dd_path = evidence_dir / "cfreds_mini_fixture.dd"
    sector_0 = bytearray(512)
    sector_0[0:3] = b"\xeb\x3c\x90"
    sector_0[510:512] = b"\x55\xaa"  # MBR boot signature
    payload = bytes((i % 256 for i in range(65536 - 512)))
    dd_path.write_bytes(bytes(sector_0) + payload)
    dd_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    return dd_path

