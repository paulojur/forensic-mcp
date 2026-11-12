"""Tests for MD5/SHA-256 hashing, system sha256sum parity, and .dd image fixture."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from forensic_mcp.tools.hashing import compute_file_hashes


def test_sha256_matches_system_sha256sum(small_sample_file: Path) -> None:
    """SHA-256 of a small file must match system sha256sum and hashlib."""
    result = compute_file_hashes(
        small_sample_file,
        case_id="CASE-001",
        source_id="SRC-SAMPLE",
    )

    expected_sha256 = hashlib.sha256(small_sample_file.read_bytes()).hexdigest()
    expected_md5 = hashlib.md5(small_sample_file.read_bytes()).hexdigest()

    assert result.sha256 == expected_sha256
    assert result.md5 == expected_md5
    assert result.provenance.hash == f"sha256:{expected_sha256}"

    sha256sum_bin = shutil.which("sha256sum")
    if sha256sum_bin is None:
        pytest.skip("sha256sum binary not available in PATH")

    proc = subprocess.run(
        [sha256sum_bin, str(small_sample_file)],
        capture_output=True,
        text=True,
        check=True,
    )
    system_sha256 = proc.stdout.split()[0]
    assert result.sha256 == system_sha256


def test_small_dd_image_fixture_provenance_and_verification(small_dd_image: Path) -> None:
    """Hashing the small .dd fixture returns all 6 provenance fields and verifies digests."""
    raw_bytes = small_dd_image.read_bytes()
    expected_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    result = compute_file_hashes(
        small_dd_image,
        case_id="CFREDS-MINI",
        source_id="DD-001",
        expected_hash=f"sha256:{expected_sha256}",
    )

    prov = result.provenance
    assert prov.case_id == "CFREDS-MINI"
    assert prov.source_id == "DD-001"
    assert prov.hash == f"sha256:{expected_sha256}"
    assert prov.inodo_ruta == str(small_dd_image)
    assert prov.timestamp_utc.endswith("Z")
    assert len(prov.rpc_call_id) > 0
    assert result.size_bytes == 65536
    assert result.verified is True

    mismatch = compute_file_hashes(
        small_dd_image,
        case_id="CFREDS-MINI",
        source_id="DD-001",
        expected_hash="0" * 64,
    )
    assert mismatch.verified is False

