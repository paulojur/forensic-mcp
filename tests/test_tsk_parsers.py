"""Unit tests for TSK parsers, geometry validation, timeout, and missing binary errors."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from forensic_mcp.adapters.tsk import (
    TSKAdapter,
    parse_fls_output,
    parse_istat_output,
    parse_mmls_output,
)
from forensic_mcp.models import ForensicToolError

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "tsk"


@pytest.fixture()
def mmls_text() -> str:
    return (FIXTURES_DIR / "mmls_output.txt").read_text(encoding="utf-8")


@pytest.fixture()
def fls_root_text() -> str:
    return (FIXTURES_DIR / "fls_root_output.txt").read_text(encoding="utf-8")


@pytest.fixture()
def fls_dir_text() -> str:
    return (FIXTURES_DIR / "fls_dir_3671_output.txt").read_text(encoding="utf-8")


@pytest.fixture()
def istat_file_text() -> str:
    return (FIXTURES_DIR / "istat_file_128_output.txt").read_text(encoding="utf-8")


@pytest.fixture()
def istat_dir_text() -> str:
    return (FIXTURES_DIR / "istat_dir_3671_output.txt").read_text(encoding="utf-8")


def test_parse_mmls_partitions_and_geometry(mmls_text: str) -> None:
    """mmls parser extracts sector size, partition table and declared total size."""
    # 4871301120 bytes is the exact required size (9514260 * 512)
    pt = parse_mmls_output(mmls_text, actual_file_size=4871301120)

    assert pt.sector_size_bytes == 512
    assert pt.max_end_sector == 9514259
    assert pt.declared_size_bytes == 4871301120
    assert len(pt.partitions) == 4

    # Verify slots and filesystem identification
    assert pt.partitions[0].slot_id == "Meta"
    assert pt.partitions[0].is_filesystem is False

    assert pt.partitions[1].description == "Unallocated"
    assert pt.partitions[1].is_filesystem is False

    ntfs = pt.partitions[2]
    assert ntfs.start_sector == 63
    assert ntfs.end_sector == 9510479
    assert ntfs.length_sectors == 9510417
    assert ntfs.description == "NTFS / exFAT (0x07)"
    assert ntfs.is_filesystem is True

    assert pt.partitions[3].description == "Unallocated"
    assert pt.partitions[3].is_filesystem is False


def test_parse_mmls_detects_truncated_geometry(mmls_text: str) -> None:
    """When the image file size is smaller than MBR declared geometry, raise explicit error."""
    # Image truncated by missing segments (e.g. only 3 GB instead of 4.87 GB)
    truncated_size = 3_000_000_000

    with pytest.raises(ForensicToolError) as exc_info:
        parse_mmls_output(mmls_text, actual_file_size=truncated_size)

    assert exc_info.value.code == "IMAGE_GEOMETRY_TRUNCATED"
    assert "truncated or incomplete" in exc_info.value.message
    assert "4871301120 bytes" in exc_info.value.message


def test_parse_fls_root_and_pagination(fls_root_text: str) -> None:
    """fls parser extracts entries, identifies deleted items, and paginates deterministically."""
    # Full list
    full_listing = parse_fls_output(fls_root_text, limit=100, offset=0)
    assert full_listing.total_entries == 46
    assert full_listing.has_more is False
    assert full_listing.next_offset is None

    # Check entry attributes
    docs_entry = next(e for e in full_listing.entries if e.name == "Documents and Settings")
    assert docs_entry.file_type == "directory"
    assert docs_entry.is_deleted is False
    assert docs_entry.inode == "3671-144-7"

    deleted_entry = next(e for e in full_listing.entries if e.name == "__esitempfile.tmp")
    assert deleted_entry.is_deleted is True
    assert deleted_entry.inode == "0"

    # Test pagination: page 1 (10 entries)
    page1 = parse_fls_output(fls_root_text, limit=10, offset=0)
    assert len(page1.entries) == 10
    assert page1.has_more is True
    assert page1.next_offset == 10
    assert page1.offset == 0
    assert page1.entries[0].name == "Documents and Settings"

    # Page 2 (10 entries)
    page2 = parse_fls_output(fls_root_text, limit=10, offset=10)
    assert len(page2.entries) == 10
    assert page2.has_more is True
    assert page2.next_offset == 20
    assert page2.offset == 10
    assert page2.entries[0].name == "Program Files"

    # Last page (offset 40, 6 entries remaining)
    last_page = parse_fls_output(fls_root_text, limit=10, offset=40)
    assert len(last_page.entries) == 6
    assert last_page.has_more is False
    assert last_page.next_offset is None


def test_parse_fls_directory_contents(fls_dir_text: str) -> None:
    """fls parser correctly handles subdirectories (Documents and Settings)."""
    listing = parse_fls_output(fls_dir_text, dir_inode="3671", limit=50, offset=0)
    assert listing.total_entries == 5
    assert listing.dir_inode == "3671"
    names = [e.name for e in listing.entries]
    assert names == ["All Users", "Default User", "LocalService", "Mr. Evil", "NetworkService"]
    assert all(e.file_type == "directory" for e in listing.entries)


def test_parse_istat_regular_file_metadata(istat_file_text: str) -> None:
    """istat parser extracts file metadata, MACB UTC times, sizes and attributes."""
    meta = parse_istat_output(istat_file_text, inode="128")

    assert meta.inode == "128"
    assert meta.entry_number == 128
    assert meta.sequence == 128
    assert meta.allocated is True
    assert meta.is_directory is False
    assert meta.links == 1
    assert "DETLOG.TXT" in meta.names
    assert "Hidden" in meta.flags
    assert "System" in meta.flags
    assert meta.parent_inode == 5
    assert meta.actual_size_bytes == 70936
    assert meta.allocated_size_bytes == 71168

    # Standard Information Timestamps in UTC
    assert meta.standard_information_times is not None
    assert meta.standard_information_times.created_utc == "2004-08-18 16:47:01.710000000 (UTC)"
    assert meta.standard_information_times.file_modified_utc == "2004-08-18 16:50:00.000000000 (UTC)"
    assert meta.standard_information_times.mft_modified_utc == "2004-08-19 22:40:19.648334400 (UTC)"
    assert meta.standard_information_times.accessed_utc == "2004-08-18 00:00:00.000000000 (UTC)"

    # Attributes
    data_attr = next(a for a in meta.attributes if a.attr_type == "$DATA")
    assert data_attr.resident is False
    assert data_attr.size_bytes == 70936


def test_parse_istat_directory_metadata(istat_dir_text: str) -> None:
    """istat parser extracts directory metadata and both 8.3 and long names."""
    meta = parse_istat_output(istat_dir_text, inode="3671")

    assert meta.inode == "3671"
    assert meta.entry_number == 3671
    assert meta.sequence == 1
    assert meta.allocated is True
    assert meta.is_directory is True
    assert meta.links == 2
    assert "DOCUME~1" in meta.names
    assert "Documents and Settings" in meta.names
    assert meta.parent_inode == 5


def test_tsk_adapter_binary_not_found(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """TSKAdapter raises TSK_NOT_INSTALLED when the requested binary does not exist."""
    fake_img = tmp_path / "fake.dd"
    fake_img.write_bytes(b"\x00" * 1024)

    adapter = TSKAdapter(mmls_cmd="non_existent_mmls_bin")
    with pytest.raises(ForensicToolError) as exc_info:
        adapter.list_partitions(fake_img)

    assert exc_info.value.code == "TSK_NOT_INSTALLED"


def test_tsk_adapter_timeout_handling(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """TSKAdapter raises TSK_TIMEOUT when command execution exceeds timeout."""
    fake_img = tmp_path / "fake.dd"
    fake_img.write_bytes(b"\x00" * 1024)

    def mock_run(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=["mmls"], timeout=0.1)

    monkeypatch.setattr(subprocess, "run", mock_run)
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/" + cmd)

    adapter = TSKAdapter(timeout_seconds=0.1)
    with pytest.raises(ForensicToolError) as exc_info:
        adapter.list_partitions(fake_img)

    assert exc_info.value.code == "TSK_TIMEOUT"
