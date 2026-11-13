"""Unit tests for bodyfile parsing, tie-breaking determinism, pipe handling, and filtering."""

from __future__ import annotations

from pathlib import Path

import pytest

from forensic_mcp.models import ForensicToolError
from forensic_mcp.tools.timeline import parse_and_filter_bodyfile_stream

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "tsk" / "fls_bodyfile_sample.txt"


@pytest.fixture()
def bodyfile_lines() -> list[str]:
    return FIXTURE_PATH.read_text(encoding="utf-8").splitlines()


def test_parse_bodyfile_stream_basic(bodyfile_lines: list[str]) -> None:
    """Stream parsing converts bodyfile lines into structured timeline events."""
    result = parse_and_filter_bodyfile_stream(
        bodyfile_lines,
        case_id="CASE-TL",
        source_id="SRC-TL",
        partition_offset=63,
        image_digest="sha256:445483b6f8d01b5f74829dc033860d199f1b6d9a01d56e45affdf312f56f8e4d",
        rpc_call_id="call-001",
        limit=50,
        offset=0,
    )

    assert result.total_matching > 0
    assert len(result.events) == 50
    assert result.has_more is True
    assert result.next_offset == 50

    first = result.events[0]
    assert first.timestamp_utc.endswith("Z")
    assert first.tag in ("mtime", "atime", "ctime", "crtime")
    assert first.provenance.case_id == "CASE-TL"
    assert first.provenance.rpc_call_id == "call-001"
    assert "offset:63:inode:" in first.provenance.inodo_ruta


def test_pipe_in_filename_handling(bodyfile_lines: list[str]) -> None:
    """Filenames containing pipe characters must be parsed without corrupting fields."""
    result = parse_and_filter_bodyfile_stream(
        bodyfile_lines,
        path_prefix="/Documents and Settings/Mr. Evil/evil|script.bat",
        case_id="CASE-TL",
        source_id="SRC-TL",
        partition_offset=63,
        image_digest="sha256:445483b6f8d01b5f74829dc033860d199f1b6d9a01d56e45affdf312f56f8e4d",
        rpc_call_id="call-002",
    )

    assert result.total_matching == 4  # 4 MACB timestamps for this file
    event = result.events[0]
    assert event.file_path == "/Documents and Settings/Mr. Evil/evil|script.bat"
    assert event.inode == "5001-128-1"
    assert event.size_bytes == 1024


def test_zero_timestamp_excluded(bodyfile_lines: list[str]) -> None:
    """Zero timestamps must be treated as undefined, not converted to 1970."""
    result = parse_and_filter_bodyfile_stream(
        bodyfile_lines,
        path_prefix="/Documents and Settings/Default User/MPC7A4.tmp",
        case_id="CASE-TL",
        source_id="SRC-TL",
        partition_offset=63,
        image_digest="sha256:445483b6f8d01b5f74829dc033860d199f1b6d9a01d56e45affdf312f56f8e4d",
        rpc_call_id="call-003",
    )

    # All timestamps were 0, so no timeline events should be emitted
    assert result.total_matching == 0
    assert len(result.events) == 0


def test_deterministic_tie_breaking(bodyfile_lines: list[str]) -> None:
    """Events with identical timestamps must break ties deterministically by inode, path, and tag."""
    # Filter only events from the tie files
    result1 = parse_and_filter_bodyfile_stream(
        bodyfile_lines,
        path_prefix="/Documents and Settings/Mr. Evil/tie_file_",
        tag="mtime",
        case_id="CASE-TL",
        source_id="SRC-TL",
        partition_offset=63,
        image_digest="sha256:445483b6f8d01b5f74829dc033860d199f1b6d9a01d56e45affdf312f56f8e4d",
        rpc_call_id="call-tie-1",
    )

    result2 = parse_and_filter_bodyfile_stream(
        bodyfile_lines,
        path_prefix="/Documents and Settings/Mr. Evil/tie_file_",
        tag="mtime",
        case_id="CASE-TL",
        source_id="SRC-TL",
        partition_offset=63,
        image_digest="sha256:445483b6f8d01b5f74829dc033860d199f1b6d9a01d56e45affdf312f56f8e4d",
        rpc_call_id="call-tie-2",
    )

    assert result1.total_matching == 2
    # Inode 5002 must strictly precede 5003 despite having identical timestamps
    assert result1.events[0].inode == "5002-128-1"
    assert result1.events[1].inode == "5003-128-1"

    # Confirm strict determinism between repeated calls (RNF2)
    assert [e.inode for e in result1.events] == [e.inode for e in result2.events]
    assert [e.file_path for e in result1.events] == [e.file_path for e in result2.events]


def test_date_range_filtering(bodyfile_lines: list[str]) -> None:
    """Filtering by UTC interval correctly confines returned events."""
    # Narrow interval around 2004-08-19
    result = parse_and_filter_bodyfile_stream(
        bodyfile_lines,
        start_time_utc="2004-08-19T00:00:00Z",
        end_time_utc="2004-08-19T23:59:59Z",
        case_id="CASE-TL",
        source_id="SRC-TL",
        partition_offset=63,
        image_digest="sha256:445483b6f8d01b5f74829dc033860d199f1b6d9a01d56e45affdf312f56f8e4d",
        rpc_call_id="call-range",
    )

    assert result.total_matching > 0
    for event in result.events:
        assert "2004-08-19" in event.timestamp_utc


def test_invalid_tag_filter_raises_error(bodyfile_lines: list[str]) -> None:
    """Invalid tag filter must raise structured error."""
    with pytest.raises(ForensicToolError) as exc_info:
        parse_and_filter_bodyfile_stream(
            bodyfile_lines,
            tag="invalid_tag",
            case_id="CASE-TL",
            source_id="SRC-TL",
            partition_offset=63,
            image_digest="sha256:445483b6f8d01b5f74829dc033860d199f1b6d9a01d56e45affdf312f56f8e4d",
            rpc_call_id="call-err",
        )
    assert exc_info.value.code == "INVALID_TAG_FILTER"

