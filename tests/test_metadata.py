"""Tests for metadata extraction and directory listing tools (RF2)."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from forensic_mcp.adapters.tsk import TSKAdapter
from forensic_mcp.server import create_server

REAL_IMAGE_PATH = Path("/mnt/f/Master Ciberseguridad/TFM/evidence/SCHARDT/hacking-case.dd")
REAL_SHA256 = "65e2002fed0b286f49541c7e97dcec0dda913d51a063ceeed86782bdacda2312"


def is_tsk_and_real_image_available() -> bool:
    """Return True only if mmls is installed and the real 4.87 GB image is available."""
    return shutil.which("mmls") is not None and REAL_IMAGE_PATH.exists()


@pytest.mark.skipif(
    not is_tsk_and_real_image_available(),
    reason="The Sleuth Kit or real hacking-case.dd image not present in test environment",
)
def test_real_image_get_file_metadata_detlog(
    tmp_path: Path,
    audit_log_path: Path,
) -> None:
    """Extract metadata for DETLOG.TXT (inode 128) from real hacking-case.dd with provenance."""
    evidence_dir = REAL_IMAGE_PATH.parent
    server = create_server(audit_log_path=audit_log_path, evidence_root=evidence_dir)

    call_result = asyncio.run(
        server.call_tool(
            "get_file_metadata",
            {
                "image_path": str(REAL_IMAGE_PATH),
                "case_id": "CFREDS-HACKING",
                "source_id": "SCHARDT-001",
                "inode": "128",
                "partition_offset": 63,
                "source_hash": f"sha256:{REAL_SHA256}",
            },
        )
    )

    assert call_result.is_error is False
    payload = call_result.structured_content
    assert payload is not None

    prov = payload["provenance"]
    assert prov["case_id"] == "CFREDS-HACKING"
    assert prov["source_id"] == "SCHARDT-001"
    assert prov["hash"] == f"sha256:{REAL_SHA256}"
    assert "inode:128" in prov["inodo_ruta"]
    assert prov["timestamp_utc"].endswith("Z")
    assert len(prov["rpc_call_id"]) > 0

    meta = payload["metadata"]
    assert meta["entry_number"] == 128
    assert "DETLOG.TXT" in meta["names"]
    assert meta["allocated"] is True
    assert meta["actual_size_bytes"] == 70936
    assert meta["parent_inode"] == 5

    # Check audit log contains matching rpc_call_id
    lines = audit_log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["rpc_call_id"] == prov["rpc_call_id"]
    assert record["tool"] == "get_file_metadata"
    assert record["status"] == "ok"


@pytest.mark.skipif(
    not is_tsk_and_real_image_available(),
    reason="The Sleuth Kit or real hacking-case.dd image not present in test environment",
)
def test_real_image_list_directory_paginated(
    tmp_path: Path,
    audit_log_path: Path,
) -> None:
    """List root directory of real image with deterministic pagination."""
    evidence_dir = REAL_IMAGE_PATH.parent
    server = create_server(audit_log_path=audit_log_path, evidence_root=evidence_dir)

    # Request first page of 10 items
    call_result = asyncio.run(
        server.call_tool(
            "list_directory",
            {
                "image_path": str(REAL_IMAGE_PATH),
                "case_id": "CFREDS-HACKING",
                "source_id": "SCHARDT-001",
                "limit": 10,
                "offset": 0,
                "source_hash": f"sha256:{REAL_SHA256}",
            },
        )
    )

    assert call_result.is_error is False
    payload = call_result.structured_content
    assert payload is not None

    prov = payload["provenance"]
    assert prov["case_id"] == "CFREDS-HACKING"
    assert prov["hash"] == f"sha256:{REAL_SHA256}"

    listing = payload["listing"]
    assert listing["limit"] == 10
    assert listing["offset"] == 0
    assert listing["has_more"] is True
    assert listing["next_offset"] == 10
    assert len(listing["entries"]) == 10
    assert listing["entries"][0]["name"] == "Documents and Settings"


def test_metadata_outside_evidence_root_rejected(
    tmp_path: Path,
    evidence_dir: Path,
    audit_log_path: Path,
) -> None:
    """Server must reject paths outside FORENSIC_MCP_EVIDENCE_ROOT with structured error."""
    server = create_server(audit_log_path=audit_log_path, evidence_root=evidence_dir)
    outside_file = tmp_path / "outside.dd"
    outside_file.write_bytes(b"\x00" * 1024)

    with pytest.raises(ToolError) as exc_info:
        asyncio.run(
            server.call_tool(
                "get_file_metadata",
                {
                    "image_path": str(outside_file),
                    "case_id": "CASE-TEST",
                    "source_id": "OUTSIDE",
                    "inode": "128",
                },
            )
        )

    raw_err = str(exc_info.value)
    prefix = "Error executing tool get_file_metadata: "
    assert raw_err.startswith(prefix)
    err_payload = json.loads(raw_err.removeprefix(prefix))
    assert err_payload["code"] == "PATH_OUTSIDE_EVIDENCE_ROOT"
    assert len(err_payload["rpc_call_id"]) > 0

    lines = audit_log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["status"] == "error"
    assert record["rpc_call_id"] == err_payload["rpc_call_id"]

