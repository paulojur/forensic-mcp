"""Integration tests for the build_timeline MCP tool (RF3)."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from forensic_mcp.server import create_server

REAL_IMAGE_PATH = Path("/mnt/f/Master Ciberseguridad/TFM/evidence/SCHARDT/hacking-case.dd")
REAL_SHA256 = "65e2002fed0b286f49541c7e97dcec0dda913d51a063ceeed86782bdacda2312"


def is_tsk_and_real_image_available() -> bool:
    """Return True only if fls is installed and the real 4.87 GB image is available."""
    return shutil.which("fls") is not None and REAL_IMAGE_PATH.exists()


@pytest.mark.skipif(
    not is_tsk_and_real_image_available(),
    reason="The Sleuth Kit or real hacking-case.dd image not present in test environment",
)
def test_real_image_build_timeline_mr_evil(
    tmp_path: Path,
    audit_log_path: Path,
) -> None:
    """Generate filtered timeline for Mr. Evil directory with deterministic pagination."""
    evidence_dir = REAL_IMAGE_PATH.parent
    server = create_server(audit_log_path=audit_log_path, evidence_root=evidence_dir)

    call_result = asyncio.run(
        server.call_tool(
            "build_timeline",
            {
                "image_path": str(REAL_IMAGE_PATH),
                "case_id": "CFREDS-HACKING",
                "source_id": "SCHARDT-001",
                "path_prefix": "/Documents and Settings/Mr. Evil",
                "limit": 20,
                "offset": 0,
                "source_hash": f"sha256:{REAL_SHA256}",
            },
        )
    )

    assert call_result.is_error is False
    payload = call_result.structured_content
    assert payload is not None

    assert payload["total_matching"] > 0
    assert len(payload["events"]) <= 20
    assert payload["limit"] == 20
    assert payload["offset"] == 0

    first_event = payload["events"][0]
    assert first_event["file_path"].startswith("/Documents and Settings/Mr. Evil")
    assert first_event["provenance"]["case_id"] == "CFREDS-HACKING"
    assert first_event["provenance"]["hash"] == f"sha256:{REAL_SHA256}"
    assert "offset:63:inode:" in first_event["provenance"]["inodo_ruta"]

    # Verify audit record
    lines = audit_log_path.read_text(encoding="utf-8").strip().splitlines()
    records = [json.loads(line) for line in lines]
    tl_record = next(r for r in records if r["tool"] == "build_timeline")
    assert tl_record["status"] == "ok"
    assert tl_record["params"]["path_prefix"] == "/Documents and Settings/Mr. Evil"


@pytest.mark.skipif(
    not is_tsk_and_real_image_available(),
    reason="The Sleuth Kit or real hacking-case.dd image not present in test environment",
)
def test_real_image_build_timeline_determinism(
    tmp_path: Path,
    audit_log_path: Path,
) -> None:
    """Two identical timeline requests must yield identical event lists (RNF2 determinism)."""
    evidence_dir = REAL_IMAGE_PATH.parent
    server = create_server(audit_log_path=audit_log_path, evidence_root=evidence_dir)

    params = {
        "image_path": str(REAL_IMAGE_PATH),
        "case_id": "CFREDS-HACKING",
        "source_id": "SCHARDT-001",
        "path_prefix": "/Documents and Settings/Mr. Evil",
        "limit": 25,
        "offset": 0,
        "source_hash": f"sha256:{REAL_SHA256}",
    }

    call1 = asyncio.run(server.call_tool("build_timeline", params))
    call2 = asyncio.run(server.call_tool("build_timeline", params))

    events1 = call1.structured_content["events"]
    events2 = call2.structured_content["events"]

    assert len(events1) == len(events2)
    for e1, e2 in zip(events1, events2, strict=True):
        assert e1["timestamp_utc"] == e2["timestamp_utc"]
        assert e1["tag"] == e2["tag"]
        assert e1["file_path"] == e2["file_path"]
        assert e1["inode"] == e2["inode"]
        assert e1["size_bytes"] == e2["size_bytes"]
        assert e1["is_allocated"] == e2["is_allocated"]


@pytest.mark.skipif(
    not is_tsk_and_real_image_available(),
    reason="The Sleuth Kit or real hacking-case.dd image not present in test environment",
)
def test_real_image_build_timeline_provenance_audit_distinction(
    tmp_path: Path,
    audit_log_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated calls produce different audit timestamps in provenance, but identical analytical data."""
    evidence_dir = REAL_IMAGE_PATH.parent
    server = create_server(audit_log_path=audit_log_path, evidence_root=evidence_dir)

    # Sequence of distinct analysis timestamps to simulate two separate executions
    timestamps = iter(["2026-11-13T16:00:00Z", "2026-11-13T16:05:00Z"])
    monkeypatch.setattr(
        "forensic_mcp.tools.timeline.utc_now_iso",
        lambda: next(timestamps),
    )

    params = {
        "image_path": str(REAL_IMAGE_PATH),
        "case_id": "CFREDS-HACKING",
        "source_id": "SCHARDT-001",
        "path_prefix": "/Documents and Settings/Mr. Evil",
        "limit": 10,
        "offset": 0,
        "source_hash": f"sha256:{REAL_SHA256}",
    }

    call1 = asyncio.run(server.call_tool("build_timeline", params))
    call2 = asyncio.run(server.call_tool("build_timeline", params))

    events1 = call1.structured_content["events"]
    events2 = call2.structured_content["events"]

    assert len(events1) == 10
    assert len(events2) == 10

    # 1. Audit metadata differs by design between executions
    for e1, e2 in zip(events1, events2, strict=True):
        prov1 = e1["provenance"]
        prov2 = e2["provenance"]
        assert prov1["timestamp_utc"] == "2026-11-13T16:00:00Z"
        assert prov2["timestamp_utc"] == "2026-11-13T16:05:00Z"
        assert prov1["timestamp_utc"] != prov2["timestamp_utc"]
        assert prov1["rpc_call_id"] != prov2["rpc_call_id"]

    # 2. Analytical finding content remains strictly identical (RNF2 determinism)
    for e1, e2 in zip(events1, events2, strict=True):
        assert e1["timestamp_utc"] == e2["timestamp_utc"]  # artifact timestamp (2004) untouched
        assert e1["tag"] == e2["tag"]
        assert e1["file_path"] == e2["file_path"]
        assert e1["inode"] == e2["inode"]
        assert e1["size_bytes"] == e2["size_bytes"]
        assert e1["is_allocated"] == e2["is_allocated"]


def test_timeline_outside_evidence_root_rejected(
    tmp_path: Path,
    evidence_dir: Path,
    audit_log_path: Path,
) -> None:
    """build_timeline must reject paths outside FORENSIC_MCP_EVIDENCE_ROOT."""
    server = create_server(audit_log_path=audit_log_path, evidence_root=evidence_dir)
    outside = tmp_path / "outside.dd"
    outside.write_bytes(b"\x00" * 1024)

    with pytest.raises(ToolError) as exc_info:
        asyncio.run(
            server.call_tool(
                "build_timeline",
                {
                    "image_path": str(outside),
                    "case_id": "CASE-TEST",
                    "source_id": "OUTSIDE",
                },
            )
        )

    raw_err = str(exc_info.value)
    prefix = "Error executing tool build_timeline: "
    assert raw_err.startswith(prefix)
    err_payload = json.loads(raw_err.removeprefix(prefix))
    assert err_payload["code"] == "PATH_OUTSIDE_EVIDENCE_ROOT"

