"""Tests verifying the non-negotiable evidence security contract and auditability."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from forensic_mcp.audit import AuditLogger
from forensic_mcp.evidence import ReadOnlyViolationError, open_evidence_readonly
from forensic_mcp.server import create_server


@pytest.mark.parametrize("forbidden_mode", ["w", "wb", "a", "ab", "r+", "rb+", "w+", "x"])
def test_open_evidence_readonly_rejects_write_modes(
    small_dd_image: Path,
    forbidden_mode: str,
) -> None:
    """Any attempt to open evidence in non-read-only mode must fail explicitly."""
    with pytest.raises(ReadOnlyViolationError) as exc_info:
        open_evidence_readonly(small_dd_image, forbidden_mode)
    assert exc_info.value.code == "READ_ONLY_VIOLATION"


def test_audit_log_cannot_reside_inside_evidence_root(evidence_dir: Path) -> None:
    """AuditLogger must refuse a log path inside the evidence directory."""
    bad_log = evidence_dir / "audit.jsonl"
    with pytest.raises(ValueError, match="outside evidence_root"):
        AuditLogger(bad_log, evidence_root=evidence_dir)


def test_mcp_tool_audit_log_and_no_sockets(
    small_dd_image: Path,
    evidence_dir: Path,
    audit_log_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calling the MCP tool opens zero sockets and writes a matching rpc_call_id audit record."""

    def forbid_socket(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Network socket creation is forbidden during tool execution")

    server = create_server(audit_log_path=audit_log_path, evidence_root=evidence_dir)

    async def _invoke() -> Any:
        # Patch socket.socket after the asyncio event loop's internal self-pipe is created.
        monkeypatch.setattr(socket, "socket", forbid_socket)
        monkeypatch.setattr(socket, "create_connection", forbid_socket)
        return await server.call_tool(
            "hash_evidence_file",
            {
                "file_path": str(small_dd_image),
                "case_id": "CASE-NET",
                "source_id": "DD-001",
            },
        )

    call_result = asyncio.run(_invoke())

    assert call_result.is_error is False
    payload = call_result.structured_content
    assert payload is not None
    rpc_call_id = payload["provenance"]["rpc_call_id"]

    lines = audit_log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["rpc_call_id"] == rpc_call_id
    assert record["tool"] == "hash_evidence_file"
    assert record["status"] == "ok"
    assert record["params"]["case_id"] == "CASE-NET"


def test_mcp_tool_returns_structured_error_without_traceback(
    evidence_dir: Path,
    audit_log_path: Path,
) -> None:
    """Missing evidence must return a structured JSON error and log it with rpc_call_id."""
    server = create_server(audit_log_path=audit_log_path, evidence_root=evidence_dir)
    missing = evidence_dir / "does_not_exist.dd"

    with pytest.raises(ToolError) as exc_info:
        asyncio.run(
            server.call_tool(
                "hash_evidence_file",
                {
                    "file_path": str(missing),
                    "case_id": "CASE-ERR",
                    "source_id": "DD-MISSING",
                },
            )
        )

    raw_err = str(exc_info.value)
    prefix = "Error executing tool hash_evidence_file: "
    assert raw_err.startswith(prefix)
    err_payload = json.loads(raw_err.removeprefix(prefix))
    assert err_payload["code"] == "EVIDENCE_NOT_FOUND"
    assert "Traceback" not in err_payload["message"]
    assert len(err_payload["rpc_call_id"]) > 0

    lines = audit_log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["status"] == "error"
    assert record["rpc_call_id"] == err_payload["rpc_call_id"]
    assert record["outcome"]["code"] == "EVIDENCE_NOT_FOUND"

