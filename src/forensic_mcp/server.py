"""Forensic MCP server (stdio transport, read-only evidence contract)."""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from forensic_mcp.audit import AuditLogger
from forensic_mcp.evidence import resolve_evidence_path
from forensic_mcp.models import (
    ForensicToolError,
    HashResult,
    StructuredError,
    new_rpc_call_id,
)
from forensic_mcp.tools.hashing import compute_file_hashes


def create_server(
    *,
    audit_log_path: Path | None = None,
    evidence_root: Path | None = None,
) -> MCPServer:
    """Create and configure the Forensic MCPServer instance."""
    resolved_audit = audit_log_path or Path(
        os.environ.get("FORENSIC_MCP_AUDIT_LOG", "audit/audit.jsonl")
    )
    env_root = os.environ.get("FORENSIC_MCP_EVIDENCE_ROOT")
    resolved_root = evidence_root or (Path(env_root) if env_root else None)

    audit = AuditLogger(resolved_audit, evidence_root=resolved_root)
    server = MCPServer(
        name="forensic-mcp",
        title="Forensic Read-Only MCP Server",
        version="0.1.0",
    )

    @server.tool(
        description=(
            "Compute and optionally verify MD5 and SHA-256 hashes of a file or raw disk image "
            "in strict read-only mode, returning mandatory 6-field provenance."
        )
    )
    def hash_evidence_file(
        file_path: str,
        case_id: str,
        source_id: str,
        expected_hash: str | None = None,
    ) -> HashResult:
        """Hash a forensic evidence file or raw image in read-only mode."""
        rpc_call_id = new_rpc_call_id()
        params = {
            "file_path": file_path,
            "case_id": case_id,
            "source_id": source_id,
            "expected_hash": expected_hash,
        }
        try:
            target = resolve_evidence_path(
                Path(file_path),
                evidence_root=resolved_root,
                rpc_call_id=rpc_call_id,
            )
            result = compute_file_hashes(
                target,
                case_id=case_id,
                source_id=source_id,
                inodo_ruta=str(target),
                expected_hash=expected_hash,
                rpc_call_id=rpc_call_id,
            )
        except ForensicToolError as exc:
            err = StructuredError(
                code=exc.code,
                message=exc.message,
                rpc_call_id=rpc_call_id,
            )
            audit.log(
                rpc_call_id=rpc_call_id,
                tool="hash_evidence_file",
                params=params,
                status="error",
                outcome=err.model_dump(),
            )
            raise ToolError(err.model_dump_json()) from None
        except Exception:
            err = StructuredError(
                code="INTERNAL_ERROR",
                message="Unexpected internal error while hashing evidence.",
                rpc_call_id=rpc_call_id,
            )
            audit.log(
                rpc_call_id=rpc_call_id,
                tool="hash_evidence_file",
                params=params,
                status="error",
                outcome=err.model_dump(),
            )
            raise ToolError(err.model_dump_json()) from None

        audit.log(
            rpc_call_id=rpc_call_id,
            tool="hash_evidence_file",
            params=params,
            status="ok",
            outcome=result.model_dump(),
        )
        return result

    return server


def main() -> None:
    """Entry point for the stdio MCP server."""
    server = create_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()

