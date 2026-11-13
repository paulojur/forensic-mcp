"""Forensic MCP server (stdio transport, read-only evidence contract)."""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from forensic_mcp.adapters.tsk import TSKAdapter
from forensic_mcp.audit import AuditLogger
from forensic_mcp.evidence import resolve_evidence_path
from forensic_mcp.models import (
    DirectoryListingResult,
    FileMetadataResult,
    ForensicToolError,
    HashResult,
    StructuredError,
    TimelineResult,
    new_rpc_call_id,
)
from forensic_mcp.tools.hashing import compute_file_hashes
from forensic_mcp.tools.metadata import extract_inode_metadata, list_image_directory
from forensic_mcp.tools.timeline import build_timeline as execute_build_timeline


def create_server(
    *,
    audit_log_path: Path | None = None,
    evidence_root: Path | None = None,
    tsk_adapter: TSKAdapter | None = None,
) -> MCPServer:
    """Create and configure the Forensic MCPServer instance."""
    resolved_audit = audit_log_path or Path(
        os.environ.get("FORENSIC_MCP_AUDIT_LOG", "audit/audit.jsonl")
    )
    env_root = os.environ.get("FORENSIC_MCP_EVIDENCE_ROOT")
    resolved_root = evidence_root or (Path(env_root) if env_root else None)

    audit = AuditLogger(resolved_audit, evidence_root=resolved_root)
    adapter = tsk_adapter or TSKAdapter()

    # Startup check: verify if the evidence root is writable and log an audit warning if so
    if resolved_root is not None and resolved_root.exists() and os.access(resolved_root, os.W_OK):
        audit.log(
            rpc_call_id=new_rpc_call_id(),
            tool="server_startup",
            params={"evidence_root": str(resolved_root)},
            status="ok",
            outcome={
                "warning": (
                    "FORENSIC_MCP_EVIDENCE_ROOT is writable by current process. "
                    "Read-only assurance currently depends on application-level and architectural controls."
                )
            },
        )

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

    @server.tool(
        description=(
            "Extract normalized metadata for an inode in a disk image (MACB UTC timestamps, "
            "actual and allocated sizes, flags, attributes/streams) with 6-field provenance."
        )
    )
    def get_file_metadata(
        image_path: str,
        case_id: str,
        source_id: str,
        inode: str,
        partition_offset: int | None = None,
        source_hash: str | None = None,
    ) -> FileMetadataResult:
        """Extract metadata for a specific filesystem inode."""
        rpc_call_id = new_rpc_call_id()
        params = {
            "image_path": image_path,
            "case_id": case_id,
            "source_id": source_id,
            "inode": inode,
            "partition_offset": partition_offset,
            "source_hash": source_hash,
        }
        try:
            target = resolve_evidence_path(
                Path(image_path),
                evidence_root=resolved_root,
                rpc_call_id=rpc_call_id,
            )
            result = extract_inode_metadata(
                target,
                case_id=case_id,
                source_id=source_id,
                inode=inode,
                partition_offset=partition_offset,
                source_hash=source_hash,
                tsk_adapter=adapter,
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
                tool="get_file_metadata",
                params=params,
                status="error",
                outcome=err.model_dump(),
            )
            raise ToolError(err.model_dump_json()) from None
        except Exception:
            err = StructuredError(
                code="INTERNAL_ERROR",
                message="Unexpected internal error while extracting inode metadata.",
                rpc_call_id=rpc_call_id,
            )
            audit.log(
                rpc_call_id=rpc_call_id,
                tool="get_file_metadata",
                params=params,
                status="error",
                outcome=err.model_dump(),
            )
            raise ToolError(err.model_dump_json()) from None

        audit.log(
            rpc_call_id=rpc_call_id,
            tool="get_file_metadata",
            params=params,
            status="ok",
            outcome=result.model_dump(),
        )
        return result

    @server.tool(
        description=(
            "List files and directories in a disk image using fls with deterministic pagination "
            "(limit and offset) and 6-field provenance."
        )
    )
    def list_directory(
        image_path: str,
        case_id: str,
        source_id: str,
        dir_inode: str | None = None,
        partition_offset: int | None = None,
        limit: int = 50,
        offset: int = 0,
        source_hash: str | None = None,
    ) -> DirectoryListingResult:
        """List directory contents within a disk image with pagination."""
        rpc_call_id = new_rpc_call_id()
        params = {
            "image_path": image_path,
            "case_id": case_id,
            "source_id": source_id,
            "dir_inode": dir_inode,
            "partition_offset": partition_offset,
            "limit": limit,
            "offset": offset,
            "source_hash": source_hash,
        }
        try:
            target = resolve_evidence_path(
                Path(image_path),
                evidence_root=resolved_root,
                rpc_call_id=rpc_call_id,
            )
            result = list_image_directory(
                target,
                case_id=case_id,
                source_id=source_id,
                dir_inode=dir_inode,
                partition_offset=partition_offset,
                limit=limit,
                offset=offset,
                source_hash=source_hash,
                tsk_adapter=adapter,
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
                tool="list_directory",
                params=params,
                status="error",
                outcome=err.model_dump(),
            )
            raise ToolError(err.model_dump_json()) from None
        except Exception:
            err = StructuredError(
                code="INTERNAL_ERROR",
                message="Unexpected internal error while listing directory entries.",
                rpc_call_id=rpc_call_id,
            )
            audit.log(
                rpc_call_id=rpc_call_id,
                tool="list_directory",
                params=params,
                status="error",
                outcome=err.model_dump(),
            )
            raise ToolError(err.model_dump_json()) from None

        audit.log(
            rpc_call_id=rpc_call_id,
            tool="list_directory",
            params=params,
            status="ok",
            outcome=result.model_dump(),
        )
        return result

    @server.tool(
        description=(
            "Generate, filter, and paginate a forensic timeline from disk image filesystem metadata "
            "(MACB bodyfile) with deterministic chronological sorting and 6-field provenance."
        )
    )
    def build_timeline(
        image_path: str,
        case_id: str,
        source_id: str,
        partition_offset: int | None = None,
        start_time_utc: str | None = None,
        end_time_utc: str | None = None,
        path_prefix: str | None = None,
        tag: str | None = None,
        include_deleted: bool = True,
        limit: int = 100,
        offset: int = 0,
        source_hash: str | None = None,
    ) -> TimelineResult:
        """Build and filter a forensic timeline from the disk image in stream."""
        rpc_call_id = new_rpc_call_id()
        params = {
            "image_path": image_path,
            "case_id": case_id,
            "source_id": source_id,
            "partition_offset": partition_offset,
            "start_time_utc": start_time_utc,
            "end_time_utc": end_time_utc,
            "path_prefix": path_prefix,
            "tag": tag,
            "include_deleted": include_deleted,
            "limit": limit,
            "offset": offset,
            "source_hash": source_hash,
        }
        try:
            target = resolve_evidence_path(
                Path(image_path),
                evidence_root=resolved_root,
                rpc_call_id=rpc_call_id,
            )
            result = execute_build_timeline(
                target,
                case_id=case_id,
                source_id=source_id,
                partition_offset=partition_offset,
                start_time_utc=start_time_utc,
                end_time_utc=end_time_utc,
                path_prefix=path_prefix,
                tag=tag,
                include_deleted=include_deleted,
                limit=limit,
                offset=offset,
                source_hash=source_hash,
                tsk_adapter=adapter,
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
                tool="build_timeline",
                params=params,
                status="error",
                outcome=err.model_dump(),
            )
            raise ToolError(err.model_dump_json()) from None
        except Exception:
            err = StructuredError(
                code="INTERNAL_ERROR",
                message="Unexpected internal error while generating timeline.",
                rpc_call_id=rpc_call_id,
            )
            audit.log(
                rpc_call_id=rpc_call_id,
                tool="build_timeline",
                params=params,
                status="error",
                outcome=err.model_dump(),
            )
            raise ToolError(err.model_dump_json()) from None

        audit.log(
            rpc_call_id=rpc_call_id,
            tool="build_timeline",
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
