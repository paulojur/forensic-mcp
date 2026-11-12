"""Read-only evidence access guard."""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO

from forensic_mcp.models import ForensicToolError

_ALLOWED_MODES = frozenset({"rb"})


class ReadOnlyViolationError(ForensicToolError):
    """Raised when any code attempts to open evidence in a non-read-only mode."""

    def __init__(self, mode: str, rpc_call_id: str = "") -> None:
        super().__init__(
            code="READ_ONLY_VIOLATION",
            message=f"Write or non-binary mode {mode!r} is forbidden on forensic evidence; only 'rb' is permitted.",
            rpc_call_id=rpc_call_id,
        )


class EvidenceNotFoundError(ForensicToolError):
    """Raised when the target evidence file does not exist or is not a regular file."""

    def __init__(self, path: Path, rpc_call_id: str = "") -> None:
        super().__init__(
            code="EVIDENCE_NOT_FOUND",
            message=f"Evidence file not found or not a regular file: {path}",
            rpc_call_id=rpc_call_id,
        )


def resolve_evidence_path(
    target: Path,
    *,
    evidence_root: Path | None = None,
    rpc_call_id: str = "",
) -> Path:
    """Resolve target path and enforce confinement within evidence_root if configured."""
    resolved = target.resolve()
    if evidence_root is not None:
        root_resolved = evidence_root.resolve()
        if not resolved.is_relative_to(root_resolved):
            raise ForensicToolError(
                code="PATH_OUTSIDE_EVIDENCE_ROOT",
                message=f"Path {resolved} is outside the configured evidence root.",
                rpc_call_id=rpc_call_id,
            )
    return resolved


def open_evidence_readonly(
    path: Path,
    mode: str = "rb",
    *,
    rpc_call_id: str = "",
) -> BinaryIO:
    """Open an evidence file strictly in OS-level read-only binary mode ('rb').

    Rejects any write, append, create, or read-write mode before touching the filesystem.
    """
    if mode not in _ALLOWED_MODES:
        raise ReadOnlyViolationError(mode=mode, rpc_call_id=rpc_call_id)

    if not path.exists() or not path.is_file():
        raise EvidenceNotFoundError(path=path, rpc_call_id=rpc_call_id)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise

