"""Central provenance, result, and structured error models."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_rpc_call_id() -> str:
    """Generate a unique identifier for a single MCP tool invocation."""
    return str(uuid4())


class Provenance(BaseModel):
    """Mandatory 6-field provenance block attached to every forensic result."""

    model_config = ConfigDict(frozen=True)

    case_id: str = Field(..., min_length=1, description="Investigation case identifier")
    source_id: str = Field(..., min_length=1, description="Forensic image or source identifier")
    hash: str = Field(..., pattern=r"^sha256:[0-9a-f]{64}$", description="Canonical SHA-256 of the source artifact")
    inodo_ruta: str = Field(..., min_length=1, description="Inode and exact path of the artifact")
    timestamp_utc: str = Field(..., min_length=1, description="UTC timestamp of the analysis")
    rpc_call_id: str = Field(..., min_length=1, description="Unique RPC call ID linking result to audit log")


class HashResult(BaseModel):
    """Output model for MD5 and SHA-256 hashing and verification."""

    model_config = ConfigDict(frozen=True)

    provenance: Provenance
    md5: str = Field(..., pattern=r"^[0-9a-f]{32}$")
    sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(..., ge=0)
    expected_hash: str | None = None
    verified: bool | None = None


class StructuredError(BaseModel):
    """Structured error payload returned to MCP clients (never raw tracebacks)."""

    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    rpc_call_id: str


class ForensicToolError(Exception):
    """Base domain exception for controlled, structured MCP tool errors."""

    def __init__(self, code: str, message: str, rpc_call_id: str = "") -> None:
        self.code = code
        self.message = message
        self.rpc_call_id = rpc_call_id
        super().__init__(message)

    def to_structured_error(self) -> StructuredError:
        """Convert to a serializable StructuredError."""
        return StructuredError(
            code=self.code,
            message=self.message,
            rpc_call_id=self.rpc_call_id,
        )

