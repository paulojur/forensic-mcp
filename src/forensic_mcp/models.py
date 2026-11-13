"""Central provenance, result, and structured error models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_rpc_call_id() -> str:
    """Generate a unique identifier for a single MCP tool invocation."""
    return str(uuid4())


class Provenance(BaseModel):
    """Mandatory 6-field provenance block attached to every forensic result.

    Semantics of the 'hash' field:
    The `hash` field always contains the canonical SHA-256 digest of the root forensic
    image or source artifact, prefixed with 'sha256:'. Hashes calculated on individual
    files or artifacts extracted within the image reside in the operation's specific
    result model (such as HashResult.md5 and HashResult.sha256), never in this provenance
    block. This ensures an identical, immutable schema and semantics across all forensic tools.
    """

    model_config = ConfigDict(frozen=True)

    case_id: str = Field(..., min_length=1, description="Investigation case identifier")
    source_id: str = Field(..., min_length=1, description="Forensic image or source identifier")
    hash: str = Field(
        ...,
        pattern=r"^sha256:[0-9a-f]{64}$",
        description="Canonical SHA-256 of the source forensic image (sha256:<hex>)",
    )
    inodo_ruta: str = Field(
        ...,
        min_length=1,
        description="Structured path of the artifact, e.g. offset:N:inode:N:name or file path",
    )
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


class PartitionEntry(BaseModel):
    """Single partition entry from mmls."""

    model_config = ConfigDict(frozen=True)

    slot_number: str
    slot_id: str
    start_sector: int
    end_sector: int
    length_sectors: int
    description: str
    is_filesystem: bool


class PartitionTable(BaseModel):
    """Complete partition table from mmls."""

    model_config = ConfigDict(frozen=True)

    sector_size_bytes: int
    partitions: list[PartitionEntry]
    max_end_sector: int
    declared_size_bytes: int


class DirectoryEntry(BaseModel):
    """Single file or directory entry from fls."""

    model_config = ConfigDict(frozen=True)

    file_type: str
    is_deleted: bool
    inode: str
    name: str


class DirectoryListing(BaseModel):
    """Paginated directory listing from fls."""

    model_config = ConfigDict(frozen=True)

    dir_inode: str | None
    partition_offset: int
    total_entries: int
    offset: int
    limit: int
    has_more: bool
    next_offset: int | None
    entries: list[DirectoryEntry]


class DirectoryListingResult(BaseModel):
    """MCP result for directory listing with provenance."""

    model_config = ConfigDict(frozen=True)

    provenance: Provenance
    listing: DirectoryListing


class MacbTimestamps(BaseModel):
    """Normalized MACB timestamps in UTC."""

    model_config = ConfigDict(frozen=True)

    created_utc: str | None = None
    file_modified_utc: str | None = None
    mft_modified_utc: str | None = None
    accessed_utc: str | None = None


class InodeAttribute(BaseModel):
    """Attribute or stream entry from istat."""

    model_config = ConfigDict(frozen=True)

    attr_type: str
    name: str
    resident: bool
    size_bytes: int


class InodeMetadata(BaseModel):
    """Normalized metadata for a specific inode from istat."""

    model_config = ConfigDict(frozen=True)

    inode: str
    entry_number: int | None = None
    sequence: int | None = None
    allocated: bool
    is_directory: bool
    links: int | None = None
    names: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    allocated_size_bytes: int | None = None
    actual_size_bytes: int | None = None
    parent_inode: int | None = None
    standard_information_times: MacbTimestamps | None = None
    file_name_times: MacbTimestamps | None = None
    attributes: list[InodeAttribute] = Field(default_factory=list)


class FileMetadataResult(BaseModel):
    """MCP result for file metadata with provenance."""

    model_config = ConfigDict(frozen=True)

    provenance: Provenance
    metadata: InodeMetadata


class TimelineEvent(BaseModel):
    """Normalized forensic timeline event."""

    model_config = ConfigDict(frozen=True)

    timestamp_utc: str = Field(..., description="ISO-8601 UTC timestamp")
    tag: Literal["atime", "mtime", "ctime", "crtime"] = Field(
        ..., description="Timestamp type: atime, mtime, ctime, or crtime"
    )
    file_path: str = Field(..., description="Full path of the file or directory")
    inode: str = Field(..., description="Filesystem inode / MFT entry")
    size_bytes: int = Field(..., ge=0, description="Size in bytes")
    is_allocated: bool = Field(..., description="True if allocated, False if deleted/unallocated")
    provenance: Provenance = Field(..., description="Provenance block for this timeline event")


class TimelineResult(BaseModel):
    """Paginated result for build_timeline tool."""

    model_config = ConfigDict(frozen=True)

    total_matching: int = Field(..., ge=0, description="Total events matching filters")
    offset: int = Field(..., ge=0, description="Current page offset")
    limit: int = Field(..., ge=1, description="Page limit")
    has_more: bool = Field(..., description="True if subsequent events exist")
    next_offset: int | None = Field(None, description="Next offset cursor if has_more is True")
    events: list[TimelineEvent] = Field(default_factory=list, description="Page of timeline events")


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

