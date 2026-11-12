"""Tool 2: Normalized filesystem metadata extraction and directory listing via TSK."""

from __future__ import annotations

import hashlib
from pathlib import Path

from forensic_mcp.adapters.tsk import TSKAdapter
from forensic_mcp.evidence import open_evidence_readonly, resolve_evidence_path
from forensic_mcp.models import (
    DirectoryListingResult,
    FileMetadataResult,
    Provenance,
    new_rpc_call_id,
    utc_now_iso,
)

_CHUNK_SIZE = 65536
_IMAGE_HASH_CACHE: dict[Path, str] = {}


def get_cached_or_compute_image_hash(
    path: Path,
    *,
    provided_hash: str | None = None,
    rpc_call_id: str = "",
) -> str:
    """Return verified image SHA-256 using provided hash, in-memory cache, or streaming computation."""
    if provided_hash:
        normalized = provided_hash.strip().lower()
        if not normalized.startswith("sha256:"):
            normalized = f"sha256:{normalized}"
        return normalized

    resolved = path.resolve()
    if resolved in _IMAGE_HASH_CACHE:
        return _IMAGE_HASH_CACHE[resolved]

    hasher = hashlib.sha256()
    with open_evidence_readonly(resolved, "rb", rpc_call_id=rpc_call_id) as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            hasher.update(chunk)

    digest = f"sha256:{hasher.hexdigest()}"
    _IMAGE_HASH_CACHE[resolved] = digest
    return digest


def extract_inode_metadata(
    image_path: Path,
    *,
    case_id: str,
    source_id: str,
    inode: str | int,
    partition_offset: int | None = None,
    source_hash: str | None = None,
    tsk_adapter: TSKAdapter | None = None,
    rpc_call_id: str | None = None,
) -> FileMetadataResult:
    """Extract normalized metadata for an inode within a disk image."""
    call_id = rpc_call_id or new_rpc_call_id()
    adapter = tsk_adapter or TSKAdapter()

    effective_offset = (
        partition_offset
        if partition_offset is not None
        else adapter.get_default_partition_offset(image_path, rpc_call_id=call_id)
    )

    metadata = adapter.get_inode_metadata(
        image_path,
        partition_offset=effective_offset,
        inode=inode,
        rpc_call_id=call_id,
    )

    image_digest = get_cached_or_compute_image_hash(
        image_path,
        provided_hash=source_hash,
        rpc_call_id=call_id,
    )

    name_label = f":{metadata.names[0]}" if metadata.names else ""
    inodo_ruta = f"offset:{effective_offset}:inode:{inode}{name_label}"

    provenance = Provenance(
        case_id=case_id,
        source_id=source_id,
        hash=image_digest,
        inodo_ruta=inodo_ruta,
        timestamp_utc=utc_now_iso(),
        rpc_call_id=call_id,
    )

    return FileMetadataResult(
        provenance=provenance,
        metadata=metadata,
    )


def list_image_directory(
    image_path: Path,
    *,
    case_id: str,
    source_id: str,
    dir_inode: str | int | None = None,
    partition_offset: int | None = None,
    limit: int = 50,
    offset: int = 0,
    source_hash: str | None = None,
    tsk_adapter: TSKAdapter | None = None,
    rpc_call_id: str | None = None,
) -> DirectoryListingResult:
    """List directory entries using fls with deterministic pagination."""
    call_id = rpc_call_id or new_rpc_call_id()
    adapter = tsk_adapter or TSKAdapter()

    effective_offset = (
        partition_offset
        if partition_offset is not None
        else adapter.get_default_partition_offset(image_path, rpc_call_id=call_id)
    )

    listing = adapter.list_directory(
        image_path,
        partition_offset=effective_offset,
        dir_inode=dir_inode,
        limit=limit,
        offset=offset,
        rpc_call_id=call_id,
    )

    image_digest = get_cached_or_compute_image_hash(
        image_path,
        provided_hash=source_hash,
        rpc_call_id=call_id,
    )

    inode_str = f"inode:{dir_inode}" if dir_inode is not None else "root"
    inodo_ruta = f"offset:{effective_offset}:{inode_str}:paged[{offset}:{offset + limit}]"

    provenance = Provenance(
        case_id=case_id,
        source_id=source_id,
        hash=image_digest,
        inodo_ruta=inodo_ruta,
        timestamp_utc=utc_now_iso(),
        rpc_call_id=call_id,
    )

    return DirectoryListingResult(
        provenance=provenance,
        listing=listing,
    )

