"""Tool 3: Normalized forensic timeline generation, filtering, and deterministic pagination."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

from forensic_mcp.adapters.tsk import TSKAdapter
from forensic_mcp.models import (
    ForensicToolError,
    Provenance,
    TimelineEvent,
    TimelineResult,
    new_rpc_call_id,
)
from forensic_mcp.tools.metadata import get_cached_or_compute_image_hash

_TAG_NAMES = ("mtime", "atime", "ctime", "crtime")


def parse_and_filter_bodyfile_stream(
    lines: Iterable[str],
    *,
    start_time_utc: str | None = None,
    end_time_utc: str | None = None,
    path_prefix: str | None = None,
    tag: str | None = None,
    include_deleted: bool = True,
    offset: int = 0,
    limit: int = 100,
    case_id: str,
    source_id: str,
    partition_offset: int,
    image_digest: str,
    rpc_call_id: str,
) -> TimelineResult:
    """Parse bodyfile lines in stream, filter on the fly, and paginate with stable sorting."""
    if limit < 1:
        limit = 100
    if limit > 1000:
        limit = 1000
    if offset < 0:
        offset = 0

    if tag is not None and tag not in _TAG_NAMES:
        raise ForensicToolError(
            code="INVALID_TAG_FILTER",
            message=f"Invalid tag filter '{tag}'. Must be one of: {', '.join(_TAG_NAMES)}",
            rpc_call_id=rpc_call_id,
        )

    matched_events: list[dict[str, Any]] = []

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line:
            continue

        parts = line.split("|")
        # Format: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
        if len(parts) < 11:
            continue

        name = "|".join(parts[1 : len(parts) - 9])
        inode = parts[-9]
        mode = parts[-8]
        try:
            size_bytes = int(parts[-5])
        except ValueError:
            size_bytes = 0

        atime_raw, mtime_raw, ctime_raw, crtime_raw = parts[-4:]

        is_deleted = (
            "(deleted)" in name
            or "(deleted-realloc)" in name
            or "----------" in mode
            or inode == "0"
        )
        is_allocated = not is_deleted

        if not include_deleted and is_deleted:
            continue

        if path_prefix is not None and not name.startswith(path_prefix):
            continue

        raw_timestamps = (
            ("mtime", mtime_raw),
            ("atime", atime_raw),
            ("ctime", ctime_raw),
            ("crtime", crtime_raw),
        )

        for mark_tag, raw_ts in raw_timestamps:
            if tag is not None and mark_tag != tag:
                continue

            try:
                epoch = int(raw_ts)
            except ValueError:
                continue

            # Zero or negative timestamps represent undefined values; exclude from timeline
            if epoch <= 0:
                continue

            try:
                dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                ts_utc = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (OverflowError, OSError, ValueError):
                continue

            if start_time_utc is not None and ts_utc < start_time_utc:
                continue
            if end_time_utc is not None and ts_utc > end_time_utc:
                continue

            matched_events.append(
                {
                    "timestamp_utc": ts_utc,
                    "tag": mark_tag,
                    "file_path": name,
                    "inode": inode,
                    "size_bytes": size_bytes,
                    "is_allocated": is_allocated,
                }
            )

    # Deterministic sorting (RNF2): chronological order, stable tie-break by (inode, path, tag)
    matched_events.sort(
        key=lambda e: (e["timestamp_utc"], e["inode"], e["file_path"], e["tag"])
    )

    total_matching = len(matched_events)
    page_slice = matched_events[offset : offset + limit]
    has_more = (offset + limit) < total_matching
    next_offset = (offset + limit) if has_more else None

    events: list[TimelineEvent] = []
    for item in page_slice:
        inodo_ruta = f"offset:{partition_offset}:inode:{item['inode']}:{item['tag']}"
        provenance = Provenance(
            case_id=case_id,
            source_id=source_id,
            hash=image_digest,
            inodo_ruta=inodo_ruta,
            timestamp_utc=item["timestamp_utc"],
            rpc_call_id=rpc_call_id,
        )
        events.append(
            TimelineEvent(
                timestamp_utc=item["timestamp_utc"],
                tag=item["tag"],
                file_path=item["file_path"],
                inode=item["inode"],
                size_bytes=item["size_bytes"],
                is_allocated=item["is_allocated"],
                provenance=provenance,
            )
        )

    return TimelineResult(
        total_matching=total_matching,
        offset=offset,
        limit=limit,
        has_more=has_more,
        next_offset=next_offset,
        events=events,
    )


def build_timeline(
    image_path: Path,
    *,
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
    tsk_adapter: TSKAdapter | None = None,
    rpc_call_id: str | None = None,
) -> TimelineResult:
    """Generate, filter, and paginate a forensic timeline from a disk image in stream."""
    call_id = rpc_call_id or new_rpc_call_id()
    adapter = tsk_adapter or TSKAdapter()

    effective_offset = (
        partition_offset
        if partition_offset is not None
        else adapter.get_default_partition_offset(image_path, rpc_call_id=call_id)
    )

    image_digest = get_cached_or_compute_image_hash(
        image_path,
        provided_hash=source_hash,
        rpc_call_id=call_id,
    )

    lines_stream = adapter.stream_bodyfile(
        image_path,
        partition_offset=effective_offset,
        mount_point="/",
        rpc_call_id=call_id,
    )

    return parse_and_filter_bodyfile_stream(
        lines_stream,
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
        path_prefix=path_prefix,
        tag=tag,
        include_deleted=include_deleted,
        offset=offset,
        limit=limit,
        case_id=case_id,
        source_id=source_id,
        partition_offset=effective_offset,
        image_digest=image_digest,
        rpc_call_id=call_id,
    )

