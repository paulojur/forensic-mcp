"""The Sleuth Kit (TSK) adapter and output parsers."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterator, Sequence

from forensic_mcp.evidence import open_evidence_readonly
from forensic_mcp.models import (
    DirectoryEntry,
    DirectoryListing,
    ForensicToolError,
    InodeAttribute,
    InodeMetadata,
    MacbTimestamps,
    PartitionEntry,
    PartitionTable,
)

_MMLS_UNITS_RE = re.compile(r"Units are in (\d+)-byte sectors", re.IGNORECASE)
_MMLS_LINE_RE = re.compile(
    r"^\s*(\d{3}):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$",
    re.MULTILINE,
)
_FLS_LINE_RE = re.compile(
    r"^([a-z\-]/[a-z\-])(\s+\*)?\s+([0-9]+(?:-[0-9]+-[0-9]+)?):\s*(.*)$"
)
_ISTAT_ENTRY_RE = re.compile(r"Entry:\s*(\d+)(?:\s+Sequence:\s*(\d+))?")
_ISTAT_ALLOC_RE = re.compile(r"^(Allocated|Not Allocated|Unallocated)\s+(File|Directory)", re.MULTILINE)
_ISTAT_LINKS_RE = re.compile(r"Links:\s*(\d+)")
_ATTR_LINE_RE = re.compile(
    r"Type:\s*([^\s]+)\s*\(([^)]+)\)\s+Name:\s*([^\s]+)\s+(Resident|Non-Resident)\s+size:\s*(\d+)"
)


def parse_mmls_output(
    text: str,
    *,
    actual_file_size: int | None = None,
    rpc_call_id: str = "",
) -> PartitionTable:
    """Parse output from mmls and validate that file size satisfies declared MBR geometry."""
    units_match = _MMLS_UNITS_RE.search(text)
    if not units_match:
        raise ForensicToolError(
            code="TSK_PARSE_ERROR",
            message="Could not determine sector size from mmls output.",
            rpc_call_id=rpc_call_id,
        )
    sector_size = int(units_match.group(1))

    partitions: list[PartitionEntry] = []
    max_end_sector = 0

    for match in _MMLS_LINE_RE.finditer(text):
        slot_num, slot_id, start_str, end_str, len_str, desc = match.groups()
        start = int(start_str)
        end = int(end_str)
        length = int(len_str)
        desc = desc.strip()

        is_fs = not (
            slot_id == "Meta"
            or "Unallocated" in desc
            or "Table" in desc
            or desc.lower() == "safety table"
        )

        partitions.append(
            PartitionEntry(
                slot_number=slot_num,
                slot_id=slot_id,
                start_sector=start,
                end_sector=end,
                length_sectors=length,
                description=desc,
                is_filesystem=is_fs,
            )
        )
        if end > max_end_sector:
            max_end_sector = end

    if not partitions:
        raise ForensicToolError(
            code="TSK_PARSE_ERROR",
            message="No partition entries found in mmls output.",
            rpc_call_id=rpc_call_id,
        )

    declared_size_bytes = (max_end_sector + 1) * sector_size

    if actual_file_size is not None and actual_file_size < declared_size_bytes:
        raise ForensicToolError(
            code="IMAGE_GEOMETRY_TRUNCATED",
            message=(
                f"Image file size ({actual_file_size} bytes) is smaller than the declared "
                f"partition geometry ({declared_size_bytes} bytes; last sector {max_end_sector} * "
                f"{sector_size} bytes/sector). The image is truncated or incomplete."
            ),
            rpc_call_id=rpc_call_id,
        )

    return PartitionTable(
        sector_size_bytes=sector_size,
        partitions=partitions,
        max_end_sector=max_end_sector,
        declared_size_bytes=declared_size_bytes,
    )


def parse_fls_output(
    text: str,
    *,
    dir_inode: str | None = None,
    partition_offset: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> DirectoryListing:
    """Parse fls output lines and apply deterministic limit and offset pagination."""
    if limit < 1:
        limit = 50
    if limit > 500:
        limit = 500
    if offset < 0:
        offset = 0

    all_entries: list[DirectoryEntry] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _FLS_LINE_RE.match(line)
        if not m:
            continue
        ft_raw, del_flag, inode, name = m.groups()
        is_deleted = bool(del_flag)

        if ft_raw.startswith("d/"):
            file_type = "directory"
        elif ft_raw.startswith("r/"):
            file_type = "regular_file"
        elif ft_raw.startswith("v/"):
            file_type = "virtual"
        else:
            file_type = ft_raw

        all_entries.append(
            DirectoryEntry(
                file_type=file_type,
                is_deleted=is_deleted,
                inode=inode,
                name=name.strip(),
            )
        )

    total_entries = len(all_entries)
    paged_entries = all_entries[offset : offset + limit]
    has_more = (offset + limit) < total_entries
    next_offset = (offset + limit) if has_more else None

    return DirectoryListing(
        dir_inode=dir_inode,
        partition_offset=partition_offset,
        total_entries=total_entries,
        offset=offset,
        limit=limit,
        has_more=has_more,
        next_offset=next_offset,
        entries=paged_entries,
    )


def _extract_timestamps(block: str) -> MacbTimestamps:
    """Extract MACB timestamps from a section of istat output."""
    created = re.search(r"Created:\s*([^\n]+)", block)
    f_mod = re.search(r"File Modified:\s*([^\n]+)", block)
    m_mod = re.search(r"MFT Modified:\s*([^\n]+)", block)
    acc = re.search(r"Accessed:\s*([^\n]+)", block)

    return MacbTimestamps(
        created_utc=created.group(1).strip() if created else None,
        file_modified_utc=f_mod.group(1).strip() if f_mod else None,
        mft_modified_utc=m_mod.group(1).strip() if m_mod else None,
        accessed_utc=acc.group(1).strip() if acc else None,
    )


def parse_istat_output(text: str, inode: str) -> InodeMetadata:
    """Parse istat -z UTC output into normalized InodeMetadata."""
    entry_m = _ISTAT_ENTRY_RE.search(text)
    entry_num = int(entry_m.group(1)) if entry_m else None
    sequence = int(entry_m.group(2)) if (entry_m and entry_m.group(2)) else None

    alloc_m = _ISTAT_ALLOC_RE.search(text)
    allocated = True
    is_directory = False
    if alloc_m:
        status_word, type_word = alloc_m.groups()
        allocated = not ("Not" in status_word or "Unallocated" in status_word)
        is_directory = (type_word == "Directory")

    links_m = _ISTAT_LINKS_RE.search(text)
    links = int(links_m.group(1)) if links_m else None

    # Flags
    flags: list[str] = []
    std_info_m = re.search(
        r"\$STANDARD_INFORMATION Attribute Values:\s*(.*?)(?=\n\n|\n\$|\nAttributes:|$)",
        text,
        re.DOTALL,
    )
    std_info_block = std_info_m.group(1) if std_info_m else ""
    flags_m = re.search(r"Flags:\s*([^\n]+)", std_info_block)
    if flags_m and flags_m.group(1).strip():
        flags = [f.strip() for f in flags_m.group(1).split(",") if f.strip()]

    std_times = _extract_timestamps(std_info_block) if std_info_block else None

    # $FILE_NAME blocks
    names: list[str] = []
    parent_inode: int | None = None
    alloc_size: int | None = None
    actual_size: int | None = None
    file_name_times: MacbTimestamps | None = None

    file_name_matches = list(
        re.finditer(
            r"\$FILE_NAME Attribute Values:\s*(.*?)(?=\n\n|\n\$|\nAttributes:|$)",
            text,
            re.DOTALL,
        )
    )
    for fn_match in file_name_matches:
        fn_block = fn_match.group(1)
        name_m = re.search(r"Name:\s*([^\n]+)", fn_block)
        if name_m:
            fn_name = name_m.group(1).strip()
            if fn_name not in names:
                names.append(fn_name)

        if parent_inode is None:
            p_m = re.search(r"Parent MFT Entry:\s*(\d+)", fn_block)
            if p_m:
                parent_inode = int(p_m.group(1))

        if alloc_size is None:
            as_m = re.search(r"Allocated Size:\s*(\d+)", fn_block)
            if as_m:
                alloc_size = int(as_m.group(1))

        if actual_size is None:
            ac_m = re.search(r"Actual Size:\s*(\d+)", fn_block)
            if ac_m:
                actual_size = int(ac_m.group(1))

        if file_name_times is None:
            file_name_times = _extract_timestamps(fn_block)

    # Attributes
    attributes: list[InodeAttribute] = []
    attrs_block_m = re.search(r"Attributes:\s*(.*)", text, re.DOTALL)
    if attrs_block_m:
        for attr_m in _ATTR_LINE_RE.finditer(attrs_block_m.group(1)):
            a_type, _id, a_name, a_res, a_size = attr_m.groups()
            attributes.append(
                InodeAttribute(
                    attr_type=a_type.strip(),
                    name=a_name.strip(),
                    resident=(a_res.strip() == "Resident"),
                    size_bytes=int(a_size),
                )
            )

    return InodeMetadata(
        inode=str(inode),
        entry_number=entry_num,
        sequence=sequence,
        allocated=allocated,
        is_directory=is_directory,
        links=links,
        names=names,
        flags=flags,
        allocated_size_bytes=alloc_size,
        actual_size_bytes=actual_size,
        parent_inode=parent_inode,
        standard_information_times=std_times,
        file_name_times=file_name_times,
        attributes=attributes,
    )


class TSKAdapter:
    """Adapter executing The Sleuth Kit binaries with security contracts and timeout control."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        mmls_cmd: str = "mmls",
        fls_cmd: str = "fls",
        istat_cmd: str = "istat",
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.mmls_cmd = mmls_cmd
        self.fls_cmd = fls_cmd
        self.istat_cmd = istat_cmd

    def _execute(
        self,
        cmd: str,
        args: Sequence[str],
        *,
        rpc_call_id: str = "",
    ) -> str:
        """Execute a binary with arguments list, enforcing timeout and no shell."""
        if shutil.which(cmd) is None:
            raise ForensicToolError(
                code="TSK_NOT_INSTALLED",
                message=f"The Sleuth Kit binary '{cmd}' was not found in system PATH.",
                rpc_call_id=rpc_call_id,
            )

        cmd_list = [cmd, *args]
        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            raise ForensicToolError(
                code="TSK_TIMEOUT",
                message=f"Execution of '{cmd}' timed out after {self.timeout_seconds} seconds.",
                rpc_call_id=rpc_call_id,
            ) from None
        except FileNotFoundError:
            raise ForensicToolError(
                code="TSK_NOT_INSTALLED",
                message=f"The Sleuth Kit binary '{cmd}' was not found.",
                rpc_call_id=rpc_call_id,
            ) from None
        except Exception as exc:
            raise ForensicToolError(
                code="TSK_EXECUTION_ERROR",
                message=f"Unexpected error executing '{cmd}': {exc}",
                rpc_call_id=rpc_call_id,
            ) from exc

        if proc.returncode != 0:
            err_msg = proc.stderr.strip() or f"Process exited with code {proc.returncode}"
            raise ForensicToolError(
                code="TSK_EXECUTION_ERROR",
                message=f"TSK command '{cmd}' failed: {err_msg}",
                rpc_call_id=rpc_call_id,
            )

        return proc.stdout

    def list_partitions(
        self,
        image_path: Path,
        *,
        rpc_call_id: str = "",
    ) -> PartitionTable:
        """Inspect disk image partitions with mmls and validate geometry."""
        with open_evidence_readonly(image_path, "rb", rpc_call_id=rpc_call_id) as fh:
            fh.seek(0, 2)
            actual_size = fh.tell()

        stdout = self._execute(
            self.mmls_cmd,
            [str(image_path)],
            rpc_call_id=rpc_call_id,
        )
        return parse_mmls_output(
            stdout,
            actual_file_size=actual_size,
            rpc_call_id=rpc_call_id,
        )

    def get_default_partition_offset(
        self,
        image_path: Path,
        *,
        rpc_call_id: str = "",
    ) -> int:
        """Find the start sector of the primary filesystem partition in the image."""
        pt = self.list_partitions(image_path, rpc_call_id=rpc_call_id)
        fs_partitions = [p for p in pt.partitions if p.is_filesystem]
        if not fs_partitions:
            raise ForensicToolError(
                code="NO_FILESYSTEM_PARTITION",
                message=f"No recognized filesystem partition found in '{image_path.name}'.",
                rpc_call_id=rpc_call_id,
            )
        return fs_partitions[0].start_sector

    def list_directory(
        self,
        image_path: Path,
        *,
        partition_offset: int,
        dir_inode: str | int | None = None,
        limit: int = 50,
        offset: int = 0,
        rpc_call_id: str = "",
    ) -> DirectoryListing:
        """List files and directories using fls (non-recursive) with pagination."""
        with open_evidence_readonly(image_path, "rb", rpc_call_id=rpc_call_id):
            pass

        args = ["-o", str(partition_offset), str(image_path)]
        if dir_inode is not None:
            args.append(str(dir_inode))

        stdout = self._execute(
            self.fls_cmd,
            args,
            rpc_call_id=rpc_call_id,
        )
        return parse_fls_output(
            stdout,
            dir_inode=str(dir_inode) if dir_inode is not None else None,
            partition_offset=partition_offset,
            limit=limit,
            offset=offset,
        )

    def get_inode_metadata(
        self,
        image_path: Path,
        *,
        partition_offset: int,
        inode: str | int,
        rpc_call_id: str = "",
    ) -> InodeMetadata:
        """Extract detailed metadata for an inode using istat -z UTC."""
        with open_evidence_readonly(image_path, "rb", rpc_call_id=rpc_call_id):
            pass

        args = ["-z", "UTC", "-o", str(partition_offset), str(image_path), str(inode)]
        stdout = self._execute(
            self.istat_cmd,
            args,
            rpc_call_id=rpc_call_id,
        )
        return parse_istat_output(stdout, inode=str(inode))

    def stream_bodyfile(
        self,
        image_path: Path,
        *,
        partition_offset: int,
        mount_point: str = "/",
        rpc_call_id: str = "",
    ) -> Iterator[str]:
        """Stream raw bodyfile lines from fls -m <mount_point> -o <offset> -r <image>."""
        with open_evidence_readonly(image_path, "rb", rpc_call_id=rpc_call_id):
            pass

        if shutil.which(self.fls_cmd) is None:
            raise ForensicToolError(
                code="TSK_NOT_INSTALLED",
                message=f"The Sleuth Kit binary '{self.fls_cmd}' was not found in system PATH.",
                rpc_call_id=rpc_call_id,
            )

        cmd = [
            self.fls_cmd,
            "-m",
            mount_point,
            "-o",
            str(partition_offset),
            "-r",
            str(image_path),
        ]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
        except FileNotFoundError:
            raise ForensicToolError(
                code="TSK_NOT_INSTALLED",
                message=f"The Sleuth Kit binary '{self.fls_cmd}' was not found.",
                rpc_call_id=rpc_call_id,
            ) from None
        except Exception as exc:
            raise ForensicToolError(
                code="TSK_EXECUTION_ERROR",
                message=f"Unexpected error executing '{self.fls_cmd}': {exc}",
                rpc_call_id=rpc_call_id,
            ) from exc

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                yield line
        finally:
            proc.stdout.close()
            try:
                proc.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise ForensicToolError(
                    code="TSK_TIMEOUT",
                    message=f"Execution of '{self.fls_cmd}' timed out after {self.timeout_seconds} seconds.",
                    rpc_call_id=rpc_call_id,
                )

        if proc.returncode != 0:
            err = proc.stderr.read().strip() if proc.stderr else ""
            raise ForensicToolError(
                code="TSK_EXECUTION_ERROR",
                message=f"TSK command '{self.fls_cmd}' failed with returncode {proc.returncode}: {err}",
                rpc_call_id=rpc_call_id,
            )

