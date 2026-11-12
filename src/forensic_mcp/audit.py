"""Append-only JSONL audit logger (metadata only, never evidence contents)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from forensic_mcp.models import utc_now_iso


class AuditRecord(BaseModel):
    """Single immutable audit entry written to the append-only JSONL log."""

    model_config = ConfigDict(frozen=True)

    timestamp_utc: str
    rpc_call_id: str
    tool: str
    params: dict[str, Any]
    status: Literal["ok", "error"]
    outcome: dict[str, Any]


class AuditLogger:
    """Append-only JSONL audit logger isolated from the evidence directory."""

    def __init__(self, log_path: Path, *, evidence_root: Path | None = None) -> None:
        resolved_log = log_path.resolve()
        if evidence_root is not None:
            resolved_root = evidence_root.resolve()
            if resolved_log.is_relative_to(resolved_root):
                raise ValueError(
                    f"Audit log path {resolved_log} must be outside evidence_root {resolved_root}."
                )
        self.log_path = resolved_log

    def log(
        self,
        *,
        rpc_call_id: str,
        tool: str,
        params: dict[str, Any],
        status: Literal["ok", "error"],
        outcome: dict[str, Any],
    ) -> AuditRecord:
        """Append one metadata-only JSONL record and flush immediately."""
        record = AuditRecord(
            timestamp_utc=utc_now_iso(),
            rpc_call_id=rpc_call_id,
            tool=tool,
            params=params,
            status=status,
            outcome=outcome,
        )
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")
            fh.flush()
        return record

