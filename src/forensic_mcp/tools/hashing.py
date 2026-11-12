"""Tool 1: Read-only MD5 and SHA-256 calculation and verification."""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path

from forensic_mcp.evidence import open_evidence_readonly
from forensic_mcp.models import (
    ForensicToolError,
    HashResult,
    Provenance,
    new_rpc_call_id,
    utc_now_iso,
)

_CHUNK_SIZE = 65536
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _verify_expected_hash(
    expected_hash: str,
    *,
    md5_hex: str,
    sha256_hex: str,
    rpc_call_id: str,
) -> bool:
    """Compare expected_hash (with optional 'md5:' or 'sha256:' prefix) in constant time."""
    normalized = expected_hash.strip().lower()
    if normalized.startswith("sha256:"):
        digest = normalized.removeprefix("sha256:")
        if not _SHA256_RE.match(digest):
            raise ForensicToolError("INVALID_INPUT", "Invalid SHA-256 expected_hash format.", rpc_call_id)
        return hmac.compare_digest(digest, sha256_hex)
    if normalized.startswith("md5:"):
        digest = normalized.removeprefix("md5:")
        if not _MD5_RE.match(digest):
            raise ForensicToolError("INVALID_INPUT", "Invalid MD5 expected_hash format.", rpc_call_id)
        return hmac.compare_digest(digest, md5_hex)
    if _SHA256_RE.match(normalized):
        return hmac.compare_digest(normalized, sha256_hex)
    if _MD5_RE.match(normalized):
        return hmac.compare_digest(normalized, md5_hex)
    raise ForensicToolError(
        "INVALID_INPUT",
        "expected_hash must be a valid 32-char MD5 or 64-char SHA-256 hex string.",
        rpc_call_id,
    )


def compute_file_hashes(
    path: Path,
    *,
    case_id: str,
    source_id: str,
    inodo_ruta: str | None = None,
    expected_hash: str | None = None,
    rpc_call_id: str | None = None,
) -> HashResult:
    """Stream an evidence file in read-only mode and compute MD5 and SHA-256."""
    call_id = rpc_call_id or new_rpc_call_id()
    md5_hasher = hashlib.md5()
    sha256_hasher = hashlib.sha256()
    size_bytes = 0

    with open_evidence_readonly(path, "rb", rpc_call_id=call_id) as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            size_bytes += len(chunk)
            md5_hasher.update(chunk)
            sha256_hasher.update(chunk)

    md5_hex = md5_hasher.hexdigest()
    sha256_hex = sha256_hasher.hexdigest()

    verified: bool | None = None
    if expected_hash is not None:
        verified = _verify_expected_hash(
            expected_hash,
            md5_hex=md5_hex,
            sha256_hex=sha256_hex,
            rpc_call_id=call_id,
        )

    provenance = Provenance(
        case_id=case_id,
        source_id=source_id,
        hash=f"sha256:{sha256_hex}",
        inodo_ruta=inodo_ruta or str(path),
        timestamp_utc=utc_now_iso(),
        rpc_call_id=call_id,
    )

    return HashResult(
        provenance=provenance,
        md5=md5_hex,
        sha256=sha256_hex,
        size_bytes=size_bytes,
        expected_hash=expected_hash,
        verified=verified,
    )

