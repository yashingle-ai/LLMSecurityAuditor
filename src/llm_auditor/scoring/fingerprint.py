"""Stable fingerprints that match the same issue across audit runs."""

import hashlib
import re
from pathlib import PurePosixPath

from llm_auditor.models import Location

_WHITESPACE = re.compile(r"\s+")


def fingerprint(check_id: str, location: Location, evidence: str) -> str:
    """Hash what identifies an issue, ignoring what shifts between runs.

    Line numbers and whitespace are left out, so editing code above a finding,
    or reformatting it, keeps the same fingerprint.
    """
    parts = (
        check_id,
        _normalize_path(location.file),
        location.artifact or "",
        _WHITESPACE.sub(" ", evidence).strip(),
    )
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:32]


def _normalize_path(path: str | None) -> str:
    if path is None:
        return ""
    return PurePosixPath(path.replace("\\", "/")).as_posix()
