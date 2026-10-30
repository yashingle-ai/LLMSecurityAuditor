"""Turn scope input entries (files, directories, glob patterns) into file lists."""

import glob
import os
from collections.abc import Iterator
from pathlib import Path

EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
        "dist",
        "build",
    }
)


def discover(root: Path, entry: str, extensions: frozenset[str]) -> list[Path]:
    """The files an input entry refers to.

    A file is taken as is. A directory is walked for files with ``extensions``,
    skipping dependency and cache directories and never following symlinks.
    Anything else is a glob pattern (``**`` allowed), relative to ``root``
    unless absolute.
    """
    path = root / entry
    if path.is_file():
        return [path]
    if path.is_dir():
        return list(_walk(path, extensions))
    files: list[Path] = []
    for match in sorted(glob.glob(entry, root_dir=root, recursive=True)):
        candidate = root / match
        if candidate.is_file():
            files.append(candidate)
        elif candidate.is_dir():
            files.extend(_walk(candidate, extensions))
    return files


def relative_path(file: Path, root: Path) -> str:
    """POSIX path relative to ``root``, or absolute if the file lies outside it."""
    resolved = file.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _walk(directory: Path, extensions: frozenset[str]) -> Iterator[Path]:
    for current, subdirs, names in os.walk(directory):
        subdirs[:] = sorted(d for d in subdirs if d not in EXCLUDED_DIRS)
        for name in sorted(names):
            file = Path(current) / name
            if file.suffix.lower() in extensions and not file.is_symlink():
                yield file
