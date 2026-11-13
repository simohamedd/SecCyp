"""File Integrity Monitor (FIM) — a minimal host-based tripwire.

Records a cryptographic baseline of a directory tree, then reports any file
that has since been created, modified, or deleted. Standard library only.

A FIM is a core blue-team control: if an attacker drops a web shell, tampers
with a binary, or alters a config file, the hash changes and the FIM notices —
even if the file's size and timestamp were forged to look unchanged.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


DEFAULT_IGNORE = ("*.pyc", "__pycache__/*", ".git/*", "*.baseline.json")


@dataclass
class Changes:
    """The diff between a baseline and the current state of a tree."""

    created: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.created or self.modified or self.deleted)

    def as_dict(self) -> dict[str, list[str]]:
        return {"created": self.created, "modified": self.modified, "deleted": self.deleted}


def hash_file(path: Path, *, chunk_size: int = 65536) -> str:
    """Return the SHA-256 hex digest of a file, read in chunks.

    Chunked reading keeps memory flat regardless of file size, so the monitor
    works on large files (logs, databases) without loading them whole.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _should_ignore(rel_path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(rel_path, pattern) for pattern in patterns)


def scan_tree(root: Path, *, ignore: Iterable[str] = DEFAULT_IGNORE) -> dict[str, str]:
    """Walk ``root`` and return a map of ``relative_path -> sha256``.

    Paths are stored relative to ``root`` and with forward slashes, so a
    baseline is portable across machines and operating systems.
    """
    root = root.resolve()
    patterns = tuple(ignore)
    result: dict[str, str] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            abs_path = Path(dirpath) / name
            rel = abs_path.relative_to(root).as_posix()
            if _should_ignore(rel, patterns):
                continue
            try:
                result[rel] = hash_file(abs_path)
            except (OSError, PermissionError):
                # Unreadable file (e.g. a socket or no permission) — record a
                # sentinel so its disappearance is still noticed later.
                result[rel] = "UNREADABLE"
    return result


def save_baseline(baseline: dict[str, str], path: Path, *, root: Path) -> None:
    """Persist a baseline to JSON, tagged with the root it was taken from."""
    payload = {"root": str(root.resolve()), "files": baseline}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_baseline(path: Path) -> dict[str, str]:
    """Load the ``path -> hash`` map from a saved baseline file."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["files"]


def diff(baseline: dict[str, str], current: dict[str, str]) -> Changes:
    """Compare a saved baseline against a fresh scan."""
    changes = Changes()
    for rel, digest in current.items():
        if rel not in baseline:
            changes.created.append(rel)
        elif baseline[rel] != digest:
            changes.modified.append(rel)
    for rel in baseline:
        if rel not in current:
            changes.deleted.append(rel)
    changes.created.sort()
    changes.modified.sort()
    changes.deleted.sort()
    return changes
