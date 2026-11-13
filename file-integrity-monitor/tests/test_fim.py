"""Unit tests for the file integrity monitor.

Uses pytest's ``tmp_path`` fixture so every test runs against a throwaway
directory — no mocking of the filesystem needed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.fim import (  # noqa: E402
    diff,
    hash_file,
    load_baseline,
    save_baseline,
    scan_tree,
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_hash_file_is_stable_and_content_sensitive(tmp_path):
    f = tmp_path / "a.txt"
    _write(f, "hello")
    first = hash_file(f)
    assert first == hash_file(f)
    _write(f, "hello!")
    assert hash_file(f) != first


def test_scan_tree_relative_paths(tmp_path):
    _write(tmp_path / "top.txt", "x")
    _write(tmp_path / "sub" / "nested.txt", "y")
    scan = scan_tree(tmp_path)
    assert set(scan) == {"top.txt", "sub/nested.txt"}


def test_scan_tree_honours_ignore(tmp_path):
    _write(tmp_path / "keep.txt", "x")
    _write(tmp_path / "junk.pyc", "y")
    scan = scan_tree(tmp_path)  # default ignore excludes *.pyc
    assert "keep.txt" in scan
    assert "junk.pyc" not in scan


def test_diff_detects_created(tmp_path):
    _write(tmp_path / "a.txt", "1")
    base = scan_tree(tmp_path)
    _write(tmp_path / "b.txt", "2")
    changes = diff(base, scan_tree(tmp_path))
    assert changes.created == ["b.txt"]
    assert not changes.modified and not changes.deleted


def test_diff_detects_modified(tmp_path):
    f = tmp_path / "a.txt"
    _write(f, "1")
    base = scan_tree(tmp_path)
    _write(f, "2")
    changes = diff(base, scan_tree(tmp_path))
    assert changes.modified == ["a.txt"]


def test_diff_detects_deleted(tmp_path):
    f = tmp_path / "a.txt"
    _write(f, "1")
    base = scan_tree(tmp_path)
    f.unlink()
    changes = diff(base, scan_tree(tmp_path))
    assert changes.deleted == ["a.txt"]


def test_clean_when_unchanged(tmp_path):
    _write(tmp_path / "a.txt", "1")
    base = scan_tree(tmp_path)
    assert diff(base, scan_tree(tmp_path)).clean


def test_baseline_round_trip(tmp_path):
    _write(tmp_path / "a.txt", "1")
    base = scan_tree(tmp_path)
    out = tmp_path / "saved.baseline.json"
    save_baseline(base, out, root=tmp_path)
    assert load_baseline(out) == base
