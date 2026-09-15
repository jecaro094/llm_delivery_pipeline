"""Tests for tar packaging and safe unpacking of a model snapshot directory."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from model_pipeline import packaging


def test_pack_unpack_round_trip_preserves_file_contents(
    fake_model_dir: Path, tmp_path: Path
) -> None:
    """Every file packed from the source directory must exist, unchanged, after unpacking."""
    archive = packaging.pack_directory(fake_model_dir)

    destination = tmp_path / "restored"
    packaging.unpack_archive(archive, destination)

    for relative_path in ["config.json", "pytorch_model.bin", "tokenizer/vocab.txt"]:
        original = (fake_model_dir / relative_path).read_bytes()
        restored = (destination / relative_path).read_bytes()
        assert restored == original


def test_unpack_rejects_parent_directory_traversal(tmp_path: Path) -> None:
    """A tar member whose name contains `..` must be rejected instead of escaping destination."""
    archive = _build_malicious_tar(name="../escaped.txt", content=b"pwned")
    destination = tmp_path / "safe-dest"

    with pytest.raises(packaging.PackagingError):
        packaging.unpack_archive(archive, destination)

    assert not (tmp_path / "escaped.txt").exists()


def test_unpack_rejects_absolute_path_member(tmp_path: Path) -> None:
    """A tar member with an absolute path name must be rejected."""
    archive = _build_malicious_tar(name="/etc/evil.txt", content=b"pwned")
    destination = tmp_path / "safe-dest"

    with pytest.raises(packaging.PackagingError):
        packaging.unpack_archive(archive, destination)


def test_unpack_rejects_absolute_symlink(tmp_path: Path) -> None:
    """A symlink member pointing at an absolute path outside destination must be rejected."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        symlink_info = tarfile.TarInfo(name="link")
        symlink_info.type = tarfile.SYMTYPE
        symlink_info.linkname = "/etc/passwd"
        tar.addfile(symlink_info)
    archive = buffer.getvalue()

    destination = tmp_path / "safe-dest"
    with pytest.raises(packaging.PackagingError):
        packaging.unpack_archive(archive, destination)


def test_unpack_rejects_symlink_escaping_destination_via_relative_path(tmp_path: Path) -> None:
    """A symlink member using `..` in its relative target must also be rejected."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        symlink_info = tarfile.TarInfo(name="link")
        symlink_info.type = tarfile.SYMTYPE
        symlink_info.linkname = "../../../etc/passwd"
        tar.addfile(symlink_info)
    archive = buffer.getvalue()

    destination = tmp_path / "safe-dest"
    with pytest.raises(packaging.PackagingError):
        packaging.unpack_archive(archive, destination)


def _build_malicious_tar(*, name: str, content: bytes) -> bytes:
    """Build an in-memory tar archive containing a single member with an arbitrary raw name."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()
