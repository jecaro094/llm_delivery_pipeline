"""Safe tar packaging and unpacking of a model snapshot directory.

A model snapshot is a directory of files (config, weights, tokenizer, ...)
that gets packed into a single uncompressed tar archive before encryption,
so that the whole model is one opaque artifact instead of many individually
named files. Unpacking validates every archive member against path
traversal and symlink escapes (tar-slip) before writing anything to disk,
since the archive comes from a source that has already been decrypted but
is not otherwise trusted.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path


class PackagingError(Exception):
    """Raised when an archive member fails path-safety validation during extraction."""


def pack_directory(source_dir: Path) -> bytes:
    """Pack every regular file under source_dir into an uncompressed in-memory tar archive."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                tar.add(path, arcname=path.relative_to(source_dir).as_posix())
    return buffer.getvalue()


def unpack_archive(data: bytes, destination_dir: Path) -> None:
    """Safely extract a tar archive produced by :func:`pack_directory` into destination_dir.

    Every member is validated before extraction: absolute paths, `..`
    traversal, and symlinks/hardlinks whose target would resolve outside
    destination_dir are all rejected with :class:`PackagingError` instead of
    being extracted. A malformed archive or a filesystem failure while
    extracting also raises :class:`PackagingError`, instead of a raw
    ``tarfile.TarError``/``OSError``, so callers only ever need to catch
    one exception type at this boundary.
    """
    destination_dir.mkdir(parents=True, exist_ok=True)
    resolved_destination = destination_dir.resolve()
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            members = tar.getmembers()
            for member in members:
                _validate_member(member, resolved_destination)
            tar.extractall(destination_dir, members=members, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise PackagingError(f"could not extract the archive: {exc}") from exc


def _validate_member(member: tarfile.TarInfo, resolved_destination: Path) -> None:
    """Raise PackagingError if extracting member could escape resolved_destination."""
    if member.isdev():
        raise PackagingError(f"refusing to extract device file: {member.name}")

    member_path = Path(member.name)
    if member_path.is_absolute():
        raise PackagingError(f"refusing to extract absolute path: {member.name}")

    target_path = (resolved_destination / member_path).resolve()
    if not _is_within(target_path, resolved_destination):
        raise PackagingError(f"refusing to extract path outside destination: {member.name}")

    if member.issym() or member.islnk():
        _validate_link_target(member, target_path, resolved_destination)


def _validate_link_target(
    member: tarfile.TarInfo, target_path: Path, resolved_destination: Path
) -> None:
    """Raise PackagingError if a symlink/hardlink member's target would escape the destination."""
    link_name = Path(member.linkname)
    link_target = link_name if link_name.is_absolute() else target_path.parent / link_name
    if not _is_within(link_target.resolve(), resolved_destination):
        raise PackagingError(f"refusing to extract link escaping destination: {member.name}")


def _is_within(path: Path, root: Path) -> bool:
    """Return True if path is root itself or a descendant of root."""
    return path == root or root in path.parents
