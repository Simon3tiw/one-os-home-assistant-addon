#!/usr/bin/env python3
"""Build the ONE.OS Edge add-on bundle with deterministic metadata."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import tarfile
from pathlib import Path

EXCLUDED_DIRECTORIES = {
    Path("one_os_edge/frontend/node_modules"),
    Path("one_os_edge/frontend/dist"),
    Path("one_os_edge/frontend/test-results"),
    Path("one_os_edge/backend/.venv"),
}


def _excluded(relative: Path) -> bool:
    return (
        any(relative == root or root in relative.parents for root in EXCLUDED_DIRECTORIES)
        or "__pycache__" in relative.parts
        or relative.suffix == ".pyc"
    )


def _mode(relative: Path, *, directory: bool) -> int:
    if directory:
        return 0o755
    if (
        len(relative.parts) >= 2
        and relative.parts[0] == "one_os_edge"
        and "services.d" in relative.parts
        and relative.name == "run"
    ):
        return 0o755
    return 0o644


def _members(repository: Path) -> list[tuple[Path, Path]]:
    members: list[tuple[Path, Path]] = []
    for relative_root in (Path("one_os_edge"), Path("README.md")):
        root = repository / relative_root
        if not root.exists():
            raise RuntimeError(f"required bundle input is missing: {relative_root}")
        candidates = [root]
        if root.is_dir():
            candidates.extend(sorted(root.rglob("*"), key=lambda path: path.as_posix()))
        for path in candidates:
            relative = path.relative_to(repository)
            if _excluded(relative):
                continue
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise RuntimeError(f"unsupported bundle input type: {relative}")
            members.append((relative, path))
    return sorted(members, key=lambda item: item[0].as_posix())


def build(repository: Path, destination: Path) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    for relative, path in _members(repository):
                        info = tarfile.TarInfo(relative.as_posix())
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        info.mtime = 0
                        info.mode = _mode(relative, directory=path.is_dir())
                        if path.is_dir():
                            info.type = tarfile.DIRTYPE
                            archive.addfile(info)
                        else:
                            info.size = path.stat().st_size
                            with path.open("rb") as source:
                                archive.addfile(info, source)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)

    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    checksum = destination.with_name(f"{destination.name}.sha256")
    checksum.write_text(f"{digest}  {destination.name}\n", encoding="utf-8")
    return digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("repository", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(build(args.repository.resolve(), args.destination.resolve()))


if __name__ == "__main__":
    main()
