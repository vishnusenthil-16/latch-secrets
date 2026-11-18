#!/usr/bin/env python3
"""Add both validated Linux build artifacts to a verified source release bundle."""
import argparse
import json
from pathlib import Path
import shutil
import tarfile

from linux_release import TARGETS, archive_name, inspect_archive
from verify_release import verify


def assemble(bundle, artifacts, tag, repository):
    metadata = verify(bundle, tag, repository)
    if metadata.get("binaries"):
        raise ValueError("bundle already contains Linux binaries")
    names = {archive_name(tag[1:], target) for target in TARGETS}
    if artifacts.is_symlink() or {p.name for p in artifacts.iterdir()} != names:
        raise ValueError("expected exactly the two Linux build archives")
    binaries = {}
    for target in TARGETS:
        name = archive_name(tag[1:], target)
        digest = inspect_archive(artifacts / name, target, metadata)
        binaries[target] = dict(archive=name, sha256=digest)
    # Validate every input before changing the bundle. A failed interrupted
    # assembly is refused by verify rather than treated as publishable.
    for entry in binaries.values():
        shutil.copyfile(artifacts / entry["archive"], bundle / entry["archive"])
    metadata["binaries"] = binaries
    checksums = (bundle / "SHA256SUMS").read_text()
    checksums += "".join(f'{entry["sha256"]}  {entry["archive"]}\n' for entry in binaries.values())
    (bundle / "SHA256SUMS").write_text(checksums)
    (bundle / "release.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    verify(bundle, tag, repository)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        assemble(args.bundle, args.artifacts, args.tag, args.repository)
    except (ValueError, OSError, KeyError, tarfile.TarError) as error:
        parser.exit(1, f"release assembly failed: {error}\n")
