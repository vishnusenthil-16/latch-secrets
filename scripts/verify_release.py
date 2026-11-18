#!/usr/bin/env python3
"""Verify a downloaded publishable bundle; never execute downloaded code."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import tarfile

from linux_release import TARGETS, archive_name, inspect_archive


def verify(bundle: Path, tag: str, repository: str, expected: Path | None = None) -> dict:
    if not re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag):
        raise ValueError("expected a stable vX.Y.Z tag")
    metadata = json.loads((bundle / "release.json").read_text())
    version = tag[1:]
    archive = f"latch-secrets-{version}.tar.gz"
    if (metadata.get("snapshot") is not False or metadata.get("tag") != tag
            or metadata.get("version") != version or metadata.get("repository") != repository
            or metadata.get("archive") != archive):
        raise ValueError("release metadata mismatch or non-publishable snapshot")
    binaries = metadata.get("binaries", {})
    if not isinstance(binaries, dict) or (binaries and set(binaries) != set(TARGETS)):
        raise ValueError("Linux release must contain exactly both supported targets")
    digests = {}
    for target, entry in binaries.items():
        name = archive_name(version, target)
        if not isinstance(entry, dict) or set(entry) != {"archive", "sha256"} or entry["archive"] != name:
            raise ValueError("Linux asset metadata mismatch")
        digest = inspect_archive(bundle / name, target, metadata)
        if entry["sha256"] != digest:
            raise ValueError("Linux archive checksum mismatch")
        digests[name] = digest
    inventory = {archive, "Formula/latch-secrets.rb", "SHA256SUMS", "release.json"}
    inventory.update(entry["archive"] for entry in binaries.values())
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if not p.is_dir()}
    if actual != inventory or any(p.is_symlink() for p in bundle.rglob("*")):
        raise ValueError("release bundle contains missing, unexpected, or symlink assets")
    for relative in (archive, "Formula/latch-secrets.rb"):
        path = bundle / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("missing or symlink release asset")
        digests[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata.get("sha256") != digests[archive]:
        raise ValueError("source checksum mismatch")
    checksums = {}
    for line in (bundle / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        if name in checksums:
            raise ValueError("duplicate checksum entry")
        checksums[name] = digest
    if checksums != digests:
        raise ValueError("release asset checksums mismatch")
    expected_url = f'https://github.com/{repository}/releases/download/{tag}/{archive}'
    formula = (bundle / "Formula/latch-secrets.rb").read_text()
    if f'  url "{expected_url}"\n' not in formula or f'  sha256 "{digests[archive]}"\n' not in formula:
        raise ValueError("formula does not reference this release")
    if expected is not None:
        source = verify(expected, tag, repository)
        if metadata.get("commit") != source.get("commit"):
            raise ValueError("release commit differs from checked-out tag")
        # Compare the deterministic tar stream, allowing gzip library differences
        # between macOS preparation and the Ubuntu publication job.
        if gzip.decompress((bundle / archive).read_bytes()) != gzip.decompress((expected / archive).read_bytes()):
            raise ValueError("source archive differs from checked-out tag")
        expected_formula = (expected / "Formula/latch-secrets.rb").read_text().replace(
            f'  sha256 "{source["sha256"]}"', f'  sha256 "{metadata["sha256"]}"', 1)
        if formula != expected_formula:
            raise ValueError("formula differs from checked-out tag template")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected", type=Path, help="bundle regenerated from a clean checkout of the exact tag")
    args = parser.parse_args()
    try:
        verify(args.bundle, args.tag, args.repository, args.expected)
    except (ValueError, OSError, KeyError, tarfile.TarError) as error:
        parser.exit(1, f"release verification failed: {error}\n")
    print("Release bundle checksums and metadata verified.")
