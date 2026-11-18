#!/usr/bin/env python3
"""Package an already tested Linux binary from the checked-out release tag."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

import prepare_release
from linux_release import TARGETS, archive_name, check_elf, tar_bytes


def package(binary, target, tag, repository, output):
    if not prepare_release.TAG_RE.fullmatch(tag) or not prepare_release.REPO_RE.fullmatch(repository):
        raise ValueError("invalid tag or repository")
    root = prepare_release.ROOT
    if output.is_symlink():
        raise ValueError("output cannot be a symlink")
    output = output.absolute().parent.resolve() / output.name
    prepare_release.validate_paths(output)
    commit = prepare_release.git("rev-parse", "HEAD").stdout.decode().strip()
    tagged = prepare_release.git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}").stdout.decode().strip()
    if commit != tagged or prepare_release.git("status", "--porcelain=v1", "--untracked-files=all").stdout:
        raise ValueError("Linux packaging requires a clean checkout of the release tag")
    if tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"] != tag[1:]:
        raise ValueError("package version differs from tag")
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("binary must be a regular file")
    data = binary.read_bytes()
    check_elf(data, target)
    metadata = dict(commit=commit, tag=tag, repository=repository, target=target,
                    binary_sha256=hashlib.sha256(data).hexdigest())
    contents = {"latch": data, "LICENSE": (root / "LICENSE").read_bytes(),
                "README.md": (root / "packaging/linux/README.md").read_bytes(),
                "SKILL.md": (root / "skills/latch/SKILL.md").read_bytes(),
                "build.json": (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode()}
    output.mkdir(parents=True, exist_ok=True)
    (output / archive_name(tag[1:], target)).write_bytes(tar_bytes(contents))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        package(args.binary, args.target, args.tag, args.repository, args.output)
    except (ValueError, OSError, prepare_release.ReleaseError) as error:
        parser.exit(1, f"Linux packaging failed: {error}\n")
