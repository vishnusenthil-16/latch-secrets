#!/usr/bin/env python3
"""Publish a stable release once; accept only byte-identical assets on retry."""

import argparse
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from verify_release import verify


def gh(*args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["gh", *args], text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"gh {args[0]} failed: {result.stderr.strip()}")
    return result


def find_release(repository: str, tag: str) -> dict | None:
    # The by-tag endpoint covers published releases only. The authenticated list
    # includes drafts for a token with push access, even on later pages.
    pages = json.loads(gh("api", "--paginate", "--slurp",
                          f"repos/{repository}/releases?per_page=100").stdout)
    matches = [release for page in pages for release in page if release["tag_name"] == tag]
    if len(matches) > 1:
        raise ValueError("multiple releases use the same tag")
    return matches[0] if matches else None


def publish(bundle: Path, tag: str, repository: str) -> None:
    verify(bundle, tag, repository)
    names = (f"latch-secrets-{tag[1:]}.tar.gz", "latch-secrets.rb", "SHA256SUMS", "release.json")
    paths = (bundle / names[0], bundle / "Formula/latch-secrets.rb", bundle / names[2], bundle / names[3])
    release = find_release(repository, tag)
    if release is None:
        gh("release", "create", tag, "--repo", repository, "--verify-tag", "--draft",
           "--title", f"Latch {tag}", "--notes", "macOS source release with Homebrew formula.")
        release = find_release(repository, tag)
        if release is None:
            raise ValueError("created draft was not found in release list")
    if release["prerelease"]:
        raise ValueError("existing release is prerelease")

    def compare_existing(assets: list[dict]) -> set[str]:
        actual = [asset["name"] for asset in assets]
        if len(actual) != len(set(actual)) or not set(actual) <= set(names):
            raise ValueError("existing release has duplicate or unexpected assets")
        if actual:
            with TemporaryDirectory(prefix="latch-release-check-") as directory:
                gh("release", "download", tag, "--repo", repository, "--dir", directory,
                   *(part for name in actual for part in ("--pattern", name)))
                for name, path in zip(names, paths):
                    if name in actual and (Path(directory) / name).read_bytes() != path.read_bytes():
                        raise ValueError(f"existing release asset differs: {name}")
        return set(actual)

    present = compare_existing(release["assets"])
    missing = [path for name, path in zip(names, paths) if name not in present]
    if missing:
        gh("release", "upload", tag, "--repo", repository, *(str(path) for path in missing))
        release = find_release(repository, tag)
        if release is None:
            raise ValueError("release disappeared after asset upload")
        if release["prerelease"] or compare_existing(release["assets"]) != set(names):
            raise ValueError("release assets changed or remain incomplete after upload")
    if release["draft"]:
        gh("release", "edit", tag, "--repo", repository, "--draft=false")
        release = find_release(repository, tag)
        if release is None:
            raise ValueError("release disappeared after publication")
        if release["draft"] or release["prerelease"] or compare_existing(release["assets"]) != set(names):
            raise ValueError("release failed final published-state verification")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        publish(args.bundle, args.tag, args.repository)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        parser.exit(1, f"release publication failed: {error}\n")
    print("Stable release assets published and verified.")
