#!/usr/bin/env python3
"""Update the checked-out tap's default branch with a verified formula."""

import argparse
from pathlib import Path
import re
import subprocess


VERSION_RE = re.compile(r"/releases/download/v(\d+)\.(\d+)\.(\d+)/latch-secrets-\1\.\2\.\3\.tar\.gz")


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"git {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def version(formula: bytes) -> tuple[int, int, int]:
    match = VERSION_RE.search(formula.decode())
    if not match:
        raise ValueError("formula has no stable Latch release URL")
    return tuple(map(int, match.groups()))


def update(formula_path: Path, tag: str) -> None:
    if not re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag):
        raise ValueError("expected stable release tag")
    branch = git("branch", "--show-current")
    if not branch or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("tap checkout must be on a clean branch")
    incoming = formula_path.read_bytes()
    incoming_version = version(incoming)
    if incoming_version != tuple(map(int, tag[1:].split("."))):
        raise ValueError("formula version differs from release tag")
    target = Path("Formula/latch-secrets.rb")
    if target.exists():
        current = target.read_bytes()
        current_version = version(current)
        if current_version > incoming_version:
            raise ValueError("tap already contains a newer release")
        if current_version == incoming_version:
            if current != incoming:
                raise ValueError("tap formula for this version differs from verified release")
            return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(incoming)
    git("add", "--", str(target))
    git("-c", "user.name=github-actions[bot]", "-c",
        "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit", "-m", f"Update latch-secrets to {tag}")
    git("push", "origin", f"HEAD:{branch}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--formula", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        update(args.formula, args.tag)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"tap update failed: {error}\n")
    print("Verified formula is current in the tap.")
