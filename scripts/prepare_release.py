#!/usr/bin/env python3
"""Prepare a deterministic, local Latch source release."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tomllib


ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ("Cargo.toml", "Cargo.lock", "LICENSE", "README.md", "packaging/homebrew/latch-secrets.rb.in")
SOURCE_DIRS = ("src", "tests", "skills")
TAG_RE = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class ReleaseError(Exception):
    pass


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(["git", "-C", str(ROOT), *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if check and result.returncode:
        raise ReleaseError(f"git {args[0]} failed: {result.stderr.decode(errors='replace').strip()}")
    return result


def validate_paths(output: Path) -> None:
    if not ROOT.is_dir() or ROOT.is_symlink():
        raise ReleaseError("source root must be a real directory")
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise ReleaseError("output must be a new or empty directory, not a symlink")
    if output == ROOT or output.is_relative_to(ROOT / ".git") or any(output == ROOT / d or output.is_relative_to(ROOT / d) for d in SOURCE_DIRS):
        raise ReleaseError("output cannot be inside a source directory")
    for parent in output.parents:
        if parent.is_symlink():
            raise ReleaseError("output path cannot pass through a symlink")


def allowed(rel: Path) -> bool:
    if rel.as_posix() in REQUIRED:
        return True
    if len(rel.parts) < 2 or any(part.startswith(".") for part in rel.parts):
        return False
    if rel.parts[0] in ("src", "tests"):
        return rel.suffix == ".rs"
    return rel.parts[:2] == ("skills", "latch") and rel.suffix == ".md"


def source_files(snapshot: bool) -> list[Path]:
    """Collect selected files; tagged releases draw paths from Git's index."""
    if snapshot:
        paths = [Path(p) for p in REQUIRED]
        for source in SOURCE_DIRS:
            paths.extend(p.relative_to(ROOT) for p in (ROOT / source).rglob("*")
                         if p.is_file() or p.is_symlink())
    else:
        paths = [Path(p.decode()) for p in git("ls-files", "-z").stdout.split(b"\0") if p]
    selected = sorted({p for p in paths if allowed(p)}, key=lambda p: p.as_posix())
    missing = [p for p in REQUIRED if Path(p) not in selected]
    missing += [p for p in SOURCE_DIRS if not (ROOT / p).is_dir() or (ROOT / p).is_symlink()]
    if missing:
        raise ReleaseError("missing release inputs: " + ", ".join(missing))
    for rel in selected:
        for ancestor in (rel, *rel.parents):
            if ancestor == Path("."):
                continue
            if (ROOT / ancestor).is_symlink():
                raise ReleaseError(f"symlink in source tree: {ancestor}")
        if not (ROOT / rel).is_file():
            raise ReleaseError(f"source is not a regular file: {rel}")
    return [p for p in selected if p.as_posix() != REQUIRED[-1]]


def archive_bytes(files: list[Path], version: str) -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            dirs = {Path(f"latch-secrets-{version}")}
            for rel in files:
                dirs.update(Path(f"latch-secrets-{version}", *rel.parts[:n]) for n in range(1, len(rel.parts)))
            for directory in sorted(dirs, key=lambda p: (len(p.parts), p.as_posix())):
                info = tarfile.TarInfo(directory.as_posix() + "/")
                info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, 0
                info.uid = info.gid = 0
                tar.addfile(info)
            for rel in files:
                data = (ROOT / rel).read_bytes()
                info = tarfile.TarInfo(f"latch-secrets-{version}/{rel.as_posix()}")
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                info.uid = info.gid = 0
                tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def prepare(tag: str, repository: str, output: Path, snapshot: bool) -> None:
    match = TAG_RE.fullmatch(tag)
    if not match or not REPO_RE.fullmatch(repository) or any(part in (".", "..") for part in repository.split("/")):
        raise ReleaseError("tag must be vX.Y.Z and repository must be owner/repo")
    version = tag[1:]
    # macOS commonly aliases /var to /private/var; compare canonical parents.
    # Reject the leaf symlink before resolving it.
    if output.is_symlink():
        raise ReleaseError("output must be a new or empty directory, not a symlink")
    output = output.absolute().parent.resolve() / output.name
    validate_paths(output)
    if git("rev-parse", "--show-toplevel").stdout.strip().decode() != str(ROOT):
        raise ReleaseError("source root is not the Git worktree root")
    commit = git("rev-parse", "HEAD").stdout.strip().decode()
    if not snapshot:
        if git("status", "--porcelain=v1", "--untracked-files=all").stdout:
            raise ReleaseError("release requires a clean Git worktree, including untracked files")
        ref = git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}", check=False)
        if ref.returncode or ref.stdout.strip().decode() != commit:
            raise ReleaseError(f"HEAD must equal the existing {tag} tag commit")
    files = source_files(snapshot)
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    if package["name"] != "latch-secrets" or package["version"] != version:
        raise ReleaseError("Cargo.toml package name/version does not match release tag")
    archive_name = f"latch-secrets-{version}.tar.gz"
    archive = archive_bytes(files, version)
    digest = hashlib.sha256(archive).hexdigest()
    template = (ROOT / REQUIRED[-1]).read_text()
    formula = (template.replace("@VERSION@", version)
               .replace("@REPOSITORY@", repository)
               .replace("@SHA256@", digest))
    if re.search(r"@[A-Z_]+@", formula):
        raise ReleaseError("unresolved formula placeholder")
    formula_bytes = formula.encode()
    output.mkdir(parents=True, exist_ok=True)
    (output / archive_name).write_bytes(archive)
    (output / "Formula").mkdir()
    (output / "Formula/latch-secrets.rb").write_bytes(formula_bytes)
    checksums = (f"{digest}  {archive_name}\n"
                 f"{hashlib.sha256(formula_bytes).hexdigest()}  Formula/latch-secrets.rb\n")
    (output / "SHA256SUMS").write_text(checksums)
    manifest = {"repository": repository, "tag": tag, "version": version,
                "commit": commit, "snapshot": snapshot, "archive": archive_name, "sha256": digest}
    (output / "release.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--snapshot", action="store_true", help="local testing only; permit dirty tree and missing tag")
    args = parser.parse_args()
    try:
        prepare(args.tag, args.repository, args.output, args.snapshot)
    except (ReleaseError, OSError, KeyError, ValueError, tarfile.TarError,
            tomllib.TOMLDecodeError) as error:
        print(f"prepare_release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
