#!/usr/bin/env python3
"""Verify the pinned official Linux bw artifact; execute only --version in an isolated home."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import urllib.request
import zipfile

from linux_release import TARGETS, check_elf

VERSION = "2026.8.0"
ASSETS = {
    "x86_64-unknown-linux-gnu": ("bw-linux-2026.8.0.zip", "367f618e9fcccaac4980ec12c7bafd01df739b5f3cb1af31bc9045cf75eea1d6"),
    "aarch64-unknown-linux-gnu": ("bw-linux-arm64-2026.8.0.zip", "74d822a5dceda5896ed8fc07bc61925b29afd98d96a6a3e9e525ae556c3083a8"),
}


def check(target, download_only=False):
    name, expected = ASSETS[target]
    with tempfile.TemporaryDirectory(prefix="latch-bw-preflight-") as temporary:
        root = Path(temporary)
        archive = root / name
        url = f"https://github.com/bitwarden/clients/releases/download/cli-v{VERSION}/{name}"
        with urllib.request.urlopen(url, timeout=60) as source, archive.open("wb") as output:
            total = 0
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > 128 * 1024 * 1024:
                    raise ValueError("oversized bw download")
                output.write(chunk)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise ValueError("pinned bw artifact checksum mismatch")
        with zipfile.ZipFile(archive) as compressed:
            if compressed.namelist() != ["bw"] or compressed.getinfo("bw").file_size > 256 * 1024 * 1024:
                raise ValueError("unexpected bw archive contents")
            binary = compressed.read("bw")
        check_elf(binary, target)
        if not download_only:
            machine = {"x86_64": "x86_64-unknown-linux-gnu", "aarch64": "aarch64-unknown-linux-gnu"}.get(platform.machine())
            if platform.system() != "Linux" or machine != target:
                raise ValueError("runtime preflight requires native matching Linux architecture")
            executable = root / "bw"
            executable.write_bytes(binary)
            executable.chmod(0o700)
            home = root / "home"
            home.mkdir(mode=0o700)
            env = {"PATH": os.defpath, "HOME": str(home), "BITWARDENCLI_APPDATA_DIR": str(home / "bw")}
            result = subprocess.run([str(executable), "--version"], env=env, capture_output=True, text=True, timeout=30)
            if result.returncode or result.stdout.strip() != VERSION:
                raise ValueError("pinned bw version failed on this runtime")
        print(f"{target}: official bw {VERSION} SHA256 and ELF verified" + ("; runtime not tested" if download_only else "; native --version passed"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args()
    check(args.target, args.download_only)
