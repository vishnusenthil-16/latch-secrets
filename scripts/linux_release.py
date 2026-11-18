"""Shared Linux artifact contracts. Validation never executes downloaded binaries."""
import hashlib
import io
import json
import tarfile

TARGETS = {"x86_64-unknown-linux-gnu": 62, "aarch64-unknown-linux-gnu": 183}
MAX_BINARY = 128 * 1024 * 1024
MEMBERS = {"latch", "LICENSE", "README.md", "SKILL.md", "build.json"}


def archive_name(version, target):
    if target not in TARGETS:
        raise ValueError("unsupported Linux target")
    return f"latch-secrets-{version}-{target}.tar.gz"


def check_elf(data, target):
    if (target not in TARGETS or len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(data[18:20], "little") != TARGETS[target]
            or int.from_bytes(data[16:18], "little") not in (2, 3)):
        raise ValueError("binary is not a matching 64-bit little-endian Linux ELF executable")


def inspect_archive(path, target, metadata):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BINARY:
        raise ValueError("missing, symlink, or oversized Linux archive")
    with tarfile.open(path, "r:gz") as tar:
        members = []
        total = 0
        for member in tar:
            members.append(member)
            if len(members) > len(MEMBERS) or member.name not in MEMBERS:
                raise ValueError("Linux archive member inventory mismatch")
            if not member.isfile() or member.size < 0:
                raise ValueError("Linux archive contains unsafe members")
            total += member.size
            if total > MAX_BINARY:
                raise ValueError("Linux archive is oversized")
        if len(members) != len(MEMBERS) or {m.name for m in members} != MEMBERS:
            raise ValueError("Linux archive member inventory mismatch")
        if any(m.mode != (0o755 if m.name == "latch" else 0o644) for m in members):
            raise ValueError("Linux archive permissions mismatch")
        binary = tar.extractfile("latch").read()
        check_elf(binary, target)
        build = json.load(tar.extractfile("build.json"))
        expected = {key: metadata[key] for key in ("commit", "tag", "repository")}
        expected.update(target=target, binary_sha256=hashlib.sha256(binary).hexdigest())
        if build != expected:
            raise ValueError("Linux binary provenance mismatch")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tar_bytes(contents):
    import gzip
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data in sorted(contents.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if name == "latch" else 0o644
                tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()
