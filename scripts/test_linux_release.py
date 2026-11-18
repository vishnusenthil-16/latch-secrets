"""Linux archives are target-specific, source-bound, safe, and immutable on retry."""
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from assemble_release import assemble
from linux_release import TARGETS, archive_name, check_elf, inspect_archive, tar_bytes
from verify_release import verify
import package_linux
import prepare_release
import publish_release
from test_publish_release import FakeGitHub


def elf(target):
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    data[16:18] = (3).to_bytes(2, "little")
    data[18:20] = TARGETS[target].to_bytes(2, "little")
    return bytes(data)


class LinuxReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "bundle"
        (self.bundle / "Formula").mkdir(parents=True)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.meta = dict(repository="owner/repo", tag="v0.1.0", version="0.1.0",
                         archive="latch-secrets-0.1.0.tar.gz", snapshot=False, commit="a" * 40)
        source = b"synthetic source"
        self.meta["sha256"] = hashlib.sha256(source).hexdigest()
        formula = f'  url "https://github.com/owner/repo/releases/download/v0.1.0/{self.meta["archive"]}"\n  sha256 "{self.meta["sha256"]}"\n'
        (self.bundle / self.meta["archive"]).write_bytes(source)
        (self.bundle / "Formula/latch-secrets.rb").write_text(formula)
        (self.bundle / "release.json").write_text(json.dumps(self.meta))
        (self.bundle / "SHA256SUMS").write_text(f'{self.meta["sha256"]}  {self.meta["archive"]}\n{hashlib.sha256(formula.encode()).hexdigest()}  Formula/latch-secrets.rb\n')
        for target in TARGETS:
            self.write_archive(target)

    def contents(self, target):
        binary = elf(target)
        build = {key: self.meta[key] for key in ("commit", "tag", "repository")}
        build.update(target=target, binary_sha256=hashlib.sha256(binary).hexdigest())
        return dict(latch=binary, LICENSE=b"license", **{"README.md": b"readme", "SKILL.md": b"skill", "build.json": json.dumps(build).encode()})

    def write_archive(self, target, contents=None):
        path = self.artifacts / archive_name("0.1.0", target)
        path.write_bytes(tar_bytes(contents or self.contents(target)))
        return path

    def assemble(self):
        assemble(self.bundle, self.artifacts, "v0.1.0", "owner/repo")


    def test_package_requires_clean_tag_and_matching_binary(self):
        project = self.root / "project"
        (project / "packaging/linux").mkdir(parents=True)
        (project / "skills/latch").mkdir(parents=True)
        for name, text in {"LICENSE": "license", "packaging/linux/README.md": "readme",
                           "skills/latch/SKILL.md": "skill", "Cargo.toml": '[package]\nversion="0.1.0"\n'}.items():
            (project / name).write_text(text)
        target = "aarch64-unknown-linux-gnu"
        binary = self.root / "latch"
        binary.write_bytes(elf(target))
        def git(*args):
            return subprocess.CompletedProcess(args, 0, b"" if args[0] == "status" else ("a" * 40).encode(), b"")
        with patch.object(prepare_release, "ROOT", project), patch.object(prepare_release, "git", side_effect=git):
            output = self.root / "packaged"
            package_linux.package(binary, target, "v0.1.0", "owner/repo", output)
            inspect_archive(output / archive_name("0.1.0", target), target, self.meta)
            with self.assertRaisesRegex(ValueError, "ELF"):
                package_linux.package(binary, "x86_64-unknown-linux-gnu", "v0.1.0", "owner/repo", self.root / "wrong")
        with patch.object(prepare_release, "ROOT", project), patch.object(prepare_release, "git", return_value=subprocess.CompletedProcess([], 0, b"dirty", b"")):
            with self.assertRaisesRegex(ValueError, "clean checkout"):
                package_linux.package(binary, target, "v0.1.0", "owner/repo", self.root / "dirty")

    def test_assemble_checksums_and_verify_both_targets(self):
        self.assemble()
        metadata = verify(self.bundle, "v0.1.0", "owner/repo")
        self.assertEqual(set(metadata["binaries"]), set(TARGETS))
        for target, entry in metadata["binaries"].items():
            self.assertEqual(entry["sha256"], inspect_archive(self.bundle / entry["archive"], target, metadata))
        with self.assertRaisesRegex(ValueError, "already contains"):
            self.assemble()

    def test_architecture_and_provenance_must_match(self):
        target = "aarch64-unknown-linux-gnu"
        contents = self.contents(target)
        contents["latch"] = elf("x86_64-unknown-linux-gnu")
        path = self.write_archive(target, contents)
        with self.assertRaisesRegex(ValueError, "ELF"):
            inspect_archive(path, target, self.meta)
        contents = self.contents(target)
        build = json.loads(contents["build.json"])
        build["commit"] = "b" * 40
        contents["build.json"] = json.dumps(build).encode()
        self.write_archive(target, contents)
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.assemble()
        self.assertNotIn("binaries", json.loads((self.bundle / "release.json").read_text()))

    def test_missing_target_extra_files_and_unsafe_archive_are_refused(self):
        target = "aarch64-unknown-linux-gnu"
        path = self.artifacts / archive_name("0.1.0", target)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "exactly"):
            self.assemble()
        contents = self.contents(target)
        contents["../unsafe"] = b"x"
        self.write_archive(target, contents)
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.assemble()
        self.write_archive(target)
        (self.artifacts / "unexpected").write_text("x")
        with self.assertRaisesRegex(ValueError, "exactly"):
            self.assemble()

    def test_replaced_and_undeclared_bundle_assets_are_refused(self):
        self.assemble()
        target = "aarch64-unknown-linux-gnu"
        path = self.bundle / archive_name("0.1.0", target)
        original = path.read_bytes()
        contents = self.contents(target)
        contents["README.md"] = b"changed"
        path.write_bytes(tar_bytes(contents))
        with self.assertRaisesRegex(ValueError, "checksum"):
            verify(self.bundle, "v0.1.0", "owner/repo")
        path.write_bytes(original)
        (self.bundle / "unexpected").write_text("x")
        with self.assertRaisesRegex(ValueError, "unexpected"):
            verify(self.bundle, "v0.1.0", "owner/repo")

    def test_linux_publication_and_retry_are_byte_identical(self):
        self.assemble()
        expected = {p.name: p.read_bytes() for p in self.bundle.rglob("*") if p.is_file()}
        fake = FakeGitHub(assets={"latch-secrets-0.1.0.tar.gz": b"synthetic source"})
        with patch.object(publish_release, "gh", side_effect=fake):
            publish_release.publish(self.bundle, "v0.1.0", "owner/repo")
        self.assertEqual(fake.assets, expected)
        self.assertFalse(fake.draft)
        fake.calls.clear()
        with patch.object(publish_release, "gh", side_effect=fake):
            publish_release.publish(self.bundle, "v0.1.0", "owner/repo")
        self.assertFalse(any(c[:2] in (("release", "upload"), ("release", "edit")) for c in fake.calls))
        name = archive_name("0.1.0", "aarch64-unknown-linux-gnu")
        fake.assets[name] = b"changed"
        with patch.object(publish_release, "gh", side_effect=fake), self.assertRaisesRegex(ValueError, "asset differs"):
            publish_release.publish(self.bundle, "v0.1.0", "owner/repo")


if __name__ == "__main__":
    unittest.main()
