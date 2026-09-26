"""Contract tests for the local release bundler."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import prepare_release


class ReleaseFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "project"
        self.root.mkdir()
        for rel in ("scripts/prepare_release.py", "packaging/homebrew/latch-secrets.rb.in"):
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(prepare_release.ROOT / rel, target)
        for rel, content in {
            "Cargo.toml": '[package]\nname = "latch-secrets"\nversion = "0.1.0"\n',
            "Cargo.lock": "# lock\n", "LICENSE": "license\n", "README.md": "readme\n",
            "src/main.rs": "fn main() {}\n", "tests/cli.rs": "test\n",
            "skills/latch/SKILL.md": "skill\n", ".env": "DO_NOT_PACKAGE\n",
            ".gitignore": "src/ignored.rs\nsrc/.env\n",
        }.items():
            file = self.root / rel
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content)
        self.run_git("init", "-q")
        self.run_git("config", "user.email", "test@example.invalid")
        self.run_git("config", "user.name", "Test")
        self.run_git("add", ".")
        self.run_git("commit", "-qm", "fixture")
        self.run_git("tag", "v0.1.0")
        self.original_root = prepare_release.ROOT
        prepare_release.ROOT = self.root
        self.addCleanup(setattr, prepare_release, "ROOT", self.original_root)

    def run_git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args],
                              check=True, capture_output=True)

    def release(self, name="release", **kwargs):
        out = Path(self.temp.name) / name
        prepare_release.prepare("v0.1.0", "owner/repo", out, **kwargs)
        return out

    def test_tagged_release_is_reproducible_and_complete(self):
        (self.root / "src/ignored.rs").write_text("SECRET\n")
        (self.root / "src/.env").write_text("SECRET\n")
        one = self.release(snapshot=False)
        two = self.release("again", snapshot=False)
        archive_name = "latch-secrets-0.1.0.tar.gz"
        self.assertEqual((one / archive_name).read_bytes(), (two / archive_name).read_bytes())
        archive = (one / archive_name).read_bytes()
        digest = hashlib.sha256(archive).hexdigest()
        manifest = json.loads((one / "release.json").read_text())
        self.assertEqual(manifest["sha256"], digest)
        self.assertFalse(manifest["snapshot"])
        formula = (one / "Formula/latch-secrets.rb").read_text()
        self.assertIn(f'url "https://github.com/owner/repo/releases/download/v0.1.0/{archive_name}"', formula)
        self.assertIn(f'sha256 "{digest}"', formula)
        self.assertIn('args << "--offline" unless args.include?("--offline")', formula)
        self.assertIn('system "cargo", "install", *args', formula)
        self.assertEqual((one / "SHA256SUMS").read_text(),
                         f"{digest}  {archive_name}\n"
                         f"{hashlib.sha256(formula.encode()).hexdigest()}  Formula/latch-secrets.rb\n")
        with tarfile.open(one / archive_name, "r:gz") as tar:
            names = tar.getnames()
            self.assertIn("latch-secrets-0.1.0/src/main.rs", names)
            self.assertNotIn("latch-secrets-0.1.0/.env", names)
            self.assertNotIn("latch-secrets-0.1.0/src/.env", names)
            self.assertNotIn("latch-secrets-0.1.0/src/ignored.rs", names)
            self.assertFalse(any("packaging" in name for name in names))

    def test_dirty_tag_and_version_guards(self):
        (self.root / "untracked").write_text("x")
        with self.assertRaisesRegex(prepare_release.ReleaseError, "clean Git worktree"):
            self.release(snapshot=False)
        (self.root / "untracked").unlink()
        self.run_git("tag", "-d", "v0.1.0")
        with self.assertRaisesRegex(prepare_release.ReleaseError, "tag commit"):
            self.release(snapshot=False)
        (self.root / "Cargo.toml").write_text('[package]\nname = "latch-secrets"\nversion = "0.2.0"\n')
        with self.assertRaisesRegex(prepare_release.ReleaseError, "does not match"):
            self.release(snapshot=True)

    def test_snapshot_and_symlink_guards(self):
        self.run_git("tag", "-d", "v0.1.0")
        (self.root / "src/main.rs").write_text("fn main() { /* snapshot */ }\n")
        out = self.release(snapshot=True)
        self.assertTrue(json.loads((out / "release.json").read_text())["snapshot"])
        (self.root / "src/link.rs").symlink_to("main.rs")
        with self.assertRaisesRegex(prepare_release.ReleaseError, "symlink in source"):
            self.release("another", snapshot=True)

    def test_output_conflict_and_bad_inputs(self):
        out = Path(self.temp.name) / "existing"
        out.mkdir()
        (out / "keep").write_text("x")
        with self.assertRaisesRegex(prepare_release.ReleaseError, "new or empty"):
            prepare_release.prepare("v0.1.0", "owner/repo", out, False)
        for tag, repo in (("0.1.0", "owner/repo"), ("v0.1.0", "owner/repo/extra"),
                          ("v0.1.0", "../repo")):
            with self.assertRaisesRegex(prepare_release.ReleaseError, "tag must"):
                prepare_release.prepare(tag, repo, Path(self.temp.name) / "bad", False)


if __name__ == "__main__":
    unittest.main()
