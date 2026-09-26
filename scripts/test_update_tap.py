"""Tap updates advance versions and refuse modified or older releases."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import update_tap


def formula(version: str) -> bytes:
    return f'url "https://github.com/owner/repo/releases/download/v{version}/latch-secrets-{version}.tar.gz"\n'.encode()


class UpdateTapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.original_cwd = Path.cwd()
        self.addCleanup(os.chdir, self.original_cwd)
        root = Path(self.temporary.name)
        self.remote = root / "remote.git"
        self.checkout = root / "tap"
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        subprocess.run(["git", "clone", str(self.remote), str(self.checkout)], check=True, capture_output=True)
        os.chdir(self.checkout)
        target = Path("Formula/latch-secrets.rb")
        target.parent.mkdir()
        target.write_bytes(formula("0.1.0"))
        subprocess.run(["git", "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.com",
                        "commit", "-m", "initial"], check=True, capture_output=True)
        subprocess.run(["git", "push", "origin", "HEAD"], check=True, capture_output=True)

    def test_pushes_new_version_and_retries_without_new_commit(self):
        incoming = Path(self.temporary.name) / "incoming.rb"
        incoming.write_bytes(formula("0.1.1"))
        update_tap.update(incoming, "v0.1.1")
        first = update_tap.git("rev-parse", "HEAD")
        self.assertEqual(update_tap.git("rev-parse", "HEAD"), update_tap.git("rev-parse", "origin/" + update_tap.git("branch", "--show-current")))
        update_tap.update(incoming, "v0.1.1")
        self.assertEqual(first, update_tap.git("rev-parse", "HEAD"))

    def test_refuses_different_bytes_at_same_version_and_rollback(self):
        incoming = Path(self.temporary.name) / "incoming.rb"
        incoming.write_bytes(formula("0.1.0") + b"# changed\n")
        with self.assertRaisesRegex(ValueError, "differs"):
            update_tap.update(incoming, "v0.1.0")
        incoming.write_bytes(formula("0.1.1"))
        update_tap.update(incoming, "v0.1.1")
        incoming.write_bytes(formula("0.1.0"))
        with self.assertRaisesRegex(ValueError, "newer release"):
            update_tap.update(incoming, "v0.1.0")


if __name__ == "__main__":
    unittest.main()
