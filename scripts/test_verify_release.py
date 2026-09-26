import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_release import verify


class VerifyReleaseTests(unittest.TestCase):
    def test_release_integrity_and_snapshot_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            (bundle / "Formula").mkdir()
            name = "latch-secrets-0.1.0.tar.gz"
            archive = b"synthetic archive"
            digest = hashlib.sha256(archive).hexdigest()
            formula = f'  url "https://github.com/example/latch-secrets/releases/download/v0.1.0/{name}"\n  sha256 "{digest}"\n'
            (bundle / name).write_bytes(archive)
            path = bundle / "Formula/latch-secrets.rb"
            path.write_text(formula)
            (bundle / "SHA256SUMS").write_text(f'{digest}  {name}\n{hashlib.sha256(formula.encode()).hexdigest()}  Formula/latch-secrets.rb\n')
            metadata = dict(repository="example/latch-secrets", tag="v0.1.0", version="0.1.0", archive=name, snapshot=False, sha256=digest)
            manifest = bundle / "release.json"
            manifest.write_text(json.dumps(metadata))
            verify(bundle, "v0.1.0", "example/latch-secrets")
            with self.assertRaises(ValueError):
                verify(bundle, "v0.1.1", "example/latch-secrets")
            metadata["snapshot"] = True
            manifest.write_text(json.dumps(metadata))
            with self.assertRaises(ValueError):
                verify(bundle, "v0.1.0", "example/latch-secrets")
            metadata["snapshot"] = False
            manifest.write_text(json.dumps(metadata))
            path.write_text(formula + "unexpected modification")
            with self.assertRaises(ValueError):
                verify(bundle, "v0.1.0", "example/latch-secrets")

class ProvenanceTests(unittest.TestCase):
    def test_expected_source_and_formula_are_required(self):
        import gzip
        import shutil
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = root / "expected"
            actual = root / "actual"
            (expected / "Formula").mkdir(parents=True)
            archive_name = "latch-secrets-0.1.0.tar.gz"
            def populate(bundle, content, extra="", mtime=0):
                archive = gzip.compress(content, mtime=mtime)
                digest = hashlib.sha256(archive).hexdigest()
                formula = f'  url "https://github.com/example/latch-secrets/releases/download/v0.1.0/{archive_name}"\n  sha256 "{digest}"\n{extra}'
                (bundle / archive_name).write_bytes(archive)
                (bundle / "Formula/latch-secrets.rb").write_text(formula)
                (bundle / "SHA256SUMS").write_text(f'{digest}  {archive_name}\n{hashlib.sha256(formula.encode()).hexdigest()}  Formula/latch-secrets.rb\n')
                metadata = dict(repository="example/latch-secrets", tag="v0.1.0", version="0.1.0", archive=archive_name, snapshot=False, sha256=digest, commit="a" * 40)
                (bundle / "release.json").write_text(json.dumps(metadata))
            populate(expected, b"expected source")
            shutil.copytree(expected, actual)
            verify(actual, "v0.1.0", "example/latch-secrets", expected)
            populate(actual, b"expected source", mtime=1)
            verify(actual, "v0.1.0", "example/latch-secrets", expected)
            populate(actual, b"replaced source")
            with self.assertRaisesRegex(ValueError, "archive differs"):
                verify(actual, "v0.1.0", "example/latch-secrets", expected)
            populate(actual, b"expected source", "unexpected formula code\n")
            with self.assertRaisesRegex(ValueError, "formula differs"):
                verify(actual, "v0.1.0", "example/latch-secrets", expected)


if __name__ == "__main__":
    unittest.main()
