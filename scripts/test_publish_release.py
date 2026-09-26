"""Publication retries preserve immutable assets and complete partial drafts."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import publish_release


class FakeGitHub:
    def __init__(self, assets=None, draft=True, later_page=False, duplicate=False):
        self.assets = assets
        self.draft = draft
        self.later_page = later_page
        self.duplicate = duplicate
        self.calls = []

    def __call__(self, *args, **_kwargs):
        self.calls.append(args)
        if args[0] == "api":
            pages = [[dict(tag_name="v0.0.9", draft=False, prerelease=False, assets=[])]]
            if self.assets is not None:
                target = dict(tag_name="v0.1.0", draft=self.draft, prerelease=False,
                              assets=[dict(name=name) for name in self.assets])
                if self.later_page:
                    pages.append([target])
                else:
                    pages[0].append(target)
                if self.duplicate:
                    pages.append([target])
            return subprocess.CompletedProcess(args, 0, json.dumps(pages), "")
        if args[:2] == ("release", "create"):
            self.assets = {}
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ("release", "upload"):
            for value in args[5:]:
                path = Path(value)
                self.assets[path.name] = path.read_bytes()
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ("release", "download"):
            dest = Path(args[args.index("--dir") + 1])
            for name in args[args.index("--pattern") + 1::2]:
                (dest / name).write_bytes(self.assets[name])
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ("release", "edit"):
            self.draft = False
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(f"unexpected gh operation: {args}")


class PublishReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bundle = Path(self.temporary.name)
        for name, content in (("latch-secrets-0.1.0.tar.gz", b"archive"),
                              ("Formula/latch-secrets.rb", b"formula"),
                              ("SHA256SUMS", b"checksums"), ("release.json", b"metadata")):
            path = self.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.expected = {path.name: path.read_bytes() for path in self.bundle.rglob("*") if path.is_file()}

    def publish(self, fake):
        with patch.object(publish_release, "verify"), patch.object(publish_release, "gh", side_effect=fake):
            publish_release.publish(self.bundle, "v0.1.0", "owner/repo")

    def test_new_release_is_drafted_uploaded_verified_then_published(self):
        fake = FakeGitHub()
        self.publish(fake)
        self.assertEqual(fake.assets, self.expected)
        self.assertFalse(fake.draft)
        self.assertEqual([x[:2] for x in fake.calls if x[0] == "release" and x[1] != "download"],
                         [("release", "create"), ("release", "upload"), ("release", "edit")])

    def test_existing_empty_and_partial_drafts_recover(self):
        for existing in ({}, {"latch-secrets-0.1.0.tar.gz": b"archive"}):
            with self.subTest(existing=existing):
                fake = FakeGitHub(assets=dict(existing), later_page=True)
                self.publish(fake)
                self.assertEqual(fake.assets, self.expected)
                self.assertFalse(fake.draft)
                self.assertFalse(any(call[:2] == ("release", "create") for call in fake.calls))

    def test_unknown_release_is_not_confused_with_other_tags(self):
        fake = FakeGitHub()
        with patch.object(publish_release, "gh", side_effect=fake):
            self.assertIsNone(publish_release.find_release("owner/repo", "v0.1.0"))
        self.assertEqual(fake.calls[0][:3], ("api", "--paginate", "--slurp"))

    def test_duplicate_tag_releases_are_refused(self):
        fake = FakeGitHub(assets={}, duplicate=True)
        with self.assertRaisesRegex(ValueError, "multiple releases"):
            self.publish(fake)
        self.assertFalse(any(call[0] == "release" for call in fake.calls))

    def test_existing_identical_public_release_is_noop(self):
        fake = FakeGitHub(assets=dict(self.expected), draft=False)
        self.publish(fake)
        self.assertFalse(any(call[:2] in (("release", "create"), ("release", "upload"),
                                         ("release", "edit")) for call in fake.calls))

    def test_differing_existing_asset_refused_before_mutation(self):
        fake = FakeGitHub(assets={"latch-secrets.rb": b"changed"})
        with self.assertRaisesRegex(ValueError, "asset differs"):
            self.publish(fake)
        self.assertFalse(any(call[:2] in (("release", "upload"), ("release", "edit"))
                             for call in fake.calls))

    def test_unexpected_asset_refused_before_mutation(self):
        fake = FakeGitHub(assets={"unrelated": b"contents"})
        with self.assertRaisesRegex(ValueError, "unexpected assets"):
            self.publish(fake)
        self.assertFalse(any(call[:2] in (("release", "upload"), ("release", "edit"))
                             for call in fake.calls))


if __name__ == "__main__":
    unittest.main()
