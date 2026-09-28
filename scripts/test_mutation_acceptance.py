import json
import subprocess
import unittest
from test_mutations_live import assert_deleted_refusal


class RefusalTests(unittest.TestCase):
    def result(self, message, code=1, stdout=b""):
        return subprocess.CompletedProcess([], code, stdout, json.dumps({"error": {"code": "LATCH_ERROR", "message": message}}).encode())

    def test_expected_refusal(self):
        assert_deleted_refusal(self.result("deleted items cannot be injected"), [])

    def test_unrelated_failures_and_success_rejected(self):
        for message in ["backend failed", "session unavailable", "vault busy"]:
            with self.subTest(message=message), self.assertRaises(RuntimeError):
                assert_deleted_refusal(self.result(message), [])
        for result in [self.result("deleted items cannot be injected", code=0), subprocess.CompletedProcess([], 1, b"", b"not JSON"), self.result("deleted items cannot be injected", stdout=b"CANARY")]:
            with self.assertRaises(RuntimeError):
                assert_deleted_refusal(result, ["CANARY"])
