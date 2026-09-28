#!/usr/bin/env python3
"""Opt-in acceptance test against an already unlocked Latch vault.
Creates one clearly named synthetic item and soft-deletes it in finally.
Never reads or changes existing items. Secret values stay in process memory.
Run: python3 scripts/test_mutations_live.py --latch target/debug/latch --confirm-create-test-item
"""
import argparse
import json
import os
import secrets
import subprocess
import uuid


def assert_deleted_refusal(result, canaries):
    """Only the explicit deleted-item guard proves injection was refused."""
    if any(value.encode() in result.stdout + result.stderr for value in canaries):
        raise RuntimeError("Secret leakage detected (output suppressed)")
    try:
        error = json.loads(result.stderr)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("Expected structured deleted-item refusal") from None
    if result.returncode != 1 or result.stdout or error != {"error": {
        "code": "LATCH_ERROR", "message": "deleted items cannot be injected"
    }}:
        raise RuntimeError("Expected deleted-item refusal; unrelated failure is not proof")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--latch", default="target/debug/latch")
    parser.add_argument("--confirm-create-test-item", action="store_true", required=True)
    args = parser.parse_args()
    binary = os.path.abspath(args.latch)
    canaries = [secrets.token_urlsafe(32) for _ in range(3)]

    def call(argv, payload=None):
        result = subprocess.run([binary, "--json", *argv], input=None if payload is None else json.dumps(payload), text=True, capture_output=True)
        if any(value in result.stdout + result.stderr for value in canaries):
            raise RuntimeError("secret leakage detected (output suppressed)")
        if result.returncode:
            raise RuntimeError("Latch operation failed (output suppressed): " + argv[0])
        return json.loads(result.stdout) if result.stdout.strip() else None

    status = call(["status"])
    if not status.get("session_accessible") or status.get("vault_status") != "unlocked":
        raise RuntimeError("Run latch login in your terminal before live acceptance")
    name = "latch-synthetic-mutation-test-" + str(uuid.uuid4())
    # Payload schema is shared with the public create/update interface.
    created = call(["create"], {"name": name, "login": {"username": "synthetic-test-user", "password": canaries[0]}, "fields": [{"name": "token", "value": canaries[1]}]})
    item_id = created["id"]
    print("Created synthetic test item:", item_id, flush=True)

    def verify(password, token):
        env = os.environ.copy()
        env["EXPECTED_PASSWORD"] = password
        env["EXPECTED_TOKEN"] = token
        code = "import os; assert os.environ['ACTUAL_PASSWORD'] == os.environ['EXPECTED_PASSWORD']; assert os.environ['ACTUAL_TOKEN'] == os.environ['EXPECTED_TOKEN']; assert os.environ['ACTUAL_USER'] == 'synthetic-test-user'"
        result = subprocess.run([binary, "run", "--env", f"ACTUAL_PASSWORD={item_id}/login.password", "--env", f"ACTUAL_TOKEN={item_id}/custom.token", "--env", f"ACTUAL_USER={item_id}/login.username", "--", "/usr/bin/python3", "-c", code], env=env, capture_output=True)
        if result.returncode or any(value.encode() in result.stdout + result.stderr for value in canaries):
            raise RuntimeError("Injected-value verification failed (output suppressed)")

    try:
        call(["sync"])
        verify(canaries[0], canaries[1])
        call(["update", item_id], {"login": {"password": canaries[2]}})
        call(["sync"])
        verify(canaries[2], canaries[1])
        listed = call(["list", "--search", name])
        assert any(item["id"] == item_id for item in listed)
    finally:
        # Exactly one attempt: an uncertain deletion must never be retried blindly.
        try:
            deleted = call(["delete", item_id])
            assert deleted == {"id": item_id, "deleted": True, "permanent": False}
        except Exception:
            print("Cleanup uncertain; inspect synthetic item manually:", item_id, flush=True)
            raise
    call(["sync"])
    listed = call(["list", "--search", name])
    assert not any(item["id"] == item_id for item in listed)
    result = subprocess.run([binary, "--json", "run", "--env", f"TOKEN={item_id}/login.password", "--", "/usr/bin/true"], capture_output=True)
    assert_deleted_refusal(result, canaries)
    print("PASS: create, inject, rotate, preservation, soft-delete, discovery exclusion, injection refusal")
    print("Synthetic item moved to vault trash:", item_id)


if __name__ == "__main__":
    main()
