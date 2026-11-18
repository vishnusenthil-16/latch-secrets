#!/usr/bin/env python3
"""Opt-in real systemd user-service acceptance with synthetic session/backend.

Creates and removes one private test installation/unit. Never touches real vault
credentials, other Latch installations, or the user's lingering setting.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from check_linux_keyring import request, stop, wait_ready


def check(binary):
    unit = None
    foreground = None
    config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    with tempfile.TemporaryDirectory(prefix="latch-systemd-", dir="/tmp") as temporary:
        root = Path(temporary)
        bw = root / "synthetic-bw"
        bw.write_text('''#!/usr/bin/python3
import json,sys
if sys.argv[1] == '--version': print('2026.8.0')
elif sys.argv[1] == 'status': print(json.dumps({'status':'unauthenticated','serverUrl':'https://vault.example.test'}))
elif sys.argv[1] in ('lock','config'): pass
else: sys.exit(1)
''')
        bw.chmod(0o700)
        state = root / "state"
        # Know the exact task-owned unit before configure, so partial install
        # failures are cleaned up too.
        unit = "latch-session-" + hashlib.sha256(os.fsencode(state.resolve())).hexdigest() + ".service"
        argv = [str(binary), "--state-dir", str(state), "--json"]
        configure = argv + ["configure", "--server", "https://vault.example.test",
                            "--bw", str(bw), "--session-backend", "memory"]

        def run(args, success=True):
            result = subprocess.run(args, capture_output=True, text=True, timeout=45)
            if (result.returncode == 0) != success:
                raise RuntimeError("synthetic service command had unexpected exit status: " + result.stderr)
            return result

        try:
            configured = json.loads(run(configure).stdout)
            assert unit == configured["helper_service"]
            assert unit.startswith("latch-session-") and unit.endswith(".service")
            info = request(state, "info")
            main_pid = int(run(["systemctl", "--user", "show", "--property=MainPID", "--value", unit]).stdout)
            assert info["pid"] == main_pid
            assert request(state, "put", token="SYNTHETIC_SERVICE_SESSION")["ok"]
            run(configure)
            assert request(state, "get")["token"] == "SYNTHETIC_SERVICE_SESSION"
            run(["systemctl", "--user", "restart", unit])
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    if request(state, "ping").get("ok"):
                        break
                except OSError:
                    pass
                time.sleep(.05)
            assert request(state, "get_optional")["token"] is None
            run(["systemctl", "--user", "stop", unit])
            run(configure)
            assert request(state, "get_optional")["token"] is None
            assert request(state, "put", token="SYNTHETIC_LOCK_SESSION")["ok"]
            assert json.loads(run(argv + ["lock"]).stdout)["locked"]
            assert request(state, "get_optional")["token"] is None

            # A foreground broker must not impersonate a successful managed
            # installation when the actual unit cannot acquire its socket.
            run(["systemctl", "--user", "stop", unit])
            foreground = subprocess.Popen(argv + ["session-serve", "--session-backend", "memory"],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            wait_ready(state, foreground)
            run(configure, success=False)
            assert json.loads((state / "config.json").read_text())["recovery_pending"]
            run(["systemctl", "--user", "stop", unit])
            stop(foreground)
            foreground = None
            run(configure)
            assert not json.loads((state / "config.json").read_text())["recovery_pending"]
            print("PASS: real systemd user unit, PID identity, live transfer, restart loss, stopped-helper repair, lock, foreground-conflict recovery")
        finally:
            stop(foreground)
            if unit:
                disabled = subprocess.run(["systemctl", "--user", "disable", "--now", unit],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                if disabled.returncode and (config_home / "systemd/user" / unit).exists():
                    raise RuntimeError("test unit cleanup failed; inspect the task-owned unit " + unit)
                (config_home / "systemd/user" / unit).unlink(missing_ok=True)
                subprocess.run(["systemctl", "--user", "daemon-reload"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=True)
                subprocess.run(["systemctl", "--user", "reset-failed", unit],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--latch", type=Path, required=True)
    parser.add_argument("--confirm-disposable-user-service", action="store_true", required=True)
    args = parser.parse_args()
    check(args.latch.resolve(strict=True))
