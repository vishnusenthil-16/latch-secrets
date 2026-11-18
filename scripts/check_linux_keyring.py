#!/usr/bin/env python3
"""Opt-in Linux acceptance against an isolated GNOME Keyring and private D-Bus.

Only synthetic tokens are used. No user's existing keyring/session bus is opened.
Requires dbus-run-session, gnome-keyring-daemon, busctl, and a built latch binary.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time

CANARY = "SYNTHETIC_LATCH_KEYRING_ACCEPTANCE"
PASSWORD = b"synthetic-disposable-keyring-password\n"


def request(state, operation, **values):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(6)
        stream.connect(str(state / "session/broker.sock"))
        stream.sendall(json.dumps(dict(op=operation, **values)).encode())
        stream.shutdown(socket.SHUT_WR)
        chunks = []
        while data := stream.recv(32768):
            chunks.append(data)
        return json.loads(b"".join(chunks))


def wait_ready(state, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("isolated broker exited before ready")
        try:
            if request(state, "ping").get("ok"):
                return
        except (OSError, ValueError):
            pass
        time.sleep(.05)
    raise RuntimeError("isolated broker did not become ready")


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


class FakeServices:
    """Run real broker children without talking to any systemd user manager."""

    def __init__(self, binary, root):
        self.binary, self.root = binary, root
        tools = root / "bin"
        tools.mkdir(mode=0o700)
        self.bw = tools / "bw"
        self.bw.write_text("""#!/usr/bin/python3
import json, sys
if sys.argv[1] == '--version': print('2026.8.0')
elif sys.argv[1] == 'status': print(json.dumps({'status': 'unauthenticated', 'serverUrl': 'https://vault.example.test'}))
elif sys.argv[1] != 'config': sys.exit(1)
""")
        self.bw.chmod(0o700)
        self.systemctl = tools / "systemctl"
        self.systemctl.write_text(r"""#!/usr/bin/python3
import json, os, pathlib, shlex, signal, subprocess, sys, time
root = pathlib.Path(os.environ['TEST_SERVICE_ROOT'])
records = root / 'service-pids'
records.mkdir(mode=0o700, exist_ok=True)
args = sys.argv[1:]
assert args[0] == '--user'
operation = args[1]
if operation in ('daemon-reload', 'enable'): sys.exit(0)
unit = args[-1]
assert unit.startswith('latch-session-') and unit.endswith('.service') and '/' not in unit
record = records / (unit + '.json')
def process_identity(pid):
    try:
        fields = pathlib.Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        return None if fields[0] == 'Z' else fields[19]
    except (FileNotFoundError, ProcessLookupError): return None
def current():
    if not record.exists(): return None
    saved = json.loads(record.read_text())
    return saved if process_identity(saved['pid']) == saved['start'] else None
def stop():
    saved = current()
    if saved:
        os.kill(saved['pid'], signal.SIGTERM)
        until = time.monotonic() + 5
        while current() and time.monotonic() < until: time.sleep(.02)
        if current(): os.kill(saved['pid'], signal.SIGKILL)
    record.unlink(missing_ok=True)
if operation == 'is-active': sys.exit(0 if current() else 3)
if operation == 'show':
    saved = current()
    print(saved['pid'] if saved else 0)
    sys.exit(0)
if operation == 'stop': stop(); sys.exit(0)
assert operation == 'restart'
stop()
unitfile = pathlib.Path(os.environ['XDG_CONFIG_HOME']) / 'systemd/user' / unit
line = next(line.removeprefix('ExecStart=') for line in unitfile.read_text().splitlines() if line.startswith('ExecStart='))
child = subprocess.Popen(shlex.split(line), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
start = process_identity(child.pid)
assert start is not None, 'test broker exited at startup'
record.write_text(json.dumps({'pid': child.pid, 'start': start}))
record.chmod(0o600)
""")
        self.systemctl.chmod(0o700)
        self.env = dict(os.environ, PATH=str(tools) + os.pathsep + os.defpath,
                        TEST_SERVICE_ROOT=str(root))

    def unit(self, state):
        import hashlib
        return "latch-session-" + hashlib.sha256(os.fsencode(state.resolve())).hexdigest() + ".service"

    def manage(self, operation, state):
        subprocess.run([str(self.systemctl), "--user", operation, self.unit(state)],
                       env=self.env, check=True, capture_output=True, timeout=10)

    def configure(self, state, *, backend="secret-service", server="https://vault.example.test", success=True):
        result = subprocess.run(
            [str(self.binary), "--state-dir", str(state), "--json", "configure",
             "--server", server, "--bw", str(self.bw), "--session-backend", backend],
            env=self.env, capture_output=True, text=True, timeout=25)
        assert CANARY not in result.stdout + result.stderr, "synthetic token appeared in CLI output"
        assert (result.returncode == 0) == success, "unexpected configure result (diagnostics withheld)"
        if success:
            assert json.loads(result.stdout)["helper_installed"]
            assert not json.loads((state / "config.json").read_text())["recovery_pending"]
        return result

    def close(self):
        records = self.root / "service-pids"
        for record in records.glob("*.service.json"):
            subprocess.run([str(self.systemctl), "--user", "stop", record.name.removesuffix(".json")],
                           env=self.env, check=True, capture_output=True, timeout=10)


def configure_regressions(manager, service_call, collection, restart_provider):
    def read_alias(name="default"):
        result = subprocess.run(service_call + ["ReadAlias", "s", name],
                                check=True, capture_output=True, text=True, timeout=5)
        fields = shlex.split(result.stdout)
        assert len(fields) == 2 and fields[0] == "o", "unexpected alias response"
        return fields[1]

    def alias(path):
        subprocess.run(service_call + ["SetAlias", "so", "default", path], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if path != "/":
            assert read_alias() == path, "provider did not select requested default"

    def remove_default():
        # GNOME treats a removed default alias as the login collection. Merely
        # SetAlias('/') does NOT establish absence. Delete only this disposable,
        # unlocked login collection, then verify the actual provider response.
        alias("/")
        assert read_alias() == collection, "unexpected GNOME default fallback"
        deleted = subprocess.run(service_call[:-2] + [collection, "org.freedesktop.Secret.Collection", "Delete"],
                                 check=True, capture_output=True, text=True, timeout=5)
        assert shlex.split(deleted.stdout) == ["o", "/"], "disposable collection deletion required a prompt"
        assert read_alias() == "/", "provider still has a default collection"

    # A fresh empty but locked default must not become "configured" merely
    # because the broker responds. The saved transition must remain recoverable.
    locked = manager.root / "locked-empty"
    subprocess.run(service_call + ["Lock", "ao", "1", collection], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    manager.configure(locked, success=False)
    assert json.loads((locked / "config.json").read_text())["recovery_pending"]
    assert request(locked, "probe")["error"] == "store_locked"
    restart_provider()
    manager.configure(locked)

    missing = manager.root / "missing-empty"
    remove_default()
    manager.configure(missing, success=False)
    assert json.loads((missing / "config.json").read_text())["recovery_pending"]
    assert request(missing, "probe")["error"] == "store_collection_missing"
    # Source readiness is checked before changing even an already configured,
    # empty store. A failed reconfigure leaves its saved configuration intact.
    before = (locked / "config.json").read_bytes()
    manager.configure(locked, success=False)
    assert (locked / "config.json").read_bytes() == before
    # Leaving an empty persistent store requires reading/deleting its owned
    # items, not creating a new item through the missing default collection.
    manager.configure(locked, backend="memory")
    assert request(locked, "get_optional")["token"] is None
    account = "uid:" + str(os.getuid()) + ":" + os.fsencode(locked.resolve()).hex()
    remaining = subprocess.run(service_call + ["SearchItems", "a{ss}", "2", "service", "com.latch-secrets.session", "account", account],
                               check=True, capture_output=True, text=True, timeout=5)
    assert shlex.split(remaining.stdout) == ["aoao", "0", "0"], "old persistent store retained an item"
    restart_provider()
    assert read_alias() == collection
    manager.configure(missing)

    pending = manager.root / "pending"
    manager.configure(pending)
    assert request(pending, "put", token=CANARY)["ok"]
    # Simulate the durable boundary after a successful target put but before
    # the final configuration save. No production fault-injection hook is used.
    config_path = pending / "config.json"
    config = json.loads(config_path.read_text())
    config["recovery_pending"] = True
    config_path.write_text(json.dumps(config))
    before = config_path.read_bytes()
    manager.manage("stop", pending)
    manager.configure(pending, backend="memory", success=False)
    assert config_path.read_bytes() == before
    manager.configure(pending, server="https://other.example.test", success=False)
    assert config_path.read_bytes() == before
    manager.manage("restart", pending)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            if request(pending, "ping").get("ok"): break
        except OSError: pass
        time.sleep(.05)
    assert request(pending, "get")["token"] == CANARY, "rejected switch lost persistent session"
    # Recovery is allowed only with the saved backend/server and completes to
    # an empty, usable store. The caller can then explicitly log in again.
    manager.configure(pending)
    assert request(pending, "get_optional")["token"] is None

    # GNOME's built-in session collection lets the fixture create an item
    # outside the disposable login collection without opening a password prompt.
    other = read_alias("session")
    assert other not in ("/", collection), "isolated session collection unavailable"
    alias(other)
    assert request(pending, "put", token=CANARY)["ok"]
    alias(collection)
    remove_default()
    # Existing item is now in a nondefault collection. A same-backend restart
    # must preserve it rather than delete and recreate through the missing alias.
    manager.configure(pending)
    assert request(pending, "get")["token"] == CANARY
    assert read_alias() == "/", "reconfigure unexpectedly recreated a default"
    assert request(pending, "delete")["ok"]
    restart_provider()
    assert read_alias() == collection
    print("PASS: real keyring CLI configure rejects locked/missing defaults, preserves pending identity and nondefault sessions, repairs saved settings, and leaves an empty unavailable default for memory mode")


def inside(binary, root):
    daemon = broker = manager = None
    state = root / "state"
    state.mkdir(mode=0o700)
    control = root / "control"
    control.mkdir(mode=0o700)
    try:
        daemon = subprocess.Popen(
            ["gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
             "--control-directory", str(control)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        daemon.stdin.write(PASSWORD)
        daemon.stdin.close()
        deadline = time.monotonic() + 5
        while not (control / "control").exists() and time.monotonic() < deadline:
            time.sleep(.05)
        subprocess.run(["gnome-keyring-daemon", "--start", "--components=secrets",
                        "--control-directory", str(control)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        bus = ["busctl", "--address=" + os.environ["DBUS_SESSION_BUS_ADDRESS"]]
        call = bus + ["call", "org.freedesktop.secrets", "/org/freedesktop/secrets",
                      "org.freedesktop.Secret.Service"]
        deadline = time.monotonic() + 10
        # Listing names does not autoactivate a second provider while the
        # explicitly spawned foreground daemon is still starting.
        while time.monotonic() < deadline:
            names = subprocess.run(bus + ["--no-pager", "list"], capture_output=True, text=True, timeout=4)
            if any(len(fields := line.split()) > 1 and fields[0] == "org.freedesktop.secrets" and fields[1].isdigit() for line in names.stdout.splitlines()):
                break
            time.sleep(.05)
        collection = None
        while time.monotonic() < deadline:
            found = subprocess.run(call + ["ReadAlias", "s", "default"],
                                   capture_output=True, text=True, timeout=4)
            if found.returncode == 0:
                fields = shlex.split(found.stdout)
                if len(fields) == 2 and fields[0] == "o" and fields[1] != "/":
                    collection = fields[1]
                    break
            time.sleep(.1)
        if collection is None:
            raise RuntimeError("isolated GNOME default collection unavailable")

        def launch():
            process = subprocess.Popen(
                [str(binary), "--state-dir", str(state), "session-serve",
                 "--session-backend", "secret-service"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_ready(state, process)
            return process

        broker = launch()
        assert request(state, "probe")["ok"]
        assert request(state, "put", token=CANARY)["ok"]
        assert request(state, "get")["token"] == CANARY
        stop(broker)
        broker = launch()
        assert request(state, "get")["token"] == CANARY
        subprocess.run(call + ["Lock", "ao", "1", collection],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        began = time.monotonic()
        assert request(state, "probe")["error"] == "store_locked"
        assert time.monotonic() - began < 5
        assert request(state, "ping")["ok"]
        def restart_provider():
            nonlocal daemon
            # Unlock startup password only applies to a new provider process.
            stop(daemon)
            daemon = subprocess.Popen(
                ["gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
                 "--control-directory", str(control)], stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            daemon.stdin.write(PASSWORD)
            daemon.stdin.close()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                names = subprocess.run(bus + ["--no-pager", "list"], capture_output=True, text=True, timeout=4)
                if any(len(fields := line.split()) > 1 and fields[0] == "org.freedesktop.secrets" and fields[1] == str(daemon.pid) for line in names.stdout.splitlines()):
                    break
                time.sleep(.05)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                unlocked = subprocess.run(bus + ["get-property", "org.freedesktop.secrets", collection,
                                                   "org.freedesktop.Secret.Collection", "Locked"],
                                          capture_output=True, text=True, timeout=4)
                if unlocked.returncode == 0 and unlocked.stdout.strip() == "b false":
                    return
                time.sleep(.05)
            raise RuntimeError("isolated provider did not unlock its collection")

        restart_provider()
        deadline = time.monotonic() + 5
        reply = request(state, "get")
        while reply.get("error") == "store_locked" and time.monotonic() < deadline:
            time.sleep(.05)
            reply = request(state, "get")
        assert reply.get("token") == CANARY, "unlock recovery failed: " + reply.get("error", "unexpected response")
        assert request(state, "delete")["ok"]
        assert request(state, "get_optional")["token"] is None
        print("PASS: isolated GNOME Keyring store/read/broker-restart/lock/provider-unlock/delete; no secret values emitted")
        manager = FakeServices(binary, root)
        configure_regressions(manager, call, collection, restart_provider)
    finally:
        try:
            if manager: manager.close()
        finally:
            stop(broker)
            stop(daemon)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--latch", type=Path, required=True)
    parser.add_argument("--inside", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.latch.resolve(strict=True)
    if args.inside:
        inside(binary, args.inside)
        return
    with tempfile.TemporaryDirectory(prefix="latch-keyring-", dir="/tmp") as temporary:
        root = Path(temporary)
        env = {"PATH": os.defpath, "HOME": str(root), "XDG_DATA_HOME": str(root / "data"),
               "XDG_CONFIG_HOME": str(root / "config"), "XDG_RUNTIME_DIR": str(root / "runtime"),
               "GNOME_KEYRING_CONTROL": str(root / "control")}
        (root / "runtime").mkdir(mode=0o700)
        subprocess.run(["dbus-run-session", "--", "python3", str(Path(__file__).resolve()),
                        "--latch", str(binary), "--inside", str(root)], env=env, check=True, timeout=120)


if __name__ == "__main__":
    main()
