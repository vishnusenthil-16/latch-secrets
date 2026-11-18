//! Real Linux broker processes; synthetic tokens and a disposable service-manager
//! shim only. These tests never use a desktop keyring or the host user manager.
#![cfg(target_os = "linux")]
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Broker(Child);
impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn request(state: &Path, value: Value) -> std::io::Result<Value> {
    let mut stream = UnixStream::connect(state.join("session/broker.sock"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(value.to_string().as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn start(state: &Path) -> Broker {
    let child = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "session-serve",
            "--session-backend",
            "memory",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut broker = Broker(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if request(state, json!({"op":"ping"})).is_ok() {
            return broker;
        }
        assert!(
            broker.0.try_wait().unwrap().is_none(),
            "broker exited before ready"
        );
        assert!(Instant::now() < deadline, "broker did not become ready");
        thread::sleep(Duration::from_millis(20));
    }
}
fn private_temp() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("latch-linux-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn actual_memory_broker_restart_lock_and_state_isolation() {
    let first = private_temp();
    let second = private_temp();
    let broker = start(first.path());
    let _other = start(second.path());
    assert_eq!(
        request(first.path(), json!({"op":"info"})).unwrap()["backend"],
        "memory"
    );
    assert_eq!(
        request(
            first.path(),
            json!({"op":"put","token":"SYNTHETIC_SESSION"})
        )
        .unwrap()["ok"],
        true
    );
    assert_eq!(
        request(first.path(), json!({"op":"get"})).unwrap()["token"],
        "SYNTHETIC_SESSION"
    );
    assert_eq!(
        request(second.path(), json!({"op":"get_optional"})).unwrap()["token"],
        Value::Null
    );
    drop(broker);
    let _restarted = start(first.path());
    assert_eq!(
        request(first.path(), json!({"op":"get_optional"})).unwrap()["token"],
        Value::Null
    );
    assert_eq!(
        request(
            first.path(),
            json!({"op":"put","token":"SECOND_SYNTHETIC_SESSION"})
        )
        .unwrap()["ok"],
        true
    );
    assert_eq!(
        request(first.path(), json!({"op":"delete"})).unwrap()["ok"],
        true
    );
    assert_eq!(
        request(first.path(), json!({"op":"get"})).unwrap()["error"],
        "session_empty"
    );
    assert_eq!(
        request(first.path(), json!({"op":"probe"})).unwrap()["ok"],
        true
    );
    for path in [
        first.path().join("session/broker.lock"),
        first.path().join("session/lock"),
    ] {
        if path.is_file() {
            assert!(
                !fs::read(path)
                    .unwrap()
                    .windows(9)
                    .any(|b| b == b"SYNTHETIC")
            );
        }
    }
}

fn executable(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
struct ServiceFixture {
    root: tempfile::TempDir,
    state: PathBuf,
}
impl ServiceFixture {
    fn new() -> Self {
        let root = private_temp();
        let state = root.path().join("state");
        fs::create_dir(root.path().join("bin")).unwrap();
        executable(
            &root.path().join("bin/bw"),
            r#"#!/usr/bin/python3
import json,sys
if sys.argv[1]=='--version': print('2026.8.0')
elif sys.argv[1]=='status': print(json.dumps({'status':'unauthenticated','serverUrl':'https://vault.example.test'}))
elif sys.argv[1]=='config': pass
else: sys.exit(1)
"#,
        );
        executable(
            &root.path().join("bin/systemctl"),
            r#"#!/usr/bin/python3
import os,sys,pathlib,subprocess,shlex,signal,time
root=pathlib.Path(os.environ['TEST_SERVICE_ROOT'])
if (root/'fail').exists(): sys.exit(1)
args=sys.argv[1:]
pidfile=root/'pid'
if args[1]=='show':
    print(pidfile.read_text().strip() if pidfile.exists() else '0'); sys.exit(0)
if args[1]!='restart': sys.exit(0)
if pidfile.exists():
    try: os.kill(int(pidfile.read_text()),signal.SIGTERM)
    except ProcessLookupError: pass
    time.sleep(.15)
unit=root/'config/systemd/user'/args[2]
line=next(x[len('ExecStart='):] for x in unit.read_text().splitlines() if x.startswith('ExecStart='))
p=subprocess.Popen(shlex.split(line),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
pidfile.write_text(str(p.pid))
"#,
        );
        Self { root, state }
    }
    fn call(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_latch"))
            .args(["--state-dir", self.state.to_str().unwrap(), "--json"])
            .args(args)
            .env("HOME", self.root.path())
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("TEST_SERVICE_ROOT", self.root.path())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.path().join("bin").display()),
            )
            .output()
            .unwrap()
    }
    fn configure(&self) -> std::process::Output {
        self.call(&[
            "configure",
            "--server",
            "https://vault.example.test",
            "--bw",
            self.root.path().join("bin/bw").to_str().unwrap(),
            "--session-backend",
            "memory",
        ])
    }
}
impl Drop for ServiceFixture {
    fn drop(&mut self) {
        if let Ok(pid) = fs::read_to_string(self.root.path().join("pid")) {
            // Only the synthetic helper spawned by this fixture is signalled.
            let _ = Command::new("kill").arg(pid.trim()).status();
        }
    }
}

#[test]
fn configure_recovers_failed_install_and_transfers_only_live_session() {
    let fixture = ServiceFixture::new();
    fs::write(fixture.root.path().join("fail"), "").unwrap();
    let failed = fixture.configure();
    assert!(!failed.status.success());
    let config: Value =
        serde_json::from_slice(&fs::read(fixture.state.join("config.json")).unwrap()).unwrap();
    assert_eq!(config["recovery_pending"], true);
    let blocked = fixture.call(&["sync"]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("recovery is incomplete"));
    fs::remove_file(fixture.root.path().join("fail")).unwrap();
    let recovered = fixture.configure();
    assert!(recovered.status.success(), "{recovered:?}");
    request(
        &fixture.state,
        json!({"op":"put","token":"SYNTHETIC_SESSION"}),
    )
    .unwrap();
    let upgraded = fixture.configure();
    assert!(upgraded.status.success(), "{upgraded:?}");
    assert_eq!(
        request(&fixture.state, json!({"op":"get"})).unwrap()["token"],
        "SYNTHETIC_SESSION"
    );
    let config: Value =
        serde_json::from_slice(&fs::read(fixture.state.join("config.json")).unwrap()).unwrap();
    assert_eq!(config["recovery_pending"], false);
    let pid = fs::read_to_string(fixture.root.path().join("pid")).unwrap();
    Command::new("kill").arg(pid.trim()).status().unwrap();
    thread::sleep(Duration::from_millis(150));
    let restarted = fixture.configure();
    assert!(restarted.status.success(), "{restarted:?}");
    assert_eq!(
        request(&fixture.state, json!({"op":"get_optional"})).unwrap()["token"],
        Value::Null
    );
}

#[test]
fn stopped_persistent_recovery_cannot_switch_backend_or_server() {
    for pending in [false, true] {
        let fixture = ServiceFixture::new();
        fs::create_dir(&fixture.state).unwrap();
        fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700)).unwrap();
        let path = fixture.state.join("config.json");
        let config = json!({
            "server":"https://vault.example.test",
            "bw":fixture.root.path().join("bin/bw"),
            "session_backend":"secret-service", "recovery_pending":pending
        })
        .to_string();
        fs::write(&path, &config).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        for (backend, server) in [
            ("memory", "https://vault.example.test"),
            ("secret-service", "https://other.example.test"),
        ] {
            let out = fixture.call(&[
                "configure",
                "--server",
                server,
                "--bw",
                fixture.root.path().join("bin/bw").to_str().unwrap(),
                "--session-backend",
                backend,
            ]);
            assert!(!out.status.success());
            assert!(
                String::from_utf8_lossy(&out.stderr)
                    .contains("recover the saved persistent backend")
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), config);
            assert!(!fixture.root.path().join("config/systemd/user").exists());
        }
    }
}
