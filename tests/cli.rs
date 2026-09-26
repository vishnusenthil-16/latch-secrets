//! Public CLI flows against a synthetic bw process and local in-memory broker.
//! These tests never contact a vault, install a LaunchAgent, or touch Keychain.
#![cfg(target_os = "macos")]
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
const ID: &str = "00000000-0000-4000-8000-000000000001";
const SECRET: &str = "CANARY_latch_$(not executed)'\"\\end";
struct Fixture {
    dir: tempfile::TempDir,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("latch-test-")
            .tempdir_in("/private/tmp")
            .unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(dir.path().join("bw")).unwrap();
        fs::set_permissions(dir.path().join("bw"), fs::Permissions::from_mode(0o700)).unwrap();
        let executable = dir.path().join("fake-bw");
        fs::write(&executable, r#"#!/usr/bin/python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['BITWARDENCLI_APPDATA_DIR']).parent
args = sys.argv[1:]
with (root/'calls').open('a') as log: log.write(args[0] + '\n')
if args[0] == '--version':
    print('2026.9.0' if (root/'bad-version').exists() else '2026.8.0'); sys.exit(0)
if args[0] in ('login', 'unlock'):
    if '--apikey' in args:
        assert os.environ.get('BW_CLIENTID') == 'synthetic-client-id'
        assert os.environ.get('BW_CLIENTSECRET') == 'synthetic-client-secret'
        (root/'unauthenticated').unlink(missing_ok=True)
    else:
        assert os.environ.get('LATCH_MASTER_PASSWORD') == 'synthetic-master'
        assert 'synthetic-master' not in args
        if args[0] == 'login': assert args[1] == 'test@example.test'
        (root/'unauthenticated').unlink(missing_ok=True)
        print('SYNTHETIC_SESSION')
    sys.exit(0)
assert os.environ.get('BW_PASSWORD') is None
assert os.environ.get('BW_CLIENTSECRET') is None
assert os.environ.get('LATCH_MASTER_PASSWORD') is None
if (root/'fail').exists():
    print('CANARY_backend_error'); print('CANARY_backend_error', file=sys.stderr); sys.exit(1)
if args[0] == 'status':
    print(json.dumps({'status':'unauthenticated' if (root/'unauthenticated').exists() else ('unlocked' if os.environ.get('BW_SESSION') == 'SYNTHETIC_SESSION' else 'locked'), 'lastSync':'2026-01-01T00:00:00Z', 'userEmail':'PRIVATE_METADATA', 'serverUrl': (root/'server-url').read_text() if (root/'server-url').exists() else ('https://vault.example.test' if (root/'bw').exists() else 'https://vault.bitwarden.com')})); sys.exit(0)
if args[0] == 'lock':
    (root/'locked').touch(); sys.exit(0)
assert os.environ.get('BW_SESSION') == 'SYNTHETIC_SESSION'
item = {'id':'00000000-0000-4000-8000-000000000001','name':'test-service','type':1,'organizationId':None,'collectionIds':[], 'notes':'CANARY_NOTES','login':{'username':'user','password':"CANARY_latch_$(not executed)'\"\\end"}, 'fields':[{'name':'token','type':1,'value':'CANARY_CUSTOM'}]}
if args[0] == 'list': print(json.dumps([item]))
elif args[0] == 'get': print(json.dumps(item))
elif args[0] == 'sync': pass
else: sys.exit(7)
"#).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let config = dir.path().join("config.json");
        fs::write(
            &config,
            json!({"server":"https://vault.example.test","bw":executable}).to_string(),
        )
        .unwrap();
        fs::set_permissions(config, fs::Permissions::from_mode(0o600)).unwrap();
        let lock = dir.path().join("vault.lock");
        fs::write(&lock, "").unwrap();
        fs::set_permissions(lock, fs::Permissions::from_mode(0o600)).unwrap();
        let session = dir.path().join("session");
        fs::create_dir(&session).unwrap();
        fs::set_permissions(&session, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = session.join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let finish = stop.clone();
        let worker = thread::spawn(move || {
            let mut token = Some("SYNTHETIC_SESSION".to_string());
            while !finish.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut buf = Vec::new();
                        stream.read_to_end(&mut buf).unwrap();
                        let req: Value = serde_json::from_slice(&buf).unwrap();
                        let response = match req["op"].as_str() {
                            Some("get") => match &token {
                                Some(t) => json!({"ok":true,"token":t}),
                                None => json!({"ok":false}),
                            },
                            Some("get_optional") => json!({"ok":true,"token":token}),
                            Some("put") => {
                                token = Some(req["token"].as_str().unwrap().to_owned());
                                json!({"ok":true})
                            }
                            Some("delete") => {
                                token = None;
                                json!({"ok":true})
                            }
                            Some("probe") => json!({"ok":true}),
                            _ => json!({"ok":false}),
                        };
                        stream.write_all(response.to_string().as_bytes()).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        Self {
            dir,
            stop,
            worker: Some(worker),
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_latch"));
        command
            .arg("--state-dir")
            .arg(self.dir.path())
            .arg("--json")
            .env("BW_SESSION", "PARENT_SECRET")
            .env("BW_PASSWORD", "PARENT_SECRET")
            .env("BW_CLIENTSECRET", "PARENT_SECRET")
            .env("LATCH_MASTER_PASSWORD", "PARENT_SECRET");
        command
    }
    fn call(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
fn public(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("CANARY"));
        assert!(!text.contains("SYNTHETIC_SESSION"));
        assert!(!text.contains("PARENT_SECRET"));
        assert!(!text.contains("PRIVATE_METADATA"));
    }
}
#[test]
fn metadata_status_sync_doctor_and_lock() {
    let fixture = Fixture::new();
    for args in [&["list"][..], &["status"], &["doctor"], &["sync"]] {
        let out = fixture.call(args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        public(&out);
    }
    let listed: Value =
        serde_json::from_slice(&fixture.call(&["list", "--search", "SERVICE"]).stdout).unwrap();
    assert_eq!(listed[0]["id"], ID);
    assert_eq!(listed[0].as_object().unwrap().len(), 5);
    assert!(fixture.call(&["lock"]).status.success());
    assert!(fixture.path("locked").exists());
    let out = fixture.call(&["list"]);
    assert!(!out.status.success());
    public(&out);
}
#[test]
fn run_injects_only_requested_credentials_and_preserves_exit_code() {
    let fixture = Fixture::new();
    let code = format!(
        "import os,sys; assert os.environ['TOKEN'] == {SECRET:?}; assert all(k not in os.environ for k in ['BW_SESSION','BW_PASSWORD','BW_CLIENTSECRET','LATCH_MASTER_PASSWORD']); sys.exit(37)"
    );
    let out = fixture.call(&[
        "run",
        "--env",
        &format!("TOKEN={ID}/login.password"),
        "--",
        "/usr/bin/python3",
        "-c",
        &code,
    ]);
    assert_eq!(
        out.status.code(),
        Some(37),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    public(&out);
}
#[test]
fn writes_preserve_text_and_do_not_disclose_values() {
    let fixture = Fixture::new();
    let dotenv = fixture.path(".env");
    fs::write(&dotenv, "# retained\nOTHER=keep\n").unwrap();
    let out = fixture.call(&[
        "write",
        "--env",
        &format!("TOKEN={ID}/custom.token"),
        "--dotenv",
        dotenv.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    public(&out);
    let parsed: Vec<_> = dotenvy::from_path_iter(&dotenv)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(parsed.contains(&("TOKEN".into(), "CANARY_CUSTOM".into())));
    assert!(
        fs::read_to_string(&dotenv)
            .unwrap()
            .starts_with("# retained\nOTHER=keep\n")
    );
    assert_eq!(
        fs::metadata(dotenv).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let zshrc = fixture.path(".zshrc");
    let out = fixture.call(&[
        "write",
        "--env",
        &format!("TOKEN={ID}/login.password"),
        "--zshrc",
        zshrc.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    public(&out);
    let child = Command::new("/bin/zsh")
        .args(["-f", "-c", "source \"$1\"; [[ $TOKEN == $2 ]]", "test"])
        .arg(&zshrc)
        .arg(SECRET)
        .output()
        .unwrap();
    assert!(child.status.success());
}
#[test]
fn dependency_failures_and_missing_fields_do_not_spawn_or_write() {
    let fixture = Fixture::new();
    let marker = fixture.path("should-not-exist");
    let out = fixture.call(&[
        "run",
        "--env",
        &format!("TOKEN={ID}/custom.missing"),
        "--",
        "/usr/bin/touch",
        marker.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(!marker.exists());
    public(&out);
    let dest = fixture.path(".env");
    fs::write(&dest, "UNCHANGED=yes\n").unwrap();
    let out = fixture.call(&[
        "write",
        "--env",
        &format!("TOKEN={ID}/custom.missing"),
        "--dotenv",
        dest.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert_eq!(fs::read_to_string(dest).unwrap(), "UNCHANGED=yes\n");
    public(&out);
    fs::write(fixture.path("fail"), "").unwrap();
    let out = fixture.call(&["list"]);
    assert!(!out.status.success());
    public(&out);
    fs::remove_file(fixture.path("fail")).unwrap();
    fs::write(fixture.path("bad-version"), "").unwrap();
    let out = fixture.call(&["list"]);
    assert!(!out.status.success());
    public(&out);
}
#[test]
fn help_and_noninteractive_login() {
    assert!(
        Command::new(env!("CARGO_BIN_EXE_latch"))
            .arg("--help")
            .output()
            .unwrap()
            .status
            .success()
    );
    let fixture = Fixture::new();
    let out = fixture.call(&["login"]);
    assert!(!out.status.success());
    public(&out);
}

#[test]
fn interactive_login_and_api_unlock_capture_session_without_echo() {
    // pty.fork supplies a controlling terminal for rpassword; all credentials are synthetic.
    let fixture = Fixture::new();
    let driver = r#"
import os, pty, select, sys, time, termios
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], [sys.argv[1], '--state-dir', sys.argv[2], '--json', 'login'] + sys.argv[3:])
steps = [(b'Master password:', b'synthetic-master')]
if '--api-key' in sys.argv:
    steps += [(b'Personal API client ID:', b'synthetic-client-id'), (b'Personal API client secret:', b'synthetic-client-secret')]
else:
    steps += [(b'Account email:', b'test@example.test')]
output = b''
index = 0
status = None
deadline = time.monotonic() + 10
try:
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try: chunk = os.read(fd, 4096)
            except OSError: chunk = b''
            output += chunk
            if index < len(steps) and steps[index][0] in output:
                # A PTY driver can respond faster than rpassword changes terminal mode.
                # Wait for non-echo input readiness before sending synthetic credentials.
                while termios.tcgetattr(fd)[3] & termios.ECHO:
                    assert time.monotonic() < deadline, 'terminal did not disable echo'
                    time.sleep(0.001)
                os.write(fd, steps[index][1] + b'\n')
                index += 1
        done, result = os.waitpid(pid, os.WNOHANG)
        if done:
            status = result
            break
    assert status == 0, 'login did not complete successfully'
    assert index == len(steps), 'expected authentication prompts'
    assert b'"session_stored":true' in output, 'missing success result'
    for secret in [b'synthetic-master', b'synthetic-client-secret', b'SYNTHETIC_SESSION']:
        assert secret not in output, 'secret echoed'
finally:
    if status is None:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    os.close(fd)
"#;
    for api in [false, true] {
        fs::write(fixture.path("unauthenticated"), "").unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command
            .args(["-c", driver, env!("CARGO_BIN_EXE_latch")])
            .arg(fixture.dir.path());
        if api {
            command.arg("--api-key");
        }
        let out = command.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        public(&out);
        assert!(fixture.call(&["list"]).status.success());
    }
}

#[test]
fn dangling_state_symlink_is_rejected_and_missing_bw_still_deletes_session() {
    let fixture = Fixture::new();
    fs::remove_dir(fixture.path("bw")).unwrap();
    std::os::unix::fs::symlink(fixture.path("missing"), fixture.path("bw")).unwrap();
    let out = fixture.call(&["list"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("state directories"));
    fs::remove_file(fixture.path("bw")).unwrap();
    fs::create_dir(fixture.path("bw")).unwrap();
    fs::set_permissions(fixture.path("bw"), fs::Permissions::from_mode(0o700)).unwrap();
    let script = fs::read(fixture.path("fake-bw")).unwrap();
    fs::remove_file(fixture.path("fake-bw")).unwrap();
    let out = fixture.call(&["lock"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("lock incomplete"));
    fs::write(fixture.path("fake-bw"), script).unwrap();
    fs::set_permissions(fixture.path("fake-bw"), fs::Permissions::from_mode(0o700)).unwrap();
    let status: Value = serde_json::from_slice(&fixture.call(&["status"]).stdout).unwrap();
    assert_eq!(status["session_accessible"], false);
}

#[test]
fn wrong_or_reset_endpoint_blocks_authentication_and_secret_operations() {
    for reset in [false, true] {
        let fixture = Fixture::new();
        if reset {
            fs::remove_dir(fixture.path("bw")).unwrap();
        } else {
            fs::write(fixture.path("server-url"), "https://other.example.test").unwrap();
        }
        let dest = fixture.path("output.env");
        fs::write(&dest, "UNCHANGED=yes\n").unwrap();
        let marker = fixture.path("child-started");
        let binding = format!("TOKEN={ID}/login.password");
        for args in [
            vec!["status"],
            vec!["login"],
            vec!["login", "--api-key"],
            vec!["sync"],
            vec!["list"],
            vec![
                "run",
                "--env",
                &binding,
                "--",
                "/usr/bin/touch",
                marker.to_str().unwrap(),
            ],
            vec![
                "write",
                "--env",
                &binding,
                "--dotenv",
                dest.to_str().unwrap(),
            ],
        ] {
            let out = fixture.call(&args);
            assert_eq!(out.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&out.stderr).contains("server does not match"));
            public(&out);
        }
        assert!(!marker.exists());
        assert_eq!(fs::read_to_string(dest).unwrap(), "UNCHANGED=yes\n");
        let calls = fs::read_to_string(fixture.path("calls")).unwrap();
        assert!(
            calls
                .lines()
                .all(|call| matches!(call, "--version" | "status"))
        );
        let doctor = fixture.call(&["doctor"]);
        assert!(doctor.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&doctor.stdout).unwrap()["ready"],
            false
        );
        assert!(fixture.call(&["lock"]).status.success());
    }
}

#[test]
fn configure_preserves_existing_state_when_old_helper_is_unavailable() {
    for remove_socket in [false, true] {
        let mut fixture = Fixture::new();
        fixture.stop.store(true, Ordering::SeqCst);
        fixture.worker.take().unwrap().join().unwrap();
        if remove_socket {
            fs::remove_file(fixture.path("session/broker.sock")).unwrap();
        }
        let before = fs::read(fixture.path("config.json")).unwrap();
        let out = fixture.call(&[
            "configure",
            "--server",
            "https://vault.example.test",
            "--bw",
            fixture.path("fake-bw").to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("existing session helper is unavailable")
        );
        assert_eq!(fs::read(fixture.path("config.json")).unwrap(), before);
        assert_eq!(
            fs::read_to_string(fixture.path("calls")).unwrap(),
            "--version\n"
        );
        public(&out);
    }
}
