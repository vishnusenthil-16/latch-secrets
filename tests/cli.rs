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
if (root/'item.json').exists(): item = json.loads((root/'item.json').read_text())
if args[0] in ('create', 'edit'):
    import base64
    assert args == (['create', 'item', '--nointeraction'] if args[0] == 'create' else ['edit', 'item', item['id'], '--nointeraction'])
    payload = json.loads(base64.b64decode(sys.stdin.read()))
    if (root/'mutation-fail').exists():
        print('CANARY_backend_error'); print('CANARY_backend_error', file=sys.stderr); sys.exit(1)
    payload['id'] = '00000000-0000-4000-8000-000000000001'
    (root/'item.json').write_text(json.dumps(payload))
    if (root/'bad-response').exists(): print('CANARY_invalid_response')
    else: print(json.dumps(payload))
    sys.exit(0)
if args[0] == 'delete':
    assert args == ['delete', 'item', item['id'], '--nointeraction']
    assert item.get('deletedDate') is None
    if (root/'mutation-fail').exists():
        print('CANARY_backend_error'); print('CANARY_backend_error', file=sys.stderr); sys.exit(1)
    item['deletedDate'] = '2026-09-28T00:00:00Z'
    (root/'item.json').write_text(json.dumps(item))
    print('CANARY_ignored_success_output'); sys.exit(0)
if args[0] == 'get' and (root/'missing-item').exists():
    print('CANARY_missing', file=sys.stderr); sys.exit(1)
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
            .env("HOME", self.dir.path().join("isolated-agent-home"))
            .env("LATCH_BROWSER_HOME", self.dir.path())
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
    fn input(&self, args: &[&str], input: &str) -> Output {
        let mut child = self
            .command()
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
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
fn interactive_login_masks_password_and_echoes_email() {
    // Exercise the actual terminal prompts; all credentials are synthetic.
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
awaiting_mask = False
mask_verified = False
deadline = time.monotonic() + 10
try:
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try: chunk = os.read(fd, 4096)
            except OSError: chunk = b''
            output += chunk
            if awaiting_mask and b'***' in output:
                mask_verified = True
                awaiting_mask = False
                os.write(fd, b'\r')
            elif not awaiting_mask and index < len(steps) and steps[index][0] in output:
                visible = steps[index][0] == b'Account email:'
                while bool(termios.tcgetattr(fd)[3] & termios.ECHO) != visible:
                    assert time.monotonic() < deadline, 'terminal echo mode not ready'
                    time.sleep(0.001)
                if index == 0:
                    # Verify masking while typing, before the submitted-value summary.
                    # Include a typo and backspace to check password editing too.
                    os.write(fd, b'synthetic-masteX\x7fr')
                    awaiting_mask = True
                else:
                    os.write(fd, steps[index][1] + b'\n')
                index += 1
        done, result = os.waitpid(pid, os.WNOHANG)
        if done:
            status = result
            break
    assert status == 0, 'login did not complete successfully'
    assert index == len(steps), 'expected authentication prompts'
    assert mask_verified, 'password was not visibly masked while typing'
    if '--api-key' not in sys.argv:
        assert b'Account email: test@example.test' in output, 'email was hidden'
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
            vec!["delete", ID],
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

#[test]
fn create_inject_rotate_inject_preserves_metadata_and_hides_payloads() {
    let f = Fixture::new();
    let out = f.input(&["create"], &json!({"name":"service","login":{"username":"CANARY_USER","password":"CANARY_FIRST"},"fields":[{"name":"token","value":"CANARY_TOKEN"}]}).to_string());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    public(&out);
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result, json!({"id":ID,"created":true,"updated":false}));
    let readback = |expected: &str| {
        let out = f.call(&["run","--env",&format!("TOKEN={ID}/login.password"),"--env",&format!("CUSTOM={ID}/custom.token"),"--","/usr/bin/python3","-c",&format!("import os; assert os.environ['TOKEN'] == {expected:?}; assert os.environ['CUSTOM'] == 'CANARY_TOKEN'")]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        public(&out);
    };
    readback("CANARY_FIRST");
    let mut before: Value =
        serde_json::from_slice(&fs::read(f.path("item.json")).unwrap()).unwrap();
    before["notes"] = json!("CANARY_NOTES");
    before["login"]["totp"] = json!("CANARY_TOTP");
    before["organizationId"] = json!("organization");
    before["collectionIds"] = json!(["collection"]);
    before["attachments"] = json!([{"id":"attachment"}]);
    before["revisionDate"] = json!("revision");
    fs::write(f.path("item.json"), before.to_string()).unwrap();
    let out = f.input(&["update", ID], r#"{"login":{"password":"CANARY_SECOND"}}"#);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    public(&out);
    readback("CANARY_SECOND");
    before["login"]["password"] = json!("CANARY_SECOND");
    let after: Value = serde_json::from_slice(&fs::read(f.path("item.json")).unwrap()).unwrap();
    assert_eq!(after, before);
    let calls = fs::read_to_string(f.path("calls")).unwrap();
    assert!(calls.contains("sync\ncreate\n"));
    assert!(calls.contains("sync\nget\nedit\n"));
    assert_eq!(calls.lines().filter(|s| *s == "create").count(), 1);
    assert_eq!(calls.lines().filter(|s| *s == "edit").count(), 1);
}

#[test]
fn mutation_input_and_backend_failures_are_safe_and_never_retried() {
    let f = Fixture::new();
    for input in [
        r#"{"name":"CANARY","login":{"password":null}}"#,
        r#"{"name":"CANARY","unknown":"CANARY"}"#,
        r#"{"name":"CANARY","name":"CANARY"}"#,
        "CANARY",
    ] {
        let out = f.input(&["create"], input);
        assert!(!out.status.success());
        public(&out);
    }
    let out = f.input(
        &["update", "CANARY_NOT_UUID"],
        r#"{"login":{"password":"CANARY"}}"#,
    );
    assert!(!out.status.success());
    public(&out);
    let calls = fs::read_to_string(f.path("calls")).unwrap();
    assert!(
        !calls
            .lines()
            .any(|s| matches!(s, "sync" | "create" | "edit"))
    );
    fs::write(f.path("mutation-fail"), "").unwrap();
    let out = f.input(
        &["create"],
        r#"{"name":"service","login":{"password":"CANARY"}}"#,
    );
    assert!(!out.status.success());
    public(&out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("outcome uncertain"));
    assert!(!f.path("item.json").exists());
    let calls = fs::read_to_string(f.path("calls")).unwrap();
    assert_eq!(calls.lines().filter(|s| *s == "create").count(), 1);
    fs::remove_file(f.path("mutation-fail")).unwrap();
    fs::write(f.path("bad-response"), "").unwrap();
    let out = f.input(
        &["create"],
        r#"{"name":"service","login":{"password":"CANARY"}}"#,
    );
    assert!(!out.status.success());
    public(&out);
    assert!(f.path("item.json").exists());
    let calls = fs::read_to_string(f.path("calls")).unwrap();
    assert_eq!(calls.lines().filter(|s| *s == "create").count(), 2);
}

#[test]
fn update_rejects_unsupported_items_and_ambiguous_fields_without_edit() {
    let f = Fixture::new();
    for item in [
        json!({"id":ID,"type":2}),
        json!({"id":ID,"type":1,"fields":[{"name":"t","type":0},{"name":"t","type":1}]}),
        json!({"id":ID,"type":1,"fields":[{"name":"t","type":3}]}),
        json!({"id":ID,"type":1,"deletedDate":"date"}),
        json!({"id":ID,"type":1,"archivedDate":"date"}),
        json!({"id":"different","type":1}),
    ] {
        fs::write(f.path("item.json"), item.to_string()).unwrap();
        let out = f.input(
            &["update", ID],
            r#"{"fields":[{"name":"t","value":"CANARY"}]}"#,
        );
        assert!(!out.status.success());
        public(&out);
        assert_eq!(
            fs::read_to_string(f.path("item.json")).unwrap(),
            item.to_string()
        );
    }
    assert!(
        !fs::read_to_string(f.path("calls"))
            .unwrap()
            .lines()
            .any(|s| s == "edit")
    );
}

#[test]
fn custom_field_rotation_preserves_types_and_creates_hidden_by_default() {
    let f = Fixture::new();
    let out = f.input(&["create"], r#"{"name":"service","fields":[{"name":"text","type":"text","value":"CANARY_OLD"},{"name":"hidden","value":"CANARY_OLD"}]}"#);
    assert!(out.status.success());
    public(&out);
    let out = f.input(&["update", ID], r#"{"fields":[{"name":"text","value":"CANARY_NEW"},{"name":"hidden","type":"text","value":"CANARY_NEW"},{"name":"new","value":"CANARY_NEW"}]}"#);
    assert!(out.status.success());
    public(&out);
    let item: Value = serde_json::from_slice(&fs::read(f.path("item.json")).unwrap()).unwrap();
    assert_eq!(
        item["fields"],
        json!([{"name":"text","type":0,"value":"CANARY_NEW"},{"name":"hidden","type":0,"value":"CANARY_NEW"},{"name":"new","type":1,"value":"CANARY_NEW"}])
    );
    let out = f.call(&[
        "run",
        "--env",
        &format!("TOKEN={ID}/custom.new"),
        "--",
        "/usr/bin/python3",
        "-c",
        "import os; assert os.environ['TOKEN'] == 'CANARY_NEW'",
    ]);
    assert!(out.status.success());
    public(&out);
}

#[test]
fn delete_is_soft_only_and_repeat_and_injection_are_refused() {
    let f = Fixture::new();
    let out = f.call(&["delete", ID]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    public(&out);
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap(),
        json!({"id":ID,"deleted":true,"permanent":false})
    );
    assert_eq!(
        fs::read_to_string(f.path("calls")).unwrap(),
        "--version\nstatus\nsync\nget\ndelete\n"
    );
    let out = f.call(&["delete", ID]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already deleted"));
    public(&out);
    let marker = f.path("child-started");
    let dest = f.path("output.env");
    fs::write(&dest, "UNCHANGED=yes\n").unwrap();
    for args in [
        vec![
            "run",
            "--env",
            &format!("TOKEN={ID}/login.password"),
            "--",
            "/usr/bin/touch",
            marker.to_str().unwrap(),
        ],
        vec![
            "write",
            "--env",
            &format!("TOKEN={ID}/custom.token"),
            "--dotenv",
            dest.to_str().unwrap(),
        ],
    ] {
        let out = f.call(&args);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("deleted items cannot be injected"));
        public(&out);
    }
    assert!(!marker.exists());
    assert_eq!(fs::read_to_string(dest).unwrap(), "UNCHANGED=yes\n");
    assert_eq!(
        fs::read_to_string(f.path("calls"))
            .unwrap()
            .lines()
            .filter(|c| *c == "delete")
            .count(),
        1
    );
    assert_eq!(
        f.call(&["delete", ID, "--permanent"]).status.code(),
        Some(2)
    );
}

#[test]
fn delete_rejects_invalid_missing_wrong_and_deleted_targets() {
    let f = Fixture::new();
    let out = f.call(&["delete", "CANARY_INVALID"]);
    assert!(!out.status.success());
    public(&out);
    assert!(
        !fs::read_to_string(f.path("calls"))
            .unwrap()
            .contains("sync")
    );
    for item in [
        json!(null),
        json!({"id":"CANARY_WRONG"}),
        json!({"id":ID,"deletedDate":"CANARY_DATE"}),
    ] {
        fs::write(f.path("item.json"), item.to_string()).unwrap();
        let out = f.call(&["delete", ID]);
        assert!(!out.status.success());
        public(&out);
    }
    fs::write(f.path("missing-item"), "").unwrap();
    let out = f.call(&["delete", ID]);
    assert!(!out.status.success());
    public(&out);
    assert!(
        !fs::read_to_string(f.path("calls"))
            .unwrap()
            .lines()
            .any(|c| c == "delete")
    );
}

#[test]
fn delete_failure_is_uncertain_sanitized_and_not_retried() {
    let f = Fixture::new();
    fs::write(f.path("mutation-fail"), "").unwrap();
    let out = f.call(&["delete", ID]);
    assert!(!out.status.success());
    public(&out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("delete outcome uncertain"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not automatically retried"));
    assert_eq!(
        fs::read_to_string(f.path("calls")).unwrap(),
        "--version\nstatus\nsync\nget\ndelete\n"
    );
    assert!(!f.path("item.json").exists());
}

#[test]
fn delete_reuses_dependency_session_and_lock_guards() {
    for failure in ["bad-version", "session", "lock"] {
        let f = Fixture::new();
        let held = fs::File::open(f.path("vault.lock")).unwrap();
        match failure {
            "bad-version" => fs::write(f.path("bad-version"), "").unwrap(),
            "session" => assert!(f.call(&["lock"]).status.success()),
            "lock" => fs2::FileExt::lock_exclusive(&held).unwrap(),
            _ => unreachable!(),
        }
        let out = f.call(&["delete", ID]);
        assert!(!out.status.success());
        public(&out);
        let calls = fs::read_to_string(f.path("calls")).unwrap_or_default();
        assert!(
            !calls
                .lines()
                .any(|c| matches!(c, "sync" | "get" | "delete"))
        );
    }
}

#[test]
fn stalled_mutation_stdin_does_not_hold_vault_lock() {
    for args in [vec!["create"], vec!["update", ID]] {
        let f = Fixture::new();
        let mut child = f
            .command()
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"{\"login\":")
            .unwrap();
        thread::sleep(Duration::from_millis(250));
        let pending = child.try_wait().unwrap().is_none();
        let out = f.call(&["status"]);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(pending);
        assert!(
            out.status.success(),
            "status must remain available while stdin is open"
        );
        public(&out);
    }
}

#[test]
fn ssh_key_read_preserves_multiline_values_and_metadata_privacy() {
    let f = Fixture::new();
    let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY_SYNTHETIC_KEY\n-----END OPENSSH PRIVATE KEY-----\n";
    fs::write(f.path("item.json"), json!({"id":ID,"name":"ssh-test","type":5,
        "sshKey":{"privateKey":key,"publicKey":"CANARY_PUBLIC","keyFingerprint":"CANARY_FINGERPRINT"}
    }).to_string()).unwrap();
    let listed = f.call(&["list"]);
    assert!(listed.status.success());
    public(&listed);
    assert_eq!(
        serde_json::from_slice::<Value>(&listed.stdout).unwrap()[0]["type"],
        5
    );
    let mappings = [
        format!("KEY={ID}/sshKey.privateKey"),
        format!("PUB={ID}/sshKey.publicKey"),
        format!("FP={ID}/sshKey.keyFingerprint"),
    ];
    let run = f.call(&["run", "--env", &mappings[0], "--env", &mappings[1], "--env", &mappings[2], "--", "/usr/bin/python3", "-c",
        "import os; assert os.environ['KEY'] == '-----BEGIN OPENSSH PRIVATE KEY-----\\nCANARY_SYNTHETIC_KEY\\n-----END OPENSSH PRIVATE KEY-----\\n'; assert os.environ['PUB'] == 'CANARY_PUBLIC'; assert os.environ['FP'] == 'CANARY_FINGERPRINT'; assert 'BW_SESSION' not in os.environ"]);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    public(&run);
    for format in ["--dotenv", "--zshrc"] {
        let path = f.path(if format == "--dotenv" {
            "ssh.env"
        } else {
            "ssh.zsh"
        });
        let written = f.call(&[
            "write",
            "--env",
            &mappings[0],
            format,
            path.to_str().unwrap(),
        ]);
        public(&written);
        if format == "--dotenv" {
            assert!(!written.status.success());
            assert!(!path.exists());
            assert!(
                String::from_utf8_lossy(&written.stderr)
                    .contains("dotenv cannot store a multiline secret")
            );
        } else {
            assert!(written.status.success());
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let output = Command::new("zsh")
                .args(["-fc", "source \"$1\"; print -rn -- \"$KEY\"", "--"])
                .arg(path)
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, key.as_bytes());
        }
    }
}

#[test]
fn browser_cli_enforces_policy_and_private_transport() {
    let f = Fixture::new();
    let item = json!({"id":ID,"type":1,"reprompt":0,"login":{"password":SECRET,"uris":[{"uri":"https://example.test/login","match":3}]}});
    fs::write(f.path("item.json"), item.to_string()).unwrap();
    // Synthetic adapter validates the production CLI's pipe and sanitized env.
    fs::write(f.path("node"), r#"#!/usr/bin/python3
import json, os, sys
assert 'CANARY' not in ' '.join(sys.argv)
assert not any(k in os.environ for k in ['BW_SESSION','NODE_OPTIONS','DEBUG','PWDEBUG','EXTRA_SECRET'])
p = json.load(sys.stdin)
assert p['value'].startswith('CANARY_latch_')
assert p['rules'] == [{'origin':'https://example.test','exact':'https://example.test/login'}]
# Deliberate output must be discarded, even on failures.
print(p['value']); print(p['value'],file=sys.stderr)
sys.exit(10 if p['target']=='reject' else 11 if p['target']=='unknown' else 0)
"#).unwrap();
    fs::set_permissions(f.path("node"), fs::Permissions::from_mode(0o700)).unwrap();
    let run = |target: &str| {
        f.command()
            .env("PATH", f.dir.path())
            .env("NODE_OPTIONS", "--invalid")
            .env("DEBUG", "*")
            .env("EXTRA_SECRET", "CANARY_PARENT")
            .args([
                "browser",
                "fill",
                "--item",
                ID,
                "--endpoint",
                "ws://127.0.0.1:9222/devtools/browser/test",
                "--target",
                target,
                "--selector",
                "#p",
            ])
            .output()
            .unwrap()
    };
    let out = run("target");
    public(&out);
    assert!(out.status.success(), "{:?}", out);
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap(),
        json!({"status":"filled","fields":1})
    );
    for target in ["reject", "unknown"] {
        let out = run(target);
        public(&out);
        assert!(!out.status.success());
    }
    for value in [json!(1), json!(null)] {
        let mut changed = item.clone();
        changed["reprompt"] = value;
        fs::write(f.path("item.json"), changed.to_string()).unwrap();
        let out = run("target");
        public(&out);
        assert!(!out.status.success());
    }
    let calls = fs::read_to_string(f.path("calls")).unwrap();
    assert!(calls.contains("sync\nget\n"));
}

#[test]
fn browser_native_host_cli_discovery_fill_and_disconnect() {
    use std::os::unix::fs::MetadataExt;
    use std::{
        process::{Child, ChildStdin, Stdio},
        sync::Mutex,
    };
    struct Host {
        child: Child,
        input: Arc<Mutex<Option<ChildStdin>>>,
        worker: Option<thread::JoinHandle<()>>,
        socket: PathBuf,
    }
    impl Host {
        fn start(label: &'static str, home: &std::path::Path) -> Self {
            let runtime = home.join(".latch-browser");
            let sockets = || {
                fs::read_dir(&runtime)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path())
                    .collect::<Vec<_>>()
            };
            let before = sockets();
            let mut child = Command::new(env!("CARGO_BIN_EXE_latch"))
                .env("HOME", home)
                .env("LATCH_BROWSER_HOME", home)
                .arg(format!(
                    "chrome-extension://{}/",
                    include_str!("../browser/extension-id.txt").trim()
                ))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut output = child.stdout.take().unwrap();
            let input = Arc::new(Mutex::new(child.stdin.take()));
            let writer = input.clone();
            let worker = thread::spawn(move || {
                loop {
                    let mut header = [0; 4];
                    if output.read_exact(&mut header).is_err() {
                        break;
                    }
                    let mut body = vec![0; u32::from_ne_bytes(header) as usize];
                    output.read_exact(&mut body).unwrap();
                    let req: Value = serde_json::from_slice(&body).unwrap();
                    let reply = if req["op"] == "targets" {
                        assert!(req.get("value").is_none());
                        json!({"status":"ok","targets":[{"handle":ID,"origin":"https://example.test","title":"Login","profile":ID,"label":label,"active":true,"window":1}]})
                    } else {
                        assert_eq!(req["value"], SECRET);
                        assert_eq!(req["handle"], ID);
                        assert_eq!(req["rules"][0]["exact"], "https://example.test/login");
                        if req["selector"] == "#slow" {
                            thread::sleep(Duration::from_secs(11));
                        }
                        if req["selector"] == "#no-reply" {
                            continue; // Chrome consumed the payload but never answers.
                        }
                        if req["selector"] == "#disconnect" {
                            writer.lock().unwrap().take();
                            break;
                        }
                        json!({"status":if req["selector"] == "#reject" {"rejected"} else {"filled"},"value":SECRET,"error":SECRET})
                    };
                    let bytes = serde_json::to_vec(&reply).unwrap();
                    let mut lock = writer.lock().unwrap();
                    let Some(input) = lock.as_mut() else {
                        break;
                    };
                    input
                        .write_all(&(bytes.len() as u32).to_ne_bytes())
                        .unwrap();
                    input.write_all(&bytes).unwrap();
                    input.flush().unwrap();
                }
            });
            let mut socket = None;
            for _ in 0..100 {
                socket = sockets().into_iter().find(|p| !before.contains(p));
                if socket.is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let socket = socket.expect("native host socket");
            assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&runtime).unwrap().mode() & 0o777, 0o700);
            Self {
                child,
                input,
                worker: Some(worker),
                socket,
            }
        }
    }
    impl Drop for Host {
        fn drop(&mut self) {
            self.input.lock().unwrap().take();
            for _ in 0..100 {
                if self.child.try_wait().unwrap().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.worker.take().unwrap().join().unwrap();
            let mut errors = String::new();
            self.child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut errors)
                .unwrap();
            assert!(errors.is_empty());
            assert!(
                !self.socket.exists(),
                "host must clean up socket on Chrome EOF"
            );
        }
    }
    let f = Fixture::new();
    let first = Host::start("Bridge fixture A", f.dir.path());
    let second = Host::start("Bridge fixture B", f.dir.path());
    fs::write(f.path("item.json"),json!({"id":ID,"type":1,"reprompt":0,"login":{"password":SECRET,"uris":[{"uri":"https://example.test/login","match":3}]}}).to_string()).unwrap();
    let stale = f.path(".latch-browser/11111111111111111111111111111111.sock");
    let listener = UnixListener::bind(&stale).unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
    drop(listener);
    let out = f.call(&["browser", "targets", "--item", ID]);
    assert!(
        stale.exists(),
        "refusal must not unlink a potentially busy host"
    );
    public(&out);
    assert!(out.status.success(), "{out:?}");
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["unavailable_connections"], 1);
    let targets = result["targets"].as_array().unwrap();
    let a = targets
        .iter()
        .find(|t| t["label"] == "Bridge fixture A")
        .unwrap()["handle"]
        .as_str()
        .unwrap();
    let b = targets
        .iter()
        .find(|t| t["label"] == "Bridge fixture B")
        .unwrap()["handle"]
        .as_str()
        .unwrap();
    assert_ne!(a, b);
    assert_eq!(
        targets.len(),
        2,
        "only isolated fixture hosts are discovered"
    );
    // Two 11-second fills exceed the old 20-second client timeout when
    // serialized. The second client now waits before sending its payload.
    let other_vault = Fixture::new();
    fs::copy(f.path("item.json"), other_vault.path("item.json")).unwrap();
    thread::scope(|scope| {
        let run = |vault: &Fixture| {
            let out = vault
                .command()
                .env("HOME", f.dir.path())
                .env("LATCH_BROWSER_HOME", f.dir.path())
                .args([
                    "browser",
                    "fill",
                    "--item",
                    ID,
                    "--target",
                    a,
                    "--selector",
                    "#slow",
                ])
                .output()
                .unwrap();
            public(&out);
            assert!(out.status.success(), "{out:?}");
        };
        let f_ref = &f;
        let other_ref = &other_vault;
        let first = scope.spawn(move || run(f_ref));
        let second = scope.spawn(move || run(other_ref));
        first.join().unwrap();
        second.join().unwrap();
    });
    // A caller that abandons the ready queue sends no payload and cannot
    // produce a later native request. Block accept briefly with an idle peer.
    let mut idle = std::os::unix::net::UnixStream::connect(&first.socket).unwrap();
    let mut header = [0; 4];
    idle.read_exact(&mut header).unwrap();
    let mut ready = vec![0; u32::from_ne_bytes(header) as usize];
    idle.read_exact(&mut ready).unwrap();
    let mut abandoned = std::os::unix::net::UnixStream::connect(&first.socket).unwrap();
    abandoned
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(abandoned.read(&mut [0; 1]).is_err());
    drop(abandoned);
    drop(idle);
    for (target, selector, status) in [
        (a, "#p", "filled"),
        (b, "#reject", "rejected"),
        (b, "#disconnect", "outcome_unknown"),
    ] {
        let out = f.call(&[
            "browser",
            "fill",
            "--item",
            ID,
            "--target",
            target,
            "--selector",
            selector,
        ]);
        public(&out);
        assert_eq!(out.status.success(), status == "filled", "{out:?}");
        assert_eq!(
            serde_json::from_slice::<Value>(&out.stdout).unwrap()["status"],
            status
        );
    }
    let out = f.call(&[
        "browser",
        "fill",
        "--item",
        ID,
        "--target",
        a,
        "--selector",
        "#no-reply",
    ]);
    public(&out);
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["status"],
        "outcome_unknown"
    );
    drop(second);
    drop(first);
    let out = f.call(&[
        "browser",
        "fill",
        "--item",
        ID,
        "--target",
        a,
        "--selector",
        "#p",
    ]);
    public(&out);
    assert!(!out.status.success());
    // A stopped Chrome reader must not block native pipe writes forever. This
    // payload exceeds pipe capacity; never read or print the host's stdout.
    let runtime = f.path(".latch-browser");
    let before = fs::read_dir(&runtime)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect::<Vec<_>>();
    let mut stalled = Command::new(env!("CARGO_BIN_EXE_latch"))
        .env("HOME", f.dir.path())
        .env("LATCH_BROWSER_HOME", f.dir.path())
        .arg(format!(
            "chrome-extension://{}/",
            include_str!("../browser/extension-id.txt").trim()
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut socket = None;
    for _ in 0..100 {
        socket = fs::read_dir(&runtime)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| !before.contains(p));
        if socket.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let socket = socket.unwrap();
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut ready_header = [0; 4];
    stream.read_exact(&mut ready_header).unwrap();
    let mut ready = vec![0; u32::from_ne_bytes(ready_header) as usize];
    stream.read_exact(&mut ready).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&ready).unwrap(),
        json!({"status":"ready"})
    );
    let bytes = serde_json::to_vec(&json!({"op":"fill","handle":ID,"selector":"#p",
        "rules":[{"origin":"https://example.test","exact":null}],"value":"X".repeat(128*1024)}))
    .unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_ne_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let mut reply = vec![0; u32::from_ne_bytes(header) as usize];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply).unwrap(),
        json!({"status":"outcome_unknown"})
    );
    for _ in 0..100 {
        if stalled.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let exited = stalled.try_wait().unwrap().is_some();
    if !exited {
        let _ = stalled.kill();
    }
    let _ = stalled.wait();
    assert!(exited, "native write timeout must terminate the host");
    assert!(!socket.exists());
}

#[test]
fn browser_install_is_vault_independent_and_host_origin_is_silent() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_latch"))
        .env("HOME", dir.path().join("isolated-agent-home"))
        .env("LATCH_BROWSER_HOME", dir.path())
        .args(["browser", "install-host", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(result["manifest"].as_str().unwrap()).unwrap()).unwrap();
    assert!(
        result["manifest"].as_str().unwrap().starts_with(
            dir.path()
                .join("Library/Application Support")
                .to_str()
                .unwrap()
        )
    );
    assert_eq!(manifest["path"], env!("CARGO_BIN_EXE_latch"));
    assert_eq!(manifest["allowed_origins"].as_array().unwrap().len(), 1);
    let extension = PathBuf::from(result["extension_path"].as_str().unwrap());
    for file in [
        "manifest.json",
        "worker.js",
        "fill.js",
        "setup.js",
        "setup.html",
    ] {
        assert!(extension.join(file).is_file());
    }
    let out = Command::new(env!("CARGO_BIN_EXE_latch"))
        .arg("chrome-extension://wrong/")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
}
