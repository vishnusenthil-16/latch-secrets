//! Agent-neutral native messaging transport. Chrome owns host lifetime; no daemon.
use anyhow::{Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const LIMIT: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);
const HOST: &str = "com.latch_secrets.browser";
const EXTENSION_ID: &str = include_str!("../browser/extension-id.txt");

fn uid() -> u32 {
    // SAFETY: geteuid takes no arguments and has no preconditions.
    unsafe { libc::geteuid() }
}
fn runtime_dir() -> Result<PathBuf> {
    // Private per-user location, independent of vault state-dir. Chrome and
    // CLI must share HOME; tests use a disposable home for isolation.
    let home =
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME unavailable"))?);
    ensure!(home.is_absolute(), "HOME must be absolute");
    let dir = home.join(".latch-browser");
    match fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => bail!("browser runtime directory unavailable"),
    }
    let meta = fs::symlink_metadata(&dir)?;
    ensure!(
        meta.is_dir() && meta.uid() == uid() && meta.mode() & 0o077 == 0,
        "insecure browser runtime directory"
    );
    Ok(dir)
}
fn verify_peer(stream: &UnixStream) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let (mut user, mut group) = (0, 0);
        // SAFETY: output pointers are valid, and stream owns a live socket.
        let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut user, &mut group) };
        ensure!(result == 0 && user == uid(), "unauthorized browser peer");
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = stream;
        bail!("browser bridge currently supports macOS only");
    }
    Ok(())
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn valid_instance(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit())
}
fn valid_handle(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok() && s.len() == 36
}

// Both native messaging and local IPC use bounded length-prefixed JSON frames.
fn read_frame(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_ne_bytes(header) as usize;
    ensure!(len > 0 && len <= LIMIT, "invalid browser frame size");
    let mut bytes = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= LIMIT,
        "invalid browser frame size"
    );
    writer.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    origin: String,
    exact: Option<String>,
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Targets {
        rules: Vec<Rule>,
    },
    Fill {
        rules: Vec<Rule>,
        handle: String,
        selector: String,
        value: String,
    },
}
fn validate_request(bytes: &[u8]) -> Result<bool> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid browser request"))?;
    let (rules, fill) = match &request {
        Request::Targets { rules } => (rules, false),
        Request::Fill {
            rules,
            handle,
            selector,
            value,
        } => {
            ensure!(
                valid_handle(handle)
                    && !selector.is_empty()
                    && selector.len() <= 4096
                    && !value.is_empty(),
                "invalid fill request"
            );
            (rules, true)
        }
    };
    ensure!(
        !rules.is_empty() && rules.len() <= 256,
        "invalid destination rules"
    );
    for rule in rules {
        let url = url::Url::parse(&rule.origin).map_err(|_| anyhow::anyhow!("invalid origin"))?;
        ensure!(
            url.scheme() == "https" && url.origin().ascii_serialization() == rule.origin,
            "invalid origin"
        );
        if let Some(exact) = &rule.exact {
            let u = url::Url::parse(exact).map_err(|_| anyhow::anyhow!("invalid exact URL"))?;
            ensure!(
                u.origin() == url.origin() && u.username().is_empty() && u.password().is_none(),
                "invalid exact URL"
            );
        }
    }
    Ok(fill)
}
// Reconstruct replies from a fixed allowlist: never relay exception messages or arbitrary fields.
fn sanitize_reply(bytes: &[u8], fill: bool) -> Result<Value> {
    let v: Value =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid bridge response"))?;
    if fill {
        return Ok(match v["status"].as_str() {
            Some("filled") => json!({"status":"filled","fields":1}),
            Some("rejected") => json!({"status":"rejected"}),
            _ => json!({"status":"outcome_unknown"}),
        });
    }
    ensure!(v["status"] == "ok", "browser discovery rejected");
    let targets = v["targets"]
        .as_array()
        .filter(|a| a.len() <= 128)
        .ok_or_else(|| anyhow::anyhow!("invalid target list"))?;
    let mut result = Vec::new();
    for t in targets {
        let handle = t["handle"]
            .as_str()
            .filter(|s| valid_handle(s))
            .ok_or_else(|| anyhow::anyhow!("invalid handle"))?;
        let origin = t["origin"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid origin"))?;
        let u = url::Url::parse(origin)?;
        ensure!(
            u.scheme() == "https" && u.origin().ascii_serialization() == origin,
            "invalid origin"
        );
        let profile = t["profile"]
            .as_str()
            .filter(|s| valid_handle(s))
            .ok_or_else(|| anyhow::anyhow!("invalid profile"))?;
        result.push(json!({"handle":handle,"origin":origin,"profile":profile,
            "title":t["title"].as_str().unwrap_or("").chars().take(256).collect::<String>(),
            "label":t["label"].as_str().unwrap_or("").chars().take(80).collect::<String>(),
            "active":t["active"].as_bool().unwrap_or(false),"window":t["window"].as_i64()}));
    }
    Ok(json!({"status":"ok","targets":result}))
}
struct SocketFile(PathBuf);
impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub(crate) fn serve(origin: &str) -> Result<()> {
    ensure!(
        origin == format!("chrome-extension://{}/", EXTENSION_ID.trim()),
        "unauthorized extension"
    );
    let path = runtime_dir()?.join(format!("{}.sock", random_id()?));
    let listener = UnixListener::bind(&path)?;
    let _cleanup = SocketFile(path.clone());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    // A bounded reader detects Chrome EOF even when no CLI is connected.
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        loop {
            let frame = read_frame(&mut input);
            let failed = frame.is_err();
            if tx.send(frame).is_err() || failed {
                break;
            }
        }
    });
    // Chrome may stop reading its pipe. Keep writes off the dispatcher so the
    // deadline also covers a full native pipe, not only waiting for the reply.
    let (out_tx, out_rx) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(1);
    let (ack_tx, ack_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut output = std::io::stdout().lock();
        while let Ok(bytes) = out_rx.recv() {
            let result = write_frame(&mut output, &bytes);
            drop(bytes);
            let failed = result.is_err();
            if ack_tx.send(result).is_err() || failed {
                break;
            }
        }
    });
    loop {
        // There are no unsolicited native messages in this protocol.
        match rx.try_recv() {
            Err(mpsc::TryRecvError::Empty) => (),
            _ => return Ok(()),
        }
        let (mut stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => bail!("browser listener failed"),
        };
        // macOS accepted sockets inherit the listener's nonblocking flag.
        if stream.set_nonblocking(false).is_err()
            || verify_peer(&stream).is_err()
            || stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .is_err()
            || stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .is_err()
        {
            continue;
        }
        // Do not accept a payload until this host is ready to dispatch it. A
        // caller that times out in the backlog never sends a password.
        if write_frame(&mut stream, br#"{"status":"ready"}"#).is_err() {
            continue;
        }
        let Ok(bytes) = read_frame(&mut stream) else {
            continue;
        };
        let Ok(fill) = validate_request(&bytes) else {
            let _ = write_frame(&mut stream, br#"{"status":"rejected"}"#);
            continue;
        };
        // Once dispatched, an interruption is uncertain. End this connection on timeout;
        // a late response can never be mistaken for a subsequent request's result.
        let deadline = Instant::now() + TIMEOUT;
        let sent = out_tx.send(bytes).is_ok() && matches!(ack_rx.recv_timeout(TIMEOUT), Ok(Ok(())));
        let response = if sent {
            rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .ok()
                .and_then(Result::ok)
        } else {
            None
        };
        let Some(response) = response else {
            let _ = write_frame(&mut stream, br#"{"status":"outcome_unknown"}"#);
            return Ok(());
        };
        let sanitized = sanitize_reply(&response, fill)
            .unwrap_or_else(|_| json!({"status":if fill {"outcome_unknown"} else {"rejected"}}));
        let _ = write_frame(&mut stream, &serde_json::to_vec(&sanitized)?);
    }
}
fn connect(instance: &str) -> Result<UnixStream> {
    ensure!(valid_instance(instance), "invalid browser target");
    let path = runtime_dir()?.join(format!("{instance}.sock"));
    let m = fs::symlink_metadata(&path).map_err(|_| {
        anyhow::anyhow!(
            "browser bridge unavailable; reconnect extension and discover targets again"
        )
    })?;
    ensure!(
        m.file_type().is_socket() && m.uid() == uid() && m.mode() & 0o077 == 0,
        "insecure browser socket"
    );
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        // Only ECONNREFUSED proves there is no listener. Never unlink a busy
        // or inaccessible socket. The directory is private to this user.
        if e.kind() == std::io::ErrorKind::ConnectionRefused {
            let _ = fs::remove_file(&path);
        }
        anyhow::anyhow!("browser bridge unavailable")
    })?;
    verify_peer(&stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let ready = read_frame(&mut stream)
        .map_err(|_| anyhow::anyhow!("browser bridge busy or unavailable; no request sent"))?;
    ensure!(
        &*ready == br#"{"status":"ready"}"#,
        "incompatible browser host; reconnect extension"
    );
    Ok(stream)
}
pub(crate) fn targets(rules: &[Value]) -> Result<Value> {
    let request = serde_json::to_vec(&json!({"op":"targets","rules":rules}))?;
    let mut targets = Vec::new();
    let mut connected = 0;
    let mut unavailable = 0;
    for entry in fs::read_dir(runtime_dir()?)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(instance) = name
            .to_str()
            .and_then(|s| s.strip_suffix(".sock"))
            .filter(|s| valid_instance(s))
        else {
            continue;
        };
        let Ok(mut stream) = connect(instance) else {
            continue;
        };
        connected += 1;
        let result = (|| -> Result<Value> {
            write_frame(&mut stream, &request)?;
            sanitize_reply(&read_frame(&mut stream)?, false)
        })();
        let Ok(mut result) = result else {
            unavailable += 1;
            continue;
        };
        for t in result["targets"].as_array_mut().expect("sanitized targets") {
            t["handle"] = json!(format!(
                "{instance}.{}",
                t["handle"].as_str().expect("sanitized handle")
            ));
            targets.push(t.clone());
        }
    }
    ensure!(
        connected > 0,
        "browser bridge unavailable; install host, enable extension and connect"
    );
    ensure!(
        connected > unavailable,
        "browser discovery unavailable; reconnect extension"
    );
    Ok(json!({"targets":targets,"unavailable_connections":unavailable,"expires_in_seconds":60}))
}
pub(crate) fn validate_target(target: &str, selector: &str) -> Result<()> {
    let (instance, handle) = target
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("discover a browser target handle first"))?;
    ensure!(
        valid_instance(instance)
            && valid_handle(handle)
            && !selector.is_empty()
            && selector.len() <= 4096,
        "invalid browser target or selector"
    );
    Ok(())
}
pub(crate) fn fill(payload: &[u8]) -> Result<Value> {
    let mut v: Value = serde_json::from_slice(payload)?;
    let target = v["target"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid target"))?;
    let (instance, handle) = target
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("invalid target"))?;
    let mut stream = connect(instance)?; // no dispatch yet; unavailable is a definite rejection
    let request = Zeroizing::new(serde_json::to_vec(&json!({"op":"fill","handle":handle,
        "rules":v["rules"],"selector":v["selector"],"value":v["value"]}))?);
    v["value"] = Value::Null;
    validate_request(&request)?;
    let result = (|| -> Result<Value> {
        write_frame(&mut stream, &request)?;
        sanitize_reply(&read_frame(&mut stream)?, true)
    })();
    Ok(result.unwrap_or_else(|_| json!({"status":"outcome_unknown"})))
}

pub(crate) fn install(browser: &str, user_data_dir: Option<&Path>) -> Result<Value> {
    ensure!(
        cfg!(target_os = "macos"),
        "browser host installation currently supports macOS only"
    );
    let vendor = match browser {
        "chrome" => "Google/Chrome",
        "chrome-beta" => "Google/Chrome Beta",
        "chrome-canary" => "Google/Chrome Canary",
        "chromium" => "Chromium",
        "chrome-for-testing" => "Google/Chrome for Testing",
        _ => bail!(
            "supported browsers: chrome, chrome-beta, chrome-canary, chromium, chrome-for-testing"
        ),
    };
    let home =
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME unavailable"))?);
    let support = home.join("Library/Application Support");
    let extension = support.join("Latch/browser-extension");
    if let Some(dir) = user_data_dir {
        ensure!(dir.is_absolute(), "user-data-dir must be absolute");
    }
    let manifest_dir = user_data_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| support.join(vendor))
        .join("NativeMessagingHosts");
    fs::create_dir_all(&manifest_dir)?;
    let manifest = manifest_dir.join(format!("{HOST}.json"));
    let contents = serde_json::to_vec_pretty(
        &json!({"name":HOST,"description":"Latch private password delivery",
        "path":std::env::current_exe()?,"type":"stdio","allowed_origins":[format!("chrome-extension://{}/",EXTENSION_ID.trim())]}),
    )?;
    // Do not silently replace another application's registration under our name.
    if manifest.exists() {
        let old: Value = serde_json::from_slice(&fs::read(&manifest)?)?;
        ensure!(
            old["name"] == HOST
                && old["allowed_origins"]
                    == json!([format!("chrome-extension://{}/", EXTENSION_ID.trim())]),
            "existing native host registration conflicts with Latch"
        );
    }
    fs::create_dir_all(&extension)?;
    for (name, contents) in [
        (
            "manifest.json",
            include_str!("../browser/extension/manifest.json"),
        ),
        ("worker.js", include_str!("../browser/extension/worker.js")),
        ("fill.js", include_str!("../browser/extension/fill.js")),
        (
            "setup.html",
            include_str!("../browser/extension/setup.html"),
        ),
        ("setup.js", include_str!("../browser/extension/setup.js")),
    ] {
        atomic_write(&extension.join(name), contents.as_bytes())?;
    }
    atomic_write(&manifest, &contents)?;
    Ok(
        json!({"installed":true,"manifest":manifest,"extension_path":extension,"extension_id":EXTENSION_ID.trim(),
        "next":"Load unpacked extension from extension_path in chrome://extensions, then grant HTTPS site access in its popup. Re-run install-host after moving or upgrading the Latch binary."}),
    )
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().expect("installation path parent"))?;
    file.write_all(bytes)?;
    file.persist(path)
        .map_err(|_| anyhow::anyhow!("could not install browser files"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_frames_and_strict_protocol() {
        for size in [0u32, LIMIT as u32 + 1, u32::MAX] {
            assert!(read_frame(&mut &size.to_ne_bytes()[..]).is_err());
        }
        let mut bytes = Vec::new();
        write_frame(&mut bytes, b"{}").unwrap();
        assert_eq!(&*read_frame(&mut &bytes[..]).unwrap(), b"{}");
        assert!(validate_request(br#"{"op":"eval","code":"CANARY"}"#).is_err());
        assert!(validate_request(br#"{"op":"targets","rules":[{"origin":"https://example.com","exact":null}],"extra":"CANARY"}"#).is_err());
        assert!(
            !validate_request(
                br#"{"op":"targets","rules":[{"origin":"https://example.com","exact":null}]}"#
            )
            .unwrap()
        );
    }
    #[test]
    fn response_allowlist_and_path_traversal() {
        let response = sanitize_reply(
            br#"{"status":"filled","value":"CANARY","error":"CANARY"}"#,
            true,
        )
        .unwrap();
        assert_eq!(response, json!({"status":"filled","fields":1}));
        assert_eq!(
            sanitize_reply(br#"{"error":"CANARY"}"#, true).unwrap()["status"],
            "outcome_unknown"
        );
        assert!(validate_target("../../file", "#p").is_err());
        assert!(serve("chrome-extension://wrong/").is_err());
    }
}
