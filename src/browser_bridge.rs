//! Agent-neutral native messaging transport. Chrome owns host lifetime; no daemon.
use anyhow::{Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    ffi::{CStr, OsStr},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
// Resolve the OS account, not an agent-specific HOME environment override.
fn account_home() -> Result<PathBuf> {
    let mut buffer = vec![0u8; 4096];
    loop {
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: record, result and buffer are writable for the supplied sizes.
        let code = unsafe {
            libc::getpwuid_r(
                uid(),
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if code == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        ensure!(
            code == 0 && !result.is_null(),
            "OS account home unavailable"
        );
        // SAFETY: success with a non-null result initializes record; pw_dir is
        // a NUL-terminated string in buffer, copied before buffer is dropped.
        let record = unsafe { record.assume_init() };
        ensure!(!record.pw_dir.is_null(), "OS account home unavailable");
        let home = PathBuf::from(OsStr::from_bytes(unsafe {
            CStr::from_ptr(record.pw_dir).to_bytes()
        }));
        ensure!(home.is_absolute(), "OS account home must be absolute");
        return Ok(home);
    }
}
fn browser_home() -> Result<PathBuf> {
    // Explicit isolation override for synthetic tests. Both processes must agree.
    if let Some(home) = std::env::var_os("LATCH_BROWSER_HOME") {
        let home = PathBuf::from(home);
        ensure!(home.is_absolute(), "LATCH_BROWSER_HOME must be absolute");
        return Ok(home);
    }
    account_home()
}
fn runtime_dir() -> Result<PathBuf> {
    let home = browser_home()?;
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
    #[cfg(target_os = "linux")]
    {
        let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: stream owns a live socket; credentials and length are writable
        // for their supplied sizes. Read credentials only after a complete result.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut length,
            )
        };
        ensure!(
            result == 0 && length as usize == std::mem::size_of::<libc::ucred>(),
            "unauthorized browser peer"
        );
        // SAFETY: the successful getsockopt above initialized the whole value.
        ensure!(
            unsafe { credentials.assume_init() }.uid == uid(),
            "unauthorized browser peer"
        );
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = stream;
        bail!("browser bridge supports macOS and Linux only");
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
// Socket deadlines cover the entire header and body, not each successful read.
// Native stdin/stdout stay on dedicated threads bounded by the dispatch deadline.
fn socket_wait(stream: &UnixStream, events: libc::c_short, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "browser frame deadline exceeded");
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        // SAFETY: descriptor is initialized and writable for exactly one pollfd;
        // the borrowed stream keeps its descriptor live through the call.
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result > 0 {
            ensure!(
                descriptor.revents & libc::POLLNVAL == 0,
                "browser socket unavailable"
            );
            return Ok(());
        }
        if result == 0 {
            bail!("browser frame deadline exceeded");
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}
fn socket_read_exact(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    while !bytes.is_empty() {
        ensure!(Instant::now() < deadline, "browser frame deadline exceeded");
        match stream.read(bytes) {
            Ok(0) => bail!("browser connection closed"),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                socket_wait(stream, libc::POLLIN, deadline)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn read_socket_frame_until(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>> {
    stream.set_nonblocking(true)?;
    let mut header = [0; 4];
    socket_read_exact(stream, &mut header, deadline)?;
    let length = u32::from_ne_bytes(header) as usize;
    ensure!(length > 0 && length <= LIMIT, "invalid browser frame size");
    let mut bytes = Zeroizing::new(vec![0; length]);
    socket_read_exact(stream, &mut bytes, deadline)?;
    Ok(bytes)
}
fn write_socket_frame_until(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= LIMIT,
        "invalid browser frame size"
    );
    stream.set_nonblocking(true)?;
    let header = (bytes.len() as u32).to_ne_bytes();
    for mut part in [&header[..], bytes] {
        while !part.is_empty() {
            ensure!(Instant::now() < deadline, "browser frame deadline exceeded");
            match stream.write(part) {
                Ok(0) => bail!("browser connection closed"),
                Ok(count) => part = &part[count..],
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    socket_wait(stream, libc::POLLOUT, deadline)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}
fn read_socket_frame(stream: &mut UnixStream, timeout: Duration) -> Result<Zeroizing<Vec<u8>>> {
    read_socket_frame_until(stream, Instant::now() + timeout)
}
fn write_socket_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    write_socket_frame_until(stream, bytes, Instant::now() + Duration::from_secs(2))
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
// A lock proves liveness, never a successful connection. IDs are never reused.
struct InstanceFiles {
    lock: File,
    path: PathBuf,
}
fn same_lock(file: &File, path: &Path) -> bool {
    let (Ok(fd), Ok(named)) = (file.metadata(), fs::symlink_metadata(path)) else {
        return false;
    };
    fd.nlink() == 1 && fd.dev() == named.dev() && fd.ino() == named.ino()
}
impl InstanceFiles {
    fn create(mut path: PathBuf) -> Result<Self> {
        for _ in 0..16 {
            #[cfg(target_os = "macos")]
            let flags = libc::O_EXLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            #[cfg(not(target_os = "macos"))]
            let flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(flags)
                .open(&path)?;
            // Linux cannot acquire flock atomically with open. A cleaner may
            // acquire the new inode first and unlink it. Lock, then verify the
            // named inode before authorizing socket bind. macOS O_EXLOCK needs
            // the same recheck because the inode can become visible beforehand.
            #[cfg(not(target_os = "macos"))]
            fs2::FileExt::lock_exclusive(&lock)?;
            if same_lock(&lock, &path) {
                return Ok(Self { lock, path });
            }
            // Never bind on an unlinked inode or reuse its instance ID.
            path = path.with_file_name(format!("{}.lock", random_id()?));
        }
        bail!("browser lock startup contention; reconnect extension")
    }
    fn remove(&self) {
        if !same_lock(&self.lock, &self.path) {
            return;
        }
        let socket = self.path.with_extension("sock");
        match fs::symlink_metadata(&socket) {
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == uid() => {
                // Retain the lockfile if removal fails, so a later sweep can retry.
                if let Err(e) = fs::remove_file(&socket)
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return,
        }
        let _ = fs::remove_file(&self.path);
    }
}
impl Drop for InstanceFiles {
    fn drop(&mut self) {
        self.remove();
    }
}
fn cleanup_instances(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|s| s.strip_suffix(".lock")) else {
            continue;
        };
        if id.len() != 32
            || !id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            continue;
        }
        let path = entry.path();
        let Ok(lock) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
        else {
            continue;
        };
        let Ok(meta) = lock.metadata() else {
            continue;
        };
        if !meta.is_file() || meta.uid() != uid() || meta.mode() & 0o077 != 0 {
            continue;
        }
        if fs2::FileExt::try_lock_exclusive(&lock).is_err() || !same_lock(&lock, &path) {
            continue;
        }
        // Drop removes socket before lockfile, while the descriptor remains locked.
        drop(InstanceFiles { lock, path });
    }
}

pub(crate) fn serve(origin: &str) -> Result<()> {
    ensure!(
        origin == format!("chrome-extension://{}/", EXTENSION_ID.trim()),
        "unauthorized extension"
    );
    let dir = runtime_dir()?;
    cleanup_instances(&dir);
    let files = InstanceFiles::create(dir.join(format!("{}.lock", random_id()?)))?;
    let path = files.path.with_extension("sock");
    let listener = UnixListener::bind(&path)?;
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
        if verify_peer(&stream).is_err() {
            continue;
        }
        // Do not accept a payload until this host is ready to dispatch it. A
        // caller that times out in the backlog never sends a password.
        if write_socket_frame(&mut stream, br#"{"status":"ready"}"#).is_err() {
            continue;
        }
        let Ok(bytes) = read_socket_frame(&mut stream, Duration::from_secs(2)) else {
            continue;
        };
        let Ok(fill) = validate_request(&bytes) else {
            let _ = write_socket_frame(&mut stream, br#"{"status":"rejected"}"#);
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
            let _ = write_socket_frame(&mut stream, br#"{"status":"outcome_unknown"}"#);
            return Ok(());
        };
        let sanitized = sanitize_reply(&response, fill)
            .unwrap_or_else(|_| json!({"status":if fill {"outcome_unknown"} else {"rejected"}}));
        let _ = write_socket_frame(&mut stream, &serde_json::to_vec(&sanitized)?);
    }
}
fn connect(instance: &str, ready_timeout: Duration) -> Result<UnixStream> {
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
    // Refusal can also mean a full BSD listen backlog. Never unlink on
    // connection failure: it is not evidence that the owning host is dead.
    let deadline = Instant::now() + ready_timeout;
    let mut stream = crate::session::connect_with_timeout(&path, ready_timeout)
        .map_err(|_| anyhow::anyhow!("browser bridge unavailable at {}", path.display()))?;
    verify_peer(&stream)?;
    let ready = read_socket_frame_until(&mut stream, deadline)
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
    let dir = runtime_dir()?;
    cleanup_instances(&dir);
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(instance) = name
            .to_str()
            .and_then(|s| s.strip_suffix(".sock"))
            .filter(|s| valid_instance(s))
        else {
            continue;
        };
        connected += 1;
        let Ok(mut stream) = connect(instance, Duration::from_secs(2)) else {
            unavailable += 1;
            continue;
        };
        let result = (|| -> Result<Value> {
            write_socket_frame(&mut stream, &request)?;
            sanitize_reply(
                &read_socket_frame(&mut stream, Duration::from_secs(20))?,
                false,
            )
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
        "browser bridge unavailable in {}; install host, enable extension and connect",
        dir.display()
    );
    ensure!(
        connected > unavailable,
        "browser discovery unavailable in {}; host busy or disconnected",
        dir.display()
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
    let mut stream = connect(instance, Duration::from_secs(20))?; // no dispatch yet; unavailable is a definite rejection
    let request = Zeroizing::new(serde_json::to_vec(&json!({"op":"fill","handle":handle,
        "rules":v["rules"],"selector":v["selector"],"value":v["value"]}))?);
    v["value"] = Value::Null;
    validate_request(&request)?;
    let result = (|| -> Result<Value> {
        write_socket_frame(&mut stream, &request)?;
        sanitize_reply(
            &read_socket_frame(&mut stream, Duration::from_secs(20))?,
            true,
        )
    })();
    Ok(result.unwrap_or_else(|_| json!({"status":"outcome_unknown"})))
}

// Keep browser installation independent of vault configuration. An explicit test
// home also isolates XDG paths so synthetic tests cannot touch the real profile.
fn installation_paths(browser: &str, user_data_dir: Option<&Path>) -> Result<(PathBuf, PathBuf)> {
    if let Some(dir) = user_data_dir {
        ensure!(dir.is_absolute(), "user-data-dir must be absolute");
    }
    let home = browser_home()?;
    #[cfg(target_os = "macos")]
    let (support, extension, vendor) = {
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
        let support = home.join("Library/Application Support");
        let extension = support.join("Latch/browser-extension");
        (support, extension, vendor)
    };
    #[cfg(target_os = "linux")]
    let (support, extension, vendor) = {
        let vendor = match browser {
            "chrome" => "google-chrome",
            "chrome-beta" => "google-chrome-beta",
            "chrome-dev" => "google-chrome-unstable",
            "chromium" => "chromium",
            "chrome-for-testing" => "google-chrome-for-testing",
            _ => bail!(
                "supported Linux browsers: chrome, chrome-beta, chrome-dev, chromium, chrome-for-testing"
            ),
        };
        let support = if std::env::var_os("LATCH_BROWSER_HOME").is_some() {
            home.join(".config")
        } else {
            xdg_config_home(&home, std::env::var_os("XDG_CONFIG_HOME"))?
        };
        let extension = support.join("latch-secrets/browser-extension");
        (support, extension, vendor)
    };
    let manifest_dir = user_data_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| support.join(vendor))
        .join("NativeMessagingHosts");
    Ok((manifest_dir, extension))
}

#[cfg(target_os = "linux")]
fn xdg_config_home(home: &Path, value: Option<std::ffi::OsString>) -> Result<PathBuf> {
    match value.filter(|value| !value.is_empty()) {
        Some(value) => {
            let path = PathBuf::from(value);
            ensure!(path.is_absolute(), "XDG_CONFIG_HOME must be absolute");
            Ok(path)
        }
        None => Ok(home.join(".config")),
    }
}

pub(crate) fn install(browser: &str, user_data_dir: Option<&Path>) -> Result<Value> {
    let (manifest_dir, extension) = installation_paths(browser, user_data_dir)?;
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
    fn cleanup_lock_lifecycle_and_foreign_entries() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let path = |n: u32| dir.path().join(format!("{n:032x}.lock"));
        let live = InstanceFiles::create(path(1)).unwrap();
        let socket = live.path.with_extension("sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        cleanup_instances(dir.path());
        assert!(socket.exists()); // A separate open in this process cannot take our lock.
        drop(live);
        assert!(!socket.exists());
        assert!(!path(1).exists());

        // Simulate crash leftovers: lock only and bind-before-chmod socket.
        for n in [2, 3] {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path(n))
                .unwrap();
        }
        let dead_socket = path(3).with_extension("sock");
        let _dead = UnixListener::bind(&dead_socket).unwrap();
        fs::set_permissions(&dead_socket, fs::Permissions::from_mode(0o777)).unwrap();
        let legacy = path(4).with_extension("sock");
        let _legacy = UnixListener::bind(&legacy).unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, path(5)).unwrap();
        let fifo = std::ffi::CString::new(path(6).as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        fs::write(path(7), b"").unwrap();
        fs::set_permissions(path(7), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(dir.path().join("bad.lock"), b"").unwrap();
        cleanup_instances(dir.path());
        assert!(!path(2).exists());
        assert!(!path(3).exists());
        assert!(!dead_socket.exists());
        assert!(legacy.exists());
        assert_eq!(fs::read(target).unwrap(), b"untouched");
        for n in [5, 6, 7] {
            assert!(fs::symlink_metadata(path(n)).is_ok());
        }
        assert!(dir.path().join("bad.lock").exists());

        // A descriptor to an unlinked inode must not authorize deleting a replacement.
        let old = InstanceFiles::create(path(8)).unwrap();
        fs::remove_file(path(8)).unwrap();
        let replacement = InstanceFiles::create(path(8)).unwrap();
        assert!(!same_lock(&old.lock, &old.path));
        drop(old);
        assert!(path(8).exists());
        drop(replacement);
    }

    #[test]
    fn cleanup_races_startup_and_other_cleaners() {
        let dir = tempfile::Builder::new()
            .prefix("lc-")
            .tempdir_in("/tmp")
            .unwrap();
        for _ in 0..32 {
            let path = dir.path().join(format!("{}.lock", random_id().unwrap()));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            let socket = path.with_extension("sock");
            drop(UnixListener::bind(socket).unwrap());
        }
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let dir = dir.path();
                scope.spawn(move || {
                    for _ in 0..1000 {
                        cleanup_instances(dir);
                        std::thread::yield_now();
                    }
                });
            }
            for _ in 0..200 {
                let lock = InstanceFiles::create(
                    dir.path().join(format!("{}.lock", random_id().unwrap())),
                )
                .unwrap();
                let socket = lock.path.with_extension("sock");
                let listener = UnixListener::bind(&socket).unwrap();
                std::thread::yield_now();
                assert!(lock.path.exists());
                assert!(UnixStream::connect(&socket).is_ok());
                drop(listener);
                let path = lock.path.clone();
                drop(lock);
                assert!(!path.exists());
            }
        });
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn slow_frame_trickle_cannot_extend_total_read_deadline() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            writer
                .set_write_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            writer.write_all(&64u32.to_ne_bytes()).unwrap();
            for _ in 0..64 {
                if writer.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let start = Instant::now();
        assert!(read_socket_frame_until(&mut reader, start + Duration::from_millis(50)).is_err());
        assert!(start.elapsed() < Duration::from_millis(250));
        drop(reader);
        sender.join().unwrap();
    }

    #[test]
    fn slow_frame_reader_cannot_extend_total_write_deadline() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let size: libc::c_int = 4096;
        // SAFETY: writer owns the socket and size is a valid c_int of the supplied size.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    writer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        let receiver = std::thread::spawn(move || {
            reader.set_nonblocking(true).unwrap();
            let until = Instant::now() + Duration::from_millis(300);
            let mut count = 0;
            while Instant::now() < until {
                match reader.read(&mut [0; 128]) {
                    Ok(0) => break,
                    Ok(size) => count += size,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(error) => panic!("unexpected socket read error: {error}"),
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            count
        });
        let start = Instant::now();
        assert!(
            write_socket_frame_until(
                &mut writer,
                &vec![b'x'; LIMIT],
                start + Duration::from_millis(50)
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_millis(250));
        drop(writer);
        assert!(receiver.join().unwrap() > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn saturated_accept_queue_fails_before_sending_a_frame() {
        let dir = tempfile::Builder::new()
            .prefix("lb-")
            .tempdir_in("/tmp")
            .unwrap();
        let path = dir.path().join("blocked.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // SAFETY: listener is a live listening socket. Limit its queue to one
        // pending connection (Linux permits backlog + 1); deliberately never accept.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let _queued =
            crate::session::connect_with_timeout(&path, Duration::from_millis(100)).unwrap();
        let start = Instant::now();
        assert!(crate::session::connect_with_timeout(&path, Duration::from_millis(50)).is_err());
        assert!(start.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn peer_identity_is_verified_on_both_connected_endpoints() {
        let (client, server) = UnixStream::pair().unwrap();
        verify_peer(&client).unwrap();
        verify_peer(&server).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_xdg_paths_require_absolute_overrides() {
        let home = Path::new("/home/test");
        assert_eq!(xdg_config_home(home, None).unwrap(), home.join(".config"));
        assert_eq!(
            xdg_config_home(home, Some("".into())).unwrap(),
            home.join(".config")
        );
        assert_eq!(
            xdg_config_home(home, Some("/custom/config".into())).unwrap(),
            Path::new("/custom/config")
        );
        assert!(xdg_config_home(home, Some("relative".into())).is_err());
        assert!(installation_paths("chrome-canary", None).is_err());
        assert!(installation_paths("chromium", Some(Path::new("relative"))).is_err());
    }

    #[test]
    fn os_account_home_ignores_agent_home() {
        if std::env::var_os("LATCH_HOME_TEST_CHILD").is_some() {
            let home = account_home().unwrap();
            assert!(home.is_absolute());
            assert_ne!(home, PathBuf::from("/nonexistent-latch-agent-home"));
            assert_eq!(browser_home().unwrap(), home);
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "browser_bridge::tests::os_account_home_ignores_agent_home",
            ])
            .env("LATCH_HOME_TEST_CHILD", "1")
            .env("HOME", "/nonexistent-latch-agent-home")
            .env_remove("LATCH_BROWSER_HOME")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
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
