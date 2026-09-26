//! A per-user, local-only broker for the Bitwarden session token.
//!
//! The broker reads the token from the login Keychain for every request. It
//! holds no token cache and never passes a token through a process argument.

use anyhow::{Context, Result, anyhow, bail};
#[cfg(not(target_os = "macos"))]
use std::path::Path;

#[cfg(target_os = "macos")]
mod unix {
    use super::*;
    use serde_json::{Value, json};
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const SERVICE: &str = "com.latch-secrets.session";
    const MAX_MESSAGE: u64 = 32 * 1024;
    const IO_TIMEOUT: Duration = Duration::from_secs(5);

    trait SecretStore {
        fn get(&self, account: &str) -> Result<String>;
        fn get_optional(&self, account: &str) -> Result<Option<String>>;
        fn put(&self, account: &str, token: &str) -> Result<()>;
        fn delete(&self, account: &str) -> Result<()>;
    }

    #[cfg(target_os = "macos")]
    struct Keychain;

    #[cfg(target_os = "macos")]
    fn login_keychain() -> Result<security_framework::os::macos::keychain::SecKeychain> {
        use security_framework::os::macos::keychain::SecKeychain;
        let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is unavailable"))?;
        let path = PathBuf::from(home).join("Library/Keychains/login.keychain-db");
        SecKeychain::open(path).context("could not open login Keychain")
    }

    #[cfg(target_os = "macos")]
    impl SecretStore for Keychain {
        fn get(&self, account: &str) -> Result<String> {
            self.get_optional(account)?
                .ok_or_else(|| anyhow!("Keychain session unavailable"))
        }

        fn get_optional(&self, account: &str) -> Result<Option<String>> {
            let keychain = login_keychain()?;
            match keychain.find_generic_password(SERVICE, account) {
                Ok((password, _)) => String::from_utf8(password.to_owned())
                    .map(Some)
                    .context("Keychain session is invalid"),
                Err(error) if error.code() == -25300 => Ok(None),
                Err(error) => Err(error).context("could not inspect Keychain session"),
            }
        }

        fn put(&self, account: &str, token: &str) -> Result<()> {
            let keychain = login_keychain()?;
            match keychain.find_generic_password(SERVICE, account) {
                Ok((_, mut item)) => item
                    .set_password(token.as_bytes())
                    .context("could not update Keychain session"),
                // errSecItemNotFound: create an item for this broker binary.
                Err(error) if error.code() == -25300 => keychain
                    .add_generic_password(SERVICE, account, token.as_bytes())
                    .context("could not create Keychain session"),
                Err(error) => Err(error).context("could not inspect Keychain session"),
            }
            .context("could not save Keychain session")
        }

        fn delete(&self, account: &str) -> Result<()> {
            let keychain = login_keychain()?;
            match keychain.find_generic_password(SERVICE, account) {
                Ok((_, item)) => {
                    item.delete();
                    Ok(())
                }
                // errSecItemNotFound: an already empty session is locked.
                Err(error) if error.code() == -25300 => Ok(()),
                Err(error) => Err(error).context("could not delete Keychain session"),
            }?;
            // SecKeychainItem::delete discards OSStatus. Verify that the item
            // really disappeared before telling the caller lock succeeded.
            match keychain.find_generic_password(SERVICE, account) {
                Err(error) if error.code() == -25300 => Ok(()),
                _ => bail!("could not delete Keychain session"),
            }
        }
    }

    fn uid() -> libc::uid_t {
        // SAFETY: getuid has no preconditions and does not dereference pointers.
        unsafe { libc::getuid() }
    }

    fn session_dir(state_dir: &Path, create: bool) -> Result<PathBuf> {
        let state = state_dir
            .canonicalize()
            .context("state directory does not exist")?;
        let dir = state.join("session");
        if create {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&dir) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error).context("could not create session directory"),
            }
        }
        let meta = fs::symlink_metadata(&dir).context("could not inspect session directory")?;
        if !meta.file_type().is_dir() || meta.uid() != uid() || meta.mode() & 0o077 != 0 {
            bail!("session directory must be owned by this user with mode 0700");
        }
        Ok(dir)
    }

    fn account(state_dir: &Path) -> Result<String> {
        let state = state_dir
            .canonicalize()
            .context("state directory does not exist")?;
        let mut value = format!("uid:{}:", uid());
        for byte in state.as_os_str().as_bytes() {
            use std::fmt::Write as _;
            write!(value, "{byte:02x}")?;
        }
        Ok(value)
    }

    fn agent_label(state_dir: &Path) -> Result<String> {
        let state = state_dir.canonicalize()?;
        let mut label = format!("{SERVICE}.");
        for byte in state.as_os_str().as_bytes() {
            use std::fmt::Write as _;
            write!(label, "{byte:02x}")?;
        }
        Ok(label)
    }

    fn socket_path(state_dir: &Path) -> Result<PathBuf> {
        Ok(session_dir(state_dir, false)?.join("broker.sock"))
    }

    fn connect_with_timeout(path: &Path) -> Result<UnixStream> {
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: sockaddr_un is a plain C structure whose all-zero value is
        // valid; family, length and pathname are assigned before connect.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
            bail!("session socket path is invalid or too long");
        }
        address.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
        address.sun_family = libc::AF_UNIX as u8;
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: socket returns a new owned descriptor, immediately wrapped by
        // UnixStream so every early return closes it.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("could not create session socket");
        }
        // SAFETY: fd was just returned by socket and ownership moves into stream.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        stream.set_nonblocking(true)?;
        let address_ptr = &address as *const libc::sockaddr_un as *const libc::sockaddr;
        // SAFETY: address_ptr points to a fully initialized sockaddr_un and
        // remains valid for the call. The stream owns the live descriptor.
        let result = unsafe {
            libc::connect(
                fd,
                address_ptr,
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS)
                && error.raw_os_error() != Some(libc::EAGAIN)
            {
                return Err(error).context("session broker is unavailable");
            }
            let deadline = std::time::Instant::now() + IO_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    bail!("session broker connection timed out");
                }
                let mut poll_fd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
                // SAFETY: poll_fd is a valid mutable pollfd for one descriptor.
                let ready = unsafe { libc::poll(&mut poll_fd, 1, millis) };
                if ready < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(std::io::Error::last_os_error())
                        .context("session broker connection failed");
                }
                if ready == 0 {
                    bail!("session broker connection timed out");
                }
                let mut socket_error: libc::c_int = 0;
                let mut len = std::mem::size_of_val(&socket_error) as libc::socklen_t;
                // SAFETY: socket_error and len are valid writable output slots.
                let status = unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut socket_error as *mut _ as *mut libc::c_void,
                        &mut len,
                    )
                };
                if status != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("session broker connection failed");
                }
                if socket_error != 0 {
                    return Err(std::io::Error::from_raw_os_error(socket_error))
                        .context("session broker is unavailable");
                }
                break;
            }
        }
        stream.set_nonblocking(false)?;
        Ok(stream)
    }

    fn lock_broker(dir: &Path) -> Result<File> {
        let path = dir.join("broker.lock");
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: path is NUL terminated; open creates a regular owner-only file
        // and O_NOFOLLOW rejects a replaced symlink.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("could not open broker lock");
        }
        // SAFETY: fd was just returned by open and ownership moves into file.
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.file_type().is_file()
            || meta.uid() != uid()
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
        {
            bail!("broker lock file is insecure");
        }
        // SAFETY: the file descriptor remains open for the entire lock lifetime.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("session broker is already running");
        }
        Ok(file)
    }

    fn bind(state_dir: &Path) -> Result<(UnixListener, File, PathBuf)> {
        let dir = session_dir(state_dir, true)?;
        let lock = lock_broker(&dir)?;
        let path = dir.join("broker.sock");
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket() || meta.uid() != uid() {
                bail!("session socket path is occupied");
            }
            fs::remove_file(&path).context("could not remove stale session socket")?;
        }
        let listener = UnixListener::bind(&path).context("could not bind session socket")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("could not secure session socket")?;
        Ok((listener, lock, path))
    }

    fn verify_peer(stream: &UnixStream) -> Result<()> {
        let mut peer_uid: libc::uid_t = 0;
        let mut peer_gid: libc::gid_t = 0;
        // SAFETY: both output pointers are valid and the descriptor is a live Unix socket.
        let status = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut peer_uid, &mut peer_gid) };
        if status != 0 || peer_uid != uid() {
            bail!("unauthorized session client");
        }
        Ok(())
    }

    fn read_message(stream: &mut UnixStream) -> Result<Value> {
        let mut bytes = Vec::new();
        stream.take(MAX_MESSAGE + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MESSAGE {
            bail!("session request is too large");
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write_message(stream: &mut UnixStream, value: &Value) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() as u64 > MAX_MESSAGE {
            bail!("session response is too large");
        }
        stream.write_all(&bytes)?;
        Ok(())
    }

    fn dispatch(store: &impl SecretStore, account: &str, request: &Value) -> Result<Value> {
        match request.get("op").and_then(Value::as_str) {
            Some("get") => Ok(json!({"ok": true, "token": store.get(account)?})),
            Some("get_optional") => Ok(json!({"ok": true, "token": store.get_optional(account)?})),
            Some("put") => {
                let token = request
                    .get("token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("missing token"))?;
                if token.is_empty() {
                    bail!("empty token");
                }
                store.put(account, token)?;
                Ok(json!({"ok": true}))
            }
            Some("delete") => {
                store.delete(account)?;
                Ok(json!({"ok": true}))
            }
            Some("probe") => Ok(json!({"ok": true})),
            _ => bail!("invalid session operation"),
        }
    }

    fn serve_connection(stream: &mut UnixStream, store: &impl SecretStore, account: &str) {
        let result = (|| -> Result<Value> {
            verify_peer(stream)?;
            stream.set_read_timeout(Some(IO_TIMEOUT))?;
            stream.set_write_timeout(Some(IO_TIMEOUT))?;
            let request = read_message(stream)?;
            dispatch(store, account, &request)
        })();
        // Never forward Keychain or parser errors, which can contain sensitive details.
        let reply =
            result.unwrap_or_else(|_| json!({"ok": false, "error": "session request failed"}));
        let _ = write_message(stream, &reply);
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn serve(state_dir: &Path) -> Result<()> {
        crate::config::State::new(Some(state_dir.to_path_buf()))?.validate()?;
        // This broker has a single request thread. Refuse Keychain UI prompts
        // so a locked Keychain fails a request instead of hanging the helper.
        let _no_keychain_ui =
            security_framework::os::macos::keychain::SecKeychain::disable_user_interaction()
                .context("could not disable Keychain interaction")?;
        let (listener, _lock, _path) = bind(state_dir)?;
        let account = account(state_dir)?;
        for connection in listener.incoming() {
            let mut stream = connection.context("session broker accept failed")?;
            serve_connection(&mut stream, &Keychain, &account);
        }
        Ok(())
    }

    fn call(state_dir: &Path, request: Value) -> Result<Value> {
        let path = socket_path(state_dir)?;
        let meta = fs::symlink_metadata(&path).context("session broker is unavailable")?;
        if !meta.file_type().is_socket() || meta.uid() != uid() || meta.mode() & 0o077 != 0 {
            bail!("session broker socket is insecure");
        }
        let mut stream = connect_with_timeout(&path)?;
        verify_peer(&stream)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        write_message(&mut stream, &request)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let response = read_message(&mut stream).context("invalid session broker response")?;
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            bail!("session request failed");
        }
        Ok(response)
    }

    pub(crate) fn get(state_dir: &Path) -> Result<String> {
        call(state_dir, json!({"op": "get"}))?
            .get("token")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("invalid session broker response"))
    }

    pub(crate) fn get_optional(state_dir: &Path) -> Result<Option<String>> {
        let response = call(state_dir, json!({"op": "get_optional"}))?;
        match response.get("token") {
            Some(Value::Null) => Ok(None),
            Some(Value::String(token)) => Ok(Some(token.clone())),
            _ => bail!("invalid session broker response"),
        }
    }

    pub(crate) fn put(state_dir: &Path, token: &str) -> Result<()> {
        if token.is_empty() || token.len() > MAX_MESSAGE as usize / 2 {
            bail!("invalid session token length");
        }
        call(state_dir, json!({"op": "put", "token": token}))?;
        Ok(())
    }

    pub(crate) fn delete(state_dir: &Path) -> Result<()> {
        call(state_dir, json!({"op": "delete"}))?;
        Ok(())
    }

    pub(crate) fn probe(state_dir: &Path) -> Result<()> {
        call(state_dir, json!({"op": "probe"}))?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn xml_escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    #[cfg(target_os = "macos")]
    fn launch_agent_executable(exe: &Path) -> Result<PathBuf> {
        let Some(bin) = exe.parent() else {
            return Ok(exe.to_path_buf());
        };
        let Some(version) = bin.parent() else {
            return Ok(exe.to_path_buf());
        };
        let Some(formula) = version.parent() else {
            return Ok(exe.to_path_buf());
        };
        let Some(cellar) = formula.parent() else {
            return Ok(exe.to_path_buf());
        };
        if exe.file_name() != Some(std::ffi::OsStr::new("latch"))
            || bin.file_name() != Some(std::ffi::OsStr::new("bin"))
            || formula.file_name() != Some(std::ffi::OsStr::new("latch-secrets"))
            || cellar.file_name() != Some(std::ffi::OsStr::new("Cellar"))
        {
            return Ok(exe.to_path_buf());
        }

        let opt = cellar
            .parent()
            .ok_or_else(|| anyhow!("Homebrew prefix is unavailable"))?
            .join("opt/latch-secrets/bin/latch");
        let current = exe
            .canonicalize()
            .context("could not inspect Homebrew binary")?;
        let linked = opt.canonicalize().with_context(|| {
            format!(
                "Homebrew opt link is missing or broken at {}; repair the Homebrew installation and reconfigure the session broker",
                opt.display()
            )
        })?;
        if linked != current {
            bail!(
                "Homebrew opt link at {} points to another binary; repair the Homebrew installation and reconfigure the session broker",
                opt.display()
            );
        }
        Ok(opt)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn install(state_dir: &Path) -> Result<()> {
        session_dir(state_dir, true)?;
        let state = state_dir.canonicalize()?;
        let socket = state.join("session/broker.sock");
        if socket.as_os_str().as_bytes().len() >= std::mem::size_of::<libc::sockaddr_un>() - 2 {
            bail!("state directory path is too long for a session socket");
        }
        let label = agent_label(&state)?;
        let exe = launch_agent_executable(
            &std::env::current_exe().context("could not locate latch-secrets binary")?,
        )?;
        let exe_text = exe
            .to_str()
            .ok_or_else(|| anyhow!("binary path is not UTF-8"))?;
        let state_text = state
            .to_str()
            .ok_or_else(|| anyhow!("state path is not UTF-8"))?;
        let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is unavailable"))?;
        let agents = PathBuf::from(home).join("Library/LaunchAgents");
        fs::create_dir_all(&agents).context("could not create LaunchAgents directory")?;
        let plist = agents.join(format!("{label}.plist"));
        let content = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
            <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
            <plist version=\"1.0\"><dict>\n\
            <key>Label</key><string>{label}</string>\n\
            <key>ProgramArguments</key><array><string>{}</string><string>--state-dir</string><string>{}</string><string>session-serve</string></array>\n\
            <key>RunAtLoad</key><true/>\n\
            <key>KeepAlive</key><true/>\n\
            </dict></plist>\n",
            xml_escape(exe_text),
            xml_escape(state_text)
        );
        let mut temp = tempfile::NamedTempFile::new_in(&agents)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temp.write_all(content.as_bytes())?;
        temp.as_file().sync_all()?;
        temp.persist(&plist)
            .context("could not install LaunchAgent plist")?;
        let domain = format!("gui/{}", uid());
        let target = format!("{domain}/{label}");
        // A running version must be stopped before bootstrap reads the new plist.
        let _ = std::process::Command::new("/bin/launchctl")
            .args(["bootout", &target])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let status = std::process::Command::new("/bin/launchctl")
            .args(["bootstrap", &domain])
            .arg(&plist)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .context("could not start session LaunchAgent")?;
        if !status.success() {
            bail!("could not start session LaunchAgent");
        }
        let deadline = std::time::Instant::now() + IO_TIMEOUT;
        loop {
            if probe(&state).is_ok() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                bail!("session LaunchAgent started but broker did not become ready");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Mutex;

        #[derive(Default)]
        struct MemoryStore(Mutex<Option<String>>);
        impl SecretStore for MemoryStore {
            fn get(&self, _: &str) -> Result<String> {
                self.0
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or_else(|| anyhow!("missing"))
            }
            fn get_optional(&self, account: &str) -> Result<Option<String>> {
                if account == "fail" {
                    bail!("backend failure");
                }
                Ok(self.0.lock().unwrap().clone())
            }
            fn put(&self, _: &str, token: &str) -> Result<()> {
                *self.0.lock().unwrap() = Some(token.to_owned());
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<()> {
                *self.0.lock().unwrap() = None;
                Ok(())
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn homebrew_launch_agent_path_survives_upgrade() -> Result<()> {
            use std::os::unix::fs::symlink;

            let temp = tempfile::tempdir()?;
            let prefix = temp.path();
            let cellar = prefix.join("Cellar/latch-secrets");
            let opt_dir = prefix.join("opt");
            fs::create_dir_all(&opt_dir)?;
            let first = cellar.join("1.0/bin/latch");
            let second = cellar.join("2.0/bin/latch");
            fs::create_dir_all(first.parent().unwrap())?;
            fs::create_dir_all(second.parent().unwrap())?;
            fs::write(&first, b"first")?;
            fs::write(&second, b"second")?;
            let link = opt_dir.join("latch-secrets");
            let stable = link.join("bin/latch");

            symlink(cellar.join("1.0"), &link)?;
            assert_eq!(launch_agent_executable(&first)?, stable);
            assert_eq!(stable.canonicalize()?, first.canonicalize()?);

            fs::remove_file(&link)?;
            symlink(cellar.join("2.0"), &link)?;
            assert_eq!(launch_agent_executable(&second)?, stable);
            assert_eq!(stable.canonicalize()?, second.canonicalize()?);
            assert!(launch_agent_executable(&first).is_err());

            fs::remove_file(&link)?;
            assert!(launch_agent_executable(&second).is_err());
            assert_eq!(
                launch_agent_executable(&prefix.join("bin/latch"))?,
                prefix.join("bin/latch")
            );
            Ok(())
        }

        #[test]
        fn socket_protocol() -> Result<()> {
            let temp = tempfile::tempdir()?;
            let (listener, _lock, _path) = bind(temp.path())?;
            let store = MemoryStore::default();
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    for _ in 0..7 {
                        let (mut stream, _) = listener.accept().unwrap();
                        serve_connection(&mut stream, &store, "test");
                    }
                });
                let request = |value: Value| -> Result<Value> {
                    let mut stream = UnixStream::connect(socket_path(temp.path())?)?;
                    write_message(&mut stream, &value)?;
                    stream.shutdown(std::net::Shutdown::Write)?;
                    read_message(&mut stream)
                };
                assert_eq!(request(json!({"op":"put", "token":"secret"}))?["ok"], true);
                assert_eq!(request(json!({"op":"get"}))?["token"], "secret");
                assert_eq!(request(json!({"op":"get_optional"}))?["token"], "secret");
                assert_eq!(
                    request(json!({"op":"bogus"}))?["error"],
                    "session request failed"
                );
                assert_eq!(request(json!({"op":"delete"}))?["ok"], true);
                assert_eq!(request(json!({"op":"get"}))?["ok"], false);
                assert!(request(json!({"op":"get_optional"}))?["token"].is_null());
                Ok::<(), anyhow::Error>(())
            })?;
            assert!(dispatch(&store, "test", &json!({"op":"put", "token":""})).is_err());
            assert!(dispatch(&store, "fail", &json!({"op":"get_optional"})).is_err());
            Ok(())
        }

        #[test]
        fn active_broker_cannot_be_replaced() -> Result<()> {
            let temp = tempfile::tempdir()?;
            let (_listener, _lock, path) = bind(temp.path())?;
            assert!(bind(temp.path()).is_err());
            assert!(path.exists());
            Ok(())
        }

        #[test]
        fn client_round_trip_and_read_only_probe() -> Result<()> {
            let temp = tempfile::tempdir()?;
            assert!(probe(temp.path()).is_err());
            assert!(!temp.path().join("session").exists());
            let (listener, _lock, _path) = bind(temp.path())?;
            let store = MemoryStore::default();
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    for _ in 0..6 {
                        let (mut stream, _) = listener.accept().unwrap();
                        serve_connection(&mut stream, &store, "test");
                    }
                });
                probe(temp.path())?;
                assert_eq!(get_optional(temp.path())?, None);
                put(temp.path(), "secret")?;
                assert_eq!(get(temp.path())?, "secret");
                assert_eq!(get_optional(temp.path())?, Some("secret".to_owned()));
                delete(temp.path())?;
                Ok::<(), anyhow::Error>(())
            })?;
            Ok(())
        }

        #[test]
        fn lock_file_symlink_is_rejected_and_states_have_distinct_labels() -> Result<()> {
            let first = tempfile::tempdir()?;
            let second = tempfile::tempdir()?;
            assert_ne!(agent_label(first.path())?, agent_label(second.path())?);
            let dir = session_dir(first.path(), true)?;
            let target = first.path().join("target");
            fs::write(&target, b"unchanged")?;
            std::os::unix::fs::symlink(&target, dir.join("broker.lock"))?;
            assert!(lock_broker(&dir).is_err());
            assert_eq!(fs::read(&target)?, b"unchanged");
            Ok(())
        }

        #[test]
        fn oversized_message_is_rejected() -> Result<()> {
            let (mut reader, mut writer) = UnixStream::pair()?;
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    writer
                        .write_all(&vec![b'a'; MAX_MESSAGE as usize + 1])
                        .unwrap();
                    writer.shutdown(std::net::Shutdown::Write).unwrap();
                });
                assert!(read_message(&mut reader).is_err());
            });
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use unix::{delete, get, get_optional, install, probe, put, serve};

#[cfg(not(target_os = "macos"))]
pub(crate) fn install(_: &Path) -> Result<()> {
    bail!("session broker requires macOS")
}
#[cfg(not(target_os = "macos"))]
pub(crate) fn serve(_: &Path) -> Result<()> {
    bail!("session broker requires macOS")
}
#[cfg(not(target_os = "macos"))]
pub(crate) fn get(_: &Path) -> Result<String> {
    bail!("session broker requires macOS")
}
#[cfg(not(target_os = "macos"))]
pub(crate) fn get_optional(_: &Path) -> Result<Option<String>> {
    bail!("session broker requires macOS")
}
#[cfg(not(target_os = "macos"))]
pub(crate) fn put(_: &Path, _: &str) -> Result<()> {
    bail!("session broker requires macOS")
}
#[cfg(not(target_os = "macos"))]
pub(crate) fn delete(_: &Path) -> Result<()> {
    bail!("session broker requires macOS")
}
#[cfg(not(target_os = "macos"))]
pub(crate) fn probe(_: &Path) -> Result<()> {
    bail!("session broker requires macOS")
}
