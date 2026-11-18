//! A per-user, local-only broker for the Bitwarden session token.
//!
//! Persistent backends read the token on each request. The explicitly selected
//! headless backend retains only the session token in memory until lock/restart.
//! Tokens never travel through process arguments.

use anyhow::{Context, Result, anyhow, bail};
#[cfg(target_os = "linux")]
#[path = "session/linux.rs"]
mod linux;

/// The backend is explicit in configuration and in the service command line.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Backend {
    Keychain,
    Memory,
    SecretService,
}
impl Default for Backend {
    fn default() -> Self {
        if cfg!(target_os = "macos") {
            Self::Keychain
        } else {
            Self::Memory
        }
    }
}
impl Backend {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Keychain => "keychain",
            Self::Memory => "memory",
            Self::SecretService => "secret-service",
        }
    }
    pub(crate) fn validate(self) -> Result<()> {
        match self {
            Self::Keychain if cfg!(target_os = "macos") => Ok(()),
            Self::Memory | Self::SecretService if cfg!(target_os = "linux") => Ok(()),
            _ => bail!(
                "session backend {} is not supported on this platform",
                self.as_str()
            ),
        }
    }
    pub(crate) fn persistence(self) -> &'static str {
        match self {
            Self::Memory => "until-lock-or-helper-restart",
            _ => "operating-system-secret-store",
        }
    }
}
impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub(super) struct StoreError(pub(super) &'static str);
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for StoreError {}

#[cfg(any(target_os = "macos", target_os = "linux"))]
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

    #[cfg(target_os = "macos")]
    const SERVICE: &str = "com.latch-secrets.session";
    const MAX_MESSAGE: u64 = 32 * 1024;
    const IO_TIMEOUT: Duration = Duration::from_secs(5);

    pub(super) trait SecretStore {
        fn get(&self, account: &str) -> Result<String> {
            self.get_optional(account)?
                .ok_or_else(|| StoreError("session_empty").into())
        }
        fn probe(&self, account: &str) -> Result<bool> {
            Ok(zeroize::Zeroizing::new(self.get_optional(account)?).is_some())
        }
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

    #[cfg(target_os = "macos")]
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

    pub(crate) fn connect_with_timeout(path: &Path, timeout: Duration) -> Result<UnixStream> {
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: sockaddr_un is a plain C structure whose all-zero value is
        // valid; family, length and pathname are assigned before connect.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
            bail!("session socket path is invalid or too long");
        }
        #[cfg(target_os = "macos")]
        {
            address.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
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
            // AF_UNIX EAGAIN can mean a full backlog, not an in-progress
            // connection. Fail boundedly rather than treating an unconnected
            // descriptor with SO_ERROR=0 as an authenticated peer.
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error).context("session broker is unavailable");
            }
            let deadline = std::time::Instant::now() + timeout;
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
        let named = fs::symlink_metadata(dir.join("broker.lock"))?;
        if named.dev() != meta.dev() || named.ino() != meta.ino() || named.nlink() != 1 {
            bail!("broker lock file changed during startup");
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
        #[cfg(target_os = "macos")]
        {
            let mut peer_uid: libc::uid_t = 0;
            let mut peer_gid: libc::gid_t = 0;
            // SAFETY: both output pointers are valid and the descriptor is a live Unix socket.
            let status =
                unsafe { libc::getpeereid(stream.as_raw_fd(), &mut peer_uid, &mut peer_gid) };
            if status != 0 || peer_uid != uid() {
                bail!("unauthorized session peer");
            }
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: ucred is a plain C structure, with valid writable storage and length.
            let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&credentials) as libc::socklen_t;
            // SAFETY: the descriptor is live and the two output pointers are valid for their lengths.
            let status = unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut credentials as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if status != 0
                || len as usize != std::mem::size_of_val(&credentials)
                || credentials.uid != uid()
            {
                bail!("unauthorized session peer");
            }
        }
        Ok(())
    }

    fn remaining_time(deadline: std::time::Instant) -> Result<Duration> {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            bail!("session message deadline exceeded");
        }
        Ok(remaining)
    }

    fn read_message(stream: &mut UnixStream) -> Result<Value> {
        read_message_until(stream, std::time::Instant::now() + IO_TIMEOUT)
    }

    fn wait_ready(
        stream: &UnixStream,
        events: libc::c_short,
        deadline: std::time::Instant,
    ) -> Result<()> {
        loop {
            let remaining = remaining_time(deadline)?;
            let millis = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: stream.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: descriptor points to one valid pollfd and the stream owns its fd.
            let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if ready > 0 {
                if descriptor.revents & libc::POLLNVAL != 0 {
                    bail!("invalid session socket");
                }
                return Ok(());
            }
            if ready < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                return Err(std::io::Error::last_os_error()).context("session socket poll failed");
            }
        }
    }

    fn read_message_until(stream: &mut UnixStream, deadline: std::time::Instant) -> Result<Value> {
        stream.set_nonblocking(true)?;
        let result = (|| -> Result<Value> {
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            let mut buffer = zeroize::Zeroizing::new([0u8; 4096]);
            loop {
                // A timeout on each blocking read alone resets after every byte.
                // Nonblocking reads plus a remaining poll budget enforce the
                // complete message deadline even when a peer trickles data.
                remaining_time(deadline)?;
                let available = buffer.len().min(MAX_MESSAGE as usize + 1 - bytes.len());
                match stream.read(&mut buffer[..available]) {
                    Ok(0) => break,
                    Ok(count) => {
                        bytes.extend_from_slice(&buffer[..count]);
                        if bytes.len() as u64 > MAX_MESSAGE {
                            bail!("session request is too large");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        wait_ready(stream, libc::POLLIN, deadline)?
                    }
                    Err(error) => return Err(error).context("could not read session message"),
                }
            }
            Ok(serde_json::from_slice(&bytes)?)
        })();
        let reset = stream.set_nonblocking(false);
        let value = result?;
        reset?;
        Ok(value)
    }

    fn write_message(stream: &mut UnixStream, value: &Value) -> Result<()> {
        write_message_until(stream, value, std::time::Instant::now() + IO_TIMEOUT)
    }

    fn write_message_until(
        stream: &mut UnixStream,
        value: &Value,
        deadline: std::time::Instant,
    ) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
        if bytes.len() as u64 > MAX_MESSAGE {
            bail!("session response is too large");
        }
        stream.set_nonblocking(true)?;
        let result = (|| -> Result<()> {
            let mut written = 0;
            while written < bytes.len() {
                remaining_time(deadline)?;
                match stream.write(&bytes[written..]) {
                    Ok(0) => bail!("could not write session message"),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        wait_ready(stream, libc::POLLOUT, deadline)?
                    }
                    Err(error) => return Err(error).context("could not write session message"),
                }
            }
            Ok(())
        })();
        let reset = stream.set_nonblocking(false);
        result?;
        reset?;
        Ok(())
    }

    fn dispatch(
        store: &(impl SecretStore + ?Sized),
        account: &str,
        request: &Value,
    ) -> Result<Value> {
        match request.get("op").and_then(Value::as_str) {
            Some("get") => Ok(json!({"ok": true, "token": store.get(account)?})),
            Some("get_optional") => Ok(json!({"ok": true, "token": store.get_optional(account)?})),
            Some("put") => {
                let token = request
                    .get("token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("missing token"))?;
                if token.is_empty() || token.len() > MAX_MESSAGE as usize / 2 {
                    bail!("empty token");
                }
                store.put(account, token)?;
                Ok(json!({"ok": true}))
            }
            Some("delete") => {
                store.delete(account)?;
                Ok(json!({"ok": true}))
            }
            Some("probe") => Ok(json!({"ok": true, "session_present": store.probe(account)?})),
            Some("ping") => Ok(json!({"ok": true})),
            _ => bail!("invalid session operation"),
        }
    }

    fn scrub_token(value: &mut Value) {
        use zeroize::Zeroize;
        if let Some(Value::String(token)) = value.get_mut("token") {
            token.zeroize();
        }
    }

    fn serve_connection(
        stream: &mut UnixStream,
        store: &(impl SecretStore + ?Sized),
        account: &str,
        backend: Backend,
    ) {
        let result = (|| -> Result<Value> {
            verify_peer(stream)?;
            stream.set_read_timeout(Some(IO_TIMEOUT))?;
            stream.set_write_timeout(Some(IO_TIMEOUT))?;
            let mut request = read_message(stream)?;
            if request.get("op").and_then(Value::as_str) == Some("info") {
                return Ok(
                    json!({"ok": true, "backend": backend.as_str(), "persistence": backend.persistence(), "pid": std::process::id()}),
                );
            }
            let response = dispatch(store, account, &request);
            scrub_token(&mut request);
            response
        })();
        // Never forward Keychain or parser errors, which can contain sensitive details.
        let mut reply = result.unwrap_or_else(|error| {
            let code = error
                .downcast_ref::<StoreError>()
                .map_or("session request failed", |error| error.0);
            json!({"ok": false, "error": code})
        });
        let _ = write_message(stream, &reply);
        scrub_token(&mut reply);
    }

    #[cfg(target_os = "linux")]
    fn harden_linux_process() -> Result<()> {
        // RLIMIT_CORE alone does not suppress Linux core dumps sent to a
        // core_pattern pipe. Apply both controls before a store can hold a
        // session token, including when session-serve runs in the foreground.
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: limit is initialized and valid for the duration of the call.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("could not disable session broker core dumps");
        }
        // SAFETY: PR_SET_DUMPABLE takes the scalar value 0 and no pointers.
        // Unused variadic arguments are zeroed with the ABI's unsigned-long type.
        let status = unsafe {
            libc::prctl(
                libc::PR_SET_DUMPABLE,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if status != 0 {
            return Err(std::io::Error::last_os_error())
                .context("could not disable session broker dumpability");
        }
        Ok(())
    }

    pub(crate) fn serve(state_dir: &Path, backend: Backend) -> Result<()> {
        backend.validate()?;
        crate::config::State::new(Some(state_dir.to_path_buf()))?.validate()?;
        // This broker has a single request thread. Refuse Keychain UI prompts
        // so a locked Keychain fails a request instead of hanging the helper.
        #[cfg(target_os = "macos")]
        let _no_keychain_ui =
            security_framework::os::macos::keychain::SecKeychain::disable_user_interaction()
                .context("could not disable Keychain interaction")?;
        #[cfg(target_os = "macos")]
        let store: Box<dyn SecretStore> = Box::new(Keychain);
        #[cfg(target_os = "linux")]
        let store: Box<dyn SecretStore> = {
            harden_linux_process()?;
            super::linux::store(backend)?
        };
        let (listener, _lock, _path) = bind(state_dir)?;
        let account = account(state_dir)?;
        for connection in listener.incoming() {
            let mut stream = connection.context("session broker accept failed")?;
            serve_connection(&mut stream, store.as_ref(), &account, backend);
        }
        Ok(())
    }

    fn call(state_dir: &Path, mut request: Value) -> Result<Value> {
        let path = socket_path(state_dir)?;
        let meta = fs::symlink_metadata(&path).context("session broker is unavailable")?;
        if !meta.file_type().is_socket() || meta.uid() != uid() || meta.mode() & 0o077 != 0 {
            bail!("session broker socket is insecure");
        }
        let mut stream = connect_with_timeout(&path, IO_TIMEOUT)?;
        verify_peer(&stream)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let written = write_message(&mut stream, &request);
        scrub_token(&mut request);
        written?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let response = read_message(&mut stream).context("invalid session broker response")?;
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            let hint = match response.get("error").and_then(Value::as_str) {
                Some("session_empty") => "session_empty: run latch login",
                Some("store_locked") => "store_locked: unlock the desktop keyring and retry",
                Some("store_unavailable") => {
                    "store_unavailable: start a Secret Service provider on the user session bus"
                }
                Some("store_prompt_required") => {
                    "store_prompt_required: authorize the desktop keyring outside Latch and retry; no prompt was opened"
                }
                Some("store_collection_missing") => {
                    "store_collection_missing: create a default desktop keyring"
                }
                Some("store_timeout") => {
                    "store_timeout: desktop keyring request timed out; outcome may be unknown"
                }
                Some("store_conflict") => {
                    "store_conflict: multiple matching session items; inspect the desktop keyring"
                }
                _ => "session request failed",
            };
            bail!("{hint}");
        }
        Ok(response)
    }

    pub(crate) fn get(state_dir: &Path) -> Result<String> {
        let mut response = call(state_dir, json!({"op": "get"}))?;
        match response.get_mut("token").map(Value::take) {
            Some(Value::String(token)) => Ok(token),
            _ => bail!("invalid session broker response"),
        }
    }

    pub(crate) fn get_optional(state_dir: &Path) -> Result<Option<String>> {
        let mut response = call(state_dir, json!({"op": "get_optional"}))?;
        match response.get_mut("token").map(Value::take) {
            Some(Value::Null) => Ok(None),
            Some(Value::String(token)) => Ok(Some(token)),
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

    pub(crate) fn info(state_dir: &Path) -> Result<Value> {
        call(state_dir, json!({"op": "info"}))
    }

    pub(crate) fn service_name(state_dir: &Path) -> Result<String> {
        #[cfg(target_os = "macos")]
        {
            agent_label(state_dir)
        }
        #[cfg(target_os = "linux")]
        {
            super::linux::unit_name(state_dir)
        }
    }

    pub(crate) fn ping(state_dir: &Path) -> Result<()> {
        call(state_dir, json!({"op": "ping"}))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn install(state_dir: &Path, backend: Backend) -> Result<()> {
        backend.validate()?;
        session_dir(state_dir, true)?;
        super::linux::install(state_dir, backend)?;
        let deadline = std::time::Instant::now() + IO_TIMEOUT;
        loop {
            if let Ok(response) = info(state_dir)
                && response["backend"] == backend.as_str()
                && let Some(pid) = response["pid"].as_u64()
                && super::linux::owns_responder(state_dir, pid).unwrap_or(false)
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "session service did not own a ready broker; stop any foreground session-serve process for this state, inspect the user service journal, and retry configure"
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
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
    pub(crate) fn install(state_dir: &Path, backend: Backend) -> Result<()> {
        backend.validate()?;
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
            <key>ProgramArguments</key><array><string>{}</string><string>--state-dir</string><string>{}</string><string>session-serve</string><string>--session-backend</string><string>keychain</string></array>\n\
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

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_process_hardening_disables_dumpability_in_child() -> Result<()> {
            const CHILD: &str = "LATCH_DUMPABILITY_TEST_CHILD";
            if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new("1")) {
                // This is a fresh test process containing no credentials. Start
                // dumpable to prove that the production hardening changes it.
                // SAFETY: PR_SET_DUMPABLE takes only scalar arguments; no pointers.
                let enabled = unsafe {
                    libc::prctl(
                        libc::PR_SET_DUMPABLE,
                        1 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                };
                assert_eq!(enabled, 0);
                harden_linux_process()?;
                // SAFETY: PR_GET_DUMPABLE has no output pointer and unused
                // variadic arguments are zero. It does not trigger a core dump.
                let dumpable = unsafe {
                    libc::prctl(
                        libc::PR_GET_DUMPABLE,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                };
                assert_eq!(dumpable, 0);
                let mut limit = libc::rlimit {
                    rlim_cur: 1,
                    rlim_max: 1,
                };
                // SAFETY: limit is a valid writable output structure.
                assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
                assert_eq!(limit.rlim_cur, 0);
                assert_eq!(limit.rlim_max, 0);
                return Ok(());
            }
            // Spawn instead of fork so the parallel test runner's limits and
            // dumpability remain untouched; the child runs this exact test only.
            let child = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "session::unix::tests::linux_process_hardening_disables_dumpability_in_child",
                ])
                .env(CHILD, "1")
                .output()?;
            assert!(
                child.status.success(),
                "isolated process hardening check failed: {}",
                String::from_utf8_lossy(&child.stderr)
            );
            Ok(())
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
                        serve_connection(&mut stream, &store, "test", Backend::default());
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
                        serve_connection(&mut stream, &store, "test", Backend::default());
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
            assert_ne!(service_name(first.path())?, service_name(second.path())?);
            let dir = session_dir(first.path(), true)?;
            let target = first.path().join("target");
            fs::write(&target, b"unchanged")?;
            std::os::unix::fs::symlink(&target, dir.join("broker.lock"))?;
            assert!(lock_broker(&dir).is_err());
            assert_eq!(fs::read(&target)?, b"unchanged");
            Ok(())
        }

        #[test]
        fn slow_trickle_cannot_extend_read_deadline() -> Result<()> {
            let (mut reader, mut writer) = UnixStream::pair()?;
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    for _ in 0..20 {
                        if writer.write_all(b" ").is_err() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                });
                let began = std::time::Instant::now();
                let error =
                    read_message_until(&mut reader, began + Duration::from_millis(50)).unwrap_err();
                assert!(error.to_string().contains("deadline exceeded"));
                assert!(began.elapsed() < Duration::from_millis(500));
                drop(reader);
            });
            Ok(())
        }

        #[test]
        fn slow_reader_cannot_extend_write_deadline() -> Result<()> {
            let (mut reader, mut writer) = UnixStream::pair()?;
            let small_buffer: libc::c_int = 1024;
            // SAFETY: writer is a live socket and small_buffer is a valid input
            // buffer for the supplied size. This affects only this test socket.
            let status = unsafe {
                libc::setsockopt(
                    writer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &small_buffer as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&small_buffer) as libc::socklen_t,
                )
            };
            assert_eq!(status, 0);
            reader.set_read_timeout(Some(Duration::from_millis(200)))?;
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    for _ in 0..20 {
                        if !matches!(reader.read(&mut [0u8; 1]), Ok(1)) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                });
                let began = std::time::Instant::now();
                let message = json!({"token": "s".repeat(24 * 1024)});
                let error =
                    write_message_until(&mut writer, &message, began + Duration::from_millis(50))
                        .unwrap_err();
                assert!(error.to_string().contains("deadline exceeded"));
                assert!(began.elapsed() < Duration::from_millis(500));
                drop(writer);
            });
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) use unix::{
    connect_with_timeout, delete, get, get_optional, info, install, ping, probe, put, serve,
    service_name,
};
