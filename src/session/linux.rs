//! Linux storage and service lifecycle. No desktop service is required in memory mode.
use super::{Backend, StoreError, unix::SecretStore};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::HashMap,
    fs,
    io::{Read, Seek, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const STORE_TIMEOUT: Duration = Duration::from_secs(3);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(10);
const SERVICE: &str = "com.latch-secrets.session";

#[derive(Default)]
struct MemoryStore(RefCell<Option<Zeroizing<String>>>);
impl SecretStore for MemoryStore {
    fn get_optional(&self, _: &str) -> Result<Option<String>> {
        Ok(self.0.borrow().as_ref().map(|token| token.to_string()))
    }
    fn put(&self, _: &str, token: &str) -> Result<()> {
        *self.0.borrow_mut() = Some(Zeroizing::new(token.to_owned()));
        Ok(())
    }
    fn delete(&self, _: &str) -> Result<()> {
        self.0.borrow_mut().take();
        Ok(())
    }
}

struct DesktopStore {
    runtime: tokio::runtime::Runtime,
}
#[derive(Clone, Copy)]
enum Operation<'a> {
    Read,
    Probe,
    Put(&'a str),
    Delete,
}
impl DesktopStore {
    fn new() -> Result<Self> {
        Ok(Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| StoreError("store_unavailable"))?,
        })
    }
    fn execute(&self, account: &str, operation: Operation<'_>) -> Result<Option<String>> {
        // Bound the complete operation, including connection, negotiation, search,
        // and mutation. Cancellation releases this request; no stuck worker thread
        // can permanently occupy the broker. A timed-out write has unknown outcome.
        self.runtime.block_on(async {
            tokio::time::timeout(STORE_TIMEOUT, desktop_operation(account, operation))
                .await
                .map_err(|_| StoreError("store_timeout"))?
        })
    }
}
impl SecretStore for DesktopStore {
    fn probe(&self, account: &str) -> Result<bool> {
        Ok(Zeroizing::new(self.execute(account, Operation::Probe)?).is_some())
    }
    fn get_optional(&self, account: &str) -> Result<Option<String>> {
        self.execute(account, Operation::Read)
    }
    fn put(&self, account: &str, token: &str) -> Result<()> {
        self.execute(account, Operation::Put(token))?;
        Ok(())
    }
    fn delete(&self, account: &str) -> Result<()> {
        self.execute(account, Operation::Delete)?;
        Ok(())
    }
}

const BUS_NAME: &str = "org.freedesktop.secrets";
const BUS_PATH: &str = "/org/freedesktop/secrets";

fn store_error(error: zbus::Error) -> anyhow::Error {
    // Match only protocol-defined error names. Never forward provider text.
    StoreError(match error {
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.Secret.Error.IsLocked" =>
        {
            "store_locked"
        }
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.Secret.Error.NoSuchObject" =>
        {
            "store_collection_missing"
        }
        _ => "store_unavailable",
    })
    .into()
}
async fn proxy<'a>(
    connection: &'a zbus::Connection,
    path: &'a str,
    interface: &'a str,
) -> Result<zbus::Proxy<'a>> {
    zbus::Proxy::new(connection, BUS_NAME, path, interface)
        .await
        .map_err(store_error)
}
async fn refuse_prompt(
    connection: &zbus::Connection,
    path: &zbus::zvariant::OwnedObjectPath,
) -> Result<()> {
    if path.as_str() != "/" {
        // Do not call Prompt, even if a provider locks between our precheck and
        // mutation. Discard the pending operation and require external recovery.
        if let Ok(prompt) = proxy(connection, path.as_str(), "org.freedesktop.Secret.Prompt").await
        {
            let _ = prompt.call::<_, _, ()>("Dismiss", &()).await;
        }
        return Err(StoreError("store_prompt_required").into());
    }
    Ok(())
}

async fn desktop_operation(account: &str, operation: Operation<'_>) -> Result<Option<String>> {
    let connection = zbus::Connection::session().await.map_err(store_error)?;
    desktop_connected(&connection, account, operation).await
}

async fn desktop_connected(
    connection: &zbus::Connection,
    account: &str,
    operation: Operation<'_>,
) -> Result<Option<String>> {
    use zbus::zvariant::{Dict, OwnedObjectPath, OwnedValue, Value};
    let service = proxy(connection, BUS_PATH, "org.freedesktop.Secret.Service").await?;
    let attributes = HashMap::from([("service", SERVICE), ("account", account)]);
    // Search all collections: moving the desktop's default alias must never
    // orphan an older session or allow it to reappear after latch lock.
    let (items, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
        .call("SearchItems", &(attributes.clone(),))
        .await
        .map_err(store_error)?;
    ensure!(locked.is_empty(), StoreError("store_locked"));
    for path in &items {
        let item = proxy(connection, path.as_str(), "org.freedesktop.Secret.Item").await?;
        if item
            .get_property::<bool>("Locked")
            .await
            .map_err(store_error)?
        {
            return Err(StoreError("store_locked").into());
        }
    }
    if matches!(operation, Operation::Delete) {
        for path in items {
            let item = proxy(connection, path.as_str(), "org.freedesktop.Secret.Item").await?;
            let prompt: OwnedObjectPath = item.call("Delete", &()).await.map_err(store_error)?;
            refuse_prompt(connection, &prompt).await?;
        }
        let (remaining, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &(attributes,))
            .await
            .map_err(store_error)?;
        ensure!(locked.is_empty(), StoreError("store_locked"));
        ensure!(remaining.is_empty(), StoreError("store_unavailable"));
        return Ok(None);
    }
    ensure!(items.len() <= 1, StoreError("store_conflict"));
    if matches!(operation, Operation::Read | Operation::Probe) && items.is_empty() {
        if matches!(operation, Operation::Probe) {
            // Empty storage is usable only if login can create an item. This
            // non-mutating readiness check does not affect reads or deletion
            // when a default alias is moved, removed, or locked.
            let path: OwnedObjectPath = service
                .call("ReadAlias", &("default",))
                .await
                .map_err(store_error)?;
            ensure!(path.as_str() != "/", StoreError("store_collection_missing"));
            let collection = proxy(
                connection,
                path.as_str(),
                "org.freedesktop.Secret.Collection",
            )
            .await?;
            ensure!(
                !collection
                    .get_property::<bool>("Locked")
                    .await
                    .map_err(store_error)?,
                StoreError("store_locked")
            );
        }
        return Ok(None);
    }
    // "plain" is the standard Secret Service algorithm on the authenticated
    // per-user bus. Like the broker socket, this trusts the OS user and bus
    // daemon; it does not claim protection from another process of this user.
    let (_, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .map_err(store_error)?;
    let result = async {
        match operation {
            Operation::Read | Operation::Probe => {
                let item =
                    proxy(connection, items[0].as_str(), "org.freedesktop.Secret.Item").await?;
                let (returned_session, parameters, bytes, _content_type): (
                    OwnedObjectPath,
                    Vec<u8>,
                    Vec<u8>,
                    String,
                ) = item
                    .call("GetSecret", &(&session,))
                    .await
                    .map_err(store_error)?;
                let bytes = Zeroizing::new(bytes);
                ensure!(
                    returned_session == session && parameters.is_empty(),
                    StoreError("store_unavailable")
                );
                let text =
                    std::str::from_utf8(&bytes).map_err(|_| StoreError("store_unavailable"))?;
                ensure!(
                    !text.is_empty() && text.len() <= 16 * 1024,
                    StoreError("store_unavailable")
                );
                Ok(Some(text.to_owned()))
            }
            Operation::Put(token) => {
                let secret = (&session, Vec::<u8>::new(), token.as_bytes(), "text/plain");
                if let Some(path) = items.first() {
                    let item =
                        proxy(connection, path.as_str(), "org.freedesktop.Secret.Item").await?;
                    item.call::<_, _, ()>("SetSecret", &(secret,))
                        .await
                        .map_err(store_error)?;
                } else {
                    // The default collection is used only for creation. Existing
                    // items are updated in their original collection.
                    let collection_path: OwnedObjectPath = service
                        .call("ReadAlias", &("default",))
                        .await
                        .map_err(store_error)?;
                    ensure!(
                        collection_path.as_str() != "/",
                        StoreError("store_collection_missing")
                    );
                    let collection = proxy(
                        connection,
                        collection_path.as_str(),
                        "org.freedesktop.Secret.Collection",
                    )
                    .await?;
                    ensure!(
                        !collection
                            .get_property::<bool>("Locked")
                            .await
                            .map_err(store_error)?,
                        StoreError("store_locked")
                    );
                    let properties: HashMap<&str, Value<'_>> = HashMap::from([
                        (
                            "org.freedesktop.Secret.Item.Label",
                            Value::from("Latch session"),
                        ),
                        (
                            "org.freedesktop.Secret.Item.Attributes",
                            Value::from(Dict::from(attributes)),
                        ),
                    ]);
                    let (path, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
                        .call("CreateItem", &(properties, secret, true))
                        .await
                        .map_err(store_error)?;
                    refuse_prompt(connection, &prompt).await?;
                    ensure!(path.as_str() != "/", StoreError("store_unavailable"));
                }
                Ok(None)
            }
            Operation::Delete => unreachable!("delete handled before opening a session"),
        }
    }
    .await;
    // The total operation deadline also bounds Close. Dropping the connection on
    // timeout releases the session; a write timeout still has unknown outcome.
    if let Ok(session_proxy) = proxy(
        connection,
        session.as_str(),
        "org.freedesktop.Secret.Session",
    )
    .await
    {
        let _ = session_proxy.call::<_, _, ()>("Close", &()).await;
    }
    result
}

pub(super) fn store(backend: Backend) -> Result<Box<dyn SecretStore>> {
    match backend {
        Backend::Memory => Ok(Box::<MemoryStore>::default()),
        Backend::SecretService => Ok(Box::new(DesktopStore::new()?)),
        Backend::Keychain => bail!("keychain is not available on Linux"),
    }
}

pub(super) fn unit_name(state: &Path) -> Result<String> {
    let canonical = state.canonicalize()?;
    let digest = Sha256::digest(canonical.as_os_str().as_bytes());
    Ok(format!("latch-session-{digest:x}.service"))
}
fn quoted(value: &Path) -> Result<String> {
    let value = value.to_str().context("service path must be UTF-8")?;
    ensure!(
        !value.chars().any(char::is_control),
        "service path contains control characters"
    );
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}
fn unit_text(executable: &Path, state: &Path, backend: Backend) -> Result<String> {
    Ok(format!(
        "[Unit]\nDescription=Latch per-user session broker\n\n[Service]\nType=simple\nExecStart={} --state-dir {} session-serve --session-backend {}\nUMask=0077\nLimitCORE=0\nNoNewPrivileges=true\nRestart=on-failure\nRestartSec=1\nKillMode=control-group\n\n[Install]\nWantedBy=default.target\n",
        quoted(executable)?,
        quoted(state)?,
        backend.as_str()
    ))
}
fn systemctl(args: &[&str]) -> Result<()> {
    systemctl_output(args).map(|_| ())
}

fn systemctl_output(args: &[&str]) -> Result<String> {
    // Only non-secret unit state is captured. A private regular file avoids a
    // pipe reader or inherited pipe writer extending the subprocess deadline.
    let mut output = tempfile::tempfile()?;
    let mut child = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(Stdio::null())
        .spawn()
        .context("could not run systemctl --user; install systemd or run session-serve manually")?;
    let deadline = Instant::now() + SERVICE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                ensure!(
                    status.success(),
                    "systemctl --user failed; ensure a user manager is running (use a normal login session), then retry configure"
                );
                output.rewind()?;
                let mut bytes = Vec::new();
                output.take(4097).read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 4096, "systemctl output exceeded the limit");
                return String::from_utf8(bytes).context("invalid systemctl output");
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                if let Err(error) = result {
                    return Err(error).context("could not inspect systemctl");
                }
                bail!(
                    "systemctl --user timed out; inspect the user service before retrying configure"
                );
            }
        }
    }
}

pub(super) fn owns_responder(state: &Path, pid: u64) -> Result<bool> {
    if pid == 0 {
        return Ok(false);
    }
    let name = unit_name(state)?;
    systemctl(&["is-active", "--quiet", &name])?;
    let main_pid = systemctl_output(&["show", "--property=MainPID", "--value", &name])?;
    Ok(main_pid.trim().parse::<u64>().ok() == Some(pid))
}

fn reject_symlink_ancestors(directory: &Path) -> Result<()> {
    for ancestor in directory.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "user service directory must not contain symlinks"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error).context("could not inspect user service directory"),
        }
    }
    Ok(())
}

fn prepare_unit_directory(directory: &Path) -> Result<()> {
    // Check existing components before recursive creation can traverse them.
    reject_symlink_ancestors(directory)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    reject_symlink_ancestors(directory)?;
    Ok(())
}

pub(super) fn install(state: &Path, backend: Backend) -> Result<()> {
    let state = state.canonicalize()?;
    let socket = state.join("session/broker.sock");
    // Linux sockaddr_un.sun_path has 108 bytes, including its trailing NUL.
    ensure!(
        socket.as_os_str().as_bytes().len() < 108,
        "state directory path is too long for a session socket; choose a shorter --state-dir"
    );
    let name = unit_name(&state)?;
    let config = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => {
            PathBuf::from(std::env::var_os("HOME").context("HOME is unavailable")?).join(".config")
        }
    };
    ensure!(config.is_absolute(), "XDG_CONFIG_HOME must be absolute");
    let directory = config.join("systemd/user");
    prepare_unit_directory(&directory)?;
    let metadata = fs::symlink_metadata(&directory)?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "user service directory must be owned by this user and not writable by others"
    );
    let mut file = tempfile::NamedTempFile::new_in(&directory)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(unit_text(&std::env::current_exe()?, &state, backend)?.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(directory.join(&name))
        .context("could not install session user service")?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", &name])?;
    systemctl(&["restart", &name])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn memory_store_does_not_persist_across_instances() -> Result<()> {
        let first = MemoryStore::default();
        assert!(first.get_optional("a")?.is_none());
        assert!(first.get("a").is_err());
        first.put("a", "synthetic-session")?;
        assert_eq!(first.get("a")?, "synthetic-session");
        assert!(MemoryStore::default().get_optional("a")?.is_none());
        first.delete("a")?;
        first.delete("a")?;
        assert!(first.get_optional("a")?.is_none());
        Ok(())
    }
    #[test]
    fn unit_directory_symlink_is_rejected_before_creating_children() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("outside");
        fs::create_dir(&target)?;
        let link = temp.path().join("config");
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(prepare_unit_directory(&link.join("systemd/user")).is_err());
        assert!(!target.join("systemd").exists());
        Ok(())
    }

    #[test]
    fn units_are_distinct_stable_and_escape_paths() -> Result<()> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        assert_ne!(unit_name(first.path())?, unit_name(second.path())?);
        assert_eq!(
            unit_name(first.path())?,
            unit_name(&first.path().join("."))?
        );
        let text = unit_text(
            Path::new("/a b/%latch$"),
            Path::new("/state\"dir"),
            Backend::Memory,
        )?;
        assert!(text.contains("\"/a b/%%latch$$\""));
        assert!(text.contains("\"/state\\\"dir\""));
        assert!(text.contains("--session-backend memory"));
        assert!(quoted(Path::new("/newline\npath")).is_err());
        Ok(())
    }
    #[test]
    fn secret_service_errors_are_sanitized() {
        let error = zbus::Error::Failure("PRIVATE_DIAGNOSTIC".to_owned());
        assert_eq!(store_error(error).to_string(), "store_unavailable");
    }
    #[test]
    fn overall_store_deadline_cancels_a_stalled_operation() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let began = Instant::now();
        let result = runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(20), std::future::pending::<()>()).await
        });
        assert!(result.is_err());
        assert!(began.elapsed() < Duration::from_secs(1));
        // The same runtime can service the next request after cancellation.
        assert_eq!(runtime.block_on(async { 42 }), 42);
        Ok(())
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod dbus_tests;
