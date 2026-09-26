use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub server: String,
    pub bw: PathBuf,
}
impl Config {
    pub fn new(server: &str, bw: &Path) -> Result<Self> {
        let url = url::Url::parse(server).context("invalid server URL")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "server must be an HTTPS URL without credentials, query, or fragment"
        );
        ensure!(bw.is_absolute(), "bw path must be absolute");
        let bw = bw.canonicalize().context("cannot resolve bw executable")?;
        ensure!(bw.is_file(), "bw must be an executable file");
        Ok(Self {
            server: url.as_str().trim_end_matches('/').to_owned(),
            bw,
        })
    }
}

pub(crate) struct State {
    pub root: PathBuf,
}
impl State {
    pub fn new(root: Option<PathBuf>) -> Result<Self> {
        let root = match root {
            Some(root) => root,
            None => PathBuf::from(
                std::env::var_os("HOME").context("HOME is unavailable; pass --state-dir")?,
            )
            .join("Library/Application Support/latch-secrets"),
        };
        ensure!(root.is_absolute(), "state directory must be absolute");
        ensure!(
            !root
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
            "state directory cannot contain parent traversals"
        );
        Ok(Self { root })
    }
    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.json")
    }
    pub fn prepare(&self) -> Result<()> {
        // Parents are not changed; the new Latch root and bw directory are private.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
            .context("cannot create state directory")?;
        self.validate()?;
        let bw = self.root.join("bw");
        fs::DirBuilder::new().mode(0o700).create(&bw).or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })?;
        private_directory(&bw)?;
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        for path in self.root.ancestors() {
            let m = fs::symlink_metadata(path).context("cannot inspect state path")?;
            ensure!(
                !m.file_type().is_symlink(),
                "state path must not contain symlinks"
            );
        }
        private_directory(&self.root)?;
        let bw = self.root.join("bw");
        match fs::symlink_metadata(&bw) {
            Ok(_) => private_directory(&bw)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error).context("cannot inspect bw state directory"),
        }
        Ok(())
    }
    pub fn lock(&self, create: bool) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join("vault.lock"))
            .context("cannot open state lock")?;
        private_file(&file)?;
        fs2::FileExt::try_lock_exclusive(&file)
            .context("vault is busy; retry after the other latch command completes")?;
        Ok(file)
    }
    pub fn load(&self) -> Result<Config> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.config_path())
            .context("not configured; run latch configure")?;
        private_file(&file)?;
        let config: Config = serde_json::from_reader(file)
            .map_err(|_| anyhow::anyhow!("invalid configuration file"))?;
        // Loading must remain possible when bw is missing, so lock can still erase Keychain state.
        let url = url::Url::parse(&config.server).context("invalid configured server")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && config.bw.is_absolute(),
            "invalid configuration"
        );
        Ok(config)
    }
    pub fn save(&self, config: &Config) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&serde_json::to_vec_pretty(config)?)?;
        file.as_file().sync_all()?;
        file.persist(self.config_path())
            .map_err(|_| anyhow::anyhow!("could not save configuration"))?;
        Ok(())
    }
}
fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    ensure!(
        m.is_dir()
            && !m.file_type().is_symlink()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "state directories must be owned by this user with mode 0700"
    );
    Ok(())
}
fn private_file(file: &File) -> Result<()> {
    let m = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "state files must be single-link owner-only regular files"
    );
    Ok(())
}
