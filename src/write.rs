//! Persistent injection into deliberately small, unambiguous file formats.
//!
//! Dotenv accepts blank lines, comments, and one-line `NAME=value` assignments.
//! Existing multiline, `export`, and duplicate assignments are rejected rather
//! than guessed at. Values written here use dotenvy-compatible double quotes
//! with escaped `\`, `"`, and `$`; embedded line breaks are deliberately
//! unsupported for dotenv. Zsh uses
//! a managed block of `export NAME=$'...'` statements and leaves other text alone.

use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use tempfile::NamedTempFile;

const BEGIN: &str = "# >>> latch-secrets managed >>>";
const END: &str = "# <<< latch-secrets managed <<<";

#[derive(Clone, Copy, Debug)]
pub(crate) enum Format {
    Dotenv,
    Zsh,
}

/// Update selected variables without returning or logging their values.
///
/// A persistent, owner-only sidecar lock serializes cooperating invocations.
/// Unrelated writers must cooperate with the same lock to avoid a lost update.
pub(crate) fn write(path: &Path, format: Format, values: &[(String, String)]) -> Result<()> {
    let mut names = HashSet::new();
    for (name, value) in values {
        ensure!(valid_name(name), "invalid variable name");
        ensure!(names.insert(name), "duplicate selected variable name");
        ensure!(!value.contains('\0'), "secret value contains NUL");
        if matches!(format, Format::Dotenv) {
            ensure!(
                !value.contains(['\n', '\r']),
                "dotenv cannot store a multiline secret"
            );
            ensure!(
                !value.chars().any(char::is_control),
                "dotenv cannot store control characters"
            );
        } else {
            ensure!(
                !value
                    .chars()
                    .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t')),
                "zsh cannot store this control character"
            );
        }
    }
    if values.is_empty() {
        return Ok(());
    }

    let path = checked_path(path)?;
    let parent = path.parent().context("destination has no parent")?;
    let filename = path.file_name().context("destination has no filename")?;
    let mut lock_name = std::ffi::OsString::from(".");
    lock_name.push(filename);
    lock_name.push(".latch-secrets.lock");
    let lock_path = parent.join(lock_name);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&lock_path)
        .context("cannot open destination lock")?;
    check_owned_regular(&lock, true)?;
    // SAFETY: `lock` owns a valid descriptor, and flock does not retain pointers.
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0,
        "cannot lock destination"
    );

    let (original, identity) = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(mut file) => {
            let metadata = check_owned_regular(&file, false)?;
            let mut content = String::new();
            file.read_to_string(&mut content)
                .context("destination is not readable UTF-8 text")?;
            (
                content,
                Some((metadata.dev(), metadata.ino(), metadata.mode() & 0o777)),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (String::new(), None),
        Err(error) => return Err(error).context("cannot open destination"),
    };

    let updated = match format {
        Format::Dotenv => update_dotenv(&original, values)?,
        Format::Zsh => update_zsh(&original, values)?,
    };
    if updated == original && identity.is_some_and(|(_, _, mode)| mode == 0o600) {
        return Ok(());
    }

    // Check before replacement too: an unrelated writer must not silently
    // change the target during our read/parse cycle.
    match (identity, fs::symlink_metadata(&path)) {
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        (Some((dev, ino, _)), Ok(metadata))
            if metadata.file_type().is_file()
                && metadata.uid() == effective_uid()
                && metadata.nlink() == 1
                && metadata.dev() == dev
                && metadata.ino() == ino => {}
        _ => bail!("destination changed during update"),
    }

    let mut temp = NamedTempFile::new_in(parent).context("cannot create temporary destination")?;
    temp.as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("cannot set destination permissions")?;
    temp.write_all(updated.as_bytes())
        .context("cannot write temporary destination")?;
    temp.as_file()
        .sync_all()
        .context("cannot sync destination")?;
    temp.persist(&path)
        .map_err(|error| error.error)
        .context("cannot replace destination")?;
    File::open(parent)?
        .sync_all()
        .context("cannot sync destination directory")?;
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn checked_path(path: &Path) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty(), "empty destination path");
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => bail!("destination path may not contain '..'"),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "destination path contains a symlink"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && current == absolute => {}
            Err(error) => return Err(error).context("cannot inspect destination path"),
        }
    }
    ensure!(
        absolute.file_name().is_some(),
        "destination has no filename"
    );
    Ok(absolute)
}

fn check_owned_regular(file: &File, lock: bool) -> Result<fs::Metadata> {
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "destination is not a regular file");
    ensure!(
        metadata.uid() == effective_uid(),
        "destination is not owned by this user"
    );
    ensure!(metadata.nlink() == 1, "destination has multiple hard links");
    if lock {
        ensure!(
            metadata.mode() & 0o077 == 0,
            "destination lock is accessible by others"
        );
    }
    Ok(metadata)
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.bytes();
    matches!(chars.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
}

fn update_dotenv(original: &str, values: &[(String, String)]) -> Result<String> {
    let mut seen = HashSet::new();
    let mut updated = String::with_capacity(original.len() + values.len() * 32);
    for line in original.split_inclusive('\n') {
        let content = line.strip_suffix('\n').unwrap_or(line);
        let content = content.strip_suffix('\r').unwrap_or(content);
        let trimmed = content.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            updated.push_str(line);
            continue;
        }
        let (name, existing_value) = content
            .split_once('=')
            .context("dotenv contains an unsupported line")?;
        ensure!(
            valid_name(name),
            "dotenv contains an unsupported assignment"
        );
        ensure!(seen.insert(name), "dotenv contains duplicate assignments");
        validate_existing_dotenv_value(existing_value)?;
        if let Some((_, value)) = values.iter().find(|(selected, _)| selected == name) {
            updated.push_str(name);
            updated.push('=');
            updated.push_str(&quote_dotenv(value));
            if line.ends_with("\r\n") {
                updated.push_str("\r\n");
            } else if line.ends_with('\n') {
                updated.push('\n');
            }
        } else {
            updated.push_str(line);
        }
    }
    for (name, value) in values {
        if !seen.contains(name.as_str()) {
            if !updated.is_empty() && !updated.ends_with('\n') {
                updated.push('\n');
            }
            updated.push_str(name);
            updated.push('=');
            updated.push_str(&quote_dotenv(value));
            updated.push('\n');
        }
    }
    Ok(updated)
}

fn validate_existing_dotenv_value(value: &str) -> Result<()> {
    ensure!(
        !value.contains('\r'),
        "dotenv contains a multiline assignment"
    );
    // The strict subset permits plain values without quotes, whitespace or
    // backslashes, and single/double quoted values with simple escapes.
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                ensure!(
                    matches!(ch, '"' | '\\' | '$'),
                    "dotenv contains unsupported escapes"
                );
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                ensure!(ch != '"', "dotenv contains ambiguous quoting");
            }
        }
        ensure!(!escaped, "dotenv contains an incomplete escape");
    } else if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
    {
        ensure!(!inner.contains('\''), "dotenv contains ambiguous quoting");
    } else {
        ensure!(
            !value
                .chars()
                .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\'' | '\\' | '#')),
            "dotenv contains an unsupported value"
        );
    }
    Ok(())
}

fn quote_dotenv(value: &str) -> String {
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        if matches!(ch, '"' | '\\' | '$') {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

fn update_zsh(original: &str, values: &[(String, String)]) -> Result<String> {
    let marker_lines = |marker: &str| {
        original
            .match_indices(marker)
            .filter(|(index, _)| {
                (*index == 0 || original.as_bytes()[index - 1] == b'\n')
                    && (index + marker.len() == original.len()
                        || matches!(original.as_bytes()[index + marker.len()], b'\n' | b'\r'))
            })
            .collect::<Vec<_>>()
    };
    let begin = marker_lines(BEGIN);
    let end = marker_lines(END);
    ensure!(
        begin.len() == end.len() && begin.len() <= 1,
        "zsh managed block markers are malformed"
    );

    let (prefix, suffix, old, existing, end_newline) =
        if let (Some(&(start, _)), Some(&(finish, _))) = (begin.first(), end.first()) {
            ensure!(start < finish, "zsh managed block markers are reversed");
            ensure!(
                start == 0 || original.as_bytes()[start - 1] == b'\n',
                "zsh managed block marker is not on its own line"
            );
            let block_start = start + BEGIN.len();
            ensure!(
                original[block_start..].starts_with('\n'),
                "zsh managed block marker is malformed"
            );
            ensure!(
                original.as_bytes()[finish - 1] == b'\n',
                "zsh managed block marker is malformed"
            );
            let after_end = finish + END.len();
            ensure!(
                after_end == original.len() || original[after_end..].starts_with('\n'),
                "zsh managed block marker is not on its own line"
            );
            let block = &original[block_start + 1..finish];
            let mut retained = BTreeMap::new();
            for line in block.lines() {
                let statement = line
                    .strip_prefix("export ")
                    .context("zsh managed block contains unsupported content")?;
                let (name, literal) = statement
                    .split_once('=')
                    .context("zsh managed block contains unsupported content")?;
                ensure!(
                    valid_name(name),
                    "zsh managed block contains an invalid variable name"
                );
                validate_zsh_literal(literal)?;
                ensure!(
                    retained.insert(name.to_owned(), line.to_owned()).is_none(),
                    "zsh managed block contains duplicate variables"
                );
            }
            let end_newline = after_end < original.len();
            let suffix_start = if end_newline {
                after_end + 1
            } else {
                after_end
            };
            (
                &original[..start],
                &original[suffix_start..],
                retained,
                true,
                end_newline,
            )
        } else {
            (original, "", BTreeMap::new(), false, true)
        };

    let mut managed = old;
    for (name, value) in values {
        managed.insert(name.clone(), format!("export {name}={}", quote_zsh(value)));
    }
    let mut updated = String::with_capacity(original.len() + values.len() * 32);
    updated.push_str(prefix);
    if !existing && !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(BEGIN);
    updated.push('\n');
    for statement in managed.values() {
        updated.push_str(statement);
        updated.push('\n');
    }
    updated.push_str(END);
    if end_newline {
        updated.push('\n');
    }
    updated.push_str(suffix);
    Ok(updated)
}

fn validate_zsh_literal(literal: &str) -> Result<()> {
    let inner = literal
        .strip_prefix("$'")
        .and_then(|value| value.strip_suffix('\''))
        .context("zsh managed block contains an unsupported literal")?;
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            ensure!(
                matches!(ch, '\'' | '\\' | 'n' | 'r' | 't'),
                "zsh managed block contains an unsupported escape"
            );
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            ensure!(
                ch != '\'' && !ch.is_control(),
                "zsh managed block contains an unsupported literal"
            );
        }
    }
    ensure!(!escaped, "zsh managed block contains an incomplete escape");
    Ok(())
}

fn quote_zsh(value: &str) -> String {
    let mut quoted = String::from("$'");
    for ch in value.chars() {
        match ch {
            '\'' => quoted.push_str("\\'"),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            _ => quoted.push(ch),
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir_in(".").unwrap()
    }

    #[test]
    fn dotenv_preserves_unrelated_text_and_is_idempotent() {
        let dir = fixture();
        let path = dir.path().join("secrets.env");
        fs::write(&path, "# keep this\nOTHER=plain\nTOKEN=old\n").unwrap();
        let values = vec![("TOKEN".into(), "a ${OTHER} $`'\\\" # value".into())];
        write(&path, Format::Dotenv, &values).unwrap();
        let first = fs::read_to_string(&path).unwrap();
        assert!(first.starts_with("# keep this\nOTHER=plain\n"));
        assert!(first.contains("TOKEN=\"a \\${OTHER} \\$`'\\\\\\\" # value\"\n"));
        let parsed = dotenvy::from_path_iter(&path)
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            parsed.iter().find(|(name, _)| name == "TOKEN").unwrap().1,
            values[0].1
        );
        write(&path, Format::Dotenv, &values).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), first);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write(&path, Format::Dotenv, &values).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn dotenv_rejects_ambiguous_inputs_without_changing_file() {
        let dir = fixture();
        let path = dir.path().join("secrets.env");
        for original in ["A=1\nA=2\n", "A=\"line\ncontinued\"\n", "export A=1\n"] {
            fs::write(&path, original).unwrap();
            assert!(write(&path, Format::Dotenv, &[("A".into(), "safe".into())]).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
        }
        assert!(write(&path, Format::Dotenv, &[("A".into(), "a\nb".into())]).is_err());
    }

    #[test]
    fn zsh_round_trip_escapes_metacharacters_and_retains_unselected() {
        let dir = fixture();
        let path = dir.path().join("profile.zsh");
        let touched = dir.path().join("must-not-exist");
        fs::write(&path, "# outside\n").unwrap();
        let dangerous = format!("one ' \\ $() `touch {}`\nsecond {BEGIN}", touched.display());
        write(
            &path,
            Format::Zsh,
            &[
                ("A".into(), dangerous.clone()),
                ("B".into(), "retained".into()),
            ],
        )
        .unwrap();
        write(&path, Format::Zsh, &[("A".into(), dangerous.clone())]).unwrap();
        let first = fs::read_to_string(&path).unwrap();
        assert!(first.starts_with("# outside\n"));
        assert!(first.contains("export B=$'retained'"));
        write(&path, Format::Zsh, &[("A".into(), dangerous.clone())]).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), first);
        let output = Command::new("zsh")
            .args(["-fc", "source \"$1\"; print -rn -- \"$A|$B\"", "--"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, format!("{dangerous}|retained").as_bytes());
        assert!(!touched.exists());
    }

    #[test]
    fn malformed_zsh_block_and_symlinks_are_refused() {
        let dir = fixture();
        let path = dir.path().join("profile.zsh");
        let malformed = format!("{BEGIN}\nexport A='unsafe'\n{END}\n");
        fs::write(&path, &malformed).unwrap();
        assert!(write(&path, Format::Zsh, &[("A".into(), "safe".into())]).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), malformed);

        let link = dir.path().join("linked.zsh");
        symlink(&path, &link).unwrap();
        assert!(write(&link, Format::Zsh, &[("A".into(), "safe".into())]).is_err());
        let linked_dir = dir.path().join("linked-dir");
        symlink(dir.path(), &linked_dir).unwrap();
        assert!(
            write(
                &linked_dir.join("new.zsh"),
                Format::Zsh,
                &[("A".into(), "safe".into())]
            )
            .is_err()
        );
    }

    #[test]
    fn zsh_update_keeps_trailing_assignments_in_order() {
        let dir = fixture();
        let path = dir.path().join("profile.zsh");
        let original = format!(
            "# before\n{BEGIN}\nexport A=$'old'\nexport B=$'keep'\n{END}\nexport A=trailing\n# after\n"
        );
        fs::write(&path, original).unwrap();
        let values = [("A".into(), "new".into())];
        write(&path, Format::Zsh, &values).unwrap();
        let updated = fs::read_to_string(&path).unwrap();
        assert!(updated.starts_with("# before\n"));
        assert!(updated.ends_with("export A=trailing\n# after\n"));
        assert!(updated.contains("export B=$'keep'"));
        write(&path, Format::Zsh, &values).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), updated);
        let output = Command::new("zsh")
            .args(["-fc", "source \"$1\"; print -rn -- \"$A|$B\"", "--"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"trailing|keep");
    }

    #[test]
    fn fifo_target_and_lock_are_refused_without_waiting() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, Instant};

        let dir = fixture();
        let target = dir.path().join("profile.zsh");
        let c_target = CString::new(target.as_os_str().as_bytes()).unwrap();
        // SAFETY: CString is NUL terminated and points to a valid path.
        assert_eq!(unsafe { libc::mkfifo(c_target.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert!(write(&target, Format::Zsh, &[("A".into(), "value".into())]).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));

        let another = dir.path().join("another.zsh");
        let lock = dir.path().join(".another.zsh.latch-secrets.lock");
        let c_lock = CString::new(lock.as_os_str().as_bytes()).unwrap();
        // SAFETY: CString is NUL terminated and points to a valid path.
        assert_eq!(unsafe { libc::mkfifo(c_lock.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert!(write(&another, Format::Zsh, &[("A".into(), "value".into())]).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn concurrent_updates_keep_both_selected_variables() {
        let dir = fixture();
        let path = dir.path().join("secrets.env");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let threads = [("A", "one"), ("B", "two")]
            .into_iter()
            .map(|(name, value)| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    write(&path, Format::Dotenv, &[(name.into(), value.into())])
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        let parsed = dotenvy::from_path_iter(&path)
            .unwrap()
            .collect::<std::result::Result<BTreeMap<_, _>, _>>()
            .unwrap();
        assert_eq!(parsed.get("A").unwrap(), "one");
        assert_eq!(parsed.get("B").unwrap(), "two");
    }
}
