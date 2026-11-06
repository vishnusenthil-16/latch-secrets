use crate::config::{Config, State};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::Duration,
};
use std::{
    os::unix::process::{CommandExt, ExitStatusExt},
    sync::mpsc,
    time::Instant,
};
use zeroize::Zeroizing;

pub(crate) const VERSION: &str = "2026.8.0";
pub(crate) struct Bw<'a> {
    config: &'a Config,
    state: &'a State,
}
impl<'a> Bw<'a> {
    pub fn new(config: &'a Config, state: &'a State) -> Self {
        Self { config, state }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(&self.config.bw);
        clean_auth_env(&mut command);
        command
            .env("BITWARDENCLI_APPDATA_DIR", self.state.root.join("bw"))
            .env("BW_NOINTERACTION", "true")
            .env("BW_CLI_NO_COLOR", "true");
        command
    }
    pub fn check_version(&self) -> Result<()> {
        let mut command = self.command();
        command.arg("--version");
        let version = captured(command)?;
        ensure!(
            version.trim() == VERSION,
            "unsupported Bitwarden CLI; install version 2026.8.0 at the configured path"
        );
        Ok(())
    }
    pub fn call(&self, args: &[&str], token: Option<&str>) -> Result<String> {
        let mut command = self.command();
        command.args(args).arg("--nointeraction");
        if let Some(token) = token {
            command.env("BW_SESSION", token);
        }
        captured(command)
    }
    pub fn mutate(&self, args: &[&str], token: &str, input: Zeroizing<String>) -> Result<String> {
        let mut command = self.command();
        command
            .args(args)
            .arg("--nointeraction")
            .env("BW_SESSION", token);
        captured_input(command, Duration::from_secs(90), 16 * 1024 * 1024, Some(input))
            .map_err(|error| anyhow::anyhow!("mutation outcome uncertain: {error}; inspect vault before retrying (not automatically retried)"))
    }
    pub fn soft_delete(&self, id: &str, token: &str) -> Result<()> {
        // Pinned cli-v2026.8.0 apps/cli/src/vault/delete.command.ts selects
        // softDeleteWithServer unless --permanent is supplied. Never expose it.
        let _response = Zeroizing::new(self.call(&["delete", "item", id], Some(token))
            .map_err(|error| anyhow::anyhow!("delete outcome uncertain: {error}; inspect vault before retrying (not automatically retried)"))?);
        Ok(())
    }
    pub fn configure_server(&self, saved_server_changed: bool) -> Result<()> {
        let status = self.raw_status(None)?;
        if saved_server_changed || !self.server_matches(&status) {
            ensure!(
                status["status"] == "unauthenticated",
                "cannot change server while authenticated; use a separate --state-dir"
            );
            self.call(&["config", "server", &self.config.server], None)?;
        }
        self.status(None)?;
        Ok(())
    }
    fn server_matches(&self, status: &Value) -> bool {
        let Some(actual) = status["serverUrl"].as_str() else {
            return false;
        };
        // Apply the same URL normalization as Config, including a trailing slash.
        let Ok(actual) = url::Url::parse(actual) else {
            return false;
        };
        actual.as_str().trim_end_matches('/') == self.config.server
    }
    pub fn status(&self, token: Option<&str>) -> Result<Value> {
        let status = self.raw_status(token)?;
        ensure!(
            self.server_matches(&status),
            "Bitwarden server does not match Latch configuration; run configure to repair unauthenticated state or use a separate --state-dir"
        );
        Ok(status)
    }
    fn raw_status(&self, token: Option<&str>) -> Result<Value> {
        let raw = Zeroizing::new(self.call(&["status"], token)?);
        let value: Value = serde_json::from_str(&raw)
            .map_err(|_| anyhow::anyhow!("bw returned invalid status"))?;
        ensure!(
            matches!(
                value["status"].as_str(),
                Some("unauthenticated" | "locked" | "unlocked")
            ),
            "bw returned unknown status"
        );
        Ok(value)
    }
    pub fn login(&self, email: &str, password: &str) -> Result<String> {
        let mut command = self.command();
        command
            .args([
                "login",
                email,
                "--passwordenv",
                "LATCH_MASTER_PASSWORD",
                "--raw",
                "--nointeraction",
            ])
            .env("LATCH_MASTER_PASSWORD", password);
        captured(command).context("login failed; for two-factor accounts use login --api-key")
    }
    pub fn authenticate_api(&self, id: &str, secret: &str) -> Result<()> {
        let mut command = self.command();
        command
            .args(["login", "--apikey", "--nointeraction"])
            .env("BW_CLIENTID", id)
            .env("BW_CLIENTSECRET", secret);
        captured(command)?;
        Ok(())
    }
    pub fn unlock(&self, password: &str) -> Result<String> {
        let mut command = self.command();
        command
            .args([
                "unlock",
                "--passwordenv",
                "LATCH_MASTER_PASSWORD",
                "--raw",
                "--nointeraction",
            ])
            .env("LATCH_MASTER_PASSWORD", password);
        captured(command)
    }
}
pub(crate) fn clean_auth_env(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("BW_")
            || name.starts_with("BITWARDENCLI_")
            || name.starts_with("LATCH_")
        {
            command.env_remove(key);
        }
    }
    // Disable inherited debugging switches that could cause the runtime to log credentials.
    command
        .env_remove("NODE_OPTIONS")
        .env_remove("NODE_DEBUG")
        .env_remove("FORCE_COLOR")
        .env_remove("NODE_EXTRA_CA_CERTS")
        .env_remove("NODE_TLS_REJECT_UNAUTHORIZED");
}

// Match complete pinned-backend messages, never substrings of arbitrary error text.
// Only these static categories cross the process boundary; raw stderr is not logged.
const UNCLASSIFIED: &str = "unclassified backend error (details withheld)";

fn classify_stderr(bytes: &[u8]) -> &'static str {
    match std::str::from_utf8(bytes).unwrap_or("").trim() {
        "You do not have permission to add items to this collection." => {
            "collection_permission_denied: collection unavailable or not editable"
        }
        "You do not have permission to edit this item" => "item_permission_denied",
        "This item already belongs to an organization." => "already_organization_owned",
        "Not found." => "not_found",
        "`requestJson` was not provided." => "missing_request_data",
        "Error parsing the encoded request data." => "invalid_request_data",
        "You must provide at least one collection id for this item." => "missing_collection",
        _ => UNCLASSIFIED,
    }
}

fn captured(command: Command) -> Result<String> {
    captured_with_limits(command, Duration::from_secs(90), 16 * 1024 * 1024)
}

fn captured_with_limits(command: Command, timeout: Duration, limit: usize) -> Result<String> {
    captured_input(command, timeout, limit, None)
}
fn captured_input(
    mut command: Command,
    timeout: Duration,
    limit: usize,
    input: Option<Zeroizing<String>>,
) -> Result<String> {
    // A separate process group lets timeout cleanup include bw runtime children.
    // Upstream stderr can contain credentials and is never forwarded.
    let mut child = command
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot start configured bw executable")?;
    // Concurrent writing keeps a non-reading backend inside the process deadline.
    let (input_sender, input_receiver) = mpsc::channel();
    let mut input_done = input.is_none();
    if let Some(input) = input {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        std::thread::spawn(move || {
            let result = stdin.write_all(input.as_bytes());
            drop(stdin);
            let _ = input_sender.send(result);
        });
    }
    // Drain stderr concurrently under its own bound, including on successful exits.
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let (error_sender, error_receiver) = mpsc::channel();
    const STDERR_LIMIT: usize = 64 * 1024;
    std::thread::spawn(move || {
        let mut buffer = Zeroizing::new(Vec::with_capacity(STDERR_LIMIT + 1));
        let result = (|| {
            stderr
                .by_ref()
                .take(STDERR_LIMIT as u64 + 1)
                .read_to_end(&mut buffer)?;
            // Retain only a bounded prefix, but never interrupt a backend because
            // diagnostics are verbose. The extra byte marks truncated messages.
            std::io::copy(&mut stderr, &mut std::io::sink())?;
            Ok::<_, std::io::Error>(buffer)
        })();
        let _ = error_sender.send(result);
    });
    let stdout = child.stdout.take().expect("stdout is piped");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let result = stdout
            .take(limit as u64 + 1)
            .read_to_end(&mut buffer)
            .map(|_| buffer);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut bytes = None;
    let mut error_bytes = None;
    let mut input_failed = false;
    let mut input_failure_deadline = None;
    let result = (|| -> Result<String> {
        loop {
            if !input_done {
                match input_receiver.try_recv() {
                    Ok(result) => {
                        input_failed = result.is_err();
                        input_done = true;
                    }
                    Err(mpsc::TryRecvError::Empty) => (),
                    Err(mpsc::TryRecvError::Disconnected) => {
                        input_failed = true;
                        input_done = true;
                    }
                }
            }
            if bytes.is_none() {
                match receiver.try_recv() {
                    Ok(result) => {
                        let buffer = result.context("cannot read bw output")?;
                        ensure!(
                            buffer.len() <= limit,
                            "bw response exceeded the output size limit"
                        );
                        bytes = Some(buffer);
                    }
                    Err(mpsc::TryRecvError::Empty) => (),
                    Err(mpsc::TryRecvError::Disconnected) => bail!("cannot read bw output"),
                }
            }
            if error_bytes.is_none() {
                match error_receiver.try_recv() {
                    Ok(result) => {
                        let buffer = result.context("cannot read bw diagnostic output")?;
                        error_bytes = Some(buffer);
                    }
                    Err(mpsc::TryRecvError::Empty) => (),
                    Err(mpsc::TryRecvError::Disconnected) => {
                        bail!("cannot read bw diagnostic output")
                    }
                }
            }
            if status.is_none() {
                status = child.try_wait().context("cannot inspect bw process")?;
            }
            if let Some(status) = status
                && let Some(stderr) = error_bytes.as_ref()
            {
                if !status.success() {
                    if let Some(signal) = status.signal() {
                        bail!("bw process terminated by signal {signal}");
                    }
                    let category = if stderr.len() > STDERR_LIMIT {
                        UNCLASSIFIED
                    } else {
                        classify_stderr(stderr)
                    };
                    let hint = if category == UNCLASSIFIED {
                        "; check login, connectivity, and compatibility with latch doctor"
                    } else {
                        ""
                    };
                    bail!(
                        "bw exited with code {}: {category}{hint}",
                        status.code().unwrap_or(-1)
                    );
                }
                ensure!(!input_failed, "cannot write bw input");
                if input_done && let Some(bytes) = bytes.take() {
                    return String::from_utf8(bytes)
                        .map_err(|_| anyhow::anyhow!("bw returned non-UTF-8 output"));
                }
            }
            if input_failed {
                // Allow a brief window for early rejection diagnostics, not the
                // full operation timeout if the backend closes stdin and hangs.
                let failure_deadline = input_failure_deadline
                    .get_or_insert_with(|| Instant::now() + Duration::from_millis(250));
                ensure!(Instant::now() < *failure_deadline, "cannot write bw input");
            }
            ensure!(Instant::now() < deadline, "bw operation timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        // SAFETY: child was started as the leader of its own process group.
        // Negative PID targets that group, including descendants holding stdout open.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shell(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script]);
        cmd
    }
    #[test]
    fn configure_repairs_reset_endpoint_but_refuses_authenticated_changes() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("bw-test");
        fs::write(
            &script,
            r#"#!/usr/bin/python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['BITWARDENCLI_APPDATA_DIR']).parent
path = root/'status.json'
args = sys.argv[1:]
status = json.loads(path.read_text())
if args[0] == 'status': print(json.dumps(status))
elif args[:2] == ['config', 'server']:
    (root/'configured').touch()
    if not (root/'ignore-config').exists():
        status['serverUrl'] = args[2]
        path.write_text(json.dumps(status))
else: sys.exit(1)
"#,
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let config = Config::new("https://vault.example.test", &script).unwrap();
        let state = State::new(Some(dir.path().to_path_buf())).unwrap();
        let backend = Bw::new(&config, &state);
        let status_path = dir.path().join("status.json");
        for endpoint in [
            serde_json::Value::Null,
            serde_json::json!("https://other.example.test"),
        ] {
            fs::write(
                &status_path,
                serde_json::json!({"status":"unauthenticated","serverUrl":endpoint}).to_string(),
            )
            .unwrap();
            // The saved server did not change, but bw was reset or differs.
            backend.configure_server(false).unwrap();
            assert!(dir.path().join("configured").exists());
            assert!(backend.status(None).is_ok());
            fs::remove_file(dir.path().join("configured")).unwrap();
        }
        fs::write(
            &status_path,
            serde_json::json!({"status":"locked","serverUrl":"https://vault.example.test/"})
                .to_string(),
        )
        .unwrap();
        backend.configure_server(false).unwrap();
        assert!(!dir.path().join("configured").exists());
        assert!(backend.configure_server(true).is_err());
        fs::write(
            &status_path,
            serde_json::json!({"status":"locked","serverUrl":"https://other.example.test"})
                .to_string(),
        )
        .unwrap();
        assert!(backend.configure_server(false).is_err());
        assert!(!dir.path().join("configured").exists());
        fs::write(
            &status_path,
            serde_json::json!({"status":"unauthenticated"}).to_string(),
        )
        .unwrap();
        fs::write(dir.path().join("ignore-config"), "").unwrap();
        assert!(backend.configure_server(false).is_err());
    }
    #[test]
    fn caps_output_and_bounds_inherited_pipes() {
        let start = Instant::now();
        let result = captured_with_limits(shell("yes synthetic"), Duration::from_secs(2), 1024);
        assert!(result.unwrap_err().to_string().contains("size limit"));
        assert!(start.elapsed() < Duration::from_secs(2));
        let start = Instant::now();
        let result =
            captured_with_limits(shell("sleep 10 & exit 0"), Duration::from_millis(150), 1024);
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn stdin_delivery_is_bounded_and_errors_are_sanitized() {
        let start = Instant::now();
        let error = captured_input(
            shell("sleep 10"),
            Duration::from_millis(150),
            1024,
            Some(Zeroizing::new("CANARY".repeat(100_000))),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(!error.to_string().contains("CANARY"));
        assert!(start.elapsed() < Duration::from_secs(2));
        let output = captured_input(
            shell("cat"),
            Duration::from_secs(2),
            1024,
            Some(Zeroizing::new("synthetic".into())),
        )
        .unwrap();
        assert_eq!(output, "synthetic");
    }
    #[test]
    fn classifies_only_complete_known_messages() {
        for (message, category) in [
            (
                "You do not have permission to edit this item",
                "item_permission_denied",
            ),
            (
                "This item already belongs to an organization.",
                "already_organization_owned",
            ),
            ("Not found.", "not_found"),
            ("`requestJson` was not provided.", "missing_request_data"),
            (
                "Error parsing the encoded request data.",
                "invalid_request_data",
            ),
            (
                "You must provide at least one collection id for this item.",
                "missing_collection",
            ),
        ] {
            assert_eq!(
                classify_stderr(format!(" {message}\n").as_bytes()),
                category
            );
            assert_eq!(
                classify_stderr(format!("{message} CANARY").as_bytes()),
                UNCLASSIFIED
            );
            assert_eq!(
                classify_stderr(format!("CANARY {message}").as_bytes()),
                UNCLASSIFIED
            );
        }
        let known = "You do not have permission to add items to this collection.";
        assert!(classify_stderr(known.as_bytes()).contains("collection_permission_denied"));
        for unknown in [
            format!("{known} CANARY"),
            format!("CANARY\n{known}"),
            "CANARY".into(),
        ] {
            assert_eq!(
                classify_stderr(unknown.as_bytes()),
                "unclassified backend error (details withheld)"
            );
        }
        assert_eq!(
            classify_stderr(&[255]),
            "unclassified backend error (details withheld)"
        );
        let error = captured_with_limits(
            shell("echo 'You do not have permission to add items to this collection.' >&2; exit 1"),
            Duration::from_secs(2),
            1024,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("code 1: collection_permission_denied")
        );
    }
    #[test]
    fn diagnostic_flood_signal_and_inherited_pipe_are_bounded() {
        let error = captured_with_limits(shell("yes CANARY >&2"), Duration::from_millis(150), 1024)
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(!format!("{error:#}").contains("CANARY"));
        let error =
            captured_with_limits(shell("kill -TERM $$"), Duration::from_secs(2), 1024).unwrap_err();
        assert!(error.to_string().contains("signal 15"));
        let error = captured_with_limits(
            shell("sleep 10 >&2 & exit 1"),
            Duration::from_millis(150),
            1024,
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }
    #[test]
    fn early_rejection_retains_diagnostics_when_stdin_breaks() {
        let error = captured_input(
            shell("echo 'You do not have permission to add items to this collection.' >&2; exit 1"),
            Duration::from_secs(2),
            1024,
            Some(Zeroizing::new("CANARY".repeat(100_000))),
        )
        .unwrap_err();
        assert!(error.to_string().contains("collection_permission_denied"));
        assert!(!format!("{error:#}").contains("CANARY"));
        let error = captured_with_limits(
            Command::new("/nonexistent/latch-test"),
            Duration::from_secs(2),
            1024,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot start configured bw executable")
        );
    }
    #[test]
    fn verbose_diagnostics_do_not_abort_success_or_hide_exit_status() {
        for count in [10, 65536, 65537, 1000000] {
            let script = format!("head -c {count} /dev/zero >&2; printf ok");
            assert_eq!(
                captured_with_limits(shell(&script), Duration::from_secs(5), 1024).unwrap(),
                "ok"
            );
            let error = captured_with_limits(
                shell(&format!("{script}; exit 7")),
                Duration::from_secs(5),
                1024,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("code 7: unclassified backend error"));
            assert!(error.contains("latch doctor"));
        }
        // A truncated prefix that trims to a known message must not classify.
        let error = captured_with_limits(
            shell("printf 'Not found.' >&2; head -c 70000 /dev/zero | tr '\\000' ' ' >&2; exit 7"),
            Duration::from_secs(5),
            1024,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unclassified backend error"));
    }

    #[test]
    fn closed_stdin_does_not_wait_for_operation_timeout() {
        let start = Instant::now();
        let error = captured_input(
            shell("exec 0<&-; sleep 10"),
            Duration::from_secs(5),
            1024,
            Some(Zeroizing::new("CANARY".repeat(100_000))),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "cannot write bw input");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn backend_failures_do_not_include_output() {
        let error = captured_with_limits(
            shell("echo CANARY; echo CANARY >&2; exit 3"),
            Duration::from_secs(2),
            1024,
        )
        .unwrap_err();
        assert!(!error.to_string().contains("CANARY"));
    }
}
