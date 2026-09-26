mod bw;
mod config;
mod session;
mod vault;
mod write;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    io::{IsTerminal, Write},
    path::PathBuf,
    process::Command,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "latch",
    version,
    about = "Discover and inject vault credentials without printing them"
)]
struct Cli {
    /// Isolated configuration, Bitwarden state and helper socket directory.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    /// Structured results/errors. For run, stdout belongs to the child.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Configure an isolated vault and install the macOS desktop session helper.
    Configure {
        #[arg(long)]
        server: String,
        /// Absolute path to a separately installed Bitwarden CLI 2026.8.0.
        #[arg(long)]
        bw: PathBuf,
    },
    /// Interactively authenticate/unlock; store only the session in login Keychain.
    Login {
        /// Use personal API credentials (useful for accounts with two-factor auth).
        #[arg(long)]
        api_key: bool,
    },
    /// Report authentication and session availability without exposing credentials.
    Status,
    /// Refresh the local encrypted vault from the server.
    Sync,
    /// Show only item IDs, names, types, and organization/collection IDs.
    List {
        #[arg(long)]
        search: Option<String>,
    },
    /// Inject selected fields into a child; no implicit shell or synchronization.
    Run {
        #[arg(long = "env", required = true)]
        bindings: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// Persist plaintext credentials into an owner-only file.
    Write {
        #[arg(long = "env", required = true)]
        bindings: Vec<String>,
        #[arg(long, conflicts_with = "zshrc", required_unless_present = "zshrc")]
        dotenv: Option<PathBuf>,
        #[arg(long, conflicts_with = "dotenv")]
        zshrc: Option<PathBuf>,
    },
    /// Remove the stored session and lock the vault; written files remain unchanged.
    Lock,
    /// Read-only dependency, configuration, and session checks.
    Doctor,
    #[command(hide = true)]
    SessionServe,
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = execute(&cli) {
        // Internal boundaries deliberately discard raw bw output and secret values.
        if cli.json {
            eprintln!(
                "{}",
                json!({"error":{"code":"LATCH_ERROR", "message":error.to_string()}})
            );
        } else {
            eprintln!("latch: {error}");
        }
        std::process::exit(1);
    }
}

fn output(value: Value, json_output: bool) {
    if json_output {
        println!("{value}");
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("JSON Value serialization")
        );
    }
}

fn execute(cli: &Cli) -> Result<()> {
    let state = config::State::new(cli.state_dir.clone())?;
    if matches!(cli.command, Action::SessionServe) {
        return session::serve(&state.root);
    }
    if let Action::Configure { server, bw } = &cli.command {
        let proposed = config::Config::new(server, bw)?;
        state.prepare()?;
        let _guard = state.lock(true)?;
        let backend = bw::Bw::new(&proposed, &state);
        backend.check_version()?;
        let previously_configured = state.config_path().exists();
        let server_changed = if previously_configured {
            state.load()?.server != proposed.server
        } else {
            true
        };
        let old_helper_running = session::probe(&state.root).is_ok();
        ensure!(
            !previously_configured || old_helper_running,
            "existing session helper is unavailable; restore its LaunchAgent before reconfiguring, or use a new --state-dir and log in again"
        );
        backend.configure_server(server_changed)?;
        // Source-built executables have different Keychain signing identities.
        // Let the running old helper read and delete its own entry, then let the
        // new helper recreate it. Keep the session only in zeroized memory.
        let previous_session = if old_helper_running && !server_changed {
            session::get_optional(&state.root)
                .context("could not read existing session; unlock Keychain or recover the old helper before reconfiguring")?
                .map(Zeroizing::new)
        } else {
            None
        };
        if old_helper_running {
            // Confirm deletion/absence through the old helper before stopping it,
            // including when changing servers (whose session must not transfer).
            session::delete(&state.root)
                .context("could not prepare helper upgrade; unlock Keychain and retry configure")?;
        }
        session::install(&state.root)
            .context("could not restart helper; run configure again, then login if needed")?;
        if let Some(token) = previous_session {
            session::put(&state.root, &token)
                .context("helper restarted but session transfer failed; run login again")?;
        }
        state.save(&proposed)?;
        output(json!({"configured":true,"helper_installed":true}), cli.json);
        return Ok(());
    }
    if matches!(cli.command, Action::Status | Action::Doctor) && !state.config_path().exists() {
        output(json!({"configured":false,"ready":false}), cli.json);
        return Ok(());
    }
    state.validate()?;
    let _guard = state.lock(false)?;
    let config = state.load()?;
    let backend = bw::Bw::new(&config, &state);
    // Lock must still delete persisted sessions if the dependency has gone missing.
    if matches!(cli.command, Action::Lock) {
        let deleted = session::delete(&state.root);
        let locked = backend.call(&["lock"], None);
        ensure!(
            deleted.is_ok() && locked.is_ok(),
            "lock incomplete: session deletion or bw lock failed; check helper and dependency with doctor"
        );
        output(json!({"locked":true}), cli.json);
        return Ok(());
    }
    if matches!(cli.command, Action::Doctor) {
        let dependency = backend.check_version().is_ok();
        let helper = session::probe(&state.root).is_ok();
        let stored = session::get(&state.root).ok().map(Zeroizing::new);
        let status = if dependency {
            backend.status(stored.as_deref().map(|s| s.as_str())).ok()
        } else {
            None
        };
        let ready = helper
            && dependency
            && status.as_ref().and_then(|s| s["status"].as_str()) == Some("unlocked");
        output(
            json!({"configured":true,"supported_bw":dependency,"helper_reachable":helper,
            "session_accessible":stored.is_some(),"vault_status":status.as_ref().and_then(|s|s["status"].as_str()),"ready":ready}),
            cli.json,
        );
        return Ok(());
    }
    backend.check_version()?;
    // Check the actual backend endpoint before prompting or resolving credentials.
    // Lock remains available even if backend configuration needs repair.
    let initial_status = backend.status(None)?;
    match &cli.command {
        Action::Status => {
            let token = session::get(&state.root).ok().map(Zeroizing::new);
            let status = backend.status(token.as_deref().map(|s| s.as_str()))?;
            output(
                json!({"configured":true,"session_accessible":token.is_some(),
                "vault_status":status["status"],"last_sync":status["lastSync"]}),
                cli.json,
            );
        }
        Action::Login { api_key } => {
            ensure!(
                std::io::stdin().is_terminal(),
                "login requires an interactive terminal"
            );
            session::probe(&state.root).context(
                "session helper unavailable; run configure from a logged-in desktop session",
            )?;
            let status = initial_status;
            let password = Zeroizing::new(
                inquire::Password::new("Master password:")
                    .with_display_mode(inquire::PasswordDisplayMode::Masked)
                    .without_confirmation()
                    .prompt()?,
            );
            let result = if status["status"] == "unauthenticated" {
                if *api_key {
                    let id =
                        Zeroizing::new(rpassword::prompt_password("Personal API client ID: ")?);
                    let secret =
                        Zeroizing::new(rpassword::prompt_password("Personal API client secret: ")?);
                    backend.authenticate_api(&id, &secret)?;
                    backend.unlock(&password)?
                } else {
                    eprint!("Account email: ");
                    std::io::stderr().flush()?;
                    let mut email = Zeroizing::new(String::new());
                    std::io::stdin().read_line(&mut email)?;
                    backend.login(email.trim_end_matches(['\r', '\n']), &password)?
                }
            } else {
                backend.unlock(&password)?
            };
            let token = Zeroizing::new(result.trim().to_owned());
            ensure!(
                !token.is_empty() && token.len() < 16_384 && !token.contains(char::is_whitespace),
                "bw returned an invalid session"
            );
            if session::put(&state.root, &token).is_err() {
                let _ = session::delete(&state.root);
                let _ = backend.call(&["lock"], None);
                bail!("could not store session in Keychain; login did not complete");
            }
            output(
                json!({"authenticated":true,"session_stored":true}),
                cli.json,
            );
        }
        Action::Sync => {
            let token = Zeroizing::new(session::get(&state.root)?);
            backend.call(&["sync"], Some(&token))?;
            output(json!({"synced":true}), cli.json);
        }
        Action::List { search } => {
            let token = Zeroizing::new(session::get(&state.root)?);
            let raw = Zeroizing::new(backend.call(&["list", "items"], Some(&token))?);
            let items: Value = serde_json::from_str(&raw)
                .map_err(|_| anyhow::anyhow!("bw returned invalid item data"))?;
            output(vault::metadata(&items, search.as_deref())?, cli.json);
        }
        Action::Run { bindings, .. } | Action::Write { bindings, .. } => {
            let selections = vault::parse_bindings(bindings)?;
            let token = Zeroizing::new(session::get(&state.root)?);
            let values = vault::resolve(&selections, |id| {
                backend.call(&["get", "item", id], Some(&token))
            })?;
            // Never hold the shared vault lock across arbitrary child execution.
            drop(token);
            drop(_guard);
            match &cli.command {
                Action::Run { command, .. } => run_child(command, values)?,
                Action::Write { dotenv, zshrc, .. } => {
                    let (path, format) = if let Some(path) = dotenv {
                        (path, write::Format::Dotenv)
                    } else {
                        (
                            zshrc.as_ref().expect("clap requires a destination"),
                            write::Format::Zsh,
                        )
                    };
                    write::write(path, format, &values)?;
                    output(
                        json!({"written":true,"variables": values.iter().map(|(k,_)|k).collect::<Vec<_>>()}),
                        cli.json,
                    );
                }
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn run_child(command: &[OsString], values: Vec<(String, String)>) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    bw::clean_auth_env(&mut child);
    child.envs(values);
    let error = child.exec();
    Err(error).context("could not execute child command")
}
