mod browser;
mod browser_bridge;
mod bw;
mod capabilities;
mod config;
mod mutate;
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
    /// Describe the agent interface without configuration or authentication.
    Capabilities,
    /// Configure an isolated vault and install its per-user session helper.
    Configure {
        #[arg(long)]
        server: String,
        /// Absolute path to a separately installed Bitwarden CLI 2026.8.0.
        #[arg(long)]
        bw: PathBuf,
        /// Session storage: keychain (macOS), memory or secret-service (Linux).
        /// Omitted on reconfigure: preserve the existing choice.
        #[arg(long, value_enum)]
        session_backend: Option<session::Backend>,
    },
    /// Interactively authenticate/unlock and store the session in the configured backend.
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
    /// Create a personal login item from strict JSON stdin; never pass secrets as arguments.
    Create,
    /// Update a login item by UUID from strict JSON stdin (stored-value rotation only).
    Update { item_uuid: String },
    /// Move an item by UUID to vault trash; permanent deletion is never supported.
    Delete { item_uuid: String },
    /// Transfer a personal item to an organization; cannot be moved back.
    Transfer {
        item_uuid: String,
        /// Destination organization UUID.
        #[arg(long)]
        organization: String,
        /// Destination collection UUID; repeat for multiple collections.
        #[arg(long = "collection", required = true)]
        collections: Vec<String>,
    },
    /// Inject selected fields into a child; no implicit shell or synchronization.
    Run {
        #[arg(long = "env", required = true)]
        bindings: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// Fill a browser password field using vault-owned destination policy.
    Browser {
        #[command(subcommand)]
        command: BrowserAction,
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
    SessionServe {
        #[arg(long, value_enum)]
        session_backend: Option<session::Backend>,
    },
}

#[derive(Subcommand)]
enum BrowserAction {
    /// List permitted, policy-matching documents in connected Chrome profiles.
    Targets {
        #[arg(long)]
        item: String,
    },
    /// Install the native host and unpacked extension (macOS/Linux; no vault access).
    InstallHost {
        #[arg(long, default_value = "chrome")]
        browser: String,
        /// Nonstandard Chrome user-data root (not its Default/Profile N subdirectory).
        #[arg(long)]
        user_data_dir: Option<PathBuf>,
    },
    /// Fill one main-frame password input; never submit or retry.
    Fill {
        #[arg(long)]
        item: String,
        /// Loopback browser WebSocket endpoint, not an HTTP discovery URL.
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        target: String,
        #[arg(long)]
        selector: String,
    },
}

fn main() {
    // Chrome launches the registered executable with the extension origin, not a subcommand.
    // Native-host failures must never go to Chrome logs or corrupt framed stdout.
    if let Some(origin) = std::env::args()
        .nth(1)
        .filter(|s| s.starts_with("chrome-extension://"))
    {
        std::panic::set_hook(Box::new(|_| {}));
        let ok = browser_bridge::serve(&origin).is_ok();
        std::process::exit(if ok { 0 } else { 1 });
    }
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
    if matches!(cli.command, Action::Capabilities) {
        output(capabilities::manifest(), cli.json);
        return Ok(());
    }
    if let Action::Browser {
        command:
            BrowserAction::InstallHost {
                browser,
                user_data_dir,
            },
    } = &cli.command
    {
        output(
            browser_bridge::install(browser, user_data_dir.as_deref())?,
            cli.json,
        );
        return Ok(());
    }
    let state = config::State::new(cli.state_dir.clone())?;
    if let Action::SessionServe { session_backend } = &cli.command {
        let selected = session_backend.unwrap_or_default();
        selected.validate()?;
        return session::serve(&state.root, selected);
    }
    if let Action::Configure {
        server,
        bw,
        session_backend,
    } = &cli.command
    {
        let mut proposed = config::Config::new(server, bw)?;
        state.prepare()?;
        let _guard = state.lock(true)?;
        let previous = if state.config_path().exists() {
            Some(state.load()?)
        } else {
            None
        };
        proposed.session_backend = session_backend.unwrap_or_else(|| {
            previous
                .as_ref()
                .map(|c| c.session_backend)
                .unwrap_or_default()
        });
        proposed.session_backend.validate()?;
        let backend = bw::Bw::new(&proposed, &state);
        backend.check_version()?;
        let server_changed = previous
            .as_ref()
            .is_none_or(|c| c.server != proposed.server);
        // Old macOS helpers predate the transport-only ping operation.
        let old_helper_running =
            session::ping(&state.root).is_ok() || session::probe(&state.root).is_ok();
        if old_helper_running {
            let expected = previous
                .as_ref()
                .map(|c| c.session_backend)
                .unwrap_or(proposed.session_backend);
            ensure!(
                helper_backend_matches(&state, expected),
                "running helper does not match the saved session backend; stop the mismatched helper, restore the saved backend's service, and retry configure before changing storage or servers"
            );
        }
        // An unavailable memory helper contains no surviving token. Persistent
        // stores need their old helper to authorize deletion before replacement.
        ensure!(
            previous.as_ref().is_none_or(|c| {
                c.session_backend == session::Backend::Memory
                    || (c.recovery_pending
                        && c.session_backend == proposed.session_backend
                        && !server_changed)
            }) || old_helper_running,
            "existing session helper is unavailable; recover the saved persistent backend and server before switching storage or servers, or use a new --state-dir and log in again"
        );
        // A Secret Service item is not tied to executable identity. Preserve
        // it on a same-backend/server restart, including when its collection is
        // no longer the default. Keychain upgrades still require handoff.
        let preserve_store = old_helper_running
            && !server_changed
            && proposed.session_backend == session::Backend::SecretService
            && previous.as_ref().is_some_and(|c| {
                c.session_backend == proposed.session_backend && !c.recovery_pending
            });
        if old_helper_running {
            let source_backend = previous
                .as_ref()
                .map(|c| c.session_backend)
                .unwrap_or(proposed.session_backend);
            let source_ready = if source_backend == proposed.session_backend && !server_changed {
                check_session_storage(&state, source_backend)
            } else {
                // Leaving an empty store requires readable absence and verified
                // deletion, not a default collection for creating a new item.
                session::get_optional(&state.root).map(|token| {
                    let _token = Zeroizing::new(token);
                })
            };
            source_ready.context(
                "existing session storage is unavailable; unlock or repair it before reconfiguring",
            )?;
        }
        backend.configure_server(server_changed)?;
        let previous_session = if old_helper_running
            && !preserve_store
            && !server_changed
            && !previous.as_ref().is_some_and(|c| c.recovery_pending)
        {
            session::get_optional(&state.root)
                .context("could not read existing session; unlock its storage and retry configure")?
                .map(Zeroizing::new)
        } else {
            None
        };
        if old_helper_running && !preserve_store {
            session::delete(&state.root).context(
                "could not clear previous session storage; unlock it and retry configure",
            )?;
        }
        // Persist the selected backend before starting the replacement. If
        // replacement fails, configuration describes the requested recovery
        // target, never the already-cleared old store. No token goes to disk.
        proposed.recovery_pending = true;
        state.save(&proposed).context(
            "could not save configuration; repair configuration before retrying, then check session status",
        )?;
        session::install(&state.root, proposed.session_backend)
            .context("configuration saved but helper installation failed; repair the user service, rerun configure with the same options, then login")?;
        ensure!(
            helper_backend_matches(&state, proposed.session_backend),
            "replacement helper has the wrong backend; configuration recovery is pending, repair the service and rerun configure"
        );
        // A newly selected persistent backend can contain an older session for
        // this state path. Clear it before admitting only the verified handoff.
        if !preserve_store {
            session::delete(&state.root).context(
                "replacement session storage could not be cleared; unlock it, rerun configure to complete recovery, then login")?;
        }
        if let Some(token) = previous_session {
            session::put(&state.root, &token)
                .context("helper replaced but session transfer failed; rerun configure to complete recovery, then login")?;
        }
        check_session_storage(&state, proposed.session_backend).context(
            "configured session storage is unavailable; unlock or create its default keyring, then rerun configure with the saved settings")?;
        proposed.recovery_pending = false;
        state
            .save(&proposed)
            .context("helper installed but completion could not be saved; rerun configure")?;
        output(
            json!({"configured":true,"helper_installed":true,"helper_service":session::service_name(&state.root)?,
            "session_backend":proposed.session_backend,
            "session_persistence":session_persistence(proposed.session_backend)}),
            cli.json,
        );
        return Ok(());
    }
    if matches!(cli.command, Action::Status | Action::Doctor) && !state.config_path().exists() {
        output(json!({"configured":false,"ready":false}), cli.json);
        return Ok(());
    }
    // A producer may stall or itself need Latch; never hold the vault lock
    // while waiting for its stdin. Validate the complete input first.
    let mutation_input = match cli.command {
        Action::Create | Action::Update { .. } => {
            Some(mutate::read_stdin(matches!(cli.command, Action::Create))?)
        }
        _ => None,
    };
    state.validate()?;
    let _guard = state.lock(false)?;
    let config = state.load()?;
    let backend = bw::Bw::new(&config, &state);
    // Lock must still delete persisted sessions if the dependency has gone missing.
    if matches!(cli.command, Action::Lock) {
        let backend_matches = helper_backend_matches(&state, config.session_backend);
        let deleted = session::delete(&state.root);
        let locked = backend.call(&["lock"], None);
        ensure!(
            backend_matches && deleted.is_ok() && locked.is_ok(),
            "lock incomplete: helper identity, session deletion, or bw lock failed; check helper and dependency with doctor"
        );
        output(json!({"locked":true}), cli.json);
        return Ok(());
    }
    if matches!(cli.command, Action::Doctor) {
        let dependency = backend.check_version().is_ok();
        let helper = session::ping(&state.root).is_ok() || session::probe(&state.root).is_ok();
        let storage = check_session_storage(&state, config.session_backend);
        let backend_matches = helper_backend_matches(&state, config.session_backend);
        let stored = if backend_matches && !config.recovery_pending {
            session::get(&state.root).ok().map(Zeroizing::new)
        } else {
            None
        };
        let status = if dependency && backend.status(None).is_ok() {
            backend.status(stored.as_deref().map(|s| s.as_str())).ok()
        } else {
            None
        };
        let ready = helper
            && storage.is_ok()
            && backend_matches
            && !config.recovery_pending
            && dependency
            && status.as_ref().and_then(|s| s["status"].as_str()) == Some("unlocked");
        output(
            json!({"configured":true,"supported_bw":dependency,"helper_reachable":helper,
            "session_backend":config.session_backend,
            "helper_service":session::service_name(&state.root).ok(),
            "helper_backend_matches":backend_matches,"configuration_recovery_pending":config.recovery_pending,
            "session_persistence":session_persistence(config.session_backend),
            "storage_accessible":storage.is_ok(),
            "storage_error":storage.err().map(|e|e.to_string()),
            "session_accessible":stored.is_some(),"vault_status":status.as_ref().and_then(|s|s["status"].as_str()),"ready":ready}),
            cli.json,
        );
        return Ok(());
    }
    let backend_matches = helper_backend_matches(&state, config.session_backend);
    if !matches!(cli.command, Action::Status) {
        ensure!(
            !config.recovery_pending,
            "configuration recovery is incomplete; rerun configure with the saved server, bw path, and session backend"
        );
        ensure!(
            backend_matches,
            "session helper unavailable, incompatible, or using a different backend; rerun configure to repair it, then login"
        );
    }
    backend.check_version()?;
    // Check the actual backend endpoint before prompting or resolving credentials.
    // Lock remains available even if backend configuration needs repair.
    let initial_status = backend.status(None)?;
    match &cli.command {
        Action::Status => {
            let token = if backend_matches && !config.recovery_pending {
                session::get(&state.root).ok().map(Zeroizing::new)
            } else {
                None
            };
            let status = backend.status(token.as_deref().map(|s| s.as_str()))?;
            output(
                json!({"configured":true,"session_backend":config.session_backend,
                "session_persistence":session_persistence(config.session_backend),"session_accessible":token.is_some(),
                "configuration_recovery_pending":config.recovery_pending,"helper_backend_matches":backend_matches,
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
                "session storage unavailable; check doctor and repair the configured user service or unlock its keyring",
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
                bail!("could not store session in the configured backend; login did not complete");
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
        Action::Create | Action::Update { .. } => {
            let input = mutation_input.expect("mutation input was parsed before locking");
            let token = Zeroizing::new(session::get(&state.root)?);
            let id = match &cli.command {
                Action::Update { item_uuid } => Some(item_uuid.as_str()),
                _ => None,
            };
            output(mutate::execute(&backend, &token, id, input)?, cli.json);
        }
        Action::Delete { item_uuid } => {
            let token = Zeroizing::new(session::get(&state.root)?);
            output(mutate::delete(&backend, &token, item_uuid)?, cli.json);
        }
        Action::Transfer {
            item_uuid,
            organization,
            collections,
        } => {
            let token = Zeroizing::new(session::get(&state.root)?);
            output(
                mutate::transfer(&backend, &token, item_uuid, organization, collections)?,
                cli.json,
            );
        }
        Action::Browser {
            command:
                BrowserAction::Fill {
                    item,
                    endpoint,
                    target,
                    selector,
                },
        } => {
            if let Some(endpoint) = endpoint {
                browser::validate(endpoint, target, selector)?;
            } else {
                browser_bridge::validate_target(target, selector)?;
            }
            let id = uuid::Uuid::parse_str(item)
                .map_err(|_| anyhow::anyhow!("item must be a UUID"))?
                .hyphenated()
                .to_string();
            let token = Zeroizing::new(session::get(&state.root)?);
            backend.call(&["sync"], Some(&token))?;
            let raw = Zeroizing::new(backend.call(&["get", "item", &id], Some(&token))?);
            let payload = browser::payload(
                &raw,
                &id,
                endpoint.as_deref().unwrap_or(""),
                target,
                selector,
            )?;
            drop(raw);
            drop(token);
            drop(_guard);
            if endpoint.is_some() {
                browser::deliver(&payload)?;
                output(json!({"status":"filled","fields":1}), cli.json);
            } else {
                let result = browser_bridge::fill(&payload)?;
                let filled = result["status"] == "filled";
                output(result, cli.json);
                ensure!(
                    filled,
                    "browser fill did not confirm success; do not retry automatically"
                );
            }
        }
        Action::Browser {
            command: BrowserAction::Targets { item },
        } => {
            let id = uuid::Uuid::parse_str(item)
                .map_err(|_| anyhow::anyhow!("item must be a UUID"))?
                .hyphenated()
                .to_string();
            let token = Zeroizing::new(session::get(&state.root)?);
            backend.call(&["sync"], Some(&token))?;
            let raw = Zeroizing::new(backend.call(&["get", "item", &id], Some(&token))?);
            let rules = browser::rules(&raw, &id)?;
            drop(raw);
            drop(token);
            drop(_guard);
            output(browser_bridge::targets(&rules)?, cli.json);
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

fn session_persistence(backend: session::Backend) -> &'static str {
    match backend {
        session::Backend::Memory => {
            "BW_SESSION only: until helper exits; Bitwarden authentication/cache state remains on disk"
        }
        _ => {
            "BW_SESSION in OS credential store; Bitwarden authentication/cache state remains on disk"
        }
    }
}

fn helper_backend_matches(state: &config::State, selected: session::Backend) -> bool {
    match session::info(&state.root) {
        Ok(info) => info["backend"].as_str() == Some(selected.as_str()),
        // Upgrade compatibility for the original macOS-only broker protocol.
        Err(_) if cfg!(target_os = "macos") && selected == session::Backend::Keychain => {
            session::probe(&state.root).is_ok()
        }
        Err(_) => false,
    }
}

fn check_session_storage(state: &config::State, selected: session::Backend) -> Result<()> {
    if cfg!(target_os = "macos")
        && selected == session::Backend::Keychain
        && session::info(&state.root).is_err()
    {
        // The original macOS broker's probe is transport-only. An optional
        // read distinguishes accessible-but-empty Keychain from a locked store.
        let _session = Zeroizing::new(session::get_optional(&state.root)?);
        Ok(())
    } else {
        session::probe(&state.root)
    }
}
