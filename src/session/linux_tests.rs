//! Real D-Bus transport with a private, synthetic Secret Service provider.
//! Requires dbus-daemon; never connects to the user's session bus or keyring.
use super::*;
use std::{
    io::{BufRead, BufReader},
    process::Child,
    sync::{Arc, Mutex},
};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const COLLECTION: &str = "/org/freedesktop/secrets/collection/test";
const NEW_COLLECTION: &str = "/org/freedesktop/secrets/collection/new";
const ITEM: &str = "/org/freedesktop/secrets/collection/test/item";
const SESSION: &str = "/org/freedesktop/secrets/session/test";
const PROMPT: &str = "/org/freedesktop/secrets/prompt/test";
const CANARY: &str = "SYNTHETIC_SESSION_ONLY";
type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
fn path(value: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(value).unwrap()
}

#[derive(Default)]
struct ProviderState {
    token: Option<Vec<u8>>,
    item_locked: bool,
    default_locked: bool,
    missing_collection: bool,
    rotated_collection: bool,
    require_prompt: bool,
    stalled: bool,
    prompts: usize,
    dismissals: usize,
}
type Shared = Arc<Mutex<ProviderState>>;
struct Service(Shared);
#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    fn read_alias(&self, alias: &str) -> OwnedObjectPath {
        assert_eq!(alias, "default");
        let state = self.0.lock().unwrap();
        path(if state.missing_collection {
            "/"
        } else if state.rotated_collection {
            NEW_COLLECTION
        } else {
            COLLECTION
        })
    }
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        assert_eq!(attributes.get("service").map(String::as_str), Some(SERVICE));
        assert_eq!(
            attributes.get("account").map(String::as_str),
            Some("synthetic-account")
        );
        let stalled = self.0.lock().unwrap().stalled;
        if stalled {
            std::future::pending::<()>().await;
        }
        let state = self.0.lock().unwrap();
        if state.token.is_none() {
            (vec![], vec![])
        } else if state.item_locked {
            (vec![], vec![path(ITEM)])
        } else {
            (vec![path(ITEM)], vec![])
        }
    }
    fn open_session(&self, algorithm: &str, _input: OwnedValue) -> (OwnedValue, OwnedObjectPath) {
        assert_eq!(algorithm, "plain");
        (
            OwnedValue::try_from(Value::from("")).unwrap(),
            path(SESSION),
        )
    }
}
struct Collection(Shared);
#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.lock().unwrap().default_locked
    }
    async fn search_items(&self, attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
        assert_eq!(attributes.get("service").map(String::as_str), Some(SERVICE));
        assert_eq!(
            attributes.get("account").map(String::as_str),
            Some("synthetic-account")
        );
        let stalled = self.0.lock().unwrap().stalled;
        if stalled {
            std::future::pending::<()>().await;
        }
        if self.0.lock().unwrap().token.is_some() {
            vec![path(ITEM)]
        } else {
            vec![]
        }
    }
    fn create_item(
        &self,
        _properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
    ) -> (OwnedObjectPath, OwnedObjectPath) {
        assert!(replace);
        let mut state = self.0.lock().unwrap();
        if state.require_prompt {
            return (path("/"), path(PROMPT));
        }
        assert_eq!(secret.0.as_str(), SESSION);
        assert!(secret.1.is_empty());
        assert_eq!(secret.3, "text/plain");
        state.token = Some(secret.2);
        (path(ITEM), path("/"))
    }
}
struct Item(Shared);
#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.lock().unwrap().item_locked
    }
    fn get_secret(&self, session: OwnedObjectPath) -> Secret {
        assert_eq!(session.as_str(), SESSION);
        (
            session,
            vec![],
            self.0.lock().unwrap().token.clone().unwrap(),
            "text/plain".to_owned(),
        )
    }
    fn set_secret(&self, secret: Secret) {
        self.0.lock().unwrap().token = Some(secret.2);
    }
    fn delete(&self) -> OwnedObjectPath {
        let mut state = self.0.lock().unwrap();
        if state.require_prompt {
            return path(PROMPT);
        }
        state.token = None;
        path("/")
    }
}
struct Prompt(Shared);
#[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    fn prompt(&self, _window_id: &str) {
        self.0.lock().unwrap().prompts += 1;
    }
    fn dismiss(&self) {
        self.0.lock().unwrap().dismissals += 1;
    }
}
struct Session;
#[zbus::interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    fn close(&self) {}
}

struct Bus(Child);
impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Fixture {
    // Drop connections/runtime before the private bus.
    client: zbus::Connection,
    _server: zbus::Connection,
    runtime: tokio::runtime::Runtime,
    state: Shared,
    _bus: Bus,
}
impl Fixture {
    fn new() -> Result<Self> {
        let mut bus = Bus(Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--nopidfile", "--print-address=1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Linux session tests require dbus-daemon")?);
        let mut address = String::new();
        BufReader::new(bus.0.stdout.take().unwrap()).read_line(&mut address)?;
        ensure!(!address.trim().is_empty(), "test bus did not start");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let state = Shared::default();
        let (server, client) = runtime.block_on(async {
            let server = zbus::connection::Builder::address(address.trim())?
                .name(BUS_NAME)?
                .serve_at(BUS_PATH, Service(state.clone()))?
                .serve_at(COLLECTION, Collection(state.clone()))?
                .serve_at(NEW_COLLECTION, Collection(state.clone()))?
                .serve_at(ITEM, Item(state.clone()))?
                .serve_at(PROMPT, Prompt(state.clone()))?
                .serve_at(SESSION, Session)?
                .build()
                .await?;
            let client = zbus::connection::Builder::address(address.trim())?
                .build()
                .await?;
            Ok::<_, anyhow::Error>((server, client))
        })?;
        Ok(Self {
            client,
            _server: server,
            runtime,
            state,
            _bus: bus,
        })
    }
    fn execute(&self, operation: Operation<'_>, timeout: Duration) -> Result<Option<String>> {
        self.runtime.block_on(async {
            tokio::time::timeout(
                timeout,
                desktop_connected(&self.client, "synthetic-account", operation),
            )
            .await
            .map_err(|_| StoreError("store_timeout"))?
        })
    }
    fn operation(&self, operation: Operation<'_>) -> Result<Option<String>> {
        self.execute(operation, STORE_TIMEOUT)
    }
}

#[test]
fn secret_service_round_trip_and_locked_missing_diagnostics() -> Result<()> {
    let fixture = Fixture::new()?;
    assert!(fixture.operation(Operation::Read)?.is_none());
    fixture.operation(Operation::Put(CANARY))?;
    assert_eq!(fixture.operation(Operation::Read)?.as_deref(), Some(CANARY));
    fixture.operation(Operation::Put("REPLACEMENT_SYNTHETIC"))?;
    assert_eq!(
        fixture.operation(Operation::Read)?.as_deref(),
        Some("REPLACEMENT_SYNTHETIC")
    );
    fixture.state.lock().unwrap().item_locked = true;
    for operation in [Operation::Read, Operation::Put(CANARY), Operation::Delete] {
        assert_eq!(
            fixture.operation(operation).unwrap_err().to_string(),
            "store_locked"
        );
    }
    fixture.state.lock().unwrap().item_locked = false;
    fixture.operation(Operation::Delete)?;
    fixture.operation(Operation::Delete)?;
    assert!(fixture.operation(Operation::Read)?.is_none());
    fixture.state.lock().unwrap().missing_collection = true;
    assert!(fixture.operation(Operation::Read)?.is_none());
    assert_eq!(
        fixture
            .operation(Operation::Put(CANARY))
            .unwrap_err()
            .to_string(),
        "store_collection_missing"
    );
    Ok(())
}

#[test]
fn mutation_authorization_never_opens_a_prompt() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.state.lock().unwrap().require_prompt = true;
    assert_eq!(
        fixture
            .operation(Operation::Put(CANARY))
            .unwrap_err()
            .to_string(),
        "store_prompt_required"
    );
    assert!(fixture.state.lock().unwrap().token.is_none());
    fixture.state.lock().unwrap().token = Some(CANARY.as_bytes().to_vec());
    assert_eq!(
        fixture
            .operation(Operation::Delete)
            .unwrap_err()
            .to_string(),
        "store_prompt_required"
    );
    let state = fixture.state.lock().unwrap();
    assert!(state.token.is_some());
    assert_eq!(state.prompts, 0);
    assert_eq!(state.dismissals, 2);
    Ok(())
}

#[test]
fn stalled_provider_does_not_block_subsequent_requests() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.state.lock().unwrap().stalled = true;
    let began = Instant::now();
    assert_eq!(
        fixture
            .execute(Operation::Read, Duration::from_millis(50))
            .unwrap_err()
            .to_string(),
        "store_timeout"
    );
    assert!(began.elapsed() < Duration::from_secs(1));
    fixture.state.lock().unwrap().stalled = false;
    assert!(fixture.operation(Operation::Read)?.is_none());
    Ok(())
}

#[test]
fn default_collection_rotation_cannot_orphan_or_resurrect_a_session() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.operation(Operation::Put(CANARY))?;
    fixture.state.lock().unwrap().rotated_collection = true;
    assert_eq!(fixture.operation(Operation::Read)?.as_deref(), Some(CANARY));
    fixture.operation(Operation::Put("UPDATED_SYNTHETIC"))?;
    assert_eq!(
        fixture.operation(Operation::Read)?.as_deref(),
        Some("UPDATED_SYNTHETIC")
    );
    // A locked owned item in the OLD collection blocks all operations even
    // when the default alias points elsewhere. It must not be silently skipped.
    fixture.state.lock().unwrap().item_locked = true;
    for operation in [Operation::Read, Operation::Put(CANARY), Operation::Delete] {
        assert_eq!(
            fixture.operation(operation).unwrap_err().to_string(),
            "store_locked"
        );
    }
    fixture.state.lock().unwrap().item_locked = false;
    fixture.operation(Operation::Delete)?;
    fixture.state.lock().unwrap().rotated_collection = false;
    assert!(fixture.operation(Operation::Read)?.is_none());
    assert!(fixture.state.lock().unwrap().token.is_none());
    Ok(())
}

#[test]
fn readiness_requires_writable_default_only_when_no_existing_session() -> Result<()> {
    let fixture = Fixture::new()?;
    assert!(fixture.operation(Operation::Probe)?.is_none());
    fixture.state.lock().unwrap().default_locked = true;
    assert_eq!(
        fixture.operation(Operation::Probe).unwrap_err().to_string(),
        "store_locked"
    );
    assert!(fixture.operation(Operation::Read)?.is_none());
    fixture.operation(Operation::Delete)?;
    fixture.state.lock().unwrap().default_locked = false;
    fixture.state.lock().unwrap().missing_collection = true;
    assert_eq!(
        fixture.operation(Operation::Probe).unwrap_err().to_string(),
        "store_collection_missing"
    );
    fixture.state.lock().unwrap().missing_collection = false;
    fixture.operation(Operation::Put(CANARY))?;
    fixture.state.lock().unwrap().default_locked = true;
    assert_eq!(
        fixture.operation(Operation::Probe)?.as_deref(),
        Some(CANARY)
    );
    fixture.state.lock().unwrap().missing_collection = true;
    assert_eq!(
        fixture.operation(Operation::Probe)?.as_deref(),
        Some(CANARY)
    );
    fixture.operation(Operation::Delete)?;
    assert_eq!(
        fixture.operation(Operation::Probe).unwrap_err().to_string(),
        "store_collection_missing"
    );
    Ok(())
}
