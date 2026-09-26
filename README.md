# Latch

**A secrets CLI for agents and developer tools.**

Latch connects to Vaultwarden through the Bitwarden CLI, discovers vault items, and injects selected credentials into commands or configuration files. Terminal users, Codex, and OpenClaw use the same `latch` interface.

Authentication, encryption, and vault synchronization are handled by Bitwarden. Latch manages the local session and how credentials reach your tools.

> **Project status:** Early v0, macOS only. Validated on Apple silicon with Bitwarden CLI 2026.8.0 and a disposable Vaultwarden 1.37.2 instance. See [validation](#validation) for the tested scope.

[Quickstart](#quickstart) · [Usage](#usage) · [Command reference](#command-reference) · [Security](#security-model) · [Development](#development) · [License](#license)

## Features

- **Metadata-only discovery.** Find items by name without displaying their credentials.
- **Subprocess injection.** Pass selected fields as environment variables without printing them.
- **File injection.** Update a `.env` file or managed exports in `.zshrc`.
- **Keychain sessions.** Reuse a session across terminal and SSH connections through a local macOS helper.
- **Agent integration.** Structured JSON output and a thin usage skill, with authentication implemented in the CLI.

## Requirements

| Component | Requirement |
| --- | --- |
| Platform | macOS with a logged-in desktop session |
| Session storage | Unlocked login Keychain at `~/Library/Keychains/login.keychain-db` |
| Vault | A Vaultwarden account and an HTTPS server URL |
| Bitwarden CLI | Separately installed `bw` **2026.8.0** |
| Source builds | Current stable Rust with Edition 2024 support |

Latch checks the exact `bw` version before vault operations. Version 2026.9.0 has a documented Vaultwarden login regression; see [upstream issue #7750](https://github.com/dani-garcia/vaultwarden/issues/7750). Latch does not bundle or update `bw`.

Linux, Windows, relocated login Keychains, SSO, device approval, and email/password login with an OTP challenge are outside v0. Accounts using two-factor authentication can use the personal API-key login flow described below.

## Installation

### From source

From a local checkout of this repository:

```sh
cargo install --path . --locked
latch --help
```

The Cargo package is `latch-secrets`; the installed executable is `latch`.

### Homebrew

Homebrew packaging is prepared, but the tap has not been published. Use the source installation above for now. Maintainers can follow the [Homebrew release guide](packaging/homebrew/README.md) to validate and publish a release.

## Quickstart

Install Latch at a stable path, then run configuration from a logged-in macOS desktop session:

```sh
# Replace the server URL and bw path with your installation details.
latch configure --server https://vault.example.com --bw /absolute/path/to/bw

# Authenticate interactively, then refresh the local vault.
latch login
latch sync

# Find an item and copy its UUID for the next command.
latch list --search deployment --json
```

Inject a field into your application, replacing the example UUID and command:

```sh
latch run \
  --env API_TOKEN=00000000-0000-4000-8000-000000000001/login.password \
  -- deploy-tool
```

For accounts requiring two-factor authentication, use `latch login --api-key`. It prompts for the master password and personal API credentials without echoing them. Latch does not store these credentials.

## Usage

### Select fields

Both `run` and `write` accept repeated `--env NAME=ITEM_UUID/FIELD` arguments.

| Selector | Value |
| --- | --- |
| `login.username` | Login username |
| `login.password` | Login password |
| `custom.NAME` | Exactly named text or hidden custom field |

Use item UUIDs returned by `list`; item names are not selectors. Missing fields, ambiguous custom-field names, duplicate variable mappings, unsupported types, and NUL bytes fail before a command starts or a destination changes. Empty strings are valid. Variable names beginning with `BW_`, `BITWARDENCLI_`, or `LATCH_` are reserved.

### Run a command

```sh
latch run \
  --env ACCOUNT=00000000-0000-4000-8000-000000000001/login.username \
  --env API_TOKEN=00000000-0000-4000-8000-000000000001/login.password \
  -- deploy-tool --dry-run
```

Latch executes the command directly, without an implicit shell. It inherits ordinary environment variables, overwrites the selected variables, and removes Latch/Bitwarden authentication variables and inherited Node runtime overrides. The child retains its output, exit status, and signal behavior.

`list`, `run`, and `write` read the last synchronized local vault. Run `latch sync` when you need current server data; synchronization and retries are explicit.

### Write credentials to a file

**File injection persists plaintext secrets.**

```sh
latch write \
  --env API_TOKEN=00000000-0000-4000-8000-000000000001/login.password \
  --dotenv .env

latch write \
  --env API_TOKEN=00000000-0000-4000-8000-000000000001/login.password \
  --zshrc "$HOME/.zshrc"
```

| Destination | Behavior |
| --- | --- |
| `.env` | Updates selected variables and preserves unrelated supported assignments, blank lines, and comments. Uses a strict, single-line, dotenvy-compatible format. |
| `.zshrc` | Updates one marked block of safely quoted `export` statements in place. Preserves surrounding text and previously managed variables that were not selected. |

The dotenv writer rejects duplicate keys, `export` prefixes, multiline values, and unsupported quoting or inline comments. It escapes backslashes, quotes, and dollar signs; other dotenv parsers may interpret these differently. Do not source the generated `.env` file as a shell script.

Writes are atomic, use owner-only permissions (`0600`), and create no backup. The parent directory must exist. Symlinks, hard-linked files, foreign-owned files, and paths containing `..` are rejected. A private temporary file is used during replacement; a sidecar lock serializes cooperating Latch writers. Other editors do not participate in that lock.

Files are snapshots: rerun `write` after rotating credentials. New interactive zsh shells read `.zshrc`; existing shells must source it explicitly. Other shell assignments can override managed exports according to their order. Latch does not execute the file during a write.

### Use with agents

The optional [Latch skill](skills/latch/SKILL.md) documents discovery and injection for agents. It delegates authentication and session handling to the CLI.

Use `--json` for machine-readable results. Never retrieve credentials into a conversation or use a child command that prints its environment.

## Command reference

| Command | Purpose |
| --- | --- |
| `configure` | Save connection settings and install or restart the desktop session helper |
| `login` | Authenticate or unlock interactively and store the session in Keychain |
| `status` | Report configuration, session accessibility, vault state, and last sync |
| `sync` | Refresh the local encrypted vault from the server |
| `list` | Return item metadata; optionally filter names with `--search` |
| `run` | Inject selected fields into a child process |
| `write` | Persist selected fields into `.env` or `.zshrc` |
| `lock` | Delete the stored session and ask Bitwarden to lock the vault |
| `doctor` | Check dependency compatibility, helper accessibility, and vault readiness |

Run `latch <command> --help` for options.

### Output and exit codes

Results use JSON on stdout: compact with `--json`, pretty-printed otherwise. With `--json`, operational errors use this stderr format:

```json
{"error":{"code":"LATCH_ERROR","message":"..."}}
```

| Outcome | Exit behavior |
| --- | --- |
| Completed operation or inspection | `0` |
| Latch operational failure | `1` |
| Invalid CLI syntax | `2`, with CLI help/error text |
| Started child process | Child exit status and signals are preserved |

`status` and `doctor` can return `0` when the vault is not ready: inspect their result fields. For `run`, stdout and stderr belong to the child after execution begins. Noninteractive commands never prompt for authentication. Raw `bw` diagnostics are suppressed to avoid exposing credentials.

## Configuration and troubleshooting

Latch stores non-secret configuration and isolated Bitwarden state under `~/Library/Application Support/latch-secrets`. An absolute `--state-dir` selects another installation. Use a short path to fit macOS Unix socket limits. State directories must be owned by the current user with private permissions (`0700`); symlink paths are refused.

`configure` creates Latch's own state and LaunchAgent. It does not import another wrapper's sessions or reuse existing Bitwarden state. Re-running it refreshes a reachable helper and repairs the backend endpoint when unauthenticated. Latch verifies Bitwarden’s actual server before authentication and vault operations; mismatched or reset backend state fails closed. Changing servers while authenticated is refused; use another state directory. A missing Bitwarden executable can be replaced by configuring another verified 2026.8.0 binary.

Start diagnosis with:

```sh
latch status --json
latch doctor --json
```

An inaccessible Keychain or missing desktop session prevents unattended access. A missing or invalid stored session requires interactive `latch login`. Competing vault operations return a busy error; retry when the other operation finishes. Backend execution is time-limited and responses are capped at 16 MiB.

After upgrading a Homebrew installation, rerun `configure` while the existing helper is still running. It transfers a readable session through memory to the new helper. If the existing helper is unavailable or its Keychain cannot be read, configuration stops with recovery guidance. See the [upgrade notes](packaging/homebrew/README.md#runtime-dependency-and-upgrades) for the stable executable path and recovery procedure.

## Security model

Bitwarden handles cryptography, authentication, encrypted vault storage, and server communication. Latch stores only the session in the login Keychain; it does not persist the master password or personal API credentials.

The helper exposes a local Unix socket with a `0700` directory, a `0600` socket, and matching peer-UID checks. There is no TCP listener or plaintext session file. **All processes under the same OS account are trusted.** Latch does not isolate agents sharing an account or protect against root or a compromised same-user process.

`list` exposes only item IDs, names, types, organization IDs, and collection IDs. Those fields can still be sensitive, and discovery requires decrypted vault access internally.

Latch does not print injected values. A child process can print, persist, or forward its environment. File injection explicitly writes plaintext credentials, and `.zshrc` exports reach subsequent shell child processes.

`lock` prevents future session retrieval through Latch when it completes successfully. It reports partial failure and cannot recall values already resolved by another operation. It does not erase written files, unset existing shells, or revoke credentials already delivered to a process.

## Development

```sh
cargo build --release --locked
cargo fmt --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Release-tooling tests require Python 3.11 or later:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Automated tests cover metadata filtering, field selection, subprocess behavior, file formats and permissions, concurrency, session transport, and dependency compatibility. They use synthetic credentials, a fake Bitwarden process, and an in-memory session store.

### Validation

Local acceptance used synthetic credentials, the real pinned Bitwarden CLI, and a disposable Vaultwarden 1.37.2 instance. It covered login, sync, metadata-only discovery, subprocess and file injection, fresh SSH connections, helper restart, lock, and relogin. An isolated Keychain test verified prompt-free failure while locked and recovery after unlocking. A Homebrew-style binary-swap test replaced a running helper’s executable and recovered its session through `configure`.

The local test server used a test-only TLS wrapper; production TLS settings were unchanged. Intel Macs and hosted release/tap workflows have not been exercised. Local Homebrew checks compile the source archive and exercise the formula’s fetch, install, and test hooks; they do not substitute for the tap’s native dependency-installation CI. Test your deployment before replacing an existing credentials workflow.

Contributions should include focused verification for changed behavior. Keep account details, credentials, sessions, and private infrastructure configuration out of code, fixtures, issues, and pull requests. No minimum Rust version older than the current stable toolchain is promised yet.

For packaging and release procedures, see the [Homebrew release guide](packaging/homebrew/README.md).

## License

Latch is licensed under [Apache-2.0](LICENSE).
