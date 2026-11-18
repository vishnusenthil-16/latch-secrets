# Linux and Raspberry Pi installation

Release targets are `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`.
Builds run natively in Debian 12 (Bookworm), with glibc 2.36. Qualification targets
are Debian 12 or newer, Ubuntu 24.04 or newer, and **64-bit** Raspberry Pi OS
Bookworm or newer. Older glibc, musl/Alpine, 32-bit Raspberry Pi OS, and Windows
are not qualified. Cross-build success does not prove Pi lifecycle behavior.
This document defines required qualification; it does not claim that a release
has already passed the Linux or physical-Pi acceptance gate.

## Install a release

No Rust toolchain is needed. Obtain your architecture's archive and `SHA256SUMS`
from the same trusted release. `uname -m` must report `x86_64` or `aarch64`;
`armv7l`/32-bit userspace is unsupported. Replace `VERSION` below with a release
that includes Linux artifacts, without the leading `v`:

```sh
set -eu
version=VERSION
target=aarch64-unknown-linux-gnu # x86_64-unknown-linux-gnu for Intel/AMD
archive="latch-secrets-$version-$target.tar.gz"
base="https://github.com/vishnusenthil-16/latch-secrets/releases/download/v$version"
curl --fail --location --output "$archive" "$base/$archive"
curl --fail --location --output SHA256SUMS "$base/SHA256SUMS"
# Select exactly this archive; do not ignore missing-file checksum errors.
awk -v name="$archive" '$2 == name { print; count++ } END { if (count != 1) exit 1 }' SHA256SUMS > selected.sha256
sha256sum --check selected.sha256
mkdir latch-install
tar -xzf "$archive" -C latch-install
install -d "$HOME/.local/bin"
install -m 0755 latch-install/latch "$HOME/.local/bin/latch"
export PATH="$HOME/.local/bin:$PATH"
latch --version
```

The archive contains only `latch`, `LICENSE`, `README.md`, `SKILL.md`, and
`build.json`. Checksums detect corruption against release metadata; they are
not a signature or independent trust source. Retain `build.json` with test evidence.

Install Bitwarden CLI **2026.8.0** separately. Its official release includes both
native Linux architectures; npm is not required:
<https://github.com/bitwarden/clients/releases/tag/cli-v2026.8.0>.
Verify the matching published SHA256 before extracting/installing:

| Asset | SHA256 |
| --- | --- |
| `bw-linux-2026.8.0.zip` | `367f618e9fcccaac4980ec12c7bafd01df739b5f3cb1af31bc9045cf75eea1d6` |
| `bw-linux-arm64-2026.8.0.zip` | `74d822a5dceda5896ed8fc07bc61925b29afd98d96a6a3e9e525ae556c3083a8` |

`bw --version` must report `2026.8.0`. Latch does not install, upgrade, or bundle
Bitwarden. `scripts/check_linux_dependencies.py` checks the pinned digest, ELF
architecture and native `--version` in an isolated home without vault login.

## Configure the helper

Run as the intended user, not root. A systemd user manager must be available.
For headless use, substitute your actual HTTPS server and absolute `bw` path:

```sh
latch configure --server https://vault.example.com --bw "$HOME/.local/bin/bw" --session-backend memory
latch login
latch doctor --json
```

State defaults to `$XDG_STATE_HOME/latch-secrets`, or
`~/.local/state/latch-secrets`. An absolute `--state-dir` selects another isolated
installation. Keep it short enough for `<state>/session/broker.sock`; directories
must remain private and user-owned. Changing environment paths does not migrate
an existing installation.

**Memory storage means only Latch's copy of `BW_SESSION` stays in memory.**
Bitwarden maintains persistent state in `<state>/bw`; depending on login mode,
it can include authentication tokens and an API client secret. Losing the helper
process does not erase this cache, revoke tokens, or invalidate copies held by
other processes. `latch lock` clears the broker copy and invokes `bw lock`; it
is not server-side revocation or full cache deletion.

After helper restart/reboot, run `latch login` again. If stopped, rerun
`configure` with the same state/backend first. Upgrades and backend changes may
require login again; do not assume uninterrupted session transfer. Reconfiguration
retains the previous backend unless `--session-backend` is supplied. If a persistent configuration is pending and its helper stopped, first repair using its saved backend and server; switching away is refused until the original store can be safely handled. A missing or locked default keyring cannot produce a successful fresh configuration. Same-backend Secret Service restarts preserve existing items in their original collections.

For desktop persistence, install a Secret Service provider
(Debian/Ubuntu: `gnome-keyring`), then select
`--session-backend secret-service`. Unlock the keyring interactively. Missing or
locked storage must fail clearly, with no silent fallback. Starting the helper
does not unlock the keyring.

## SSH and boot

A systemd user manager can stop after the user's last session exits. An immediate
reconnect or overlapping SSH session does not verify persistence after logout.
To intentionally start user services at boot and keep them after logout:

```sh
loginctl enable-linger "$USER"
loginctl show-user "$USER" -p Linger
```

This affects the user's other services too; it is an explicit choice, not an
installer side effect. Reverse with `loginctl disable-linger "$USER"`.
Lingering does not restore a lost memory session or unlock a vault after reboot.

## Upgrade and remove

Lock first, preserve the configured state/backend, and replace the executable
at its stable absolute path. Rerun the same `configure` command, then `login`
and `doctor`; verify injection with a disposable credential before resuming an
agent. A failed replacement is not a successful authenticated upgrade.

For removal, run `latch lock` while the helper is available. Take the exact unit
name reported by `configure`/`doctor`: `latch-session-<state-path-hash>.service`.
Stop only that installation with `systemctl --user disable --now "$unit"`,
remove its exact unit file under `${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user`,
and run `systemctl --user daemon-reload`. Remove the executable only if no other
installation uses it. Preserve state unless explicitly deleting the local
Bitwarden cache/configuration is intended. Do not delete shared keyrings or
unrelated services. Browser native-host registration requires separate removal
for the installed browser/profile. Local removal is not server-side revocation.

## Release qualification

CI executes Rust and packaging tests natively on x86-64 and ARM64 against Debian
12. It does not prove SSH/systemd boot behavior or operation on a physical Pi.
For each release commit, record architecture, OS/glibc versions, commit and
artifact SHA256, Bitwarden version, and results for:

- Clean installation without Rust, configuration, login, sync, discovery,
  subprocess/file injection and lock using disposable synthetic credentials.
- Password and API-key login cache inspection: record only the presence/class
  of canary secret material, never secret contents.
- Fresh SSH, final logout after user-manager exit, restart and reboot, with
  lingering both enabled and disabled. Helper loss must require login in memory mode.
- Missing/locked Secret Service, unlock recovery, bounded failure and deletion
  against a real desktop keyring.
- Wrong-user access, unsafe permissions/symlinks, concurrency, helper death,
  failed reconfiguration, backend changes and binary upgrades.
- Synthetic browser fill/reconnect on each advertised native Chrome/Chromium
  packaging, including the Pi's actual browser distribution.
- Existing macOS checks and macOS upgrade/recovery regression checks.

Debian ARM64 verification establishes a Linux userspace baseline. If a physical
Pi is unavailable, record that limitation and do not claim Pi-specific SSH,
reboot, hardware, or browser qualification. Release notes should identify the
actual tested distributions/architectures and any unverified lifecycle checks.
The existing `release` environment controls publication authorization; no new
manual attestation variable is required.

Release tooling validates target ELF architecture, source commit, strict archive
inventories and checksums, then adds both Linux archives to the source/Homebrew
bundle. Retries accept byte-identical assets only; changed existing binaries are
never overwritten. Homebrew continues to use the source archive.
