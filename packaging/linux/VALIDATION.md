# Linux port validation

Validated locally on 2026-11-17. These results describe the reviewed Linux implementation before release publication.

## Environments

- macOS ARM64: existing host, Rust 1.100.0. Tests used private temporary directories and synthetic credentials; the installed Latch helper and real vault were not changed.
- Linux ARM64: disposable local Lima/VZ VM, Debian 12 Bookworm, glibc 2.36, native ARM64 Rust 1.100.0 and Debian Chromium 156. No host home mounts or forwarded SSH agent.
- Linux x86-64: all-target Rust cross-check only. Native CI jobs are configured but were not dispatched.

## Initial implementation evidence

- macOS Rust unit/integration suite, formatting, and Clippy with warnings denied. Final added doctor endpoint-preflight regression passed separately.
- Linux ARM64: 91 Rust tests passed (52 unit, 3 capability, 34 CLI, 2 real-process lifecycle), including native broker processes, failed-install repair, live transfer, mismatched-backend refusal, D-Bus protocol errors, missing/locked collections, default-alias changes, prompt refusal, timeouts, saturated socket backlog, and slow-read/write deadlines.
- Actual GNOME Keyring on a private D-Bus: store/read, persistence across broker restart, locked-store failure, provider restart with unlock, and deletion. No existing keyring used.
- Actual systemd user service: responder/MainPID match, live session transfer, loss on restart, stopped-helper repair, lock, rejection of a foreground helper impersonating service readiness, and recovery from that failure.
- Actual VM reboot with lingering already enabled: changed boot ID, active auto-started helper with matching MainPID, and empty memory session. The test did not change lingering.
- Nine browser tests on Debian ARM64, including real Chromium unpacked extension/native-host filling, page-value readback, replay/navigation rejection, extension reconnect, stale-socket cleanup, and CDP delivery. The macOS real extension/native-host test also passed.
- Official Bitwarden 2026.8.0 ARM64 archive checksum, ELF architecture, and native version execution in an isolated home. Both official Linux architecture archives were checksum/ELF checked.
- Real password login and vault operations with checksum-verified native Bitwarden 2026.8.0 and disposable Vaultwarden 1.37.2: ready doctor, sync, create/discovery, subprocess injection, rotation with unrelated-field preservation, soft-delete, deleted-item discovery exclusion and injection refusal. A fixture-only wrapper trusted the generated loopback TLS CA; production environment sanitization was unchanged.
- With the real cached vault, helper restart made the session inaccessible and Bitwarden reported locked; interactive relogin and explicit `latch lock` passed.
- Presence-only inspection of that password-login cache found access/refresh-token, encrypted-data, and KDF-configuration classes. The synthetic plaintext master password and exact broker session value were absent. No secret values were emitted. This does not establish the API-key login storage behavior; that path remains source-reviewed, not runtime-tested.
- Twenty-six release-tool tests: strict archive inventories, architecture and provenance rejection, checksums, and immutable retry behavior.
- Actual optimized ARM64 binary packaged through the strict release packager in a disposable local Git fixture, validated, extracted, and executed without installing a Rust toolchain into its installation prefix. The installed binary passed real keyring and systemd lifecycle checks. The fixture tag/commit were test-only; no source-repository tag or commit was created.
- Homebrew source snapshot: real formula fetch, compilation/install, and formula tests in an isolated prefix. No tap update, Cellar installation, or LaunchAgent activation.
- The initial Astra implementation review was closed, but a subsequent production-readiness review found three blockers and one legacy macOS diagnostic issue. The follow-up evidence below supersedes the initial review status.

## Reproduce

```sh
cargo fmt --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/check_linux_dependencies.py --target aarch64-unknown-linux-gnu
python3 scripts/check_linux_keyring.py --latch target/debug/latch
# Run only on a disposable machine/user session; creates and removes one test unit:
python3 scripts/check_linux_service.py --latch target/debug/latch --confirm-disposable-user-service
cd prototypes/browser-fill
npm ci
LATCH_TEST_CHROMIUM_EXECUTABLE=/usr/bin/chromium npm test
```

The keyring check requires `dbus`, `gnome-keyring`, and `busctl`; the Rust tests also require Python 3 and zsh. The service test uses a synthetic Bitwarden backend and never authenticates to a real vault.

## Limits

No physical Raspberry Pi, native Linux x86-64 machine, Intel Mac, or hosted GitHub workflow was executed. Real API-key login/cache behavior was not tested. Linux ARM64 evidence establishes the Debian userspace baseline; it does not qualify all Pi hardware, browser packages, or distro versions. Last-login shutdown with lingering disabled was not exercised. Native x86-64 and ARM64 CI jobs are present for subsequent authorized pushes. No release was published.

## Cleanup and evidence

The disposable vault container, exact test user units, TLS keys, synthetic account/cache, VM disks, portable VM tools, and task-created image-cache entry were removed. No VM process or test SSH listener remained. The user's installed Latch service, existing vault, and source Git history were not changed. Sanitized logs are retained locally under the ignored `target/linux-validation/` directory, including the real-vault acceptance summary and VM cleanup log. Validation completed before committing or pushing the changes; no release was published.

## Production-review follow-up

The follow-up corrects all three production blockers and the macOS diagnostic issue:

- A stopped persistent backend with pending recovery cannot switch backend or server until its saved settings are recovered, preventing an earlier persistent write from being abandoned.
- Configuration verifies target storage readiness before clearing the recovery flag. A fresh locked or missing default keyring fails. Same-backend Secret Service refresh preserves existing items in their original collections. Switching away from a readable empty store does not require a default collection for new writes; source deletion remains mandatory.
- Linux broker startup checks both `PR_SET_DUMPABLE=0` and the zero core-size limit before initializing session storage. A disposable child-process test verifies effective dumpability and limits.
- Legacy macOS helpers use an optional read to distinguish an empty accessible Keychain from a locked one.

The macOS ARM64 suite passed 79 tests (41 unit, 3 capability, 35 CLI), including the legacy Keychain regression. Targeted configuration/doctor tests and Clippy with warnings denied passed after the final source-preflight adjustment. The actual isolated GNOME Keyring regression passed on the final binary: genuinely absent and locked defaults, retained pending configuration and token after rejected backend/server changes, saved-settings recovery, nondefault-item preservation, and successful empty-store transition to memory with no persistent item remaining. The test verifies GNOME's actual default alias because removing the alias alone falls back to its login collection. It uses real D-Bus/keyring and broker processes with a synthetic service manager; the separate real systemd acceptance also passed.

Independent Astra re-review closed all four original findings and the additional empty-source transition regression, with no remaining actionable findings. The reviewer inspected the final real-keyring evidence and independently reran the legacy macOS diagnostic regression. The final native Debian ARM64 suite passed 93 tests (53 unit, 3 capability, 34 CLI, 3 real-process lifecycle); formatting and Clippy with warnings denied passed. Earlier browser, reboot, live-vault, and package results above cover the preceding snapshot and were not repeated for these focused corrections.

The follow-up VM and its exact test units, disks, keys, portable tools, and task-created cache were also removed. No follow-up VM process or SSH listener remained. Sanitized follow-up suite, lint, keyring, service, and cleanup logs are retained under `target/linux-validation/followup-*.log`.
