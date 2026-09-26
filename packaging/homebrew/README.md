# macOS Homebrew releases

This pipeline prepares source releases and proposes updates to an independently maintained Homebrew tap. It does not build bottles, publish automatically, merge tap PRs, install Bitwarden, or activate Latch's session helper.

## Local preparation and validation

Python 3.11+, a current Rust toolchain, and Homebrew 6+ are required for the packaging checks. Run from the repository root:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/prepare_release.py \
  --tag v0.1.0 --repository vishnusenthil-16/latch-secrets \
  --output target/homebrew-snapshot --snapshot
HOMEBREW_DEVELOPER=1 HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 \
  brew ruby scripts/check_homebrew.rb target/homebrew-snapshot
```

Use a new/empty output directory for each run. The snapshot mode permits an uncommitted working tree so changes can be tested before a release. It is marked `snapshot: true` and the publication verifier rejects it. Its generated formula URL will not be downloadable unless a corresponding release actually exists. Never publish a snapshot bundle.

The check uses Homebrew's formula loader, archive checksum verification, and actual `fetch`, `install`, and `test` methods. It compiles the packaged source and runs the resulting executable in a temporary prefix, using the invoking Rust toolchain. It also checks that the thin skill was installed. It does not install Rust through Homebrew, modify the Cellar, register a tap, install a LaunchAgent, or access Keychain. A hosted tap CI workflow covers the full `brew install` dependency path separately.

Outputs:

- `latch-secrets-X.Y.Z.tar.gz`: deterministic source archive with `Cargo.lock`.
- `Formula/latch-secrets.rb`: real release URL and computed SHA-256.
- `SHA256SUMS`: source and formula checksums.
- `release.json`: repository, tag, version, commit, checksum, and snapshot marker.

Normal preparation omits `--snapshot`. It requires a clean worktree, including untracked files, and HEAD at the existing `vX.Y.Z` tag matching `Cargo.toml`. It packages only allowlisted Git-tracked source inputs; ignored files and build artifacts are excluded. Choose an ignored output directory such as `target/` or a directory outside the worktree.

## Source release workflow

`.github/workflows/release.yml` is manually dispatched, with two inputs:

- `tag`: an existing stable tag, for example `v0.1.0`.
- `create_draft`: false by default. False produces only a downloadable Actions artifact. True creates a **draft** GitHub release after code tests, packaging tests, bundle verification, and the isolated Homebrew check pass.

The pipeline does not create or push tags. Commit/review the changes and create/push the release tag only when those actions are authorized. Run the workflow from the default branch after the pipeline is present there. Normal release inputs and the formula template come from the selected tag. The upload step rebuilds the expected source bundle from the tag, compares the decompressed archive and complete formula, and rechecks the tag commit against the artifact, and refuses to overwrite an existing release (`gh release create` fails if one already exists).

Configure the GitHub `release` environment with required reviewers if publication-related actions need an enforced approval gate. Merely naming an environment in YAML does not configure reviewers. The draft job has a narrowly scoped `contents: write` token; ordinary CI and preparation have `contents: read`.

Review the draft and complete the live macOS acceptance checks before explicitly publishing it. Draft release URLs cannot be used by ordinary Homebrew users. Once public, treat the tag and release assets as immutable; make a new version for changes rather than replacing assets.

## Tap setup and update workflow

The proposed tap is `vishnusenthil-16/homebrew-tap`. It must exist and have an initialized default branch before the update workflow is run. Creation and pushing are separate authorized actions; the pipeline does not create a remote repository.

Copy `packaging/homebrew/tap-ci.yml` into the tap as `.github/workflows/check.yml`. This workflow installs the checked-out formula from source using Homebrew's real Rust dependency, then runs `brew audit --strict` and `brew test`. No vault credentials are needed. Installation itself never invokes `configure` or starts a service.

Configure a fine-grained `TAP_GITHUB_TOKEN` secret in the source repository's `homebrew` environment. Limit it to the tap repository, with Contents and Pull requests read/write. Configure required reviewers on that environment if desired. The source repository's ordinary `GITHUB_TOKEN` cannot generally push to a separate tap repository.

After a release is public, manually dispatch `.github/workflows/homebrew.yml` with its tag and the tap repository. It:

1. Rejects draft/prerelease sources and invalid inputs.
2. Downloads the release assets; checks metadata, checksums, formula URL, and the current tag commit, then compares the source archive and complete formula against a bundle rebuilt from that tag.
3. Creates a `latch-release/vX.Y.Z` branch containing only `Formula/latch-secrets.rb`.
4. Opens a PR for review. It never force-pushes or merges. A rerun recognizes an identical existing branch/PR only when its entire PR diff changes the formula alone; conflicting or unrelated changes fail for review.

Merge that PR only after tap checks pass and merging is authorized. Once merged, users can install with:

```sh
brew install vishnusenthil-16/tap/latch-secrets
```

This command is the intended published interface, not a claim that the tap or formula is already online.

## Runtime dependency and upgrades

The formula builds `latch` and installs the usage skill under its shared-data directory. Users separately install the tested `bw` version, 2026.8.0, then explicitly run `latch configure`. Depending on Homebrew's rolling `bitwarden-cli` would defeat that compatibility constraint, so it is intentionally not a formula dependency.

For a Homebrew installation, `configure` selects `<brew-prefix>/opt/latch-secrets/bin/latch` for its LaunchAgent only if that stable path resolves to the running binary. It fails with repair guidance for an incorrect/missing `opt` link. Source/Cargo installations retain their actual executable path.

Upgrading the formula does not restart the running helper. Rerun `latch configure --server ... --bw ...` while that helper remains available. macOS binds source-built Keychain items to the executable identity, so `configure` reads the session through the old helper, removes the old item, starts the new helper, and recreates the item. The transfer stays in process memory; `configure` zeroizes its retained copy. A failure after removal may require interactive login; no master password is stored for automatic recovery.

This path passed a live macOS test with different debug/release executables: the old Cellar directory was removed, the `opt` link changed, and the new helper recovered the session. Fresh SSH access and locked-Keychain failure/recovery were also exercised separately.

For a planned upgrade where the old helper cannot remain running, run `latch lock` before upgrading, then restart the existing LaunchAgent from the desktop session, configure, and log in again. For an existing installation, `configure` refuses to replace an unavailable helper. Restore its existing LaunchAgent first, or choose a new private `--state-dir` and authenticate there.

If an earlier development build left an item that its replacement cannot read, use Keychain Access to remove only the Latch session item for that state directory, restart its existing LaunchAgent with the new executable, then configure and log in again. The service is `com.latch-secrets.session`; the account is `uid:<uid>:<hex-encoded absolute state path>`. Do not delete the login Keychain or other applications’ items. Older unreleased broker protocols may also require this recovery; automatic migration from development snapshots is not guaranteed.

macOS is the only supported release platform. Native source builds avoid a separate ARM/Intel binary matrix; each architecture still needs runtime validation before claiming support. Bottles, signing/notarization, and automatic tap merging are outside this first pipeline.
