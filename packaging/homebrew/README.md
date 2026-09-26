# macOS Homebrew releases

This pipeline publishes stable source releases and updates the Homebrew tap when a new stable tag is pushed. It does not build bottles, install Bitwarden, or activate Latch's session helper.

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

## One-time GitHub setup

The source repository needs GitHub Actions enabled and a `release` environment. The publish job uses only the source repository's `GITHUB_TOKEN` with `contents: write`; packaging and CI keep `contents: read`. Leave the `release` environment without required reviewers or restrictive tag rules for unattended publication. An approval rule will pause the run until a reviewer acts.

The public `vishnusenthil-16/homebrew-tap` repository needs an initialized default branch and `packaging/homebrew/tap-ci.yml` installed there as `.github/workflows/check.yml`. Tap CI installs the formula from source, runs `brew audit --strict`, and tests the executable without vault credentials. The default branch must allow the token owner to push formula updates; a branch protection rule that blocks direct pushes will make the tap job fail.

Create a fine-grained personal access token for the tap repository only, with **Contents: Read and write** and the automatic **Metadata: Read** permission. It needs no Pull requests or Workflows permission. Store it as the `TAP_GITHUB_TOKEN` **environment secret** in the source repository's `homebrew` environment. The token owner must have write access to the tap. Leave that environment without required reviewers or restrictive tag rules for unattended updates. The source repository's `GITHUB_TOKEN` cannot write to the separate tap.

## Releasing a version

1. Merge the release workflow, Homebrew workflow, and scripts to the source repository's default branch before creating the next tag. GitHub executes the workflow files from the tag commit.
2. Change `Cargo.toml` to the intended stable `X.Y.Z` version. Run `cargo check` to refresh the package version in `Cargo.lock`; commit both files and all release inputs, then let CI pass. The tag must match this version exactly and point at the commit to publish.
3. Create and push the stable `vX.Y.Z` tag. That push runs `.github/workflows/release.yml` automatically. It tests Rust and Python, builds and verifies four deterministic assets, exercises the formula on macOS, publishes a stable GitHub release, then directly calls the reusable Homebrew workflow. The tap job validates the published assets against the same tag before pushing `Formula/latch-secrets.rb` to the tap's default branch.

The workflow never creates or moves a tag. It creates a draft release, uploads any missing assets, verifies all four, then publishes it. On retry, an existing draft or published release can be completed only if every existing expected asset is byte-identical to the newly verified bundle; differing, duplicate, or unexpected assets fail without replacement. Prereleases are refused. The tap update is also repeatable: identical formula bytes succeed, a different formula at the same version or an older version fails. Use a new version for changes. The manually bootstrapped `v0.1.0` tap formula has an audit-only edit relative to its immutable release asset, so retrying its tap step will deliberately report a same-version mismatch; the next version advances normally.

For recovery, manually dispatch `release.yml` with the existing tag to retry the entire sequence, or `homebrew.yml` with the tag and tap repository to retry just the tap stage after the stable release is public. These recovery paths apply to tags that contain this pipeline; `v0.1.0` predates the publishing scripts and was bootstrapped manually. Do not use a release event to chain these jobs: releases created with `GITHUB_TOKEN` do not start a new release-triggered workflow. The direct reusable-workflow call guarantees the tap stage runs after publication.

Once the tap update succeeds, users can install with:

```sh
brew install vishnusenthil-16/tap/latch-secrets
```

The release and tap must both be public for Homebrew to fetch the source archive.

## Runtime dependency and upgrades

The formula builds `latch` and installs the usage skill under its shared-data directory. Users separately install the tested `bw` version, 2026.8.0, then explicitly run `latch configure`. Depending on Homebrew's rolling `bitwarden-cli` would defeat that compatibility constraint, so it is intentionally not a formula dependency.

For a Homebrew installation, `configure` selects `<brew-prefix>/opt/latch-secrets/bin/latch` for its LaunchAgent only if that stable path resolves to the running binary. It fails with repair guidance for an incorrect/missing `opt` link. Source/Cargo installations retain their actual executable path.

Upgrading the formula does not restart the running helper. Rerun `latch configure --server ... --bw ...` while that helper remains available. macOS binds source-built Keychain items to the executable identity, so `configure` reads the session through the old helper, removes the old item, starts the new helper, and recreates the item. The transfer stays in process memory; `configure` zeroizes its retained copy. A failure after removal may require interactive login; no master password is stored for automatic recovery.

This path passed a live macOS test with different debug/release executables: the old Cellar directory was removed, the `opt` link changed, and the new helper recovered the session. Fresh SSH access and locked-Keychain failure/recovery were also exercised separately.

For a planned upgrade where the old helper cannot remain running, run `latch lock` before upgrading, then restart the existing LaunchAgent from the desktop session, configure, and log in again. For an existing installation, `configure` refuses to replace an unavailable helper. Restore its existing LaunchAgent first, or choose a new private `--state-dir` and authenticate there.

If an earlier development build left an item that its replacement cannot read, use Keychain Access to remove only the Latch session item for that state directory, restart its existing LaunchAgent with the new executable, then configure and log in again. The service is `com.latch-secrets.session`; the account is `uid:<uid>:<hex-encoded absolute state path>`. Do not delete the login Keychain or other applications’ items. Older unreleased broker protocols may also require this recovery; automatic migration from development snapshots is not guaranteed.

macOS is the only supported release platform. Native source builds avoid a separate ARM/Intel binary matrix; each architecture still needs runtime validation before claiming support. Bottles and signing/notarization are outside this first pipeline.
