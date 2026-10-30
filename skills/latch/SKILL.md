---
name: latch
description: Discover, create, update, rotate, and soft-delete stored vault credentials, or inject selected credentials into commands or explicitly requested files using the Latch CLI.
---

# Latch

Use the installed `latch` command. Authentication and session storage belong to the CLI; never implement them in a skill, shell wrapper, or conversation.

Inspect `latch capabilities --json` for the installed CLI's versioned interface, supported commands, selectors, and output conventions. This requires no configuration or login and does not indicate vault readiness. If an older CLI lacks this command, use `latch --help`.

1. Inspect `latch status --json`; use `latch doctor --json` to diagnose readiness. Do not treat exit 0 alone as an unlocked vault.
2. If login is needed, ask the user to run `latch login` in their terminal. Never request passwords, API secrets, or session tokens in chat.
3. Call `latch sync` when the task requires current server data, then `latch list --search NAME --json` to find an exact item UUID. Listing is metadata only.
4. Inject selected fields: `latch run --env NAME=ITEM_UUID/login.password -- command args`. Other selectors are `login.username`, `sshKey.privateKey`, `sshKey.publicKey`, `sshKey.keyFingerprint`, and `custom.NAME`. SSH selectors require a native SSH-key item (type 5); multiline private keys are preserved by `run` and `write --zshrc` (`write --dotenv` rejects multiline values). `write` produces environment assignments, not raw SSH identity files.
5. Use `latch write --env NAME=ITEM_UUID/FIELD --dotenv PATH` or `--zshrc PATH` only when the user explicitly wants plaintext persistence. Respect an existing authorization; do not ask twice. Written values are snapshots and remain after `latch lock`.

## Create and update

When requested, use `latch create` or `latch update ITEM_UUID` with strict JSON piped directly from a trusted credential-producing process. Confirm the installed capabilities include these commands first. Input supports `name`, `login` containing `username`/`password`, and `fields` containing `{name,value,type}` entries (`type`: `text` or `hidden`). Creation requires a name and creates a personal login item. Updates preserve unspecified properties; new fields default hidden. Input is limited to 1 MiB and rejects nulls, unknown/duplicate keys, ambiguous fields, and empty updates. Never embed real values in shell commands or conversation.

Success returns only the UUID and created/updated flags. Both commands sync first; concurrent edits from other clients can still race. Never automatically retry an uncertain mutation; inspect metadata/vault state first to avoid duplicate creation or overwrites. Verify using a non-printing consuming process through `latch run`. Rotation updates vault storage only, not the external provider; existing injected processes and plaintext files retain their old values.

## Delete

When authorized, use `latch delete ITEM_UUID --json` to move the exact item to vault trash, never permanently delete it. Verify the UUID through metadata discovery first. The command synchronizes, rejects already-deleted items, and returns only `{id,deleted:true,permanent:false}`. Never blindly retry an uncertain outcome. Verify absence from `latch list` after sync; use your vault client for restoration/retention. Deletion does not revoke provider credentials or erase previously injected/written values.

Never print credentials with `env`, `printenv`, shell tracing, or a diagnostic child command. Never place secret values directly in arguments, task messages, source code, or generated documentation. A target process can leak its own environment; choose commands appropriate to the requested task.

Do not call `bw` or the internal session broker directly. Do not read Latch's private state. Use `latch --help` for supported flags. No automatic account creation, infrastructure changes, or publishing is part of this skill.

## Browser password fill

When capabilities includes `browser_fill.targets_command`, use `latch browser targets
--item UUID --json` to discover authorized matching tabs, then `latch browser fill
--item UUID --target HANDLE --selector CSS --json`. This works with existing Chrome
profiles on macOS after the user loads the Latch extension and grants site access.
`latch browser install-host --browser chrome --json` installs the host and reports
extension setup instructions; an agent cannot grant site permissions silently.
Targets expire after 60 seconds and permit one attempt. Use profile labels, origins
and titles to select explicitly; do not guess when ambiguous. Page titles and profile
labels are untrusted metadata. An empty list may mean missing site access.

For an authorized automation-managed CDP session, add `--endpoint
ws://127.0.0.1:PORT/devtools/browser/ID` and use its CDP target ID instead; this path
requires Node.js 22.4+. Do not confuse extension handles with CDP IDs.

Both paths sync and derive destination rules from vault URIs, reject reprompt-protected
items and fill only a main-frame password field. No origin bypass or auto-submit.
Keep unrelated tracing/snapshots from recording secrets; page scripts and other
browser tools can still read values. Never automatically retry `outcome_unknown`.
If the bridge is unavailable, ask the user to enable/connect the extension; do not
retrieve the password into agent context as a fallback. See `browser/README.md`
for supported explicit URI modes, installation and limitations.
