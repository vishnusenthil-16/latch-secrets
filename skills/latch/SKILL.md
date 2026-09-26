---
name: latch
description: Discover vault item metadata and inject selected credentials into commands or explicitly requested files using the Latch CLI.
---

# Latch

Use the installed `latch` command. Authentication and session storage belong to the CLI; never implement them in a skill, shell wrapper, or conversation.

1. Inspect `latch status --json`; use `latch doctor --json` to diagnose readiness. Do not treat exit 0 alone as an unlocked vault.
2. If login is needed, ask the user to run `latch login` in their terminal. Never request passwords, API secrets, or session tokens in chat.
3. Call `latch sync` when the task requires current server data, then `latch list --search NAME --json` to find an exact item UUID. Listing is metadata only.
4. Inject selected fields: `latch run --env NAME=ITEM_UUID/login.password -- command args`. Other selectors are `login.username` and `custom.NAME`.
5. Use `latch write --env NAME=ITEM_UUID/FIELD --dotenv PATH` or `--zshrc PATH` only when the user explicitly wants plaintext persistence. Respect an existing authorization; do not ask twice. Written values are snapshots and remain after `latch lock`.

Never print credentials with `env`, `printenv`, shell tracing, or a diagnostic child command. Never place secret values directly in arguments, task messages, source code, or generated documentation. A target process can leak its own environment; choose commands appropriate to the requested task.

Do not call `bw` or the internal session broker directly. Do not read Latch's private state. Use `latch --help` for supported flags. No automatic account creation, infrastructure changes, or publishing is part of this skill.
