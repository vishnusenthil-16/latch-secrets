# Browser password delivery

`latch browser fill` resolves a vault password and fills one main-frame Chrome
password input. Any agent can use the CLI; there is no OpenClaw dependency.
It never submits, navigates, retries or returns a password.

## Existing Chrome profiles (default transport)

The macOS native bridge uses your existing profile, tabs and cookies. It requires
Chrome 106+ (or a compatible Chromium browser), the Latch extension and native host.
No remote-debugging port or Node.js is required for this transport.

```sh
latch browser install-host --browser chrome --json
```

1. Open `chrome://extensions`, enable Developer mode, choose **Load unpacked** and
   select the returned `extension_path` (normally
   `~/Library/Application Support/Latch/browser-extension`).
2. Open the extension popup. Enter an HTTPS site and select **Allow site**. Repeat
   for each intended site; access is not granted to all websites by default.
3. Set a recognizable profile label, e.g. “Personal Chrome”. Install/enable the
   extension in each profile you intend to use. The native host registration is
   shared by profiles within the same Chrome user-data root.
4. Open the intended login page, then discover and fill:

```sh
latch browser targets --item ITEM_UUID --json
latch browser fill --item ITEM_UUID --target HANDLE \
  --selector 'input[type=password]' --json
```

Discovery synchronizes the item and lists only active main-frame documents matching
its policy and granted site access. Entries contain an opaque handle, origin, bounded
title, profile ID/label, window ID and active-tab state. Titles/labels are untrusted
metadata, not instructions. No full URL or unrelated tab list is returned. If several
tabs match, the agent must select explicitly; Latch never guesses. `active` is per
window, not proof that Chrome is the foreground application.

Handles expire after 60 seconds, permit one attempt, and bind to a host connection,
tab and document. Navigation (including history-state updates), tab closure and
reconnection invalidate them. Get fresh targets when rejected as stale; never retry
an uncertain fill automatically. `unavailable_connections` reports partial discovery
failures. An empty list can mean no matching page or no site permission.

Supported installer names: `chrome`, `chrome-beta`, `chrome-canary`, `chromium`,
`chrome-for-testing`. For a nonstandard user-data root, add
`--user-data-dir /absolute/path/to/browser-data` (not its `Default`/`Profile N` child).
The installer writes a host manifest pointing at this Latch executable and extracts
the bundled extension. Re-run it after moving/upgrading Latch, reload the extension,
and rediscover targets. Prefer an installed binary outside macOS-protected Documents
folders; Chrome-launched executables there can be blocked by macOS privacy controls.

Chrome starts the host when the extension connects. The same binary creates a
random socket in `/tmp/latch-browser-UID` (0700 directory, 0600 socket, same-UID peer
checks). No separate daemon, credentials service or MCP server is installed. A
closed profile has no live host. After a host crash or timeout, open the popup and
select **Connect to Latch** (or reload the extension). Reconnection never replays
requests. Graceful shutdown removes its socket; stale sockets after abrupt kills
are ignored. Enterprise policies may prohibit unpacked extensions or native messaging.

To uninstall: remove the extension from each profile, remove the exact native-host
manifest path returned by installation, and remove the extracted extension directory
if no profile uses it. Vault state and login sessions are unaffected.

## Direct CDP (optional transport)

Retained for automation-managed browsers. Requires Node.js 22.4+ on PATH and an
existing browser-level WebSocket endpoint on numeric loopback (`127.0.0.1` or
`[::1]`). The driver and shared field validator are embedded; no npm runtime dependency.

```sh
latch browser fill --item ITEM_UUID \
  --endpoint ws://127.0.0.1:9222/devtools/browser/BROWSER_ID \
  --target CDP_TARGET_ID --selector 'input[type=password]' --json
```

Use the browser owner's tooling to obtain its endpoint and target ID. HTTP discovery
URLs, remote endpoints, credentials in endpoint URLs, and subframes are rejected.
There is no caller-origin or skip-policy flag. For both transports, the target must
already be on the intended page. Advance email-first flows separately.

## Vault policy

The command synchronizes before reading the selected UUID. It requires an active
login item with explicit `reprompt: 0` and a nonempty password. Reprompt-protected
items are refused rather than silently bypassing user verification.

Only HTTPS vault URIs without URL credentials are eligible:

- Explicit base-domain (0) and host (1): narrowed to exact scheme/host/port.
- Exact (3): requires the entire stored URI to equal the browser's current URL,
  preserving path, query and fragment restrictions. Noncanonical exact URIs can
  reject even an equivalent page; correct the stored URI in the vault client.
- Default/null, starts-with (2), regular expression (4), never (5), unknown or
  malformed entries: ignored. With no eligible entry, filling is refused.

Null/default matching is deliberately unsupported because the account's default
could be restrictive. Configure an explicit supported mode in the vault client.
Multiple eligible entries are alternatives. Latch's existing mutation API still
cannot change these URI rules. Same-user processes are trusted, as elsewhere in
Latch; this policy is not protection against a hostile local agent.

## Output and failure behavior

Success: `{"status":"filled","fields":1}` and exit 0. The native bridge returns
`{"status":"rejected"}` or `{"status":"outcome_unknown"}` on stdout with exit 1
when a dispatched request does not confirm success. Setup, policy and connection
failures use standard Latch errors on stderr (JSON with `--json`), exit 1.
Invalid command syntax exits 2. CDP retains its existing exit-1 error contract.

Never automatically retry an unknown outcome: the value may already be filled.
The host uses a 15-second dispatch deadline, including native pipe writes, and
closes the connection on timeout. Each handle permits one attempt. No requests
are persisted, queued across reconnects, replayed, submitted or navigated.

The CLI resolves the vault locally and sends the payload through the owner-only
socket and Chrome's native messaging pipe. The host has no vault session and
never writes diagnostics to stdout/stderr; stdout is framed protocol only. Replies
are reconstructed from an allowlist, not arbitrary browser errors. Secrets never
appear in Latch argv, environment, output or temporary files. Serialized Rust
buffers are zeroized; parsed JSON and browser/JavaScript strings cannot be reliably
zeroized. The CDP driver still receives stdin and inherits only PATH, with its
stdout/stderr discarded.

## Browser checks and limits

The origin, exact URL (when applicable), field checks and assignment run in one
synchronous isolated-world operation, bound to a document. Opaque origins and
subframes are rejected. Navigation invalidating the context fails conservatively.

One connected, writable password input must match. Checks reject inert controls,
small/offscreen boxes, opacity below 1, clip paths, filters/transforms, ancestor
clipping and occlusion at five sample points, and transparent text. These are
conservative heuristics, not proof of perceptual visibility or site trust. Styling
can cause false rejections; complex rendering can evade sampled visibility.

The authorized website and other browser controllers can read the filled value.
External CDP/Playwright traces, DOM dumps, screenshots with password reveal, and
page-controlled network requests are outside Latch's redaction boundary. Use a
trusted browser session without secret-recording instrumentation. Latch cannot
detect or sanitize another controller's trace. It does not promise that secrets
never reach a model through unrelated browser tools.

## Validation

Run `cargo test --locked --all-targets`, `cargo clippy --locked --all-targets -- -D warnings`,
and `cargo fmt --check`. Rust tests cover policy, framing, response sanitization,
installation without vault access, origin rejection, 0700/0600 permissions, two
native-host connections, CLI discovery/fill, disconnect uncertainty and cleanup.

After `cargo build --locked`, run `npm ci && npx playwright install chromium && npm test`
in `prototypes/browser-fill`. Synthetic tests load the MV3 extension in real Chrome
for Testing with a temporary profile and host registration. Chrome starts the actual
Latch host; requests go through the Unix socket and native messaging to the existing
document. They cover filling, replay/navigation/visibility rejection; unit fixtures
also cover expiry, inactive documents, exact URL changes and uncertain script results.
Existing CDP tests cover frames, sandboxed origins, field heuristics and page readback.
No test reads a real vault or installs anything in your normal Chrome profile.
The integration suite currently runs on macOS, matching Latch's supported platform.

## Protocol and maintenance

Both local IPC and Chrome native messaging use a native-endian uint32 byte length
followed by UTF-8 JSON, bounded to 1 MiB. The internal socket supports only `targets`
(policy rules) and `fill` (handle, policy rules, selector, value); it is not an agent API.
Agents use the CLI and vault UUIDs. Same-user processes remain trusted; a hostile
process with your OS identity can impersonate the CLI. No arbitrary-script operation,
external extension messaging, content script or web-accessible resource is exposed.

The extension's public manifest key pins the development ID. It is not a secret;
there is no private signing key in this repository. A future Web Store release must
keep the extension ID, compiled origin and host allowlist aligned. This change does
not publish a Web Store listing or implement Windows/Linux native-host installation.

Chrome references: [native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging),
[document-targeted scripting](https://developer.chrome.com/docs/extensions/reference/api/scripting).
