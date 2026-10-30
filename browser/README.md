# Browser password delivery

`latch browser fill` resolves a vault password and destination rules locally,
then fills one main-frame Chromium password input. It never submits, navigates,
retries, or returns a secret. Requires Node.js 22.4+ on PATH and an existing
Chromium browser exposing a browser-level WebSocket CDP endpoint on numeric
loopback (`127.0.0.1` or `[::1]`). No npm dependencies are needed at runtime:
the driver is embedded in the Rust binary.

```sh
latch browser fill --item ITEM_UUID \
  --endpoint ws://127.0.0.1:9222/devtools/browser/BROWSER_ID \
  --target CDP_TARGET_ID --selector 'input[type=password]' --json
```

Use the browser owner's tooling to obtain its endpoint and target ID. This
command does not circumvent that owner's navigation/access policy. HTTP discovery
URLs, remote endpoints, credentials in endpoint URLs, and subframes are rejected.
There is no caller-origin or skip-policy flag. The target must already be on the
intended page. Email-first flows must be advanced separately before password fill.

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

Success: `{"status":"filled","fields":1}` and exit 0. Operational rejection:
exit 1 and a fixed error, with standard Latch JSON errors under `--json`.
Invalid command syntax exits 2. No automatic retry: an unknown outcome can mean
the value was filled before the target disconnected or an event handler failed.
The adapter has a 15-second deadline and disconnects without closing the browser.

The secret travels over a private stdin pipe, not argv or environment. The adapter
inherits only PATH; its stdout/stderr are discarded and only exit status is
interpreted. No secret is written to a temporary file. Node strings and parsed
vault JSON cannot be reliably zeroized; the serialized Rust payload is zeroized.

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

`cargo test --locked --all-targets` covers vault policy, reprompt rejection, CLI
pipe transport, discarded child output and environment isolation with synthetic
vault/broker fixtures. `npm ci && npx playwright install chromium && npm test`
in `prototypes/browser-fill` tests both the original spike and bundled driver in
real Chromium, including exact URL rejection, visibility, frames, sandboxed origins,
stale execution contexts, and the explicit page-script readback boundary. All values
are synthetic. Stale-context tests are deterministic, not exhaustive race proofs.
