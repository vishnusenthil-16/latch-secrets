# Browser fill spike — dummy credentials only

Standalone Chromium adapter; no changes to Latch's vault or Rust CLI.
Uses maintained Playwright CDP support, not a new browser driver.

## Run

Node 22+; a Chromium browser with a loopback CDP endpoint:

```sh
npm ci
npx playwright install chromium
npm test
LATCH_DEMO_PASSWORD=dummy-only node fill.mjs \
  --endpoint http://127.0.0.1:9222 --target CDP_TARGET_ID \
  --origin https://example.test --selector '#password' --env LATCH_DEMO_PASSWORD
```

The target is a raw CDP target ID (available from the browser's /json/list).
The password is read from the named environment variable, never a command
argument. This matches the child-process contract of `latch run --env`;
use only disposable dummy vault entries if testing that path.

Main-frame password inputs only. Exactly one writable input must match and pass
basic visibility checks (display, visibility, zero opacity, minimum dimensions
and viewport intersection). These checks do not prove perceptual visibility.
Validation and fill run synchronously in a document-specific isolated world.
The browser connection is disconnected after filling; the browser remains open.
No submission, navigation, extension, MCP server, username handling or retries.

Outputs are fixed metadata JSON. Failures conservatively report unknown outcome:
do not assume nothing was filled or blindly retry. Browser/page errors are not
printed. The adapter does not start tracing and disables Playwright debug output.

## Boundaries and remaining gates

This is NOT ready for real credentials. The supplied origin is an experiment
parameter, not trusted vault policy. Before production, resolve policy from vault
URIs, preserve match restrictions, reject reprompt-protected items, and test
navigation races, trace leakage and partial outcomes. Same-user processes and
agents with browser access can read filled values; this is not isolation.

HTTP is allowed only for loopback fixture pages; other destinations require HTTPS.
Only loopback CDP endpoints are accepted. Existing browser tracing and page scripts
can observe credentials. JavaScript strings cannot be reliably zeroized.

Visibility remains a production gate: near-transparent or fully transparent-styled
fields, clipping, ancestor overflow and covering overlays can pass the basic
checks. Hit-testing and clipping/ancestor checks need further design and tests;
do not treat selector matching as proof that a user can see the field.

## Validation status

`npm test` covers five groups: document validation, CDP attachment and field
rejections, opaque security origins, isolated-world iframe/stale-document
rejection, and subprocess CLI success/rejection/error behavior. CLI checks assert
exact metadata-only stdout, empty stderr (including with Playwright debug enabled),
exit codes, missing input, invalid configuration and malformed selectors.
The navigation test destroys a captured execution context before invoking the fill;
it is a deterministic stale-document check, not exhaustive race scheduling.

A live OpenClaw-managed browser demo was attempted on 2026-10-29. The browser
started with CDP available, but browser navigation policy blocked the loopback
fixture URL. No bypass was attempted. That demo remains unverified; automated
CDP tests use a separate test-controlled Chromium instance. External browser
traces and page scripts are not covered by the CLI output checks.
