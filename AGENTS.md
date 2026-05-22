# AGENTS.md

## Project Goal

This project builds a browser-oriented WASM wrapper around Signal's Rust `libsignal`
implementation, vendored at `vendor/libsignal`, so Signal protocol functionality can be used from
browser JavaScript.

The goal is API parity with the upstream Node package where that is practical in a browser. Do not
try to recreate native Node internals literally when the browser security/runtime model does not
support them.

## Repository Layout

- `src/lib.rs`: primary `wasm-bindgen` wrapper and browser API surface.
- `docs/API.md`: browser-facing API documentation and parity status. Update this whenever exports
  change.
- `pkg/`: generated WASM package from `wasm-pack build`. Regenerate after Rust API changes.
- `vendor/libsignal/`: vendored upstream Signal source. Treat this as reference code unless the
  task explicitly requires vendored changes.
- `examples/`: browser examples served by `npm run serve:example`.

## Parity Policy

Implement only functionality that can work well in a browser:

- WASM-local cryptography, serialization, stores, snapshots, zkgroup primitives, media sanitizers.
- Transport-neutral request builders and response parsers that can run over browser `fetch` or a
  caller-provided transport callback.
- Browser-backed chat helper methods where the actual I/O is delegated to JavaScript.

Label the rest clearly in `docs/API.md`:

- **Can be implemented, but needs work:** Key Transparency, CDSI, SVR-B, and provisioning facade.
  These need protocol extraction from native connection assumptions, browser transport design, and
  WASM dependency/attestation validation.
- **Cannot be implemented literally in browser:** native `Net`/`ConnectionManager`,
  DNS/proxy/TLS routing, raw sockets, native websocket runtime, and native cancellable runtime
  semantics. These require browser-backed equivalents, not direct ports.

At the time this file was written, no obvious browser-clean Node parity helpers are known to be
pending. If upstream adds a helper that is just request construction, parsing, or local crypto,
prefer implementing it in the current browser facade style.

## Implementation Guidelines

- Prefer existing patterns in `src/lib.rs`: flat `wasm-bindgen` exports, small wrapper structs, and
  transport-backed `BrowserChatConnection` helpers.
- Keep browser network APIs transport-neutral. Build `HttpRequest` values and parse `ChatResponse`
  values; do not add direct `fetch` or WebSocket dependencies in Rust.
- When adding a request helper, add the matching parser when the Node API returns a structured
  value.
- Preserve Node-compatible wire shapes where possible: paths, JSON field names, headers, base64
  padding/url-safe variants, status handling, and byte formats.
- Use structured parsing/serialization (`serde_json`, upstream types, existing helper functions)
  instead of ad hoc string manipulation.
- Keep generated TypeScript/browser artifacts in `pkg/` in sync after changing exported Rust APIs.
- Do not refactor unrelated wrapper areas while filling a parity gap.

## Build And Verification

Run these before handing off changes:

```sh
cargo fmt --check
cargo check --target wasm32-unknown-unknown
npm run build
npm run test:browser
```

`npm run build` runs `wasm-pack build --target web --out-dir pkg --release`. In sandboxed
environments this may fail while creating a `wasm-bindgen` temp directory with a read-only
filesystem error. When that happens, rerun the same command with the appropriate escalation rather
than changing the build.

For API additions, also run a focused Node smoke test against `pkg/libsignal_wasm.js` and
`pkg/libsignal_wasm_bg.wasm` to verify:

- generated exports exist in `pkg/libsignal_wasm.d.ts`;
- request method/path/header/body shape matches upstream Node tests;
- parser status handling and decoded values match expected behavior.

Browser tests live under `tests/browser/` and use Playwright. They intentionally adapt upstream
Node test expectations where possible, while loading the generated `pkg/libsignal_wasm.js` in a
real browser page.

## Documentation Requirements

Update `docs/API.md` for every new browser export:

- Add the function/class to the relevant API table.
- Document byte formats and required object shapes.
- Update the parity table.
- Keep the feasibility labels current.

If behavior intentionally differs from Node, document it under the relevant "Current differences
from Node" section.

## Upstream Reference Workflow

Use upstream files as the source of truth for parity details:

- Node API shape: `vendor/libsignal/node/ts/**`
- Node tests and expected request shapes: `vendor/libsignal/node/ts/test/**`
- Rust request/response implementation: `vendor/libsignal/rust/net/chat/src/**`
- Shared bridge behavior: `vendor/libsignal/rust/bridge/shared/src/**`

When unsure about paths, headers, JSON bodies, or status handling, inspect upstream tests first.

## Current Browser Network Facade

`BrowserChatConnection` accepts a JavaScript transport function. The Rust side calls that transport
with a Node-shaped request object and returns `Promise.resolve(response)`.

Request helpers currently include pre-key lookup, sealed sender, multi-recipient messages,
authenticated messages, sync messages, upload forms, username lookup, account existence,
registration sessions/account creation, SVR2 credential checks, and backup upload-form helpers.

Response parsers currently include pre-key lookup, upload forms, username hash/link lookup,
account existence, registration session/account creation, and SVR2 credential checks.

## Do Not

- Do not introduce direct browser I/O from Rust unless the project direction changes.
- Do not attempt literal native parity for Node-only connection manager features.
- Do not edit vendored upstream code for wrapper API work unless explicitly required.
- Do not remove or hand-edit generated `pkg/` files as a substitute for running `npm run build`.
