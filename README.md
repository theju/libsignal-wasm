# libsignal-wasm

Browser-oriented WASM wrapper for Signal's Rust `libsignal` implementation.

This repository vendors `signalapp/libsignal` under `vendor/libsignal` and builds a small
`wasm-bindgen` adapter crate at the repo root. This code has been generated against
`libsignal` v0.94.0. The current exported surface covers the first browser-compatible slice of
the Node API:

- `PublicKey`, `PrivateKey`, and `IdentityKeyPair`
- HPKE `seal`/`open` on public/private keys
- `PreKeyRecord`, `SignedPreKeyRecord`, and `SessionRecord`
- `ServiceId`, `Aci`, `Pni`, and `ProtocolAddress`
- `KEMKeyPair`, `KyberPreKeyRecord`, and `PreKeyBundle`
- in-memory `SignalProtocolStore`
- `SignalProtocolStore` snapshot export/restore for IndexedDB persistence
- `processPreKeyBundle`, `signalEncrypt`, and `signalDecrypt`
- single- and multi-recipient sealed sender certificates, envelope encryption, and message
  decryption
- group sender-key distribution, group encryption, and group decryption
- username hash/proof/link primitives
- account entropy, backup-key derivation, and PIN hash primitives
- `hkdf`, `Aes256GcmSiv`, and fingerprint APIs
- legacy raw key helpers for generated/imported key pairs, signing, verification, and X25519
  agreement

Signal's upstream repository states that external use is unsupported and APIs can change without
notice. Keep this wrapper narrow and pin the vendored upstream revision when publishing builds.

## Disclaimer

This codebase is completely AI generated. Treat it as experimental until it has been reviewed,
audited, and validated for the security and reliability requirements of your application.
The project is a WASM port of libsignal with minimal changes and is neither affiliated nor 
endorsed by Signal or its developers.

## Prerequisites

- Rust with the `wasm32-unknown-unknown` target installed
- `wasm-pack`
- `protoc` available on `PATH`, or `PROTOC` / `PROTOC_INCLUDE` set by your build environment

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

This repository does not vendor `protoc`; bring the Protocol Buffers compiler from your system,
toolchain, or CI image.

## Build

```sh
npm run check:wasm
npm run build
```

The browser package is emitted into `pkg/`.

## Browser Tests

Browser tests use Playwright and are served from the repo root so the generated WASM package is
loaded the same way a browser app would load it.

```sh
npm run build
npm run test:browser
```

The tests in `tests/browser/` adapt upstream Node test expectations where possible, especially for
network request method/path/header shapes and response parsing.

## Example

After `npm run build`:

```sh
npm run serve:example
```

Then open `http://localhost:8080/examples/basic.html`.

## Browser API

See [docs/API.md](docs/API.md) for the browser-facing API exported by `pkg/libsignal_wasm.js`,
including byte formats, initialization, examples, current Node parity, and remaining gaps.
See [docs/Architecture.md](docs/Architecture.md) for the upstream libsignal crate map and browser
architecture notes.

## Current Scope

This is not yet a complete TypeScript-compatible replacement for `@signalapp/libsignal-client`.
The upstream Node package is a native addon, while this project exposes a browser WASM module.
The next milestone should add the remaining zkgroup credential flows or backup/SVR network support
as needed by the app.
