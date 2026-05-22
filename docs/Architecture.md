# libsignal Architecture

This document explains how Signal Protocol concepts map to the upstream `libsignal` Rust crates
vendored in this repository, and how this browser/WASM wrapper exposes the browser-compatible
parts. The project is generated against `libsignal` v0.94.0.

## Big Picture

Signal's client-side library is not one protocol implementation. It is a collection of protocol,
cryptography, credential, networking, media, backup, and utility crates that are composed by the
Node, Java, Swift, and Rust bindings.

In this project the browser stack is:

| Layer | Role |
| --- | --- |
| Upstream `vendor/libsignal/rust/*` crates | Source of truth for protocol and crypto behavior |
| Root `src/lib.rs` | `wasm-bindgen` adapter that exposes browser-safe classes/functions |
| Generated `pkg/` | Browser ES module and `.wasm` artifact |
| Browser app | Owns storage, transport, account lifecycle, service worker/fetch/WebSocket code, and UI |

The browser package should be understood as an adapter, not a reimplementation. It forwards into
upstream Rust for protocol state transitions, cryptographic operations, credential proofs, media
sanitization, and serialization formats.

## Signal Protocol Flow

The core one-to-one message flow has these phases:

1. **Identity and device addressing**
   - Users/devices are addressed with service IDs (`Aci`, `Pni`, `ServiceId`) and
     `ProtocolAddress`.
   - Each device has a long-term identity key pair and a local registration ID.

2. **Pre-key publishing and retrieval**
   - A receiving device publishes pre-key material: classic pre-key, signed pre-key, and Kyber
     pre-key material.
   - A sending device fetches that data as a `PreKeyBundle`.

3. **Session setup**
   - `processPreKeyBundle(...)` establishes a Signal session with the remote device.
   - Upstream protocol code performs the X3DH/PQXDH-style key agreement and initializes ratchet
     state.

4. **Message encryption**
   - `signalEncrypt(...)` encrypts one-to-one payloads using the established session.
   - Under the hood, upstream `libsignal-protocol` manages Double Ratchet state and, in current
     protocol paths, post-quantum ratchet/SPQR state via the internal Triple Ratchet layer.

5. **Message decryption**
   - `signalDecrypt(...)` consumes incoming `CiphertextMessage` values and advances local session
     state.
   - Session records include sender/receiver chains, ratchet keys, counters, identity data, and
     post-quantum state.

6. **Persistence**
   - Node exposes separate store traits for identities, sessions, pre-keys, signed pre-keys, Kyber
     pre-keys, and sender keys.
   - This browser package exposes a combined `SignalProtocolStore`, plus
     `exportSnapshot()` / `fromSnapshot(...)` for IndexedDB-style persistence.

## Major Upstream Crates

| Crate | Upstream purpose | Browser wrapper status |
| --- | --- | --- |
| `libsignal-core` | Shared identities, service IDs, addresses, device IDs, Curve25519 key wrappers, version utilities | Used for `Aci`, `Pni`, `ServiceId`, `ProtocolAddress`, `PublicKey`, `PrivateKey` |
| `libsignal-protocol` | Signal Protocol sessions, pre-keys, PQ/Kyber pre-keys, Double Ratchet, Triple Ratchet/SPQR internals, sender keys, sealed sender, fingerprints | Heavily exposed through keys, records, `SignalProtocolStore`, `processPreKeyBundle`, `signalEncrypt`, `signalDecrypt`, sender-key APIs, sealed-sender APIs, fingerprints |
| `signal-crypto` | Shared crypto utilities: HPKE, AES-CBC/CTR/GCM, hashes/MACs | Used directly for HPKE-style `PublicKey.seal(...)` / `PrivateKey.open(...)`; also used transitively by other upstream crates |
| `libsignal-account-keys` | Account entropy pool, backup key derivations, SVR key derivation, PIN hashing | Exposed as `AccountEntropyPool`, `BackupKey`, `BackupForwardSecrecyToken`, `PinHash`, `Pin` |
| `usernames` | Username hashing, proofs, username link encryption/decryption | Exposed through `username*` browser exports |
| `zkgroup` | Zero-knowledge group/profile credentials, auth credentials, receipts, call-link credentials, backup auth credentials, group-send endorsements | Exposed as flat browser classes/functions for group/profile/auth/receipt/call-link/backup/group-send endorsement flows |
| `zkcredential` and `poksho` | Lower-level zero-knowledge credential and proof machinery used by `zkgroup` | Used transitively by `zkgroup`; not exposed as a separate browser API |
| `signal-media` | MP4/WebP sanitizer logic over byte streams | Exposed as `mp4SanitizerSanitize(...)`, `mp4SanitizerSanitizeWithCompoundedMdatBoxes(...)`, `webpSanitizerSanitize(...)` |
| `libsignal-net` | Native networking, chat service request/response modeling, CDSI, SVR/SVR-B, websocket/runtime/network infrastructure | Not ported literally. Browser wrapper implements selected transport-neutral chat request builders/parsers and leaves I/O to JavaScript |
| `libsignal-message-backup` | Remote message backup parsing, validation, HMAC checking, backup data model, JSON/test utilities | Not exposed as a browser API in this wrapper; account/backup key and backup auth pieces are exposed through other crates |
| `libsignal-svrb` | SVR-B backup/restore protocol messages and crypto flow | Not exposed directly; browser wrapper only includes `checkSvr2Credentials` request/parser helper |
| `keytrans` | Key Transparency data structures and verification | Labeled "can be implemented, but needs work"; not currently exposed |
| `attest` | Attestation helpers, including enclave/SVR-related support | Not exposed directly |
| `device-transfer` | Device-to-device transfer support, RSA key and self-signed certificate generation | Not exposed in the browser wrapper |

## Core Protocol APIs

The browser API wraps `libsignal-protocol` with Node-shaped classes where possible:

| Browser API | Upstream area | What it represents |
| --- | --- | --- |
| `PrivateKey`, `PublicKey`, `IdentityKeyPair` | `libsignal-core`, `libsignal-protocol` | Long-term and ephemeral Curve25519 keys |
| `Aci`, `Pni`, `ServiceId`, `ProtocolAddress` | `libsignal-core` | Account/device addressing |
| `PreKeyRecord`, `SignedPreKeyRecord`, `KyberPreKeyRecord` | `libsignal-protocol::state` | Locally stored pre-key material |
| `PreKeyBundle` | `libsignal-protocol::state` | Remote pre-key material used to start a session |
| `SessionRecord` | `libsignal-protocol::state` | Serialized one-to-one session and ratchet state |
| `SignalProtocolStore` | Browser wrapper around upstream store traits | Combined browser store for identities, sessions, pre-keys, signed pre-keys, Kyber pre-keys, and sender keys |
| `processPreKeyBundle` | `libsignal-protocol::session` | Session setup from remote bundle |
| `signalEncrypt`, `signalDecrypt` | `libsignal-protocol::session_management` | One-to-one message encryption/decryption |

The browser wrapper intentionally does not expose the internal Double Ratchet, Triple Ratchet, root
key, chain key, or message key types. Applications should treat sessions as opaque and use the
stable session operations.

## Sealed Sender

Sealed sender hides sender metadata from the service while still allowing the recipient to verify
the sender certificate. The upstream implementation lives in `libsignal-protocol::sealed_sender`.

Browser APIs:

- `ServerCertificate`
- `SenderCertificate`
- `UnidentifiedSenderMessageContent`
- `SealedSenderDecryptionResult`
- `sealedSenderEncryptMessage`
- `sealedSenderDecryptMessage`
- `sealedSenderEncrypt`
- `sealedSenderDecryptToUsmc`
- `sealedSenderMultiRecipientEncrypt`
- `sealedSenderMultiRecipientMessageForSingleRecipient`

One-to-one sealed sender builds on existing one-to-one sessions. Multi-recipient sealed sender
packages a sender-key/group payload for recipients that already have sessions.

## Sender Keys and Group Messaging

Sender keys are the group-message encryption layer used after group members have received a sender
key distribution message.

Browser APIs:

- `SenderKeyDistributionMessage.create(...)`
- `processSenderKeyDistributionMessage(...)`
- `groupEncrypt(...)`
- `groupDecrypt(...)`
- `SenderKeyRecord`

The underlying implementation is `libsignal-protocol::group_cipher` and `sender_keys`. The
browser store keeps sender-key records alongside one-to-one session state.

## `signal-crypto`

`signal-crypto` is a shared crypto utility crate, not the main Signal Protocol session engine. It
contains reusable primitives such as:

- HPKE sender/receiver helpers;
- AES-CBC, AES-CTR, and AES-GCM helpers;
- cryptographic hash and MAC wrappers.

This wrapper uses `signal-crypto` directly for `PublicKey.seal(...)` and `PrivateKey.open(...)`.
Other upstream crates use it internally for their own crypto operations. Separately, this wrapper
also exposes `Aes256GcmSiv` and `hkdf(...)` using Rust crypto crates to match Node API utilities.

## Account Keys, Backup Keys, and PINs

`libsignal-account-keys` contains local account-key primitives:

- `AccountEntropyPool` generation and validation;
- SVR key derivation;
- backup key derivation;
- backup ID, EC key, media key, and thumbnail transit key derivation;
- local PIN hash and SVR2 PIN hash helpers.

Browser APIs:

- `AccountEntropyPool`
- `BackupKey`
- `BackupForwardSecrecyToken`
- `PinHash`
- `Pin`

These are local cryptographic derivations. They do not perform network backup or SVR/SVR-B
protocol calls by themselves.

## zkgroup, Profiles, Receipts, Call Links, and Backup Auth

`zkgroup` provides Signal's zero-knowledge credential and group/privacy primitives. It depends on
lower-level proof/credential crates such as `zkcredential` and `poksho`.

The wrapper exposes the local browser-safe flows:

- group secret/public params;
- UUID/profile-key encryption for groups;
- profile-key credentials;
- auth credentials with PNI;
- receipt credentials;
- call-link create/auth credentials;
- generic server params;
- backup auth credential request/response/credential/presentation;
- group-send endorsements and tokens.

These APIs are used when the app needs to prove authorization, present credentials, encrypt group
member identity/profile data, or build auth headers for backup upload helpers. The server issuance
and verification flows are represented as local request/response/presentation objects; actual I/O
belongs to the browser app.

## Usernames

The `usernames` crate implements local username primitives:

- username hash;
- username proof generation/verification;
- encrypted username links;
- username link decryption.

The browser wrapper exposes these as flat `username*` functions. Network lookup helpers live in
`BrowserChatConnection` and only build/parse chat service request/response data.

## Media APIs

`signal-media` contains media sanitizer implementations:

- MP4 sanitizer;
- WebP sanitizer.

The browser wrapper exposes in-memory byte-array APIs:

- `signalMediaCheckAvailable()`
- `mp4SanitizerSanitize(input)`
- `mp4SanitizerSanitizeWithCompoundedMdatBoxes(input, cumulativeMdatBoxSize)`
- `webpSanitizerSanitize(input)`

Node and native bindings can work with stream-like inputs. The browser wrapper keeps this simple:
the app passes `Uint8Array` data and receives sanitized MP4 metadata or validation errors.

## Network and Chat APIs

Upstream `libsignal-net` includes native runtime and network components:

- chat request/response flows;
- websocket support;
- environment and connection management;
- CDSI;
- SVR and SVR-B;
- enclave/attestation helpers;
- TLS/proxy/DNS/native socket infrastructure through network support crates.

Browsers cannot expose equivalent raw socket and runtime controls. This wrapper therefore does not
port `libsignal-net` literally. Instead it exposes `BrowserChatConnection`, a transport-neutral
facade:

1. Rust builds Node-shaped request objects: method, path, headers, and body.
2. JavaScript transport callback sends the request using browser-owned infrastructure.
3. Rust parser helpers convert response bytes/JSON into API objects.

Implemented browser request/parser areas include:

- pre-key lookup;
- sealed-sender and multi-recipient send request shapes;
- authenticated send and sync-message request shapes;
- upload form parsing;
- username hash/link lookups;
- account existence checks;
- backup upload-form auth headers;
- registration session and account registration helpers;
- SVR2 credential check request/parser.

## Device Transfer

The upstream `device-transfer` crate supports Signal's device-to-device transfer feature. It
contains helpers for RSA private key generation and self-signed certificate creation using native
TLS/X.509 dependencies.

This browser wrapper does not expose device-transfer APIs today. A browser implementation would
need a browser-compatible transfer protocol design, careful handling of key material, and likely a
JavaScript/WebCrypto or WASM-compatible certificate/key generation path.

## Message Backup and SVR-B

`libsignal-message-backup` reads and validates remote message backup files. It handles backup
frames, HMAC validation, protobuf parsing, unknown-field reporting, and optional JSON/test
utilities.

`libsignal-svrb` implements SVR-B backup/restore protocol message construction and parsing.

This wrapper currently exposes only browser-clean pieces around account entropy, backup key
derivation, backup auth credentials, and backup upload-form request helpers. Full message backup
validation and SVR-B restore flows are not exposed as browser APIs yet.

## Key Transparency, CDSI, and Attestation

These areas exist upstream but are not currently exposed by the browser wrapper:

| Area | Upstream crate/module | Browser status |
| --- | --- | --- |
| Key Transparency | `keytrans` | Can be implemented, but needs browser transport/protocol integration |
| CDSI | `libsignal-net::cdsi` plus attestation/network support | Can be implemented, but needs browser transport and enclave/attestation validation |
| Attestation | `attest`, `libsignal-net::enclave` | Not directly exposed |
| SVR/SVR-B native flows | `libsignal-net::svr`, `libsignal-net::svrb`, `libsignal-svrb` | Can be implemented with more browser-specific design |

## What This WASM Wrapper Exposes

This wrapper directly depends on:

- `libsignal-protocol`
- `libsignal-account-keys`
- `signal-crypto`
- `signal-media`
- `usernames`
- `zkgroup`

It does not directly depend on:

- `device-transfer`
- `libsignal-net`
- `libsignal-message-backup`
- `libsignal-svrb`
- `keytrans`
- `attest`

Some functionality from those non-dependent areas is represented by browser-built request shapes
or by local primitives from other crates. For example, backup upload authentication uses `zkgroup`
backup auth credentials and browser chat request helpers, not the full native backup/network stack.

## Browser Design Boundaries

The browser security model is the main architectural constraint:

- no raw sockets;
- no native DNS/proxy/TLS routing control;
- no native async runtime or native cancellable network tasks;
- no direct access to platform keychains unless the app supplies one;
- persistence must be app-owned, usually IndexedDB or another browser storage mechanism.

For that reason, this package focuses on:

- protocol and cryptographic state transitions in WASM;
- byte-compatible serialized records;
- Node-shaped request construction and response parsing;
- browser-owned transport and persistence.

This is the line between "browser-clean parity" and "native-only behavior." APIs that cross that
line should be modeled as browser-backed facades rather than literal ports of Node/native internals.
