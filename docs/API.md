# Browser API

The browser package is generated into `pkg/` by:

```sh
npm run build
```

Import the generated ES module from `pkg/libsignal_wasm.js` and initialize the WASM module before
using any exported API:

```js
import init, {
  IdentityKeyPair,
  PrivateKey,
  PreKeyRecord,
  PublicKey,
} from "./pkg/libsignal_wasm.js";

await init();
```

All byte inputs and outputs are `Uint8Array`. Functions that fail throw a JavaScript `Error`
converted from the underlying Rust/libsignal error.

## Architecture Overview

This project is a browser-oriented WASM adapter around Signal's Rust `libsignal` implementation.
The upstream library remains the source of truth for protocol logic; this repository adds the
thin JavaScript/WASM boundary needed to use the browser-compatible parts from web code.

At a high level, the stack is:

| Layer | Responsibility |
| --- | --- |
| Upstream Rust `libsignal` crates | Cryptographic primitives, Signal Protocol sessions, sealed sender, sender keys, zkgroup, usernames, media sanitizers, and serialized record formats |
| Root Rust adapter crate | `wasm-bindgen` exports, browser-safe type wrappers, combined browser store, response parsers, and request builders |
| Generated `pkg/` package | ES module glue and `.wasm` artifact consumed by browser apps |
| Browser application | Owns persistence, fetch/WebSocket transport, credentials, account lifecycle, and UI state |

The WASM package intentionally does not reimplement Signal cryptography in JavaScript. Browser
code calls exported classes such as `PrivateKey`, `SignalProtocolStore`, `PreKeyBundle`,
`SenderCertificate`, and zkgroup/profile helpers; those wrappers forward into upstream Rust
implementations compiled to `wasm32-unknown-unknown`.

### Protocol State

Node's libsignal package exposes separate store traits for identity keys, sessions, pre-keys,
signed pre-keys, Kyber pre-keys, and sender keys. The browser package exposes a single
`SignalProtocolStore` that contains those stores together. This keeps the WASM API synchronous and
browser-friendly while preserving the same underlying protocol state:

- identity key pair and local registration ID;
- trusted remote identity keys;
- one-to-one session records;
- pre-key, signed pre-key, and Kyber pre-key records;
- group sender-key records.

`SignalProtocolStore.exportSnapshot()` returns a versioned binary snapshot that can be stored in
IndexedDB or another browser persistence layer. `SignalProtocolStore.fromSnapshot(bytes)` restores
that state later. The snapshot contains private key material, so applications must treat it as
sensitive account data.

### Protocol Operations

The app-facing protocol flow is the same shape as Node, but uses the combined store:

1. Fetch or receive a remote pre-key bundle.
2. Build or parse a `PreKeyBundle`.
3. Call `processPreKeyBundle(bundle, remoteAddress, localAddress, store, now)`.
4. Call `signalEncrypt(...)` and `signalDecrypt(...)` with the same store.

Sealed sender, multi-recipient sealed sender, and sender-key group messaging are layered on top of
the same store. Certificates, unidentified-sender content, sender-key distribution messages, and
group ciphertexts are still backed by upstream libsignal types.

### Browser Network Boundary

The upstream Node package includes native network machinery. Browsers cannot expose the same raw
socket, DNS, proxy, TLS, or runtime controls, so this package uses a transport facade instead:

- `BrowserChatConnection` accepts a JavaScript callback.
- Request helpers build Node-shaped method/path/header/body requests.
- The application executes those requests using browser `fetch`, WebSocket code, a service worker,
  or another app-owned transport.
- Response parser helpers convert successful server JSON into browser/WASM API objects.

This keeps protocol and request-shape parity close to Node while leaving browser networking under
application control.

### Browser-Safe Scope

The implemented browser surface is limited to functionality that can run well in a browser:

- local cryptography and protocol state transitions;
- sealed sender and group sender keys;
- zkgroup/profile/account/username primitives;
- media sanitizers over in-memory byte arrays;
- request construction and response parsing for app-provided chat transport.

Native connection management, raw sockets, DNS/proxy/TLS routing, and native cancellable runtime
semantics are not implemented literally because the browser platform does not expose equivalent
capabilities. Key Transparency, CDSI, SVR-B, and provisioning are documented as implementable only
after additional browser transport and dependency design work.

## Byte Formats

| Value | Format | Length |
| --- | --- | ---: |
| Public key | libsignal serialized Curve25519 public key, including key type byte | 33 bytes |
| Private key | raw Curve25519 private key bytes | 32 bytes |
| Signature | libsignal Curve25519 signature | 64 bytes |
| Shared secret | X25519 agreement output | 32 bytes |
| Serialized identity key pair | libsignal protobuf identity-key-pair structure | variable |
| Serialized pre-key record | libsignal protobuf pre-key record structure | variable |
| Serialized signed pre-key record | libsignal protobuf signed-pre-key record structure | variable |
| Serialized Kyber pre-key record | libsignal protobuf signed-pre-key record structure for KEM keys | variable |
| Serialized session record | libsignal protobuf session record structure | variable |

The public key format is the same format returned by `PublicKey::serialize()` in upstream
`libsignal-protocol`.

## Initialization

### `default init(moduleOrPath?)`

Initializes the WASM module. In a browser, `await init()` loads the sibling
`libsignal_wasm_bg.wasm` file emitted by `wasm-pack`.

```js
import init from "./pkg/libsignal_wasm.js";

await init();
```

For bundlers or custom loading flows, pass a URL, `Request`, `Response`, `ArrayBuffer`, or
`WebAssembly.Module` supported by wasm-bindgen:

```js
await init({
  module_or_path: new URL("./pkg/libsignal_wasm_bg.wasm", import.meta.url),
});
```

## Node-Compatible Key API

The browser module exports Node-shaped key classes for the key layer.

### `PublicKey`

```js
const publicKey = PublicKey.deserialize(bytes);
const bytes = publicKey.serialize();
const rawCurveBytes = publicKey.getPublicKeyBytes();
const valid = publicKey.verify(message, signature);
const same = publicKey.equals(otherPublicKey);
```

Methods:

| Method | Notes |
| --- | --- |
| `PublicKey.deserialize(buf)` | Parses a 33-byte serialized public key |
| `serialize()` | Returns the 33-byte serialized public key |
| `getPublicKeyBytes()` | Returns the raw 32-byte Curve25519 public key |
| `verify(msg, sig)` | Verifies a 64-byte signature |
| `verifyAlternateIdentity(other, signature)` | Verifies an alternate identity signature |
| `seal(msg, info, associatedData?)` | HPKE-seals bytes for `PrivateKey.open` |
| `equals(other)` | Constant-time equality for matching key types |

`seal` currently accepts `info` as `Uint8Array`; Node also accepts a string and UTF-8 encodes it.

### `PrivateKey`

```js
const privateKey = PrivateKey.generate();
const publicKey = privateKey.getPublicKey();
const signature = privateKey.sign(message);
const sharedSecret = privateKey.agree(remotePublicKey);
```

Methods:

| Method | Notes |
| --- | --- |
| `PrivateKey.generate()` | Generates a new private key |
| `PrivateKey.deserialize(buf)` | Parses a 32-byte private key |
| `serialize()` | Returns the 32-byte private key |
| `sign(msg)` | Returns a 64-byte signature |
| `agree(otherPublicKey)` | Returns a 32-byte X25519 shared secret |
| `getPublicKey()` | Derives the public key |
| `open(ciphertext, info, associatedData?)` | Opens bytes from `PublicKey.seal` |

`open` currently accepts `info` as `Uint8Array`; Node also accepts a string and UTF-8 encodes it.

### `IdentityKeyPair`

```js
const identity = IdentityKeyPair.generate();
const encoded = identity.serialize();
const decoded = IdentityKeyPair.deserialize(encoded);
const alternateSignature = identity.signAlternateIdentity(decoded.publicKey);
```

Members and methods:

| API | Notes |
| --- | --- |
| `new IdentityKeyPair(publicKey, privateKey)` | Constructs an identity key pair |
| `IdentityKeyPair.generate()` | Generates a new identity key pair |
| `IdentityKeyPair.deserialize(buffer)` | Parses serialized identity-key-pair bytes |
| `identity.publicKey` | Returns a `PublicKey` |
| `identity.privateKey` | Returns a `PrivateKey` |
| `serialize()` | Returns libsignal identity-key-pair protobuf bytes |
| `signAlternateIdentity(otherPublicKey)` | Signs another identity public key |

## Node-Compatible Record API

## Address API

The browser module now exports `ServiceId`, `Aci`, `Pni`, and `ProtocolAddress`.

```js
const aci = Aci.fromUuid("11111111-1111-4111-8111-111111111111");
const address = ProtocolAddress.newFromAci(aci, 1);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `ServiceId.parseFromServiceIdString(value)` | Parses ACI/PNI service-id string |
| `ServiceId.parseFromServiceIdBinary(bytes)` | Parses variable-width binary service ID |
| `ServiceId.parseFromServiceIdFixedWidthBinary(bytes)` | Parses fixed-width binary service ID |
| `Aci.fromUuid(uuid)` / `Aci.fromUuidBytes(bytes)` | Creates an ACI |
| `Pni.fromUuid(uuid)` / `Pni.fromUuidBytes(bytes)` | Creates a PNI |
| `getServiceIdBinary()` | Returns variable-width service-id bytes |
| `getServiceIdFixedWidthBinary()` | Returns 17-byte fixed-width service-id bytes |
| `getServiceIdString()` | Returns service-id string |
| `getRawUuid()` | Returns UUID string without service-id kind |
| `ProtocolAddress.new(name, deviceId)` | Creates an address from a string name |
| `ProtocolAddress.newFromAci(aci, deviceId)` | Creates an address from an ACI |
| `ProtocolAddress.newFromPni(pni, deviceId)` | Creates an address from a PNI |
| `address.name()` / `address.deviceId()` | Returns address fields |
| `address.serviceId()` | Parses address name as a service ID, if possible |

### `PreKeyRecord`

```js
const record = PreKeyRecord.new(id, publicKey, privateKey);
const encoded = record.serialize();
const decoded = PreKeyRecord.deserialize(encoded);
```

Methods:

| Method | Notes |
| --- | --- |
| `PreKeyRecord.new(id, pubKey, privKey)` | Creates a pre-key record |
| `PreKeyRecord.deserialize(buffer)` | Parses serialized pre-key record bytes |
| `id()` | Returns the numeric pre-key ID |
| `publicKey()` | Returns a `PublicKey` |
| `privateKey()` | Returns a `PrivateKey` |
| `serialize()` | Returns libsignal pre-key protobuf bytes |

### `SignedPreKeyRecord`

```js
const record = SignedPreKeyRecord.new(
  id,
  Date.now(),
  publicKey,
  privateKey,
  signature,
);
```

Methods:

| Method | Notes |
| --- | --- |
| `SignedPreKeyRecord.new(id, timestamp, pubKey, privKey, signature)` | Creates a signed pre-key record |
| `SignedPreKeyRecord.deserialize(buffer)` | Parses serialized signed-pre-key record bytes |
| `id()` | Returns the numeric signed pre-key ID |
| `timestamp()` | Returns milliseconds since Unix epoch |
| `publicKey()` | Returns a `PublicKey` |
| `privateKey()` | Returns a `PrivateKey` |
| `signature()` | Returns signature bytes |
| `serialize()` | Returns libsignal signed-pre-key protobuf bytes |

### `SessionRecord`

```js
const fresh = SessionRecord.newFresh();
const encoded = fresh.serialize();
const decoded = SessionRecord.deserialize(encoded);
```

Methods:

| Method | Notes |
| --- | --- |
| `SessionRecord.newFresh()` | Creates an empty session record |
| `SessionRecord.deserialize(buffer)` | Parses serialized session record bytes |
| `serialize()` | Returns libsignal session-record protobuf bytes |
| `archiveCurrentState()` | Archives the current state if present |
| `hasCurrentState(now)` | Checks whether the current session has a non-stale PQXDH/SPQR sender chain |
| `currentRatchetKeyMatches(key)` | Checks current ratchet key match |
| `localRegistrationId()` | Returns local registration ID; throws for fresh records |
| `remoteRegistrationId()` | Returns remote registration ID; throws for fresh records |

Unlike Node, `hasCurrentState` requires a numeric `now` timestamp in milliseconds. Node accepts an
optional `Date` and defaults it to the current time.

## KEM And Bundle API

Modern libsignal pre-key sessions require Kyber/ML-KEM pre-key material.

```js
const kem = KEMKeyPair.generate();
const kyberSignature = identity.privateKey.sign(kem.getPublicKey().serialize());
const kyberRecord = KyberPreKeyRecord.new(30, Date.now(), kem, kyberSignature);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `KEMKeyPair.generate()` | Generates a Kyber1024 key pair |
| `kem.getPublicKey()` / `kem.getSecretKey()` | Returns KEM public/secret keys |
| `KEMPublicKey.deserialize(bytes)` / `serialize()` | Parses/serializes KEM public keys |
| `KEMSecretKey.deserialize(bytes)` / `serialize()` | Parses/serializes KEM secret keys |
| `KyberPreKeyRecord.new(id, timestamp, keyPair, signature)` | Creates a Kyber pre-key record |
| `KyberPreKeyRecord.deserialize(bytes)` / `serialize()` | Parses/serializes Kyber records |
| `kyberRecord.publicKey()` / `secretKey()` / `keyPair()` | Returns key material |
| `kyberRecord.signature()` / `timestamp()` / `id()` | Returns record metadata |
| `PreKeyBundle.new(...)` | Creates the bundle used by `processPreKeyBundle` |

## Session API

`SignalProtocolStore` is a browser-facing in-memory store wrapper for the libsignal session,
identity, pre-key, signed-pre-key, Kyber-pre-key, and sender-key store traits.

```js
const store = new SignalProtocolStore(identityKeyPair, registrationId);
store.savePreKey(id, preKeyRecord);
store.saveSignedPreKey(id, signedPreKeyRecord);
store.saveKyberPreKey(id, kyberPreKeyRecord);
```

Session functions use Node-like argument ordering, but take the combined browser store where Node
takes separate store interfaces.

```js
processPreKeyBundle(bundle, remoteAddress, localAddress, localStore, Date.now());

const ciphertext = signalEncrypt(
  plaintext,
  remoteAddress,
  localAddress,
  localStore,
  Date.now(),
);

const plaintext = signalDecrypt(
  ciphertext,
  remoteAddress,
  localAddress,
  localStore,
);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `new SignalProtocolStore(identityKeyPair, registrationId)` | Creates an in-memory protocol store |
| `SignalProtocolStore.fromSnapshot(bytes)` | Restores a store from bytes returned by `exportSnapshot()` |
| `store.exportSnapshot()` | Exports a versioned binary snapshot for IndexedDB persistence |
| `store.savePreKey(id, record)` | Saves a pre-key record |
| `store.saveSignedPreKey(id, record)` | Saves a signed pre-key record |
| `store.saveKyberPreKey(id, record)` | Saves a Kyber pre-key record |
| `store.loadSession(address)` | Returns a `SessionRecord` or `undefined` |
| `store.storeSession(address, record)` | Saves a session record |
| `store.saveSenderKey(sender, distributionId, record)` | Saves a group sender-key record |
| `store.getSenderKey(sender, distributionId)` | Returns a `SenderKeyRecord` or `undefined` |
| `processPreKeyBundle(bundle, address, localAddress, store, now)` | Establishes a sending session |
| `signalEncrypt(message, address, localAddress, store, now)` | Encrypts and returns `CiphertextMessage` |
| `signalDecrypt(message, address, localAddress, store)` | Decrypts `CiphertextMessage` |
| `CiphertextMessage.deserialize(type, bytes)` | Parses whisper/pre-key/sender-key ciphertext |
| `ciphertext.serialize()` / `ciphertext.type()` | Returns wire bytes and message type |

The snapshot contains private identity keys, session state, pre-keys, signed pre-keys, Kyber
pre-keys, known identities, replay-tracking state, and sender-key records. Treat it as secret key
material. Store it in IndexedDB only under the app's normal local-data security model, and prefer
encrypting it with a user- or platform-protected key when available.

## Group Sender-Key API

The browser module now exposes the Node sender-key APIs used for Signal group messages. These APIs
reuse `SignalProtocolStore` as the sender-key store.

```js
const distributionId = "d1d1d1d1-7000-11eb-b32a-33b8a8a487a6";
const distribution = SenderKeyDistributionMessage.create(
  senderAddress,
  distributionId,
  senderStore,
);

processSenderKeyDistributionMessage(senderAddress, distribution, receiverStore);

const groupCiphertext = groupEncrypt(
  senderAddress,
  distributionId,
  senderStore,
  plaintext,
);

const plaintext = groupDecrypt(
  senderAddress,
  receiverStore,
  groupCiphertext.serialize(),
);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `SenderKeyRecord.deserialize(buffer)` | Parses sender-key record bytes |
| `senderKeyRecord.serialize()` | Returns sender-key record bytes |
| `SenderKeyDistributionMessage.create(sender, distributionId, store)` | Creates or reuses sender-key state and returns a distribution message |
| `SenderKeyDistributionMessage.deserialize(buffer)` | Parses a distribution message |
| `SenderKeyDistributionMessage._new(...)` | Test helper matching Node |
| `skdm.serialize()` / `chainKey()` / `iteration()` / `chainId()` / `distributionId()` | Returns distribution message fields |
| `processSenderKeyDistributionMessage(sender, message, store)` | Stores received group sender-key state |
| `groupEncrypt(sender, distributionId, store, message)` | Encrypts group plaintext and returns `CiphertextMessage` type `7` |
| `groupDecrypt(sender, store, message)` | Decrypts serialized sender-key message bytes |
| `SenderKeyMessage.deserialize(buffer)` | Parses a serialized sender-key message |
| `SenderKeyMessage._new(...)` | Test helper matching Node |
| `senderKeyMessage.serialize()` / `ciphertext()` / `iteration()` / `chainId()` / `distributionId()` | Returns sender-key message fields |
| `senderKeyMessage.verifySignature(publicKey)` | Verifies the sender-key message signature |

Current differences from Node: group APIs are synchronous because the browser store is in-memory,
and they take the combined browser `SignalProtocolStore`; Node accepts a separate `SenderKeyStore`.

## Username API

The upstream Node package exports these under `usernames`. The browser module exposes the same
local primitives as flat exports with a `username` prefix.

```js
const candidates = usernameGenerateCandidates("alice", 3, 32);
const { username, hash } = usernameFromParts("alice", "42", 3, 32);
const proof = usernameGenerateProof(username);
usernameVerifyProof(proof, hash);

const link = usernameCreateLink(username);
const decrypted = usernameDecryptLink(link.entropy, link.encryptedUsername);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `usernameGenerateCandidates(nickname, minNicknameLength, maxNicknameLength)` | Returns candidate username strings |
| `usernameFromParts(nickname, discriminator, minNicknameLength, maxNicknameLength)` | Returns `{ username, hash }` |
| `usernameHash(username)` | Returns the 32-byte username hash |
| `usernameGenerateProof(username)` | Generates a username proof with browser randomness |
| `usernameGenerateProofWithRandom(username, random)` | Deterministic proof helper; `random` must be 32 bytes |
| `usernameVerifyProof(proof, hash)` | Throws if proof verification fails |
| `usernameCreateLink(username, previousEntropy?)` | Returns `UsernameLink` with `entropy` and `encryptedUsername` |
| `usernameDecryptLink(entropy, encryptedUsername)` | Decrypts a username link |

Current differences from Node: these functions are flat exports instead of a `usernames` namespace,
and `usernameCreateLink` returns a `UsernameLink` class instance rather than a plain object. Network
lookups for username hash/link resolution are not included.

## Account-Key API

The browser module exposes the local `AccountKeys` primitives used for backup keys and PIN/SVR key
derivation.

```js
const accountEntropy = AccountEntropyPool.generate();
const backupKey = AccountEntropyPool.deriveBackupKey(accountEntropy);
const backupId = backupKey.deriveBackupId(aci);
const localPinHash = Pin.localHash(normalizedPin);
const pinHash = PinHash.fromSalt(normalizedPin, salt);
const svr2PinHash = PinHash.fromUsernameMrenclave(normalizedPin, username, mrenclave);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `AccountEntropyPool.generate()` | Returns a random 64-character account entropy string |
| `AccountEntropyPool.isValid(value)` | Validates account entropy string structure |
| `AccountEntropyPool.deriveSvrKey(value)` | Returns a 32-byte SVR key |
| `AccountEntropyPool.deriveBackupKey(value)` | Returns `BackupKey` |
| `new BackupKey(contents)` / `BackupKey.generateRandom()` | Creates a 32-byte backup key |
| `backupKey.serialize()` / `getContents()` | Returns backup-key bytes |
| `backupKey.deriveBackupId(aci)` | Returns a 16-byte backup ID |
| `backupKey.deriveEcKey(aci)` | Returns a `PrivateKey` |
| `backupKey.deriveLocalBackupMetadataKey()` | Returns a 32-byte local metadata key |
| `backupKey.deriveMediaId(mediaName)` | Returns a media ID |
| `backupKey.deriveMediaEncryptionKey(mediaId)` | Returns 64 bytes: HMAC key plus AES-CBC key |
| `backupKey.deriveThumbnailTransitEncryptionKey(mediaId)` | Returns 64 bytes: HMAC key plus AES-CBC key |
| `new BackupForwardSecrecyToken(contents)` | Validates and wraps a 32-byte token |
| `token.serialize()` / `getContents()` | Returns token bytes |
| `PinHash.fromSalt(normalizedPin, salt)` | Derives SVR PIN encryption/access keys using explicit 32-byte salt |
| `PinHash.fromUsernameMrenclave(normalizedPin, username, mrenclave)` | Derives the SVR2 salt from the Basic Auth username and a known 32-byte SVR2 mrenclave, then derives PIN encryption/access keys |
| `pinHash.encryptionKey` / `pinHash.accessKey` | Returns 32-byte keys |
| `Pin.localHash(normalizedPin)` / `pinLocalHash(normalizedPin)` | Creates a local PHC-encoded PIN hash |
| `Pin.verifyLocalHash(encodedHash, normalizedPin)` / `pinVerifyLocalHash(...)` | Verifies a local PIN hash |

Current differences from Node: backup/SVR network calls are not included. The browser
`PinHash.fromUsernameMrenclave` method uses the vendored SVR2 mrenclave-to-group-id table for the
known Signal SVR2 enclaves.

## zkgroup Group/Profile API

The browser module exposes the local zkgroup group cipher and profile-key primitives used by group
state encryption and profile-key handling.

```js
const groupSecretParams = GroupSecretParams.generate();
const groupPublicParams = groupSecretParams.getPublicParams();
const groupIdentifier = groupPublicParams.getGroupIdentifier();
const groupCipher = new ClientZkGroupCipher(groupSecretParams);

const encryptedServiceId = groupCipher.encryptServiceId(aci);
const decryptedServiceId = groupCipher.decryptServiceId(encryptedServiceId);

const profileKey = ProfileKey.generate();
const encryptedProfileKey = groupCipher.encryptProfileKey(profileKey, aci);
const decryptedProfileKey = groupCipher.decryptProfileKey(encryptedProfileKey, aci);
const profileKeyVersion = profileKey.getProfileKeyVersion(aci).toString();
```

Supported APIs:

| API | Notes |
| --- | --- |
| `ServerSecretParams.generate()` / `generateWithRandom(random)` | Creates zkgroup server secret params; deterministic random must be 32 bytes |
| `new ServerSecretParams(contents)` / `serialize()` / `getContents()` | Parses and serializes server secret params |
| `serverSecretParams.getPublicParams()` | Returns `ServerPublicParams` |
| `serverSecretParams.sign(message)` / `signWithRandom(random, message)` | Creates a `NotarySignature` |
| `new ServerPublicParams(contents)` / `serialize()` / `getContents()` | Parses and serializes server public params |
| `serverPublicParams.verifySignature(message, notarySignature)` | Verifies a notary signature |
| `new GroupMasterKey(contents)` | Wraps a 32-byte group master key |
| `GroupSecretParams.generate()` / `generateWithRandom(random)` | Creates group secret params; deterministic random must be 32 bytes |
| `GroupSecretParams.deriveFromMasterKey(groupMasterKey)` | Derives group secret params from a master key |
| `new GroupSecretParams(contents)` / `serialize()` / `getContents()` | Parses and serializes zkgroup group secret params |
| `groupSecretParams.getMasterKey()` | Returns `GroupMasterKey` |
| `groupSecretParams.getPublicParams()` | Returns `GroupPublicParams` |
| `new GroupPublicParams(contents)` / `serialize()` / `getContents()` | Parses and serializes group public params |
| `groupPublicParams.getGroupIdentifier()` | Returns `GroupIdentifier` |
| `new GroupIdentifier(contents)` / `toString()` | Wraps a 32-byte group identifier; `toString()` returns padded base64 |
| `new ProfileKey(contents)` / `ProfileKey.generate()` / `generateWithRandom(random)` | Creates a 32-byte profile key |
| `profileKey.getCommitment(aci)` | Returns `ProfileKeyCommitment` |
| `profileKey.getProfileKeyVersion(aci)` | Returns `ProfileKeyVersion`; `toString()` returns the 64-byte ASCII hex version |
| `profileKey.deriveAccessKey()` | Returns the 16-byte profile access key |
| `new UuidCiphertext(contents)` / `new ProfileKeyCiphertext(contents)` | Parses zkgroup ciphertext wrappers |
| `UuidCiphertext.serializeAndConcatenate(ciphertexts)` | Matches Node helper for concatenating UUID ciphertexts |
| `new ClientZkGroupCipher(groupSecretParams)` | Creates the local group cipher |
| `groupCipher.encryptServiceId(serviceId)` / `decryptServiceId(ciphertext)` | Encrypts/decrypts `ServiceId` values |
| `groupCipher.encryptProfileKey(profileKey, aci)` / `decryptProfileKey(ciphertext, aci)` | Encrypts/decrypts profile keys for an ACI |
| `groupCipher.encryptBlob(plaintext)` / `encryptBlobWithRandom(random, plaintext)` | Encrypts a group blob with zero padding |
| `groupCipher.encryptBlobWithPadding(random, plaintext, paddingLen)` | Deterministic helper with explicit padding |
| `groupCipher.decryptBlob(ciphertext)` | Decrypts blobs produced by the padding encrypt helpers |

### zkgroup Profile Credential API

The browser module also exposes the expiring profile-key credential flow used to prove group
membership/profile-key ownership without revealing plaintext identifiers to the service.

```js
const serverSecretParams = ServerSecretParams.generate();
const serverPublicParams = serverSecretParams.getPublicParams();
const clientProfileOps = new ClientZkProfileOperations(serverPublicParams);
const serverProfileOps = new ServerZkProfileOperations(serverSecretParams);

const requestContext = clientProfileOps.createProfileKeyCredentialRequestContext(aci, profileKey);
const request = requestContext.getRequest();
const commitment = profileKey.getCommitment(aci);
const expiration = Math.floor(Date.now() / 1000) + 3 * 86400;
const response = serverProfileOps.issueExpiringProfileKeyCredential(
  request,
  aci,
  commitment,
  expiration,
);
const credential = clientProfileOps.receiveExpiringProfileKeyCredential(
  requestContext,
  response,
  Math.floor(Date.now() / 1000),
);
const presentation = clientProfileOps.createExpiringProfileKeyCredentialPresentation(
  groupSecretParams,
  credential,
);
serverProfileOps.verifyProfileKeyCredentialPresentation(
  groupSecretParams.getPublicParams(),
  presentation,
  Math.floor(Date.now() / 1000),
);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `new ClientZkProfileOperations(serverPublicParams)` | Creates client-side profile credential operations |
| `createProfileKeyCredentialRequestContext(aci, profileKey)` | Creates a request context with browser randomness |
| `createProfileKeyCredentialRequestContextWithRandom(random, aci, profileKey)` | Deterministic request helper; random must be 32 bytes |
| `requestContext.getRequest()` | Returns `ProfileKeyCredentialRequest` to send to the issuer |
| `receiveExpiringProfileKeyCredential(context, response, nowSeconds?)` | Validates and receives an expiring credential; `nowSeconds` defaults to browser time |
| `createExpiringProfileKeyCredentialPresentation(groupSecretParams, credential)` | Creates a presentation with browser randomness |
| `createExpiringProfileKeyCredentialPresentationWithRandom(random, groupSecretParams, credential)` | Deterministic presentation helper |
| `new ServerZkProfileOperations(serverSecretParams)` | Creates issuer/verifier profile credential operations |
| `issueExpiringProfileKeyCredential(request, aci, commitment, expirationInSeconds)` | Issues an expiring credential response with browser randomness |
| `issueExpiringProfileKeyCredentialWithRandom(random, request, aci, commitment, expirationInSeconds)` | Deterministic issuer helper |
| `verifyProfileKeyCredentialPresentation(groupPublicParams, presentation, nowSeconds?)` | Verifies a profile-key credential presentation |
| `new ProfileKeyCredentialRequestContext/Request/ExpiringProfileKeyCredentialResponse/ExpiringProfileKeyCredential/ProfileKeyCredentialPresentation(contents)` | Parses serialized credential flow values |
| `credential.getExpirationTime()` | Returns a JavaScript `Date` |
| `presentation.getUuidCiphertext()` / `getProfileKeyCiphertext()` | Extracts encrypted presentation fields |

### zkgroup Auth Credential API

The browser module exposes the auth credential with PNI flow used by group membership
presentations.

```js
const serverSecretParams = ServerSecretParams.generate();
const serverPublicParams = serverSecretParams.getPublicParams();
const clientAuthOps = new ClientZkAuthOperations(serverPublicParams);
const serverAuthOps = new ServerZkAuthOperations(serverSecretParams);
const redemptionTime = Math.floor(Date.now() / 86400000) * 86400;

const response = serverAuthOps.issueAuthCredentialWithPniZkc(aci, pni, redemptionTime);
const credential = clientAuthOps.receiveAuthCredentialWithPniAsServiceId(
  aci,
  pni,
  redemptionTime,
  response,
);
const presentation = clientAuthOps.createAuthCredentialWithPniPresentation(
  groupSecretParams,
  credential,
);
serverAuthOps.verifyAuthCredentialPresentation(
  groupSecretParams.getPublicParams(),
  presentation,
  Math.floor(Date.now() / 1000),
);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `new ClientZkAuthOperations(serverPublicParams)` | Creates client-side auth credential operations |
| `receiveAuthCredentialWithPniAsServiceId(aci, pni, redemptionTime, response)` | Validates and receives an auth credential with PNI |
| `createAuthCredentialWithPniPresentation(groupSecretParams, credential)` | Creates a presentation with browser randomness |
| `createAuthCredentialWithPniPresentationWithRandom(random, groupSecretParams, credential)` | Deterministic presentation helper |
| `new ServerZkAuthOperations(serverSecretParams)` | Creates issuer/verifier auth credential operations |
| `issueAuthCredentialWithPniZkc(aci, pni, redemptionTime)` | Issues a ZKC auth credential response with browser randomness |
| `issueAuthCredentialWithPniZkcWithRandom(random, aci, pni, redemptionTime)` | Deterministic issuer helper |
| `verifyAuthCredentialPresentation(groupPublicParams, presentation, nowSeconds?)` | Verifies an auth credential presentation |
| `new AuthCredentialWithPniResponse/AuthCredentialWithPni/AuthCredentialPresentation(contents)` | Parses serialized auth credential flow values |
| `presentation.getUuidCiphertext()` / `getPniCiphertext()` | Extracts encrypted ACI/PNI fields |
| `presentation.getRedemptionTime()` | Returns a JavaScript `Date` |

### zkgroup Receipt Credential API

The browser module exposes the receipt credential flow used by receipt issuance and presentation.

```js
const clientReceiptOps = new ClientZkReceiptOperations(serverPublicParams);
const serverReceiptOps = new ServerZkReceiptOperations(serverSecretParams);
const receiptSerial = new ReceiptSerial(crypto.getRandomValues(new Uint8Array(16)));
const requestContext = clientReceiptOps.createReceiptCredentialRequestContext(receiptSerial);
const request = requestContext.getRequest();
const expiration = Math.floor(Date.now() / 86400000 + 7) * 86400;
const response = serverReceiptOps.issueReceiptCredential(request, expiration, 1n);
const credential = clientReceiptOps.receiveReceiptCredential(requestContext, response);
const presentation = clientReceiptOps.createReceiptCredentialPresentation(credential);
serverReceiptOps.verifyReceiptCredentialPresentation(presentation);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `new ReceiptSerial(contents)` | Wraps a 16-byte receipt serial |
| `new ClientZkReceiptOperations(serverPublicParams)` | Creates client-side receipt credential operations |
| `createReceiptCredentialRequestContext(receiptSerial)` | Creates a request context with browser randomness |
| `createReceiptCredentialRequestContextWithRandom(random, receiptSerial)` | Deterministic request helper; random must be 32 bytes |
| `requestContext.getRequest()` | Returns `ReceiptCredentialRequest` to send to the issuer |
| `receiveReceiptCredential(context, response)` | Validates and receives a receipt credential |
| `createReceiptCredentialPresentation(credential)` | Creates a presentation with browser randomness |
| `createReceiptCredentialPresentationWithRandom(random, credential)` | Deterministic presentation helper |
| `new ServerZkReceiptOperations(serverSecretParams)` | Creates issuer/verifier receipt credential operations |
| `issueReceiptCredential(request, expirationTime, receiptLevel)` | Issues a receipt credential response with browser randomness |
| `issueReceiptCredentialWithRandom(random, request, expirationTime, receiptLevel)` | Deterministic issuer helper |
| `verifyReceiptCredentialPresentation(presentation)` | Verifies a receipt credential presentation |
| `new ReceiptCredentialRequestContext/Request/Response/Credential/Presentation(contents)` | Parses serialized receipt credential flow values |
| `credential.getReceiptExpirationTime()` / `presentation.getReceiptExpirationTime()` | Returns epoch seconds |
| `credential.getReceiptLevel()` / `presentation.getReceiptLevel()` | Returns the receipt level as `bigint` |
| `presentation.getReceiptSerialBytes()` | Returns `ReceiptSerial` |

### zkgroup Call-Link Credential API

The browser module exposes the call-link params, create-call-link credential flow, and call-link
auth credential flow.

```js
const genericSecretParams = GenericServerSecretParams.generate();
const genericPublicParams = genericSecretParams.getPublicParams();
const callLinkParams = CallLinkSecretParams.deriveFromRootKey(rootKey);
const callLinkPublicParams = callLinkParams.getPublicParams();

const roomContext = CreateCallLinkCredentialRequestContext.forRoomId(roomId);
const roomRequest = roomContext.getRequest();
const timestamp = Math.floor(Date.now() / 86400000) * 86400;
const roomResponse = roomRequest.issueCredential(aci, timestamp, genericSecretParams);
const roomCredential = roomContext.receive(roomResponse, aci, genericPublicParams);
const roomPresentation = roomCredential.present(
  roomId,
  aci,
  genericPublicParams,
  callLinkParams,
);
roomPresentation.verify(roomId, genericSecretParams, callLinkPublicParams);

const authResponse = CallLinkAuthCredentialResponse.issueCredential(
  aci,
  timestamp,
  genericSecretParams,
);
const authCredential = authResponse.receive(aci, timestamp, genericPublicParams);
const authPresentation = authCredential.present(
  aci,
  timestamp,
  genericPublicParams,
  callLinkParams,
);
authPresentation.verify(genericSecretParams, callLinkPublicParams);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `GenericServerSecretParams.generate()` / `generateWithRandom(random)` | Creates generic server params for call-link credentials |
| `new GenericServerSecretParams(contents)` / `getPublicParams()` | Parses server secret params and derives public params |
| `new GenericServerPublicParams(contents)` | Parses generic server public params |
| `CallLinkSecretParams.deriveFromRootKey(rootKey)` | Derives call-link secret params; only the first 16 bytes of root key are used by upstream |
| `new CallLinkSecretParams(contents)` / `getPublicParams()` | Parses secret params and derives public params |
| `callLinkSecretParams.encryptUserId(aci)` / `decryptUserId(ciphertext)` | Encrypts/decrypts call-link user IDs |
| `new CallLinkPublicParams(contents)` | Parses call-link public params |
| `CreateCallLinkCredentialRequestContext.forRoomId(roomId)` | Creates a request context with browser randomness |
| `CreateCallLinkCredentialRequestContext.forRoomIdWithRandom(roomId, random)` | Deterministic request helper |
| `requestContext.getRequest()` / `requestContext.receive(response, aci, genericPublicParams)` | Gets issuer request and receives credential response |
| `request.issueCredential(aci, timestamp, genericSecretParams)` | Issues create-call-link credential response |
| `request.issueCredentialWithRandom(aci, timestamp, genericSecretParams, random)` | Deterministic issuer helper |
| `credential.present(roomId, aci, genericPublicParams, callLinkSecretParams)` | Creates create-call-link presentation |
| `credential.presentWithRandom(roomId, aci, genericPublicParams, callLinkSecretParams, random)` | Deterministic presentation helper |
| `presentation.verify(roomId, genericSecretParams, callLinkPublicParams, nowSeconds?)` | Verifies create-call-link presentation |
| `CallLinkAuthCredentialResponse.issueCredential(aci, redemptionTime, genericSecretParams)` | Issues auth credential response |
| `CallLinkAuthCredentialResponse.issueCredentialWithRandom(aci, redemptionTime, genericSecretParams, random)` | Deterministic issuer helper |
| `authResponse.receive(aci, redemptionTime, genericPublicParams)` | Receives call-link auth credential |
| `authCredential.present(aci, redemptionTime, genericPublicParams, callLinkSecretParams)` | Creates auth presentation |
| `authCredential.presentWithRandom(aci, redemptionTime, genericPublicParams, callLinkSecretParams, random)` | Deterministic presentation helper |
| `authPresentation.verify(genericSecretParams, callLinkPublicParams, nowSeconds?)` | Verifies call-link auth presentation |
| `authPresentation.getUserId()` | Returns encrypted user ID as `UuidCiphertext` |
| `new CreateCallLinkCredentialRequest/Response/Credential/Presentation(contents)` | Parses create-call-link credential values |
| `new CallLinkAuthCredentialResponse/Credential/Presentation(contents)` | Parses call-link auth credential values |

### zkgroup Backup Auth Credential API

The browser module exposes backup auth credential issuance and presentation.

```js
const genericSecretParams = GenericServerSecretParams.generate();
const genericPublicParams = genericSecretParams.getPublicParams();
const redemptionTime = Math.floor(Date.now() / 86400000) * 86400;

const requestContext = BackupAuthCredentialRequestContext.create(
  backupKey.getContents(),
  aci,
);
const request = requestContext.getRequest();
const response = request.issueCredential(
  redemptionTime,
  BackupLevel.Free,
  BackupCredentialType.Messages,
  genericSecretParams,
);
const credential = requestContext.receive(response, redemptionTime, genericPublicParams);
const presentation = credential.present(genericPublicParams);
presentation.verify(genericSecretParams, Math.floor(Date.now() / 1000));
```

Supported APIs:

| API | Notes |
| --- | --- |
| `BackupLevel.Free` / `BackupLevel.Paid` | Matches Node enum values `200` / `201` |
| `BackupCredentialType.Messages` / `BackupCredentialType.Media` | Matches Node enum values `1` / `2` |
| `BackupAuthCredentialRequestContext.create(backupKey, aci)` | Creates deterministic request context from 32-byte backup key and ACI |
| `new BackupAuthCredentialRequestContext(contents)` | Parses request context |
| `requestContext.getRequest()` | Returns `BackupAuthCredentialRequest` to send to issuer |
| `requestContext.receive(response, redemptionTime, genericPublicParams)` | Receives backup auth credential |
| `request.issueCredential(redemptionTime, backupLevel, credentialType, genericSecretParams)` | Issues response with browser randomness |
| `request.issueCredentialWithRandom(redemptionTime, backupLevel, credentialType, genericSecretParams, random)` | Deterministic issuer helper |
| `new BackupAuthCredentialRequest/Response/Credential/Presentation(contents)` | Parses serialized backup auth credential values |
| `credential.present(genericPublicParams)` / `presentWithRandom(genericPublicParams, random)` | Creates backup auth presentation |
| `presentation.verify(genericSecretParams, nowSeconds?)` | Verifies backup auth presentation |
| `credential.getBackupId()` / `presentation.getBackupId()` | Returns the 16-byte backup ID |
| `credential.getBackupLevel()` / `presentation.getBackupLevel()` | Returns `BackupLevel` |
| `credential.getType()` / `presentation.getType()` | Returns `BackupCredentialType` |

Current differences from Node: these classes are flat browser exports rather than imports from
`@signalapp/libsignal-client/zkgroup`.

### zkgroup Group-Send Endorsement API

The browser module exposes the local group-send endorsement primitives used to issue, receive,
combine, subtract, convert, and verify endorsement tokens.

```js
const serverSecretParams = ServerSecretParams.generate();
const serverPublicParams = serverSecretParams.getPublicParams();
const groupSecretParams = GroupSecretParams.generate();
const cipher = new ClientZkGroupCipher(groupSecretParams);

const members = [localAci, remoteAci];
const encryptedMembers = members.map((member) => cipher.encryptServiceId(member));
const expiration = Math.ceil((Date.now() / 1000 + 86400) / 86400) * 86400;

const keyPair = GroupSendDerivedKeyPair.forExpiration(expiration, serverSecretParams);
const response = GroupSendEndorsementsResponse.issue(encryptedMembers, keyPair);
const received = response.receiveWithServiceIds(
  members,
  localAci,
  groupSecretParams,
  serverPublicParams,
);

const endorsement = received.combinedEndorsement;
const token = endorsement.toToken(groupSecretParams);
const fullToken = token.toFullToken(expiration);
fullToken.verify([remoteAci], keyPair);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `GroupSendDerivedKeyPair.forExpiration(expirationSeconds, serverSecretParams)` | Derives issuer key pair for an epoch-second expiration |
| `new GroupSendDerivedKeyPair(contents)` | Parses a serialized derived key pair |
| `new GroupSendEndorsementsResponse(contents)` | Parses a serialized endorsements response |
| `GroupSendEndorsementsResponse.issue(groupMembers, keyPair)` | Issues endorsements for encrypted UUID ciphertext members with browser randomness |
| `GroupSendEndorsementsResponse.issueWithRandom(groupMembers, keyPair, random)` | Deterministic issuer helper |
| `response.getExpiration()` | Returns a JavaScript `Date` |
| `response.receiveWithServiceIds(groupMembers, localUser, groupSecretParams, serverPublicParams, nowSeconds?)` | Receives endorsements from clear `Aci`/`Pni` service IDs |
| `response.receiveWithCiphertexts(groupMembers, localUserCiphertext, serverPublicParams, nowSeconds?)` | Receives endorsements from encrypted UUID ciphertext members |
| `receive*().endorsements` | Returns per-member `GroupSendEndorsement` values |
| `receive*().combinedEndorsement` | Returns the combined endorsement for all non-local members |
| `new GroupSendEndorsement(contents)` | Parses a serialized endorsement |
| `GroupSendEndorsement.combine(endorsements)` | Combines a JavaScript array of endorsements |
| `endorsement.byRemoving(otherEndorsement)` | Removes one endorsement from a combined endorsement |
| `endorsement.toToken(groupSecretParams)` | Converts a group endorsement to `GroupSendToken` |
| `endorsement.toTokenWithCallLinkParams(callLinkSecretParams)` | Converts a call-link endorsement to `GroupSendToken` |
| `endorsement.toFullToken(groupSecretParams, expirationSeconds)` | Converts directly to `GroupSendFullToken` |
| `endorsement.toFullTokenWithCallLinkParams(callLinkSecretParams, expirationSeconds)` | Converts directly to a call-link full token |
| `new GroupSendToken(contents)` / `token.toFullToken(expirationSeconds)` | Parses or completes an endorsement token |
| `new GroupSendFullToken(contents)` / `fullToken.getExpiration()` | Parses a full token and returns its expiration as `Date` |
| `fullToken.verify(userIds, keyPair, nowSeconds?)` | Verifies token recipients against `Aci`/`Pni` service IDs |

Current differences from Node: expiration inputs use epoch seconds rather than `Date` objects, and
the browser binding exposes explicit call-link variants instead of Node's overloaded
`GroupSecretParams | CallLinkSecretParams` parameter. For call-link tokens, issue and receive
endorsements over UUID ciphertexts produced by `CallLinkSecretParams.encryptUserId(...)`, then call
`toTokenWithCallLinkParams(...)`.

## Sealed Sender API

The browser module exposes the single-recipient sealed sender APIs used by Node for 1:1 message
delivery. These APIs reuse the combined `SignalProtocolStore`; Node accepts separate identity,
session, pre-key, signed-pre-key, and Kyber-pre-key store interfaces.

```js
const serverCert = ServerCertificate.new(keyId, serverPublicKey, trustRootPrivateKey);
const senderCert = SenderCertificate.new(
  senderAci.getServiceIdString(),
  null,
  localAddress.deviceId(),
  identity.publicKey,
  expiration,
  serverCert,
  serverPrivateKey,
);

const sealed = sealedSenderEncryptMessage(
  plaintext,
  remoteAddress,
  senderCert,
  localStore,
);

const result = sealedSenderDecryptMessage(
  sealed,
  trustRootPublicKey,
  Date.now(),
  null,
  localAci.getServiceIdString(),
  localAddress.deviceId(),
  remoteStore,
);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `ContentHint.Default` / `Resendable` / `Implicit` | Numeric content-hint enum values |
| `ServerCertificate.new(keyId, serverKey, trustRoot)` | Creates a server certificate |
| `ServerCertificate.deserialize(bytes)` | Parses serialized server-certificate bytes |
| `serverCert.certificateData()` | Returns signed certificate payload bytes |
| `serverCert.key()` / `serverCert.keyId()` | Returns server key and key ID |
| `serverCert.serialize()` / `serverCert.signature()` | Returns wire bytes and signature |
| `SenderCertificate.new(senderUuid, senderE164, senderDeviceId, senderKey, expiration, signerCert, signerKey)` | Creates a sender certificate |
| `SenderCertificate.deserialize(bytes)` | Parses serialized sender-certificate bytes |
| `senderCert.serialize()` / `certificate()` / `signature()` | Returns wire bytes, signed payload, and signature |
| `senderCert.expiration()` / `key()` | Returns expiration timestamp and sender identity key |
| `senderCert.senderUuid()` / `senderE164()` / `senderAci()` / `senderDeviceId()` | Returns sender identity fields |
| `senderCert.serverCertificate()` | Returns embedded server certificate |
| `senderCert.validate(trustRoot, time)` | Validates against one trust root |
| `senderCert.validateWithTrustRoots(trustRoots, time)` | Validates against a JS array of trust roots |
| `UnidentifiedSenderMessageContent.new(message, senderCert, contentHint, groupId?)` | Wraps a `CiphertextMessage` |
| `UnidentifiedSenderMessageContent.deserialize(bytes)` | Parses USMC bytes |
| `usmc.serialize()` / `contents()` / `msgType()` | Returns USMC wire bytes, inner ciphertext bytes, and message type |
| `usmc.senderCertificate()` / `contentHint()` / `groupId()` | Returns USMC metadata |
| `sealedSenderEncryptMessage(message, address, senderCert, store, now?)` | Encrypts plaintext into a sealed sender message; `now` defaults to browser time |
| `sealedSenderEncrypt(usmc, address, store)` | Encrypts an existing USMC |
| `sealedSenderMultiRecipientEncrypt(usmc, recipients, store, excludedRecipients?)` | Encrypts one SSv2 payload for a JS array of recipients with existing sessions |
| `sealedSenderMultiRecipientMessageForSingleRecipient(message)` | Extracts the single-recipient received message from a one-recipient SSv2 payload |
| `sealedSenderDecryptMessage(message, trustRoot, timestamp, localE164, localUuid, localDeviceId, store)` | Validates certificate and decrypts inner Signal message |
| `sealedSenderDecryptToUsmc(message, store)` | Decrypts only the sealed envelope into USMC |
| `SealedSenderDecryptionResult.message()` | Returns plaintext bytes |
| `result.senderUuid()` / `senderE164()` / `senderAci()` / `deviceId()` | Returns authenticated sender fields |

Current differences from Node: `SenderCertificate.new` accepts the sender UUID as a string; pass
`aci.getServiceIdString()` when starting with an `Aci`. `sealedSenderMultiRecipientEncrypt` accepts
JS arrays directly and the combined browser `SignalProtocolStore`; Node also supports an options
object overload and separate identity/session stores.

## Crypto Utility API

### `hkdf(outputLength, keyMaterial, label, salt?)`

Derives bytes with HKDF-SHA-256.

```js
const output = hkdf(32, keyMaterial, label, salt);
```

### `Aes256GcmSiv`

Node-compatible AES-256-GCM-SIV one-shot encryption/decryption.

```js
const cipher = Aes256GcmSiv.new(key);
const ciphertext = cipher.encrypt(plaintext, nonce, associatedData);
const plaintext = cipher.decrypt(ciphertext, nonce, associatedData);
```

Inputs:

| Value | Length |
| --- | ---: |
| `key` | 32 bytes |
| `nonce` | 12 bytes |
| authentication tag appended to ciphertext | 16 bytes |

## Media Sanitizer API

The browser module exposes the MP4 and WebP media sanitizer primitives using in-memory
`Uint8Array` inputs.

```js
signalMediaCheckAvailable();

const sanitized = mp4SanitizerSanitize(mp4Bytes);
const metadata = sanitized.getMetadata();
const dataOffset = sanitized.getDataOffset();
const dataLen = sanitized.getDataLen();

webpSanitizerSanitize(webpBytes);
```

Supported APIs:

| API | Notes |
| --- | --- |
| `signalMediaCheckAvailable()` | No-op feature probe; succeeds when media sanitizers are compiled in |
| `mp4SanitizerSanitize(input)` | Sanitizes an MP4 byte array and returns `SanitizedMetadata` |
| `mp4SanitizerSanitizeWithCompoundedMdatBoxes(input, cumulativeMdatBoxSize)` | Browser export for the compounded-MDAT sanitizer path |
| `new SanitizedMetadata(...)` | Not constructible directly; returned by MP4 sanitizer functions |
| `sanitized.getMetadata()` | Returns a `Uint8Array` containing rewritten MP4 metadata, or `null` when no rewrite is needed |
| `sanitized.getDataOffset()` / `getDataLen()` | Return `bigint` offsets into the processed input |
| `webpSanitizerSanitize(input)` | Validates a WebP byte array and throws on invalid or unsupported input |

Current differences from Node: browser MP4 sanitization takes a complete `Uint8Array` instead of an
`InputStream` plus explicit length, and these functions are flat exports instead of
`Mp4Sanitizer`/`WebpSanitizer` namespaces.

## Network API

The browser module exposes the first network parity slice as a transport-backed chat facade. It
keeps libsignal's chat request/response shape in WASM while leaving actual browser I/O to an
application-provided JavaScript transport function.

```js
const chat = new BrowserChatConnection(async (request) => {
  const response = await fetch(request.path, {
    method: request.verb,
    headers: Object.fromEntries(request.headers),
    body: request.body ?? undefined,
  });
  return {
    status: response.status,
    message: response.statusText,
    headers: [...response.headers.entries()],
    body: new Uint8Array(await response.arrayBuffer()),
  };
});

const response = await chat.fetch({
  verb: "GET",
  path: "/v1/config",
  headers: [["accept", "application/json"]],
});

await chat.getPreKeys(
  remoteAci,
  null,
  "accessKey",
  unidentifiedAccessKey,
);

await chat.sendSealedSenderMessage(
  remoteAci,
  Date.now(),
  [{ deviceId: 1, registrationId: 1234, contents: sealedSenderMessage }],
  "accessKey",
  unidentifiedAccessKey,
  false,
  true,
);

await chat.sendMultiRecipientMessage(
  sealedSenderV2Payload,
  Date.now(),
  "groupSend",
  groupSendFullToken.getContents(),
  false,
  true,
);

await chat.sendAuthenticatedMessage(
  remoteAci,
  Date.now(),
  [{ deviceId: 1, registrationId: 1234, contents: ciphertextMessage }],
  false,
  true,
);

await chat.sendSyncMessage(
  localAci,
  Date.now(),
  [{ deviceId: 2, registrationId: 5678, contents: syncCiphertextMessage }],
  true,
);

await chat.getUploadForm(12345n);

const createSessionResponse = await chat.createRegistrationSession(
  "+18005550101",
  null,
  null,
  null,
  null,
);
const registrationSession = parseRegistrationSessionResponse(
  ChatResponse.fromObject(createSessionResponse),
);

await chat.requestVerificationCode(
  registrationSession.sessionId,
  "sms",
  "browser",
  ["en-US"],
);
await chat.submitVerificationCode(registrationSession.sessionId, "123456");
await chat.disconnect();
```

Supported APIs:

| API | Notes |
| --- | --- |
| `Environment.Staging` / `Environment.Production` | Numeric enum values matching Node |
| `BuildVariant.Production` / `BuildVariant.Beta` | Numeric enum values matching Node |
| `new HttpRequest(method, path, body?)` | Creates a chat request |
| `buildHttpRequest({ verb, path, headers, body?, timeoutMillis? })` | Parses a Node-shaped chat request object |
| `request.addHeader(name, value)` / `request.setTimeoutMillis(ms?)` | Mutates a browser request |
| `request.toObject()` | Returns `{ verb, method, path, headers, body, timeoutMillis? }` |
| `new ChatResponse(status, message?, body?)` | Creates a chat response |
| `ChatResponse.fromObject({ status, message?, headers?, body? })` | Parses a Node-shaped chat response |
| `response.addHeader(name, value)` / `response.toObject()` | Mutates or serializes response values |
| `parseGetPreKeysResponse(response)` | Parses successful pre-key JSON into `{ identityKey, preKeyBundles }` |
| `parseUploadFormResponse(response)` | Parses successful upload-form JSON into `{ cdn, key, headers, signedUploadUrl }` |
| `parseLookUpUsernameHashResponse(response)` | Parses username-hash lookup JSON into `Aci | null` |
| `parseLookUpUsernameLinkResponse(response, entropy)` | Parses and decrypts username-link JSON into `{ username, hash } | null` |
| `parseAccountExistsResponse(response)` | Parses account-existence `HEAD` responses into `boolean` |
| `parseRegistrationSessionResponse(response)` | Parses registration session JSON into `{ sessionId, sessionState }` |
| `parseRegisterAccountResponse(response)` | Parses registration JSON into `{ aci, uuid, pni, number, usernameHash, usernameLinkHandle, storageCapable, entitlements, reregistration }` |
| `parseCheckSvr2CredentialsResponse(response)` | Parses SVR2 credential-check JSON into a token-result object |
| `new BrowserChatConnection(transport)` | Creates a chat connection backed by a JS function |
| `connection.fetch(chatRequest)` | Calls `transport(requestObject)` and returns `Promise.resolve(...)` |
| `connection.getPreKeys(target, deviceId?, authKind, authPayload?)` | Sends `/v2/keys/{target}/{device}` using access-key, group-send, or unrestricted auth |
| `connection.sendSealedSenderMessage(destination, timestampMillis, contents, authKind, authPayload?, onlineOnly, urgent)` | Sends `/v1/messages/{destination}` with sealed-sender JSON body |
| `connection.sendMultiRecipientMessage(payload, timestampMillis, authKind, authPayload?, onlineOnly, urgent)` | Sends `/v1/messages/multi_recipient` with SSv2 payload |
| `connection.sendAuthenticatedMessage(destination, timestampMillis, contents, onlineOnly, urgent)` | Sends authenticated unsealed message JSON to `/v1/messages/{destination}` |
| `connection.sendSyncMessage(localAci, timestampMillis, contents, urgent)` | Sends sync-message JSON using the local ACI as destination |
| `connection.getUploadForm(uploadSize)` | Sends authenticated attachment upload-form request to `/v4/attachments/form/upload` |
| `connection.lookUpUsernameHash(hash)` | Sends `GET /v1/accounts/username_hash/{base64urlHash}` |
| `connection.lookUpUsernameLink(uuid)` | Sends `GET /v1/accounts/username_link/{uuid}` |
| `connection.accountExists(account)` | Sends `HEAD /v1/accounts/account/{serviceId}` |
| `connection.getBackupUploadForm(uploadSize, credential, serverParams, signingKey)` | Sends backup upload-form request to `/v1/archives/upload/form` |
| `connection.getBackupMediaUploadForm(uploadSize, credential, serverParams, signingKey)` | Sends media backup upload-form request to `/v1/archives/media/upload/form` |
| `connection.createRegistrationSession(e164, pushTokenType?, pushToken?, mcc?, mnc?)` | Sends `POST /v1/verification/session` |
| `connection.getRegistrationSession(sessionId)` | Sends `GET /v1/verification/session/{sessionId}` |
| `connection.submitRegistrationCaptcha(sessionId, captcha)` | Sends captcha update for a registration session |
| `connection.requestRegistrationPushChallenge(sessionId, pushTokenType, pushToken)` | Sends APNs/FCM push-token update for a session |
| `connection.submitRegistrationPushChallenge(sessionId, pushChallenge)` | Sends push challenge response for a session |
| `connection.requestVerificationCode(sessionId, transport, client, languages)` | Sends `POST /v1/verification/session/{sessionId}/code` |
| `connection.submitVerificationCode(sessionId, code)` | Sends `PUT /v1/verification/session/{sessionId}/code` |
| `connection.registerAccount(e164, accountPassword, sessionId?, recoveryPassword?, skipDeviceTransfer, fetchesMessages, pushTokenType?, pushToken?, accountAttributes, aciIdentityKey, pniIdentityKey, aciSignedPreKey, pniSignedPreKey, aciPqLastResortPreKey, pniPqLastResortPreKey)` | Sends `POST /v1/registration` |
| `connection.checkSvr2Credentials(e164, tokens)` | Sends `POST /v2/backup/auth/check` |
| `connection.disconnect()` | Marks the connection disconnected and returns a resolved promise |
| `connection.connectionInfo()` | Returns browser placeholder connection info |

For `authKind`, pass `"accessKey"` with a 16-byte unidentified access key, `"groupSend"` with a
serialized `GroupSendFullToken`, `"unrestricted"` with no payload, or `"story"` for story sends.
`sendSealedSenderMessage` `contents` entries match Node's `SingleOutboundSealedSenderMessage`
shape: `{ deviceId, registrationId, contents }`. Authenticated helper `contents` entries match
Node's `SingleOutboundUnsealedMessage` shape, where `contents` is a `CiphertextMessage`.
`registerAccount` accepts an `accountAttributes` object with `recoveryPassword`,
`registrationId`, `pniRegistrationId`, `unidentifiedAccessKey`, `unrestrictedUnidentifiedAccess`,
`discoverableByPhoneNumber`, optional `registrationLock`, optional device-name bytes as `name`,
and optional string-array `capabilities`. Signed pre-key arguments may be
`SignedPreKeyRecord`/`KyberPreKeyRecord` instances or plain objects with `keyId`/`id`,
`publicKey`, and `signature` fields.
Username hash and link parsers return `null` for 404 responses. `parseLookUpUsernameLinkResponse`
expects the same 32-byte entropy that was used to create the username link and returns the
validated username plus its 32-byte username hash.
Backup upload-form helpers generate the backup auth presentation and signature inside WASM, then
send the request through the browser transport. Their responses use `parseUploadFormResponse`.

Current differences from Node: this browser slice does not embed libsignal's native connection
manager, TLS routing, websocket listener, CDSI, SVR-B, or key-transparency yet.
`parseUploadFormResponse` returns `signedUploadUrl` as a string rather than a `URL` instance, and
`sendSyncMessage` requires the local ACI because the browser facade does not own authenticated
username/device state. The transport callback is responsible for browser fetch/WebSocket behavior,
authentication headers outside these helper requests, CORS, retry policy, and response
normalization.

## Fingerprint API

```js
const fingerprint = Fingerprint.new(
  1024,
  1,
  localIdentifier,
  localIdentity.publicKey,
  remoteIdentifier,
  remoteIdentity.publicKey,
);

const display = fingerprint.displayableFingerprint().toString();
const scannable = fingerprint.scannableFingerprint().toBuffer();
```

Supported APIs:

| API | Notes |
| --- | --- |
| `Fingerprint.new(iterations, version, localIdentifier, localKey, remoteIdentifier, remoteKey)` | Creates a fingerprint |
| `fingerprint.displayableFingerprint()` | Returns `DisplayableFingerprint` |
| `fingerprint.scannableFingerprint()` | Returns `ScannableFingerprint` |
| `displayable.toString()` | Returns numeric display string |
| `scannable.toBuffer()` | Returns scannable protobuf bytes |
| `scannable.compare(other)` | Compares two scannable fingerprints |

## Legacy Raw Key API

The earlier raw wrapper remains available for compatibility. Prefer the Node-shaped classes above
for new browser app code.

## `WasmKeyPair`

Represents a libsignal Curve25519 key pair.

### `WasmKeyPair.generate(): WasmKeyPair`

Generates a new key pair using browser-compatible cryptographic randomness.

```js
const keyPair = WasmKeyPair.generate();
```

### `new WasmKeyPair(publicKey, privateKey)`

Imports an existing key pair.

```js
const keyPair = new WasmKeyPair(publicKeyBytes, privateKeyBytes);
```

Arguments:

| Name | Type | Notes |
| --- | --- | --- |
| `publicKey` | `Uint8Array` | 33-byte serialized public key |
| `privateKey` | `Uint8Array` | 32-byte private key |

### `keyPair.public_key(): Uint8Array`

Returns the serialized public key.

```js
const publicKey = keyPair.public_key();
```

### `keyPair.private_key(): Uint8Array`

Returns the private key bytes.

```js
const privateKey = keyPair.private_key();
```

Treat this output as secret material. Do not log it, send it over the network, or store it
unencrypted.

### `keyPair.sign(message): Uint8Array`

Signs a message.

```js
const message = new TextEncoder().encode("hello");
const signature = keyPair.sign(message);
```

Arguments:

| Name | Type | Notes |
| --- | --- | --- |
| `message` | `Uint8Array` | Message bytes to sign |

Returns a 64-byte signature.

### `keyPair.calculate_agreement(theirPublicKey): Uint8Array`

Calculates an X25519 shared secret with another public key.

```js
const sharedSecret = alice.calculate_agreement(bob.public_key());
```

Arguments:

| Name | Type | Notes |
| --- | --- | --- |
| `theirPublicKey` | `Uint8Array` | Other party's 33-byte serialized public key |

Returns a 32-byte shared secret.

## Functions

### `generate_key_pair(): WasmKeyPair`

Function form of `WasmKeyPair.generate()`.

```js
const keyPair = generate_key_pair();
```

### `public_key_from_private_key(privateKey): Uint8Array`

Derives a serialized public key from a private key.

```js
const publicKey = public_key_from_private_key(privateKey);
```

Arguments:

| Name | Type | Notes |
| --- | --- | --- |
| `privateKey` | `Uint8Array` | 32-byte private key |

### `verify_signature(publicKey, message, signature): boolean`

Verifies a signature.

```js
const valid = verify_signature(publicKey, message, signature);
```

Arguments:

| Name | Type | Notes |
| --- | --- | --- |
| `publicKey` | `Uint8Array` | 33-byte serialized public key |
| `message` | `Uint8Array` | Message bytes |
| `signature` | `Uint8Array` | 64-byte signature |

Returns `true` when the signature is valid for the public key and message.

### `calculate_agreement(privateKey, publicKey): Uint8Array`

Function form of `keyPair.calculate_agreement(...)`.

```js
const aliceShared = calculate_agreement(alice.private_key(), bob.public_key());
const bobShared = calculate_agreement(bob.private_key(), alice.public_key());
```

Arguments:

| Name | Type | Notes |
| --- | --- | --- |
| `privateKey` | `Uint8Array` | Local 32-byte private key |
| `publicKey` | `Uint8Array` | Remote 33-byte serialized public key |

Returns a 32-byte shared secret.

### `is_canonical_public_key(publicKey): boolean`

Checks whether a serialized public key is canonical according to upstream libsignal's Curve25519
validation.

```js
const canonical = is_canonical_public_key(publicKey);
```

Arguments:

| Name | Type | Notes |
| --- | --- | --- |
| `publicKey` | `Uint8Array` | 33-byte serialized public key |

## Complete Browser Example

```html
<script type="module">
  import init, {
    Aci,
    IdentityKeyPair,
    PrivateKey,
    KEMKeyPair,
    KyberPreKeyRecord,
    PreKeyBundle,
    PreKeyRecord,
    ProtocolAddress,
    SignalProtocolStore,
    SignedPreKeyRecord,
    signalDecrypt,
    signalEncrypt,
    processPreKeyBundle,
  } from "./pkg/libsignal_wasm.js";

  await init();

  const now = Date.now();
  const aliceAddress = ProtocolAddress.newFromAci(
    Aci.fromUuid("11111111-1111-4111-8111-111111111111"),
    1,
  );
  const bobAddress = ProtocolAddress.newFromAci(
    Aci.fromUuid("22222222-2222-4222-8222-222222222222"),
    1,
  );

  const aliceIdentity = IdentityKeyPair.generate();
  const bobIdentity = IdentityKeyPair.generate();
  const aliceStore = new SignalProtocolStore(aliceIdentity, 1001);
  const bobStore = new SignalProtocolStore(bobIdentity, 1002);

  const bobPreKeyPrivate = PrivateKey.generate();
  const bobPreKey = PreKeyRecord.new(10, bobPreKeyPrivate.getPublicKey(), bobPreKeyPrivate);
  bobStore.savePreKey(10, bobPreKey);

  const bobSignedPreKeyPrivate = PrivateKey.generate();
  const bobSignedPreKeySignature = bobIdentity.privateKey.sign(
    bobSignedPreKeyPrivate.getPublicKey().serialize(),
  );
  const bobSignedPreKey = SignedPreKeyRecord.new(
    20,
    now,
    bobSignedPreKeyPrivate.getPublicKey(),
    bobSignedPreKeyPrivate,
    bobSignedPreKeySignature,
  );
  bobStore.saveSignedPreKey(20, bobSignedPreKey);

  const bobKem = KEMKeyPair.generate();
  const bobKyberSignature = bobIdentity.privateKey.sign(bobKem.getPublicKey().serialize());
  const bobKyberPreKey = KyberPreKeyRecord.new(30, now, bobKem, bobKyberSignature);
  bobStore.saveKyberPreKey(30, bobKyberPreKey);

  const bundle = PreKeyBundle.new(
    1002,
    1,
    10,
    bobPreKey.publicKey(),
    20,
    bobSignedPreKey.publicKey(),
    bobSignedPreKey.signature(),
    bobIdentity.publicKey,
    30,
    bobKyberPreKey.publicKey(),
    bobKyberPreKey.signature(),
  );

  processPreKeyBundle(bundle, bobAddress, aliceAddress, aliceStore, now);

  const message = new TextEncoder().encode("hello from the browser");
  const ciphertext = signalEncrypt(message, bobAddress, aliceAddress, aliceStore, now);
  const plaintext = signalDecrypt(ciphertext, aliceAddress, bobAddress, bobStore);

  console.log({
    type: ciphertext.type(),
    plaintext: new TextDecoder().decode(plaintext),
  });
</script>
```

## Parity With Node

| Area | Browser status |
| --- | --- |
| `PublicKey`, `PrivateKey`, `IdentityKeyPair` | Mostly implemented |
| HPKE `seal/open` | Implemented; `info` must be `Uint8Array` |
| `PreKeyRecord`, `SignedPreKeyRecord`, `SessionRecord` | Implemented |
| `ServiceId`, `Aci`, `Pni`, `ProtocolAddress` | Implemented; no TS inheritance facade yet |
| `PreKeyBundle`, `KEMPublicKey`, `KEMKeyPair`, Kyber pre-keys | Implemented |
| Store interfaces | In-memory combined browser store implemented |
| Store persistence | Versioned binary snapshot export/restore implemented |
| Session setup, `processPreKeyBundle` | Implemented with combined store |
| Message encrypt/decrypt | Implemented for `CiphertextMessage` |
| Sealed sender | Single- and multi-recipient APIs implemented with combined store |
| Group sender keys | Implemented with combined store |
| Username local primitives | Implemented as flat `username*` exports |
| Account entropy, backup-key, PIN local primitives | Implemented |
| Fingerprints, HKDF, AES-GCM-SIV | Implemented |
| zkgroup group/profile local primitives | Implemented as flat exports |
| zkgroup expiring profile-key credentials | Implemented as flat exports |
| zkgroup auth credentials with PNI | Implemented as flat exports |
| zkgroup receipt credentials | Implemented as flat exports |
| zkgroup call-link credentials | Implemented as flat exports |
| zkgroup backup auth credentials | Implemented as flat exports |
| zkgroup group-send endorsements | Implemented as flat exports |
| Media sanitizers | Implemented as flat exports |
| Network chat request/response transport facade | Implemented as flat exports |
| Network unauth pre-key and sealed-sender request helpers | Implemented as flat exports |
| Network authenticated message and upload-form request helpers | Implemented as flat exports |
| Network unauth username lookup request helpers and response parsers | Implemented as flat exports |
| Network unauth account-existence request helper and response parser | Implemented as flat exports |
| Network unauth backup upload-form request helpers | Implemented as flat exports |
| Network pre-key and upload-form response parsers | Implemented as flat exports |
| Network registration session request helpers and response parsers | Implemented as flat exports |
| Network registration account creation request helper and response parser | Implemented as flat exports |
| Browser-clean remaining APIs | None known in the current Node network surface |
| Key transparency, CDSI, SVR-B | Can be implemented, but needs browser transport/protocol design and WASM dependency validation |
| Native network manager, DNS/proxy/TLS routing, native sockets, native cancellable runtime | Cannot be implemented literally in browser; requires browser-backed equivalents |

### Remaining Feasibility Labels

| Label | Items | Reason |
| --- | --- | --- |
| Implemented because it works well in browser | Transport-backed chat requests, message/pre-key/upload/registration/username/account-existence/backup-upload helpers, local crypto, stores, zkgroup, media sanitizers | Uses WASM-local logic plus browser-provided `fetch`/transport |
| Can be implemented, but needs work | Key transparency, CDSI, SVR-B, provisioning facade | Needs protocol extraction from native connection assumptions, browser transport design, and attestation/dependency validation |
| Cannot be implemented literally in browser | Native `Net`/`ConnectionManager`, DNS/proxy/TLS routing, raw sockets, native websocket runtime, native cancellable runtime semantics | Browser security model exposes only browser networking APIs |

## Scope

This browser API now covers one-to-one pre-key session setup, message encrypt/decrypt, and
snapshot-based persistence for browser storage, plus sealed sender, group sender keys, and
username/account-key/zkgroup group-profile/profile-credential/auth-credential/receipt-credential/
call-link-credential/backup-auth-credential/group-send-endorsement/fingerprint/HKDF/AES utility
parity, plus media sanitizer parity and a browser-provided chat transport facade with
unauthenticated pre-key/sealed-sender/username-lookup/account-existence/backup-upload,
authenticated message/upload-form, and registration session and account-creation request helpers.
It does not expose libsignal's native network manager, DNS/proxy/TLS routing, native socket
runtime, CDSI, SVR-B, provisioning, or key-transparency APIs.
