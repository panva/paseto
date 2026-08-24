# paseto

`paseto` is a JavaScript module for Platform-Agnostic Security Tokens (PASETO) and Platform-Agnostic
Serialized Keys (PASERK). This module is designed to work across various Web-interoperable runtimes
including Node.js, browsers, Cloudflare Workers, Deno, Bun, and others.

## [💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find
this module useful, please consider supporting this project by
[becoming a sponsor](https://github.com/sponsors/panva).

## Dependencies: 0

`paseto` has no dependencies and it exports tree-shakeable ESM.

The root `paseto` module is a flat, import-free runtime API. Built-in implementations are published
separately under `paseto/v1/local` through `paseto/v4/public` and use Web Cryptography and other
standard runtime APIs.

## [API Reference](docs/README.md)

`paseto` is distributed via [npmjs.com](https://www.npmjs.com/package/paseto),
[jsdelivr.com](https://www.jsdelivr.com/package/npm/paseto), and
[github.com](https://github.com/panva/paseto).

## Quick Start

Local-purpose tokens use a symmetric key for authenticated encryption.

```ts
import { LocalProtocol } from 'paseto'
import { DecryptFactory, EncryptFactory, GenerateKeyFactory } from 'paseto/v3/local'

const v3 = new LocalProtocol(GenerateKeyFactory, EncryptFactory, DecryptFactory)
const key = await v3.GenerateKey()
const token = await v3.Encrypt(key, { sub: 'alice', role: 'admin' })

const { claims } = await v3.Decrypt(key, token)
console.log(claims.sub) // "alice"
```

Public-purpose tokens use an asymmetric signing key pair.

```ts
import { PublicProtocol } from 'paseto'
import { GenerateKeyPairFactory, SignFactory, VerifyFactory } from 'paseto/v4/public'

const v4 = new PublicProtocol(GenerateKeyPairFactory, SignFactory, VerifyFactory)
const { publicKey, secretKey } = await v4.GenerateKeyPair()
const token = await v4.Sign(secretKey, { sub: 'alice' })

const { claims } = await v4.Verify(publicKey, token)
```

## [Examples](examples/README.md)

The [examples directory](examples/README.md) demonstrates local-purpose tokens, public-purpose
tokens, PASERK serialization, and external implementation integration.

## Composition and Tree Shaking

`LocalProtocol` and `PublicProtocol` accept one or more capability factories from one protocol
version and purpose. Every selected operation is exposed directly on the resulting protocol.
Operations that were not selected are absent from both the runtime object and its TypeScript type.

```ts
import { LocalProtocol } from 'paseto'
import { DecryptFactory, ImportKeyFactory } from 'paseto/v3/local'

const v3 = new LocalProtocol(DecryptFactory, ImportKeyFactory)
const key = await v3.ImportKey(serialized)
const result = await v3.Decrypt(key, token)
```

Import only the operations an application needs. Each named export from a version-and-purpose
subpath is independently tree-shakeable, so a bundler can discard other versions, purposes, token
operations, key lifecycle operations, and PASERK operations.

The version-independent `InspectFooter(token)` root export extracts an unauthenticated footer for
key routing. Its result must not be trusted until `Decrypt` or `Verify` authenticates the token.

## Native CryptoKey Adapters

Built-in subpaths expose standalone adapters when a protocol key can be represented by one Web
Cryptography `CryptoKey`. They validate its role, algorithm, and usages and are not protocol
capabilities.

| Subpath            | Adapter     | Required `CryptoKey`                                                               |
| :----------------- | :---------- | :--------------------------------------------------------------------------------- |
| `paseto/v1/local`  | `LocalKey`  | Secret HKDF key with the `deriveBits` usage                                        |
| `paseto/v3/local`  | `LocalKey`  | Secret HKDF key with the `deriveBits` usage                                        |
| `paseto/v1/public` | `PublicKey` | Public RSA-PSS key using SHA-384, a 2048-bit modulus, exponent 65537, and `verify` |
| `paseto/v1/public` | `SecretKey` | Private RSA-PSS key using SHA-384, a 2048-bit modulus, exponent 65537, and `sign`  |
| `paseto/v2/public` | `PublicKey` | Public Ed25519 key with the `verify` usage                                         |
| `paseto/v2/public` | `SecretKey` | Private Ed25519 key with the `sign` usage                                          |
| `paseto/v3/public` | `PublicKey` | Extractable public ECDSA P-384 key with the `verify` usage                         |
| `paseto/v3/public` | `SecretKey` | Private ECDSA P-384 key with the `sign` usage                                      |
| `paseto/v4/public` | `PublicKey` | Public Ed25519 key with the `verify` usage                                         |
| `paseto/v4/public` | `SecretKey` | Private Ed25519 key with the `sign` usage                                          |

`LocalKeyFromCryptoKey` synchronously wraps a native HKDF key for v1.local or v3.local.
`LocalKeyToCryptoKey` returns the exact same handle.

```ts
import { LocalProtocol } from 'paseto'
import { EncryptFactory, LocalKeyFromCryptoKey, LocalKeyToCryptoKey } from 'paseto/v3/local'

const cryptoKey = await crypto.subtle.importKey(
  'raw',
  crypto.getRandomValues(new Uint8Array(32)),
  'HKDF',
  false,
  ['deriveBits'],
)
const key = LocalKeyFromCryptoKey(cryptoKey)
const v3 = new LocalProtocol(EncryptFactory)

await v3.Encrypt(key, { sub: 'alice' })
console.log(LocalKeyToCryptoKey(key) === cryptoKey) // true
```

`PublicKeyFromCryptoKey` asynchronously wraps a native verification key and `PublicKeyToCryptoKey`
returns the exact same handle. v1.public, v2.public, and v4.public use that handle directly for
verification and accept both extractable and non-extractable public keys. v3.public requires an
extractable public key because its pre-authentication encoding includes the encoded public key,
which cannot be recovered from a non-extractable `CryptoKey`.

`SecretKeyFromCryptoKey` asynchronously wraps a native private key. It obtains the corresponding
public key with `SubtleCrypto.getPublicKey()`, falling back to JWK export and public-key import when
the private key is extractable. A non-extractable private key therefore requires a runtime that
implements `SubtleCrypto.getPublicKey()`. `SecretKeyToCryptoKey` synchronously returns the exact
private-key handle that was supplied.

```ts
import { PublicProtocol } from 'paseto'
import {
  PublicKeyFromCryptoKey,
  PublicKeyToCryptoKey,
  SecretKeyFromCryptoKey,
  SecretKeyToCryptoKey,
  SignFactory,
  VerifyFactory,
} from 'paseto/v4/public'

const pair = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair
const publicKey = await PublicKeyFromCryptoKey(pair.publicKey)
const secretKey = await SecretKeyFromCryptoKey(pair.privateKey)
const v4 = new PublicProtocol(SignFactory, VerifyFactory)

const token = await v4.Sign(secretKey, { sub: 'alice' })
await v4.Verify(publicKey, token)

console.log(PublicKeyToCryptoKey(publicKey) === pair.publicKey) // true
console.log(SecretKeyToCryptoKey(secretKey) === pair.privateKey) // true
```

Returning a `CryptoKey` handle does not export its key material or change its extractability.
Non-extractable v1.public, v2.public, and v4.public verification keys remain usable by `Verify` but
cannot be serialized as PASERK public keys. Non-extractable local and secret keys likewise cannot be
serialized or protected with PASERK operations that require their plaintext key material.

Web Cryptography only permits non-extractable HKDF keys and does not expose their input length. The
local-key adapter can validate the key type, algorithm, and usages, but the caller must ensure it
was imported from exactly 32 bytes as required by PASETO.

## Extension Implementations

The root module exports a creator for every PASETO and PASERK operation in versions 1 through 4.
Creators such as `LocalEncrypt`, `LocalDecrypt`, `PublicSign`, and `PublicVerify` bind a low-level
`{ version, run }` implementation to a composable capability factory.

For example, a runtime with a native v4.local implementation can bind its own opaque key handle to
the protocol.

```ts
import { LocalDecrypt, LocalProtocol } from 'paseto'

interface NativeLocalKey {
  readonly algorithm: { readonly name: 'native-paseto-v4.local' }
  readonly extractable: false
  readonly type: 'secret'
  readonly handle: bigint
}

declare function nativeDecrypt(
  key: NativeLocalKey,
  payload: Uint8Array,
  footer: Uint8Array,
  implicitAssertion: Uint8Array,
): Promise<Uint8Array>

const DecryptFactory = LocalDecrypt({ version: 4, run: nativeDecrypt })
const v4 = new LocalProtocol(DecryptFactory)
```

An implementation can use Web Cryptography keys, HSM handles, native-addon keys, or its own opaque
key objects. Custom capabilities that exchange keys must agree on their key representation; this is
intentionally the composer's responsibility.

The creator handles claims, token framing, footers, and implicit assertions where applicable. Its
`run` implementation only performs the supplied key or cryptographic operation. This makes it
possible to provide one missing operation without retaining implementations for sibling operations.

Factories are recognized across installed or bundled copies of `paseto`, so an extension does not
need to share the application's physical module instance. The shared runtime marker used for this is
not an authenticity or security boundary. Compose only factories from code you trust.

`KDF_ARGON2ID` is the built-in Web Cryptography Argon2id factory. Password-based implementations can
use it or provide their own `Argon2idFactory`.

The repository's [`examples/noble-suite`](examples/noble-suite/README.md) is a private reference
implementation used by the test suite. It demonstrates the same public extension API but it is not
published, supported as a separate package, or loaded by `paseto` at runtime.

## Supported Runtimes

This module is compatible with JavaScript runtimes that support the utilized Web API globals and
standard built-in objects.

The following runtimes are supported _(this is not an exhaustive list)_:

- Bun
- Browsers
- Cloudflare Workers
- Deno
- Electron
- Node.js

Some built-in capabilities may not be available depending on the runtime's Web Cryptography
implementation. The extension API can provide those capabilities without changing how protocols are
composed.

## Protocol Support

Built-in implementations are provided where the required primitives are exposed by standard runtime
APIs. Every other operation can be supplied through the [extension API](#extension-implementations).

### PASETO

The table lists the token operations included with each version-and-purpose subpath. Local-purpose
tokens are authenticated and encrypted; public-purpose tokens are signed and verified.

| Version | `local` `Encrypt` / `Decrypt` | `public` `Sign` / `Verify` |
| :------ | :---------------------------- | :------------------------- |
| v1      | Built in                      | Built in                   |
| v2      | Extension API                 | Built in                   |
| v3      | Built in                      | Built in                   |
| v4      | Extension API                 | Built in                   |

Every local subpath also includes symmetric-key generation and PASERK import/export. Every public
subpath includes signing-key-pair generation, public and secret PASERK import/export, and public-key
derivation.

Symmetric, signing, wrapping, and sealing secret keys are non-extractable by default. Pass
`{ extractable: true }` when generating, importing, unwrapping, or unsealing one if it will later be
exported or protected with PASERK. Public keys are always extractable.

### PASERK

The table lists the PASERK operations built into each version. “Local” refers to symmetric PASETO
keys, while “public” and “secret” refer to the two halves of a public-purpose signing key pair.

| Version | Plaintext serialization | Identifiers   | PIE wrapping  | Password wrapping | Sealing       |
| :------ | :---------------------- | :------------ | :------------ | :---------------- | :------------ |
| k1      | local, public, secret   | lid, pid, sid | local, secret | local, secret     | Extension API |
| k2      | local, public, secret   | Extension API | Extension API | Extension API     | Extension API |
| k3      | local, public, secret   | lid, pid, sid | local, secret | local, secret     | local         |
| k4      | local, public, secret   | Extension API | Extension API | Extension API     | Extension API |

Every version-and-purpose subpath independently exports wrapping-key generation, import, and export.
These keys are consumed by `local-wrap.pie` and `secret-wrap.pie` implementations, whether the
wrapping operation itself is built in or supplied through the extension API.

PASERK ID operations accept any compatible serialization for that key, including wrapped,
password-wrapped, and sealed forms. Custom wrapping implementations preserve their PASERK prefix;
built-in wrapping factories specialize it to `pie`.

`v2.local` and `v4.local` tokens, together with most k2 and k4 key-protection operations, require
BLAKE2b, XChaCha20, or Ed25519-to-X25519 conversion. PASERK k1 sealing requires a constant-time raw
RSA operation. These operations are covered by the repository-only reference implementations using
the same public extension API.

The runnable [`v2.local`](examples/04-v2-local-with-noble.ts) and
[`v4.local`](examples/05-v4-local-with-noble.ts) examples show how to provide the missing token
operations directly with `@noble/ciphers` and `@noble/hashes`.

Generated tokens receive `iat` and `exp` claims by default. Token consumers validate temporal claims
and can additionally require an expected audience, issuer, subject, token identifier, footer, and
application-specific claims.

## Errors

Protocol, authentication, key, claim, and unavailable-algorithm errors extend
[`PasetoError`](docs/paseto/classes/PasetoError.md). Their `code` is a stable literal from
[`PasetoErrorCode`](docs/paseto/type-aliases/PasetoErrorCode.md). Invalid API arguments and options
use `TypeError` or `RangeError`.

## Specifications

- [PASETO specification](https://github.com/paseto-standard/paseto-spec)
- [PASERK specification](https://github.com/paseto-standard/paserk)

The implementations are tested using the official project test vectors.

## Supported Versions

| Version                                           | Security Fixes 🔑 | Other Bug Fixes 🐞 | New Features ⭐ |
| ------------------------------------------------- | ----------------- | ------------------ | --------------- |
| [v4.x](https://github.com/panva/paseto/tree/v4.x) | [Security Policy] | ✓                  | ✓               |

[Security Policy]: https://github.com/panva/paseto/security/policy
