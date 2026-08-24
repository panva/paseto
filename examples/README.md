# Examples

This directory contains practical examples demonstrating PASETO, PASERK, and external implementation
integration.

Each example selects only the capability factories or operation creators it needs. `LocalProtocol`
and `PublicProtocol` expose exactly the selected operations, allowing a bundler to discard other
versions, purposes, token operations, key lifecycle operations, and PASERK operations.

## Token Examples

### [01-local.ts](01-local.ts)

Local-purpose PASETO using only standard runtime APIs. Demonstrates:

- Generating a symmetric key
- Encrypting a `v3.local` token
- Authenticating and decrypting the token

### [02-public.ts](02-public.ts)

Public-purpose PASETO using only standard runtime APIs. Demonstrates:

- Generating an asymmetric signing key pair
- Signing a `v4.public` token
- Authenticating the token and verifying its signature

## `@noble` Local Examples

Each example implements the version-bound `LocalKey` type from `paseto/v2/local` or
`paseto/v4/local`. Custom operations define their own key implementation because keys created by the
built-in capabilities are intentionally opaque to external implementations.

### [04-v2-local-with-noble.ts](04-v2-local-with-noble.ts)

`v2.local` using `@noble/ciphers` and `@noble/hashes` through the extension API. Demonstrates:

- Defining an opaque application key type
- Providing key generation, encryption, and decryption capability factories
- Composing only those capabilities into a `v2.local` protocol

### [05-v4-local-with-noble.ts](05-v4-local-with-noble.ts)

`v4.local` using `@noble/ciphers` and `@noble/hashes` through the extension API. Demonstrates:

- Implementing the v4.local BLAKE2b key derivation and authentication steps
- Providing key generation, encryption, and decryption capability factories
- Producing and consuming a token with an implicit assertion

## PASERK Example

### [03-paserk.ts](03-paserk.ts)

PASERK key serialization without selecting any token operation. Demonstrates:

- Exporting an extractable local key
- Importing its plaintext PASERK serialization
- Calculating its PASERK key identifier

## External Implementation Integration

### [noble-suite/](noble-suite/)

Repository-only `@noble/*` reference implementations used to test primitives that Web Cryptography
does not expose. This directory is private and is not published or supported as a separate package.

The reference implementations use the same public operation creators exported by `paseto`, such as
`LocalEncrypt`, `LocalDecrypt`, `PublicSign`, and `PublicVerify`. Applications can provide their own
key representations and implementations through those creators, then compose them alongside
compatible built-in operations.

## Running Examples

Examples run directly with Node.js 22.19.0 or newer.

```bash
git clone https://github.com/panva/paseto.git
cd paseto
npm install
node examples/01-local.ts
node examples/04-v2-local-with-noble.ts
node examples/05-v4-local-with-noble.ts
```
