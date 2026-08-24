# Security Policy

## Supported Versions

The following major versions are currently supported with security updates.

| Version                                           | End-of-life |
| ------------------------------------------------- | ----------- |
| [v4.x](https://github.com/panva/paseto/tree/v4.x) | TBD         |

End-of-life for the current release will be determined before its successor is released.

## Reporting a Vulnerability

Report vulnerabilities through the
[project's security advisory](https://github.com/panva/paseto/security/advisories/new). Do not open
a public issue for a suspected vulnerability.

Using the project's security advisory does not authorize reporters to disclose details to or
coordinate with third-party CVE Numbering Authorities without the maintainers' prior explicit
consent.

## Threat Model

`paseto` implements PASETO versions 1 through 4 and their corresponding PASERK operations. Its
built-in factories are intended for applications with a trusted Web Cryptography runtime. The public
factory interfaces also admit implementations backed by other trusted cryptographic libraries,
native bindings, or hardware.

The library considers attackers that can observe, modify, replay, truncate, reorder, and inject
tokens, PASERKs, footers, implicit assertions, claims, passwords, and serialized key material. A
compromised application, runtime, operating system, random-number generator, or key store is outside
the threat model.

### Trust assumptions

An application trusts the cryptographic implementation it selects, that implementation's
cryptographically secure random-number generator and key store, and the surrounding runtime.
Built-in factories use Web Cryptography. JavaScript does not provide guaranteed secure memory or
constant-time execution; side-channel resistance ultimately depends on the selected implementation,
runtime, and operating environment.

The published `paseto` package has no runtime dependencies. Repository tests use `@noble/*` as
development-only reference implementations; those packages are not loaded by `paseto` at runtime.

### Application responsibilities

Applications are responsible for secure key storage, key rotation, choosing the correct PASETO
version and purpose, and keeping implicit assertions consistent between producers and consumers.
Applications must also enforce their own authorization, revocation, and replay policies.

Web Cryptography requires HKDF keys to be non-extractable and does not expose their input length.
`LocalKeyFromCryptoKey()` therefore cannot validate the key-material length. Applications supplying
an HKDF `CryptoKey` are responsible for ensuring that it was imported from exactly 32 bytes;
acceptance of a key whose length cannot be inspected is outside the threat model.

A footer read with `InspectFooter()` is untrusted until the complete token is successfully verified
or decrypted. `InspectFooter()` does not inspect the token payload. Applications must not make
security decisions from an inspected footer alone.

Diagnostic error classes and messages must not be forwarded directly to an attacker. Normalize
externally visible failures where distinct errors could become a token, key, or password oracle.

Password-wrapped PASERKs accept resource-intensive parameters. Consumers should retain the default
unwrap limits or configure stricter limits before processing attacker-controlled inputs.

Applications are responsible for bounding attacker-controlled input before passing it to this
module. `paseto` intentionally does not impose general token, PASERK, JSON size, JSON depth, or
claim count limits.

The published package does not implement PASERK `k1.seal` because Web Cryptography does not expose
the required constant-time raw RSA operation. Repository tests use a private Node.js native-crypto
reference for official-vector coverage; a JavaScript big-integer fallback would not provide an
acceptable side-channel guarantee.

Versions 1 and 2 are provided for protocol interoperability. Versions 3 and 4 are their respective
NIST-oriented and Sodium-oriented successors. Applications should not silently accept a token
version or purpose other than the one they explicitly configured.

### Non-goals

The library does not provide token storage, transport security, key distribution, revocation, replay
detection, application authorization, or protection against a compromised host. Plaintext length and
any token footer remain observable.

The following are not considered vulnerabilities in this project: prototype pollution elsewhere in
an application, debugger or process-memory access, a compromised JavaScript runtime, insecure key
storage, application-level authorization errors, or denial of service where an application has
accepted oversized input or disabled or raised documented password-unwrapping limits.
