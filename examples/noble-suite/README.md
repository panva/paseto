# Noble Reference Implementations

This private directory contains PASETO and PASERK reference implementations used by the `paseto`
test suite. They use Paul Miller's [@noble](https://paulmillr.com/noble/) cryptographic libraries to
exercise primitives that Web Cryptography does not expose or does not compose in the way these
protocols require.

This is not a published or supported package and it is not loaded by `paseto` at runtime. Its
capability factories conform to the public extension API exported by `paseto`; applications can
provide their own implementations through the same API.

## Included Implementations

The suite provides reference implementations for:

- PASETO v2 and v4 local and public operations
- PASERK k2 and k4 identifiers, PIE wrapping, password wrapping, and sealing
- Keyed and unkeyed BLAKE2b with variable-length output
- XChaCha20 and XChaCha20-Poly1305
- Ed25519 key conversion to X25519
- Argon2id

`k1-seal.node.ts` separately exercises PASERK k1 sealing using Node.js constant-time raw RSA
operations. Raw RSA is not available through Web Cryptography and must not be emulated using
JavaScript big integers.

## Usage in Tests

`V2_LOCAL`, `V2_PUBLIC`, `V4_LOCAL`, and `V4_PUBLIC` are flat maps of atomic capability factories.
Spread a map's values into `LocalProtocol` or `PublicProtocol` to compose its complete reference
implementation.

```ts
import { LocalProtocol } from 'paseto'
import { V4_LOCAL } from './index.ts'

const complete = new LocalProtocol(...Object.values(V4_LOCAL))
const decryptOnly = new LocalProtocol(V4_LOCAL.Decrypt, V4_LOCAL.ImportKey)
```

Tests that require deterministic randomness or a particular Argon2id implementation use
`createLocalCapabilities(version, options)` or `createPublicCapabilities(version, options)` and
compose the returned factories in the same way.

Applications should use the atomic creators documented by the root `paseto` module with an
implementation they control.
