# Type Alias: CryptoKey

> **CryptoKey** = *typeof* `globalThis` *extends* `object` ? `Extract`<`R`, { `type`: `string`; }> : `CryptoKeyStructuralFallback`

A Web Cryptography key as declared by the host runtime.

This aliases the key type returned by the host's `SubtleCrypto.generateKey()` API when it is
exposed on `globalThis`. A structural fallback keeps the package portable to TypeScript projects
that do not include DOM or Node.js ambient types.
