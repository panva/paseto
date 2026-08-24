# Function: SecretKeyFromCryptoKey()

> **SecretKeyFromCryptoKey**(`key`): `Promise`<[`SecretKey`](../interfaces/SecretKey.md)>

Wraps a native RSA-PSS private key for use with the built-in v1.public capabilities.

The key must use SHA-384, a 2048-bit modulus, exponent 65537, and include the `sign` usage. The
exact private-key instance is retained. Its public key is obtained with
`SubtleCrypto.getPublicKey()` or, when extractable, by exporting its JWK.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Native RSA-PSS private key |

## Returns

`Promise`<[`SecretKey`](../interfaces/SecretKey.md)>
