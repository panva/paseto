# Function: SecretKeyFromCryptoKey()

> **SecretKeyFromCryptoKey**(`key`): `Promise`<[`SecretKey`](../interfaces/SecretKey.md)>

Wraps a native Ed25519 private key for use with the built-in v2.public capabilities.

The key usages must include `sign`. The exact private-key instance is retained. Its public key is
obtained with `SubtleCrypto.getPublicKey()` or, when extractable, by exporting its JWK.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Native Ed25519 private key |

## Returns

`Promise`<[`SecretKey`](../interfaces/SecretKey.md)>
