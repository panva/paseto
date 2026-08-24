# Function: PublicKeyFromCryptoKey()

> **PublicKeyFromCryptoKey**(`key`): `Promise`<[`PublicKey`](../interfaces/PublicKey.md)>

Wraps a native RSA-PSS public key for use with the built-in v1.public capabilities.

The key must use SHA-384, a 2048-bit modulus, exponent 65537, and include the `verify` usage. The
exact public-key instance is retained, including when it is non-extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Native RSA-PSS public key |

## Returns

`Promise`<[`PublicKey`](../interfaces/PublicKey.md)>
