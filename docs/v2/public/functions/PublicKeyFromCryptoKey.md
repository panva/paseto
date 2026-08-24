# Function: PublicKeyFromCryptoKey()

> **PublicKeyFromCryptoKey**(`key`): `Promise`<[`PublicKey`](../interfaces/PublicKey.md)>

Wraps a native Ed25519 public key for use with the built-in v2.public capabilities.

The key usages must include `verify`. The exact public-key instance is retained, including when
it is non-extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Native Ed25519 public key |

## Returns

`Promise`<[`PublicKey`](../interfaces/PublicKey.md)>
