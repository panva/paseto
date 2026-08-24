# Function: PublicKeyFromCryptoKey()

> **PublicKeyFromCryptoKey**(`key`): `Promise`<[`PublicKey`](../interfaces/PublicKey.md)>

Wraps a native ECDSA P-384 public key for use with the built-in v3.public capabilities.

The key usages must include `verify` and the key must be extractable. v3.public includes the
encoded public key in its pre-authentication encoding, so a native handle alone is insufficient.
The exact public-key instance is retained.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Native ECDSA P-384 public key |

## Returns

`Promise`<[`PublicKey`](../interfaces/PublicKey.md)>
